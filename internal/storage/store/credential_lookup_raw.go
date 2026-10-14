// credential_lookup_raw.go — H3 (PERF-3, docs/specs/read-path-caching.md):
// a hand-written database/sql prepared statement for
// GetMachineIdentityCredentialWithIdentityStateByHash, the one query on the
// machine-token read path that runs on EVERY request regardless of any
// cache (it's the live revocation re-check — PR-1/PR-2 deliberately never
// cache it, see those PRs' own spec sections) and was PERF-2's own
// highest-flagged GORM-reflection cost (`gorm.io/gorm.Scan`,
// `reflect.(*rtype).Implements`). Scans directly into named Go variables —
// no reflection, no query-builder allocation — then assembles the same
// *models.MachineIdentityCredential the GORM path returns.
//
// GORM remains the source of truth for the query logic and schema: this
// file's SQL text is a literal transcription of
// GetMachineIdentityCredentialWithIdentityStateByHash's own
// Table/Select/Joins/Where chain, and
// TestCredentialLookupRaw_MatchesGORM_Fuzz (fuzzed hashes, fuzzed row
// shapes) asserts the two paths return byte-identical results for every
// input the corpus generates. If the GORM method's query ever changes,
// that test is the thing that will catch this file going stale, not a
// human remembering to keep them in sync.
//
// Only used when ls is the ROOT LocalStorage (ls.rawStmts != nil) — a
// transaction-scoped LocalStorage (see WithTransaction) does not get this
// field populated, the same deliberate "nil on a clone, falls back to the
// always-correct original" pattern entry.go's own auditFlusher field
// documents. This read is never issued inside an explicit write
// transaction in practice (it's a pure auth-path read), so the fallback
// path is not a hot path losing its optimization, just a safety net.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Column name note: models.MachineIdentityCredential.AllowedCIDRs is
// NOT "allowed_cidrs" — GORM's default naming strategy treats "CIDRs" as
// four separate word boundaries (C/I/D/Rs), producing "allowed_c_id_rs".
// Confirmed against the real migrated schema on BOTH SQLite
// (TestCredentialLookupRaw_MatchesGORM_Fuzz) and Postgres (checked
// one-off against this session's own pve01/local Postgres container via
// information_schema.columns against the real production migration path —
// not committed as a test, since internal/storage/store cannot import
// internal/storage, the package that owns the production migration entry
// point, without an import cycle; TestCredentialLookupRaw_MatchesGORM_Fuzz
// against SQLite plus every other test in this package exercising the real
// GetMachineIdentityCredentialWithIdentityStateByHash is the committed
// coverage), not assumed — exactly the kind of column-name guess this
// repo's own "prefer the machine-checked over the asserted" principle
// warns against baking into raw SQL by hand.
// #nosec G101 -- a SQL query string referencing column names like
// "token_hash" is not a hardcoded credential; the actual token is a `$1`
// bind parameter, never embedded in this string.
const credentialLookupRawQuery = `
SELECT c.id, c.machine_identity_id, c.name, c.token_hash, c.token_prefix,
       c.allowed_c_id_rs, c.last_used_at, c.expires_at, c.revoked, c.created_at,
       c.classification, m.state AS identity_state
FROM machine_identity_credentials c
JOIN machine_identities m ON m.id = c.machine_identity_id
WHERE c.token_hash = $1`

// rawStatements holds prepared statements for the root LocalStorage only
// (see this file's own header for why a transaction-scoped copy never gets
// one). Lazily prepared on first use, guarded by sync.Once, so opening a
// LocalStorage that never exercises this path never pays for it.
type rawStatements struct {
	once             sync.Once
	prepErr          error
	credentialLookup *sql.Stmt
}

func (ls *LocalStorage) prepareRawStatements() error {
	if ls.rawStmts == nil {
		return errBusinessNoRawStatements
	}
	ls.rawStmts.once.Do(func() {
		sqlDB, err := ls.db.DB()
		if err != nil {
			ls.rawStmts.prepErr = err
			return
		}
		stmt, err := sqlDB.Prepare(rebindForDialect(ls.db.Dialector.Name(), credentialLookupRawQuery))
		if err != nil {
			ls.rawStmts.prepErr = err
			return
		}
		ls.rawStmts.credentialLookup = stmt
	})
	return ls.rawStmts.prepErr
}

var errBusinessNoRawStatements = errors.New("raw statements unavailable on a transaction-scoped store")

// rebindForDialect rewrites $1-style placeholders to ?-style for SQLite —
// SQLite's driver does not understand Postgres positional parameters.
// Postgres gets the query unchanged. This package's only two backends are
// SQLite and Postgres (see internal/storage/factory.go); a third dialect
// would need its own case here, which a wrong result from
// TestCredentialLookupRaw_MatchesGORM_Fuzz run against that dialect would
// surface immediately (the fuzz test runs against whichever backend
// KEYORIX_TEST_PG_DSN selects, same as this package's other dialect-aware
// tests).
func rebindForDialect(dialect, query string) string {
	if dialect == "sqlite" {
		return strings.ReplaceAll(query, "$1", "?")
	}
	return query
}

// getMachineIdentityCredentialWithIdentityStateByHashRaw is the H3 fast
// path. Returns (nil, false, nil) to signal "not available, use the GORM
// path instead" (no rawStmts, or prepare failed) — never an error the
// caller would surface as a user-facing failure for what is purely a
// query-strategy choice; GetMachineIdentityCredentialWithIdentityStateByHash
// falls back to the GORM query in that case.
func (ls *LocalStorage) getMachineIdentityCredentialWithIdentityStateByHashRaw(ctx context.Context, hash string) (*models.MachineIdentityCredential, string, bool, error) {
	if ls.rawStmts == nil {
		return nil, "", false, nil
	}
	var (
		c             *models.MachineIdentityCredential
		identityState string
		err           error
	)
	if ls.nativeReads != nil {
		// Postgres: the same statement on the native pool (native_reads.go).
		c, identityState, err = scanCredentialRow(ls.nativeReads.QueryRow(ctx, credentialLookupRawQuery, hash))
		if errors.Is(err, pgx.ErrNoRows) {
			err = sql.ErrNoRows
		}
	} else {
		if err := ls.prepareRawStatements(); err != nil {
			return nil, "", false, nil //nolint:nilerr // prepare failure -> caller falls back to GORM, not a user-facing error
		}
		c, identityState, err = scanCredentialRow(ls.rawStmts.credentialLookup.QueryRowContext(ctx, hash))
	}
	if err != nil {
		// Mirrors GetMachineIdentityCredentialWithIdentityStateByHash's own
		// unconditional ErrorNotFound wrap (both sql.ErrNoRows and any other
		// driver error map to the same caller-visible message there) — kept
		// byte-identical so the differential test can compare error TEXT too,
		// not just the success case.
		return nil, "", true, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return c, identityState, true, nil
}

// scanCredentialRow scans one row of credentialLookupRawQuery, from either
// driver, into the credential and its identity state.
func scanCredentialRow(row interface{ Scan(dest ...any) error }) (*models.MachineIdentityCredential, string, error) {
	var c models.MachineIdentityCredential
	var identityState string
	var lastUsedAt, expiresAt, createdAt sql.NullTime
	err := row.Scan(
		&c.ID, &c.MachineIdentityID, &c.Name, &c.TokenHash, &c.TokenPrefix,
		&c.AllowedCIDRs, &lastUsedAt, &expiresAt, &c.Revoked, &createdAt,
		&c.Classification, &identityState,
	)
	if err == nil {
		err = assignCredentialTimes(&c, lastUsedAt, expiresAt, createdAt)
	}
	return &c, identityState, err
}

// assignCredentialTimes copies the scanned times into c. The scan goes through
// sql.NullTime rather than straight into *time.Time / **time.Time: database/sql
// converts the value exactly the same way either way, but with Go 1.27's
// column scanner the pgx driver checks every destination type against three
// interfaces by reflection on each row, and that check walks time.Time's whole
// method set. sql.NullTime answers the first check at once. created_at is NOT
// NULL; a NULL there is an error, as scanning it into a time.Time was.
func assignCredentialTimes(c *models.MachineIdentityCredential, lastUsedAt, expiresAt, createdAt sql.NullTime) error {
	if !createdAt.Valid {
		return errCredentialCreatedAtNull
	}
	c.CreatedAt = createdAt.Time
	if lastUsedAt.Valid {
		c.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		c.ExpiresAt = &expiresAt.Time
	}
	return nil
}

var errCredentialCreatedAtNull = errors.New("machine_identity_credentials.created_at is NULL")
