// restore_postgres.go holds `admin restore`'s Postgres-TARGET-specific
// pieces (design-b3-backup-v2.md §4's "Postgres target restore" bullet):
// everything restore.go's SQLite-shaped helpers (readExistingDatabase
// AuditEventCount, destinationEventsNewerThan, removeStaleSQLiteSidecars,
// verifyRestoredAudit's OpenSQLiteReadOnly) cannot do against a Postgres
// target, because there is no single database FILE to stat/open directly.
package admin

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"gorm.io/gorm/schema"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// postgresWitnessAnchorDir returns a stable, host-local directory to anchor
// the rollback-protection witness file against (design §6.3) when the
// restore target is Postgres, which has no single database FILE for
// auditverify.WitnessPath's usual "sibling to the database" convention to
// resolve against. Uses the FIRST key-material file's own directory --
// already the one piece of genuinely host-local state a Postgres deployment
// has (key files are always local filesystem paths regardless of storage
// backend), and already effectively "this deployment's identity" the same
// way a SQLite db path already is (one config file/key-material set per
// deployment in both cases).
func postgresWitnessAnchorDir(cfg *config.Config) (string, error) {
	paths, err := expectedKeyFilePaths(cfg)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", fmt.Errorf("internal error: no key-material files to anchor the rollback-protection witness against")
	}
	return filepath.Dir(paths[0]), nil
}

// postgresTargetIdentityPath synthesizes the string restore.go's shared,
// backend-agnostic helpers (checkRollbackProtection, refuseNonEmptyExisting's
// SQLite sibling) treat as "dbPath" purely for ITS DIRECTORY COMPONENT (via
// auditverify.WitnessPath) -- never opened as a file itself for Postgres.
func postgresTargetIdentityPath(cfg *config.Config) (string, error) {
	dir, err := postgresWitnessAnchorDir(cfg)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "postgres-target"), nil
}

// postgresOpenSQL opens cfg's configured Postgres DSN via database/sql
// directly (the "pgx" driver, already registered process-wide by
// internal/auditverify's own blank import) -- a short-lived raw connection
// for the small existence/count queries below, independent of the
// REPEATABLE READ snapshot connection backup uses or the GORM connection
// migration/LoadArchive use.
func postgresOpenSQL(cfg *config.Config) (*sql.DB, error) {
	cc, err := config.ResolvePostgresConnConfig(&cfg.Storage.Database)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db := stdlib.OpenDB(*cc)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return db, nil
}

// refuseNonEmptyPostgresTarget is refuseNonEmptyExisting's Postgres
// equivalent: refuses if the target database already has ANY user table
// (information_schema.tables, excluding Postgres/pg_catalog's own internal
// schemas) -- there is no single "does the database file exist and have
// content" check the way there is for SQLite, so this asks the same
// question ("is there already something here") the only way that's
// meaningful for a whole database/schema.
func refuseNonEmptyPostgresTarget(cfg *config.Config) error {
	if restoreOverwriteExisting {
		return nil
	}
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return nil // can't connect -- migrateDatabase will surface this loudly on its own; not this check's job
	}
	defer db.Close() //nolint:errcheck

	var count int
	const q = `SELECT COUNT(*) FROM information_schema.tables ` +
		`WHERE table_schema NOT IN ('pg_catalog', 'information_schema')`
	if err := db.QueryRow(q).Scan(&count); err != nil {
		return fmt.Errorf("check target Postgres database for existing tables: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("target Postgres database already has %d table(s) -- restore refuses to overwrite it "+
			"(pass --overwrite-existing if you are certain, e.g. this is a genuine disaster-recovery restore; "+
			"the normal flow is restoring into a fresh/empty database)", count)
	}
	return nil
}

// postgresAuditEventCount is readExistingDatabaseAuditEventCount's Postgres
// equivalent: MAX(id) from audit_events in the TARGET Postgres database, 0
// if the table doesn't exist yet (a fresh/pre-migration database) or the
// database can't be reached at all (nothing to compare against yet).
func postgresAuditEventCount(cfg *config.Config) (int64, error) {
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return 0, nil //nolint:nilerr // unreachable target has nothing to compare against, same as SQLite's os.IsNotExist case
	}
	defer db.Close() //nolint:errcheck

	var count sql.NullInt64
	err = db.QueryRow("SELECT MAX(id) FROM audit_events").Scan(&count)
	if err != nil {
		if isPostgresUndefinedTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read audit_events count from target Postgres database: %w", err)
	}
	return count.Int64, nil
}

// postgresAuditEventsNewerThan is destinationEventsNewerThan's Postgres
// equivalent.
func postgresAuditEventsNewerThan(cfg *config.Config, archiveHead int64) (int64, error) {
	db, err := postgresOpenSQL(cfg)
	if err != nil {
		return 0, nil //nolint:nilerr // unreachable target has nothing newer, same reasoning as postgresAuditEventCount
	}
	defer db.Close() //nolint:errcheck

	var n int64
	// Postgres placeholders are positional ($1, $2, ...), unlike SQLite's
	// "?" -- destinationEventsNewerThan's query text isn't reusable verbatim.
	q := "SELECT COUNT(*) FROM audit_events WHERE id > $1 AND event_type NOT IN ("
	args := []any{archiveHead}
	for i, et := range rollbackBookkeepingEventTypes {
		if i > 0 {
			q += ", "
		}
		q += fmt.Sprintf("$%d", i+2)
		args = append(args, et)
	}
	q += ")"
	if err := db.QueryRow(q, args...).Scan(&n); err != nil { // nosemgrep: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- q's dynamic part is only a "$2,$3,..." placeholder run sized off len(rollbackBookkeepingEventTypes) (a package-level literal slice); every actual value is passed as a parameterized arg, never interpolated
		if isPostgresUndefinedTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("count newer audit events in target Postgres database: %w", err)
	}
	return n, nil
}

// isPostgresUndefinedTable reports whether err is Postgres's "relation does
// not exist" error (SQLSTATE 42P01) -- the fresh/pre-migration-database
// case, not a real error, mirroring the SQLite helpers' own
// strings.Contains(err.Error(), "no such table") check.
func isPostgresUndefinedTable(err error) bool {
	return strings.Contains(err.Error(), "42P01") || strings.Contains(err.Error(), "does not exist")
}

// postgresResyncSchemaCache is its own cache (not internal/backupfmt's --
// unexported to that package), shared across every parseSchemaForResync call
// within one process so repeated schema.Parse calls on the same model don't
// re-walk its struct tags every time.
var postgresResyncSchemaCache sync.Map

// resyncPostgresSequences fixes a real, reproducible gap found live building
// this restore path (design §11.1/H6's version-skip upgrade proof): LoadArchive
// inserts every row with its ORIGINAL, explicit primary-key value (design's
// whole point -- cross-table references must keep resolving), but a Postgres
// SERIAL/BIGSERIAL column's underlying sequence is NEVER auto-advanced by an
// explicit-value INSERT (only a value-omitted one calls nextval()) -- exactly
// the gap pg_dump/pg_restore's own well-known `setval(...)` fixup exists to
// close, which nothing in this restore path was doing.
//
// Left unfixed, the very next auto-generated INSERT on any restored table
// collides with an already-restored row's id: found live as three duplicate-
// key failures on audit_events during this very code path's own POST-restore
// admin.restore_completed audit write and the server's own first-boot startup
// writes (role.assigned, data_retention.policy_configured, license.evaluated),
// and traced to a SECOND, more damaging symptom: whichever pooled Postgres
// connection one of those failed writes leaves in an aborted-transaction
// state serves the very NEXT unrelated request beside it -- observed as the
// first real login attempt against a freshly-restored server returning 401
// (a poisoned connection, not a credentials problem: the same password/hash
// pair succeeds on every later request once that connection cycles). A
// side-by-side control confirmed this is restore-specific -- an equivalent
// fresh (non-restored) Postgres install's first login always succeeds,
// because it has no pre-existing audit_events rows to collide with in the
// first place.
//
// Runs for every model storage.AllModels() defines that GORM would manage
// via a sequence-backed "id" primary key (composite-PK join tables have no
// single sequence to resync and are skipped, matching
// internal/backupfmt/order.go's own ChildHasIDColumn convention for the
// identical structural reason) -- registry-driven, not a hand-picked table
// list, so a model added to the registry later is covered automatically.
func resyncPostgresSequences(db *sql.DB) error {
	for _, m := range storage.AllModels() {
		s, err := schema.Parse(m, &postgresResyncSchemaCache, schema.NamingStrategy{})
		if err != nil {
			return fmt.Errorf("parse schema for %T: %w", m, err)
		}
		if s.LookUpField("ID") == nil {
			continue // composite-PK join table -- no single sequence to resync
		}
		// #nosec G201 -- s.Table/idCol come from parseSchema resolving storage.AllModels()'s
		// compiled-in Go structs via GORM's own naming strategy, never from archive or request content.
		q := fmt.Sprintf( // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query
			`SELECT setval(pg_get_serial_sequence('%s', 'id'), COALESCE((SELECT MAX(id) FROM %s), 1), `+
				`(SELECT MAX(id) FROM %s) IS NOT NULL)`,
			s.Table, quoteIdentPG(s.Table), quoteIdentPG(s.Table))
		if _, err := db.Exec(q); err != nil { // nosemgrep: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- q is built entirely from s.Table above, never from archive/request content; see the #nosec G201 note
			return fmt.Errorf("resync sequence for table %q: %w", s.Table, err)
		}
	}
	return nil
}

// quoteIdentPG double-quotes a Postgres identifier this package itself
// derived from a Go struct's own table name (never operator/archive input),
// matching the same identifier set referenceEdges()/AllModels() already
// trust elsewhere in this codebase.
func quoteIdentPG(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// verifyRestoredAuditPostgres is verifyRestoredAudit's Postgres equivalent,
// using auditverify.OpenPostgres (already existing, backend-neutral
// infrastructure -- internal/auditverify's own independence requirement
// means it already speaks both dialects) instead of OpenSQLiteReadOnly.
func verifyRestoredAuditPostgres(cfg *config.Config) error {
	cc, err := config.ResolvePostgresConnConfig(&cfg.Storage.Database)
	if err != nil {
		return fmt.Errorf("open restored database for automatic verify-audit: %w", err)
	}
	db, err := auditverify.OpenPostgresConfig(cc)
	if err != nil {
		return fmt.Errorf("open restored database for automatic verify-audit: %w", err)
	}
	defer db.Close() //nolint:errcheck
	return runVerifyRestoredAudit(cfg, db)
}
