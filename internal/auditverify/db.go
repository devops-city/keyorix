package auditverify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	// Drivers registered directly with database/sql — no GORM, no
	// storage.Storage, per this package's independence requirement (doc.go).
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Backend identifies which SQL dialect a DB was opened against — needed
// only to pick the right placeholder syntax (SQLite/`?` vs Postgres/`$n`);
// every query issued is otherwise identical across both.
type Backend int

const (
	BackendSQLite Backend = iota
	BackendPostgres
)

// DB is a minimal, read-oriented handle over an audit database artifact.
type DB struct {
	sql     *sql.DB
	backend Backend
}

// OpenSQLiteReadOnly opens a SQLite file read-only (file:<path>?mode=ro) —
// it never writes to the artifact being verified, and works unmodified
// against a copy taken from a live deployment.
func OpenSQLiteReadOnly(path string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro", path)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	return &DB{sql: sqlDB, backend: BackendSQLite}, nil
}

// OpenPostgres opens a Postgres DSN via pgx. A read-only DB role is a
// deployment-level concern (GRANT SELECT ON audit_events, audit_checkpoints,
// system_metadata) — this package issues only SELECT statements regardless.
func OpenPostgres(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return &DB{sql: sqlDB, backend: BackendPostgres}, nil
}

// OpenPostgresConfig is OpenPostgres for an already-parsed connection config
// (config.ResolvePostgresConnConfig), so a password resolved from the
// environment reaches the driver without ever being written into a DSN.
func OpenPostgresConfig(cc *pgx.ConnConfig) (*DB, error) {
	sqlDB := stdlib.OpenDB(*cc)
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return &DB{sql: sqlDB, backend: BackendPostgres}, nil
}

// Close closes the underlying connection(s).
func (d *DB) Close() error {
	return d.sql.Close()
}

// Backend reports which dialect this DB was opened against.
func (d *DB) Backend() Backend {
	return d.backend
}

// rebind rewrites `?` placeholders to Postgres `$1, $2, ...` positional
// syntax when needed; a no-op for SQLite, whose driver accepts `?` as-is.
func (d *DB) rebind(query string) string {
	if d.backend != BackendPostgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

const auditEventColumns = `id, event_type, user_id, secret_node_id, project_id, ip_address, ` +
	`description, success, event_time, diff, impersonated_by, acting_as, impersonation, ` +
	`actor_type, prev_hash, entry_hash`

// StreamAuditEvents returns up to limit audit_events rows with id > afterID,
// in ascending id order — the same keyset-paginated shape
// VerifyAuditChain/auditChainVerifyBatch already uses, so a multi-GB audit
// table is never loaded into memory at once. An empty, nil-error result
// means the walk has reached the end of the table.
func (d *DB) StreamAuditEvents(ctx context.Context, afterID uint64, limit int) ([]*AuditEventRow, error) {
	q := d.rebind(`SELECT ` + auditEventColumns + ` FROM audit_events WHERE id > ? ORDER BY id ASC LIMIT ?`)
	rows, err := d.sql.QueryContext(ctx, q, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit_events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]*AuditEventRow, 0, limit)
	for rows.Next() {
		e, err := scanAuditEventRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit_events: %w", err)
	}
	return out, nil
}

// rowScanner is the subset of *sql.Rows this package's row decoder needs —
// satisfied by *sql.Rows in production and by a fixed in-memory stand-in in
// FuzzAuditChainRowDecode, so the fuzz target can drive the exact same
// decode path with adversarial column values without a live database.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanAuditEventRow decodes one audit_events row. This is the row decoder
// the design's fuzz target (FuzzAuditChainRowDecode) exercises directly:
// nullable integer/bool columns must never panic or silently misclassify a
// NULL as a present value, since a corrupted or adversarially crafted
// SQLite file is explicitly in scope for this package (doc.go).
func scanAuditEventRow(r rowScanner) (*AuditEventRow, error) {
	var e AuditEventRow
	var userID, secretNodeID, projectID, impersonatedBy, actingAs sql.NullInt64
	var success sql.NullBool

	if err := r.Scan(
		&e.ID, &e.EventType, &userID, &secretNodeID, &projectID, &e.IPAddress,
		&e.Description, &success, &e.EventTime, &e.Diff, &impersonatedBy, &actingAs,
		&e.Impersonation, &e.ActorType, &e.PrevHash, &e.EntryHash,
	); err != nil {
		return nil, fmt.Errorf("scan audit_events row: %w", err)
	}

	var err error
	if e.UserID, err = nonNegativeUint64(userID, "user_id"); err != nil {
		return nil, err
	}
	if e.SecretNodeID, err = nonNegativeUint64(secretNodeID, "secret_node_id"); err != nil {
		return nil, err
	}
	if e.ProjectID, err = nonNegativeUint64(projectID, "project_id"); err != nil {
		return nil, err
	}
	if e.ImpersonatedBy, err = nonNegativeUint64(impersonatedBy, "impersonated_by"); err != nil {
		return nil, err
	}
	if e.ActingAs, err = nonNegativeUint64(actingAs, "acting_as"); err != nil {
		return nil, err
	}
	if success.Valid {
		v := success.Bool
		e.Success = &v
	}
	return &e, nil
}

// nonNegativeUint64 converts a nullable signed column to *uint64, returning
// an error instead of silently wrapping a negative value around to a huge
// unsigned one (G115) — this package explicitly treats a corrupted or
// adversarially crafted DB file as in scope (doc.go), so a negative id-like
// column must surface as a decode error, not a fabricated large id.
func nonNegativeUint64(v sql.NullInt64, column string) (*uint64, error) {
	if !v.Valid {
		return nil, nil
	}
	if v.Int64 < 0 {
		return nil, fmt.Errorf("column %s has a negative value %d, which is not a valid row id", column, v.Int64)
	}
	u := uint64(v.Int64)
	return &u, nil
}

// LatestCheckpoint returns the most recently written audit_checkpoints row,
// or (nil, nil) when none exists.
func (d *DB) LatestCheckpoint(ctx context.Context) (*Checkpoint, error) {
	q := d.rebind(`SELECT id, chained_events, head_id, head_hash, key_version, signature, ` +
		`anchor_token, anchored_at, anchor_provider FROM audit_checkpoints ORDER BY id DESC LIMIT 1`)
	row := d.sql.QueryRowContext(ctx, q)

	var cp Checkpoint
	var anchorToken []byte
	var anchoredAt sql.NullTime
	var anchorProvider sql.NullString
	err := row.Scan(&cp.ID, &cp.ChainedEvents, &cp.HeadID, &cp.HeadHash, &cp.KeyVersion,
		&cp.Signature, &anchorToken, &anchoredAt, &anchorProvider)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query audit_checkpoints: %w", err)
	}
	cp.AnchorToken = anchorToken
	if anchoredAt.Valid {
		t := anchoredAt.Time
		cp.AnchoredAt = &t
	}
	cp.AnchorProvider = anchorProvider.String
	return &cp, nil
}

// AuditEntryHashByID returns the entry_hash of the audit_events row with the
// given id; found is false when no such row exists (e.g. truncated away).
func (d *DB) AuditEntryHashByID(ctx context.Context, id uint64) (hash string, found bool, err error) {
	q := d.rebind(`SELECT entry_hash FROM audit_events WHERE id = ?`)
	err = d.sql.QueryRowContext(ctx, q, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("query audit_events by id: %w", err)
	}
	return hash, true, nil
}

// GetSystemMetadata returns the value stored for key; found is false when
// the key has never been set.
func (d *DB) GetSystemMetadata(ctx context.Context, key string) (value string, found bool, err error) {
	q := d.rebind(`SELECT value FROM system_metadata WHERE key = ?`)
	err = d.sql.QueryRowContext(ctx, q, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("query system_metadata: %w", err)
	}
	return value, true, nil
}

// EventRange reports the id and time bounds of the audit_events table.
// empty is true when the table has no rows at all.
//
// Deliberately two plain SELECT ... ORDER BY ... LIMIT 1 queries rather than
// one MIN(id), MAX(id), MIN(event_time), MAX(event_time) query: SQLite (via
// modernc.org/sqlite) does not propagate a column's declared type through an
// aggregate function, so MIN(event_time)/MAX(event_time) comes back as a
// bare string the driver cannot Scan into *time.Time — a plain column
// reference preserves the declared "datetime" type and scans natively.
func (d *DB) EventRange(ctx context.Context) (fromID, toID uint64, fromTime, toTime time.Time, empty bool, err error) {
	var minID, maxID sql.NullInt64
	if err := d.sql.QueryRowContext(ctx, `SELECT MIN(id), MAX(id) FROM audit_events`).Scan(&minID, &maxID); err != nil {
		return 0, 0, time.Time{}, time.Time{}, false, fmt.Errorf("query audit_events id range: %w", err)
	}
	if !minID.Valid {
		return 0, 0, time.Time{}, time.Time{}, true, nil
	}
	if err := d.sql.QueryRowContext(ctx, `SELECT event_time FROM audit_events ORDER BY id ASC LIMIT 1`).Scan(&fromTime); err != nil {
		return 0, 0, time.Time{}, time.Time{}, false, fmt.Errorf("query audit_events earliest event_time: %w", err)
	}
	if err := d.sql.QueryRowContext(ctx, `SELECT event_time FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&toTime); err != nil {
		return 0, 0, time.Time{}, time.Time{}, false, fmt.Errorf("query audit_events latest event_time: %w", err)
	}
	fromIDPtr, err := nonNegativeUint64(minID, "id")
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, false, err
	}
	toIDPtr, err := nonNegativeUint64(maxID, "id")
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, false, err
	}
	return *fromIDPtr, *toIDPtr, fromTime, toTime, false, nil
}
