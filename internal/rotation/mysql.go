// mysql.go — the MySQL rotation executor (ADR-047). Rotate sets an account's password
// via ALTER USER against an admin connection opened from the backend's DSN. Account
// names and the password are emitted as single-quoted MySQL string literals with
// internal quotes and backslashes doubled, so neither can break out of the statement
// (injection-safe in both the default and NO_BACKSLASH_ESCAPES sql_modes).
package rotation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" sql driver

	"github.com/keyorixhq/keyorix/internal/rotation/quote"
)

// mysqlConn is the slice of a MySQL connection the executor uses — an interface seam so
// the driver stays contained here and tests inject a fake.
type mysqlConn interface {
	Exec(ctx context.Context, query string, args ...any) error
	Close() error
}

// MySQLExecutor rotates MySQL account passwords.
type MySQLExecutor struct {
	name        string
	dsn         string
	allowedRefs []string
	// newConn opens an admin connection; nil uses the real database/sql conn. Tests inject.
	newConn func(ctx context.Context, dsn string) (mysqlConn, error)
}

// NewMySQLExecutor builds a MySQL rotation executor. dsn is the admin connection string
// (operator-provided, env-sourced, scoped to the accounts it may rotate). allowedRefs,
// when non-empty, restricts which account names this backend will rotate (prefix
// allowlist); a rotation backend must declare one (fail-closed).
func NewMySQLExecutor(name, dsn string, allowedRefs []string) *MySQLExecutor {
	return &MySQLExecutor{name: name, dsn: dsn, allowedRefs: allowedRefs}
}

func (e *MySQLExecutor) Name() string { return e.name }
func (e *MySQLExecutor) Type() string { return "mysql" }

func (e *MySQLExecutor) conn(ctx context.Context) (mysqlConn, error) {
	if e.newConn != nil {
		return e.newConn(ctx, e.dsn)
	}
	db, err := sql.Open("mysql", e.dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql: open: %w", err)
	}
	return &mysqlDBConn{db: db}, nil
}

// Rotate sets account `ref`'s password to newValue via ALTER USER. ref is the account
// name as `user` or `user@host` (host defaults to '%').
func (e *MySQLExecutor) Rotate(ctx context.Context, ref, newValue string) error {
	if ref == "" {
		return fmt.Errorf("mysql: account name (ref) is required")
	}
	if newValue == "" {
		return fmt.Errorf("mysql: new value is required")
	}
	// Fail closed: a rotation backend runs privileged DDL with an admin DSN, so it must
	// carry an explicit allow-list.
	if len(e.allowedRefs) == 0 {
		return fmt.Errorf("mysql: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return fmt.Errorf("mysql: account %q is not permitted by this backend's allowed_refs", ref)
	}
	if e.dsn == "" {
		return fmt.Errorf("mysql: backend %q has no admin DSN configured", e.name)
	}
	c, err := e.conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	user, host, _ := strings.Cut(ref, "@")
	if host == "" {
		host = "%"
	}
	// ALTER USER 'user'@'host' IDENTIFIED BY 'pw' — every component a quoted literal
	// Account names are quoted literals (MySQL DDL cannot parameterise identifiers);
	// the new password is passed as a ? placeholder so it never appears in the
	// statement string and cannot break out via string interpolation.
	q := fmt.Sprintf("ALTER USER %s@%s IDENTIFIED BY ?",
		quoteMySQLString(user), quoteMySQLString(host))
	if err := c.Exec(ctx, q, newValue); err != nil {
		// Redact before wrapping so the live credential never egresses via the
		// rotation-failure SIEM audit / notification broadcast (#132).
		return redactSQLError("mysql", ref, err)
	}
	return nil
}

// quoteMySQLString renders s as a single-quoted MySQL string literal with internal
// backslashes and single-quotes doubled — injection-safe under both the default and
// NO_BACKSLASH_ESCAPES sql_modes. Thin wrapper over quote.QuoteMySQLString
// (internal/rotation/quote), moved there so the escaping logic can be fuzzed cheaply as a
// leaf package — see that package's doc.go. This is layer TWO of defense in depth: layer
// ONE is core.validateRotationRef (internal/core/rotation_executor.go), which already
// rejects quotes/backslashes/semicolons (plus path/query metacharacters and control
// characters) in the ref at configuration time, before it is ever persisted. Keep both —
// this quoting must not be removed just because the earlier layer also covers it; this
// function is the only defense against a ref/host reaching this backend through any
// future write path.
func quoteMySQLString(s string) string { return quote.QuoteMySQLString(s) }

// mysqlDBConn adapts *sql.DB to the mysqlConn seam.
type mysqlDBConn struct{ db *sql.DB }

func (m *mysqlDBConn) Exec(ctx context.Context, query string, args ...any) error {
	_, err := m.db.ExecContext(ctx, query, args...)
	return err
}
func (m *mysqlDBConn) Close() error { return m.db.Close() }
