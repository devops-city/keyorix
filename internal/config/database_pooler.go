package config

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// storage.database.pooler values (docs/postgresql-poolers.md). The setting names
// the connection pooler between Keyorix and PostgreSQL. A pooler cannot be
// detected reliably from the client side (PgBouncer's SHOW pool_mode answers
// only on its admin console), so the operator states it.
const (
	// PoolerNone (also the empty value, the default) is a direct connection,
	// or a pooler that pins one server connection to each client connection
	// for its whole life. Nothing changes.
	PoolerNone = "none"
	// PoolerPgBouncerSession is PgBouncer in pool_mode=session. A client
	// connection keeps one server connection, so it behaves like a direct
	// one; the value exists so the configuration says what is deployed.
	// Nothing changes at runtime.
	PoolerPgBouncerSession = "pgbouncer-session"
	// PoolerPgBouncerTransaction is PgBouncer in pool_mode=transaction: a
	// client connection holds a server connection only for one transaction.
	// See TransactionPooling for what that changes.
	PoolerPgBouncerTransaction = "pgbouncer-transaction"
)

// TransactionPooling reports whether storage.database.pooler says a
// transaction-mode pooler sits in front of PostgreSQL. When it does:
//
//   - every pgx connection runs statements in QueryExecModeExec, with no
//     statement or description cache (ResolvePostgresConnConfig), so nothing
//     depends on a named prepared statement that lives on one server
//     connection;
//   - every advisory lock the server holds across statements is taken as a
//     transaction-scoped lock inside a transaction kept open for the whole
//     critical section (the pooler keeps a client on one server connection
//     for exactly as long as a transaction is open), instead of a
//     session-scoped lock, which would be left on whatever server connection
//     the statement happened to run on.
func (d *DatabaseConfig) TransactionPooling() bool {
	return d.Pooler == PoolerPgBouncerTransaction
}

// validatePooler refuses an unknown storage.database.pooler value, and any
// value other than none on a backend without a PostgreSQL connection, rather
// than ignoring it.
func validatePooler(storageType string, d *DatabaseConfig) error {
	switch d.Pooler {
	case "", PoolerNone:
		return nil
	case PoolerPgBouncerSession, PoolerPgBouncerTransaction:
		if storageType != "postgres" && storageType != "postgresql" {
			return fmt.Errorf("storage.database.pooler %q applies only to storage.type postgres; remove it", d.Pooler)
		}
		return nil
	default:
		return fmt.Errorf("storage.database.pooler %q is not supported; use %q, %q or %q (see docs/postgresql-poolers.md)",
			d.Pooler, PoolerNone, PoolerPgBouncerSession, PoolerPgBouncerTransaction)
	}
}

// applyPoolerConnConfig sets the pgx execution mode a transaction-mode pooler
// needs. pgx's default caches a named prepared statement per query on the
// server connection it prepared it on; behind transaction pooling the next
// statement may run on another server connection, where that name does not
// exist (or, with PgBouncer's own prepared-statement tracking, is re-prepared
// on every server connection). QueryExecModeExec sends each statement with
// the extended protocol and an unnamed statement in one round trip, and needs
// no state on the server connection between statements.
func applyPoolerConnConfig(d *DatabaseConfig, cc *pgx.ConnConfig) {
	if !d.TransactionPooling() {
		return
	}
	cc.DefaultQueryExecMode = pgx.QueryExecModeExec
	cc.StatementCacheCapacity = 0
	cc.DescriptionCacheCapacity = 0
}

// pgVersionTransactionTimeout is the first server_version_num that has
// transaction_timeout (PostgreSQL 17). Setting it on an older server is an
// "unrecognized configuration parameter" error.
const pgVersionTransactionTimeout = 170000

// PinnedLockTxSetupSQL is what a transaction that pins a transaction-scoped
// advisory lock (pooler: pgbouncer-transaction) must run right after BEGIN, for
// a server of serverVersionNum.
//
// The lock lives exactly as long as that transaction, and the transaction is
// idle for the holder's whole critical section (the presence lock: the server's
// lifetime). Any server-side timeout that ends it silently drops the lock while
// the holder still relies on it, so each one that could fire is set to 0 for
// this transaction alone (SET LOCAL reverts at ROLLBACK):
//
//   - idle_in_transaction_session_timeout (every supported version);
//   - transaction_timeout (PostgreSQL 17+, whatever level it was set at:
//     cluster, database or role). Not set before 17, where it does not exist.
//
// idle_session_timeout is not in the list: it only applies outside a
// transaction. The pooler's own timeouts cannot be set from SQL; see
// docs/postgresql-poolers.md.
func PinnedLockTxSetupSQL(serverVersionNum int) []string {
	stmts := []string{"SET LOCAL idle_in_transaction_session_timeout = 0"}
	if serverVersionNum >= pgVersionTransactionTimeout {
		stmts = append(stmts, "SET LOCAL transaction_timeout = 0")
	}
	return stmts
}

// BeginPinnedLockTx opens the transaction a transaction-scoped advisory lock
// lives in on conn and removes the server-side timeouts that would end it (see
// PinnedLockTxSetupSQL). On error the transaction may be open; the caller ends
// it (ROLLBACK) or discards the connection.
func BeginPinnedLockTx(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return err
	}
	var v string
	if err := conn.QueryRowContext(ctx, "SHOW server_version_num").Scan(&v); err != nil {
		return fmt.Errorf("read server_version_num: %w", err)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("parse server_version_num %q: %w", v, err)
	}
	for _, q := range PinnedLockTxSetupSQL(n) {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// poolerTrackedStartupParams are the startup parameters PgBouncer accepts from
// a client by default and tracks per client (lower case). Any other one in the
// connection settings is refused by PgBouncer ("unsupported startup
// parameter"), unless its ignore_startup_parameters or track_extra_parameters
// names it; a transaction-mode pooler cannot keep a per-client setting anyway.
var poolerTrackedStartupParams = map[string]bool{
	"application_name":            true,
	"client_encoding":             true,
	"datestyle":                   true,
	"timezone":                    true,
	"standard_conforming_strings": true,
}

// PoolerStartupParamWarning returns a start-up warning when storage.database.pooler
// names a pooler and the connection settings (DSN or fields) carry startup
// parameters such as search_path or options, which PgBouncer refuses or drops
// (docs/postgresql-poolers.md, "PgBouncer requirements"). Empty when there is
// nothing to warn about, when no pooler is declared, or when the settings do
// not parse (the connection error reports that). A warning, not a refusal: the
// operator may have set ignore_startup_parameters on the pooler.
func PoolerStartupParamWarning(d *DatabaseConfig) string {
	switch d.Pooler {
	case PoolerPgBouncerSession, PoolerPgBouncerTransaction:
	default:
		return ""
	}
	cc, err := ResolvePostgresConnConfig(d)
	if err != nil {
		return ""
	}
	var names []string
	for k := range cc.RuntimeParams {
		if !poolerTrackedStartupParams[strings.ToLower(k)] {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return ""
	}
	slices.Sort(names)
	return fmt.Sprintf("WARNING: storage.database.pooler is %s, but the connection settings carry the startup parameter(s) %s. "+
		"PgBouncer refuses a parameter it does not know (or drops it, with ignore_startup_parameters), and a transaction-mode "+
		"pooler cannot keep a per-client setting. Remove them from the DSN and set them on the database role instead "+
		"(ALTER ROLE ... SET ...); see docs/postgresql-poolers.md.",
		d.Pooler, strings.Join(names, ", "))
}
