package config

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

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

// DefaultNativeReadPoolMax is the native read pool's cap when
// storage.database.native_read_pool_max is unset.
const DefaultNativeReadPoolMax = 8

// MaxNativeReadPoolMax is the largest storage.database.native_read_pool_max
// accepted. Far above any useful value (the pool never exceeds max_open_conns,
// whose own default is 25); it keeps a typo from asking PostgreSQL for
// thousands of connections.
const MaxNativeReadPoolMax = 1000

// EffectiveNativeReadPoolMax is the configured native read pool cap, or
// DefaultNativeReadPoolMax when unset.
func (d *DatabaseConfig) EffectiveNativeReadPoolMax() int {
	if d.NativeReadPoolMax > 0 {
		return d.NativeReadPoolMax
	}
	return DefaultNativeReadPoolMax
}

// validateNativeReadPoolMax refuses a negative or absurd native_read_pool_max,
// and any value on a backend without a PostgreSQL connection, rather than
// ignoring it.
func validateNativeReadPoolMax(storageType string, d *DatabaseConfig) error {
	if d.NativeReadPoolMax == 0 {
		return nil
	}
	if d.NativeReadPoolMax < 0 || d.NativeReadPoolMax > MaxNativeReadPoolMax {
		return fmt.Errorf("storage.database.native_read_pool_max %d is out of range; use 1 to %d, or leave it unset for the default of %d",
			d.NativeReadPoolMax, MaxNativeReadPoolMax, DefaultNativeReadPoolMax)
	}
	if storageType != "postgres" && storageType != "postgresql" {
		return fmt.Errorf("storage.database.native_read_pool_max applies only to storage.type postgres; remove it")
	}
	return nil
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
