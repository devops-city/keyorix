package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
)

// advisoryLockSession is the connection a Postgres advisory lock is held on
// across statements (WithNamedLock, WithSchedulerLock, WithBootstrapLock,
// WithAuditCheckpointLock). It has two shapes, picked once per LocalStorage by
// SetTransactionPooling (storage.database.pooler):
//
//   - session (the default): pg_advisory_lock / pg_try_advisory_lock and an
//     explicit pg_advisory_unlock, as before. Correct on a direct connection
//     and behind a session-mode pooler, where one client connection keeps one
//     server connection.
//   - transaction (pooler: pgbouncer-transaction): BEGIN, then
//     pg_advisory_xact_lock / pg_try_advisory_xact_lock, held until ROLLBACK
//     at close. A transaction-mode pooler gives a client a server connection
//     only while a transaction is open, so a session lock taken in autocommit
//     would stay on a server connection that is then handed to other clients
//     (and the unlock would run on another one). Inside an open transaction
//     the pooler keeps this client on one server connection, and the lock
//     ends with the transaction whatever happens to the client: ROLLBACK, or
//     the pooler closing the server connection when the client disconnects
//     mid-transaction.
//
// The lock transaction runs no writes; it exists only to pin the server
// connection and scope the lock. idle_in_transaction_session_timeout and, on
// PostgreSQL 17+, transaction_timeout are set to 0 for it alone (SET LOCAL,
// config.PinnedLockTxSetupSQL), because the critical section's own queries run
// on other connections and this one is idle in transaction meanwhile; a
// server-side timeout ending it would release the lock while the holder is
// still inside its critical section. The pooler's own idle_transaction_timeout
// and transaction timeouts must be 0 or longer than any critical section
// (docs/postgresql-poolers.md).
type advisoryLockSession struct {
	conn *sql.Conn
	xact bool
}

// openAdvisoryLockSession starts a lock session on conn. In transaction shape
// it opens the pinning transaction; the caller must call close.
func openAdvisoryLockSession(ctx context.Context, conn *sql.Conn, xact bool) (*advisoryLockSession, error) {
	s := &advisoryLockSession{conn: conn, xact: xact}
	if !xact {
		return s, nil
	}
	if err := config.BeginPinnedLockTx(ctx, conn); err != nil {
		// May or may not be inside the transaction: ROLLBACK is harmless
		// outside one (a warning), and a failed ROLLBACK discards the conn.
		s.close(ctx)
		return nil, fmt.Errorf("begin advisory lock transaction: %w", err)
	}
	return s, nil
}

// lock blocks until the exclusive advisory lock key is held.
func (s *advisoryLockSession) lock(ctx context.Context, key int64) error {
	q := "SELECT pg_advisory_lock($1)"
	if s.xact {
		q = "SELECT pg_advisory_xact_lock($1)"
	}
	_, err := s.conn.ExecContext(ctx, q, key)
	return err
}

// tryLock takes the exclusive advisory lock key if no one else holds it.
func (s *advisoryLockSession) tryLock(ctx context.Context, key int64) (bool, error) {
	q := "SELECT pg_try_advisory_lock($1)"
	if s.xact {
		q = "SELECT pg_try_advisory_xact_lock($1)"
	}
	var locked bool
	err := s.conn.QueryRowContext(ctx, q, key).Scan(&locked)
	return locked, err
}

// unlock releases one hold of key. It ignores ctx's cancellation: a caller
// whose request was cancelled inside its critical section must still unlock.
// In transaction shape a transaction-scoped lock cannot be released early, so
// this is a no-op and the lock ends at close; a nested key held that way is
// released when the outermost lock is (held longer, never shorter). Returns
// false if the unlock failed, in which case the session has been marked bad
// (database/sql closes it, which ends the backend and every lock on it).
func (s *advisoryLockSession) unlock(ctx context.Context, key int64, who string) bool {
	if s.xact {
		return true
	}
	if _, err := s.conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", key); err != nil {
		log.Printf("%s: pg_advisory_unlock(%d) failed, discarding the connection instead of pooling it: %v", who, key, err)
		s.discard()
		return false
	}
	return true
}

// close ends the pinning transaction (transaction shape), which releases every
// transaction-scoped lock taken on it. ROLLBACK, not COMMIT: the transaction
// wrote nothing, and ROLLBACK also ends a transaction a failed lock statement
// aborted. If it fails the connection is discarded, so it never goes back to
// the pool inside a transaction. A no-op in session shape.
func (s *advisoryLockSession) close(ctx context.Context) {
	if !s.xact {
		return
	}
	if _, err := s.conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK"); err != nil {
		log.Printf("advisory lock: ending the lock transaction failed, discarding the connection: %v", err)
		s.discard()
	}
}

func (s *advisoryLockSession) discard() {
	_ = s.conn.Raw(func(_ any) error { return driver.ErrBadConn })
}

// SetTransactionPooling switches every advisory lock this storage holds across
// statements to the transaction shape (see advisoryLockSession). The storage
// factory sets it from storage.database.pooler: pgbouncer-transaction. Call it
// before serving traffic.
func (ls *LocalStorage) SetTransactionPooling(on bool) {
	ls.transactionPooling = on
}
