package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/jackc/pgx/v5"

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
//
// In transaction shape the lock statements go over the simple query protocol.
// An extended-protocol SELECT inside a transaction block leaves its unnamed
// portal, and that portal's snapshot, open until the transaction ends, so the
// idle lock transaction would hold back the database's xmin for the whole
// critical section: VACUUM keeps dead rows, and every CREATE INDEX
// CONCURRENTLY (the audit index build, which runs under this lock) waits for
// it to end.
//
// The lock statements and the liveness ping (watch) share conn, so each lock
// statement holds gate while it runs and the ping is only sent while gate is
// free (config.PinnedConnGate): a ping queued behind a nested lock wait
// would time out before it was sent, and the driver would close the healthy
// connection, ending the transaction and every lock on it.
type advisoryLockSession struct {
	conn *sql.Conn
	xact bool
	gate config.PinnedConnGate
}

// ErrAdvisoryLockLost is returned (joined with the critical section's own
// error, if any) by a lock holder whose lock transaction died while it held the
// lock (transaction shape only; see advisoryLockSession.watch). The lock was
// released by the database at that moment, so the critical section may have
// overlapped another holder's: the caller must treat its result as unproven.
var ErrAdvisoryLockLost = errors.New("advisory lock lost: the lock connection died while the lock was held")

// watch starts the liveness check of the lock transaction (transaction shape;
// call it once the lock is held) and returns the context the critical section
// must run under, cancelled with cause ErrAdvisoryLockLost when the check finds
// the connection gone, and finish. finish(err) stops the check, which must
// happen before close, and returns err joined with ErrAdvisoryLockLost if the
// lock was lost meanwhile (also when err is nil: the section ran without its
// lock for part of its time). In session shape the connection is not pinned by
// a transaction and watch is a pass-through.
func (s *advisoryLockSession) watch(ctx context.Context, who string) (context.Context, func(error) error) {
	if !s.xact {
		return ctx, func(err error) error { return err }
	}
	wctx, cancel := context.WithCancelCause(ctx)
	var lost atomic.Bool
	stop := config.WatchPinnedLockConnGated(s.conn, s.gate, who, func(err error) {
		lost.Store(true)
		cancel(fmt.Errorf("%w: %v", ErrAdvisoryLockLost, err))
	})
	return wctx, func(err error) error {
		stop()
		cancel(nil)
		if lost.Load() {
			return errors.Join(err, ErrAdvisoryLockLost)
		}
		return err
	}
}

// openAdvisoryLockSession starts a lock session on conn. In transaction shape
// it opens the pinning transaction; the caller must call close.
func openAdvisoryLockSession(ctx context.Context, conn *sql.Conn, xact bool) (*advisoryLockSession, error) {
	s := &advisoryLockSession{conn: conn, xact: xact, gate: config.NewPinnedConnGate()}
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
	if err := s.gate.Enter(ctx); err != nil {
		return err
	}
	defer s.gate.Leave()
	if s.xact {
		_, err := s.conn.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", pgx.QueryExecModeSimpleProtocol, key)
		return err
	}
	_, err := s.conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key)
	return err
}

// tryLock takes the exclusive advisory lock key if no one else holds it.
func (s *advisoryLockSession) tryLock(ctx context.Context, key int64) (bool, error) {
	if err := s.gate.Enter(ctx); err != nil {
		return false, err
	}
	defer s.gate.Leave()
	var locked bool
	if s.xact {
		err := s.conn.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", pgx.QueryExecModeSimpleProtocol, key).Scan(&locked)
		return locked, err
	}
	err := s.conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked)
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

// TransactionPooling reports SetTransactionPooling's setting.
func (ls *LocalStorage) TransactionPooling() bool {
	return ls.transactionPooling
}
