package storage

// pgbouncer_locks_test.go — the blocking advisory locks (bootstrap, audit
// checkpoint) in their transaction shape (storage.database.pooler:
// pgbouncer-transaction), and every held lock against server-side timeouts.
// Environment: see pgbouncer_postgres_test.go.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// withBlockingLocks runs fn for the bootstrap and the audit-checkpoint lock.
func withBlockingLocks(t *testing.T, fn func(t *testing.T, name string, with func(replica int, ctx context.Context, body func() error) error), replicas ...any) {
	t.Helper()
	type bootstrapper interface {
		WithBootstrapLock(ctx context.Context, fn func() error) error
	}
	type checkpointer interface {
		WithAuditCheckpointLock(ctx context.Context, fn func() error) error
	}
	for _, name := range []string{"BootstrapLock", "AuditCheckpointLock"} {
		t.Run(name, func(t *testing.T) {
			fn(t, name, func(replica int, ctx context.Context, body func() error) error {
				if name == "BootstrapLock" {
					return replicas[replica].(bootstrapper).WithBootstrapLock(ctx, body)
				}
				return replicas[replica].(checkpointer).WithAuditCheckpointLock(ctx, body)
			})
		})
	}
}

// TestPgBouncer_BlockingLocks_ExcludeAcrossReplicas: while replica A is inside
// the bootstrap / audit-checkpoint critical section, replica B blocks (its
// context expires without entering), and after A returns B enters and no
// advisory lock is left behind. Mutual exclusion is the assertion, not "no
// error".
func TestPgBouncer_BlockingLocks_ExcludeAcrossReplicas(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	tg := pgBouncerTargetFor(t)
	a, b := tg.open(t, false), tg.open(t, false)
	withBlockingLocks(t, func(t *testing.T, name string, with func(int, context.Context, func() error) error) {
		for round := range 3 {
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- with(0, context.Background(), func() error {
					close(entered)
					<-release
					return nil
				})
			}()
			<-entered
			var bEntered atomic.Bool
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			err := with(1, ctx, func() error { bEntered.Store(true); return nil })
			cancel()
			require.False(t, bEntered.Load(), "round %d: replica B entered %s while replica A held it", round, name)
			require.Error(t, err, "round %d: replica B should have been blocked until its context expired", round)
			close(release)
			require.NoError(t, <-done)
			require.NoError(t, with(1, context.Background(), func() error { bEntered.Store(true); return nil }))
			require.True(t, bEntered.Load(), "round %d: replica B could not enter %s after A released it", round, name)
		}
		require.Zero(t, tg.advisoryLocks(t), "advisory locks still held after every %s holder returned", name)
	}, a, b)
}

// TestPgBouncer_Locks_SurviveServerTimeouts: a lock held for longer than the
// database's transaction_timeout (PostgreSQL 17+) and
// idle_in_transaction_session_timeout (both 1s) is still held: replica B cannot enter.
// The lock transaction is idle for the whole critical section; a server-side
// timeout ending it would drop the lock with no error anywhere.
func TestPgBouncer_Locks_SurviveServerTimeouts(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	tg := pgBouncerTargetFor(t)
	admin := pgRawOpen(t, tg.direct)
	var vnum int
	require.NoError(t, admin.Raw("SELECT current_setting('server_version_num')::int").Scan(&vnum).Error)
	var db string
	require.NoError(t, admin.Raw("SELECT current_database()").Scan(&db).Error)
	t.Logf("server_version_num %d", vnum)
	_ = tg.open(t, false) // migrate the fresh database before any timeout applies
	settings := []string{"idle_in_transaction_session_timeout"}
	if vnum >= 170000 {
		settings = append(settings, "transaction_timeout")
	}
	for _, k := range settings {
		require.NoError(t, admin.Exec(fmt.Sprintf("ALTER DATABASE %s SET %s = '1s'", db, k)).Error)
	}
	// A backend takes database-level settings when it starts. End the ones
	// that predate the ALTER (the migration's, and a pooler's idle server
	// connections), so the storages below only ever get new ones.
	require.NoError(t, admin.Exec("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()").Error)
	time.Sleep(500 * time.Millisecond)
	a, b := tg.open(t, false), tg.open(t, false)
	withBlockingLocks(t, func(t *testing.T, name string, with func(int, context.Context, func() error) error) {
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- with(0, context.Background(), func() error {
				close(entered)
				<-release
				return nil
			})
		}()
		<-entered
		time.Sleep(2500 * time.Millisecond)
		var bEntered atomic.Bool
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_ = with(1, ctx, func() error { bEntered.Store(true); return nil })
		cancel()
		close(release)
		require.NoError(t, <-done)
		require.False(t, bEntered.Load(), "%s: replica B entered after a 1s server-side timeout should have ended A's lock transaction", name)
	}, a, b)
}
