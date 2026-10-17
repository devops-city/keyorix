package store

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pgLockPool opens a separate pool on dsn for SetSchedulerLockDB, as the
// storage factory does in production.
func pgLockPool(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := pgOpen(t, dsn).DB()
	require.NoError(t, err)
	return db
}

// TestWithSchedulerLock_LockPool_JobRunsOnAOneConnectionRequestPool pins the
// POOL-HANG-1 property at its smallest: with the request pool capped at ONE
// connection, a job holding its scheduler lock can still query through that
// pool, because the lock session is not taken from it. Without the lock pool
// the job's query waits for the connection its own lock session pins, until
// the context ends.
func TestWithSchedulerLock_LockPool_JobRunsOnAOneConnectionRequestPool(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	ls.SetSchedulerLockDB(pgLockPool(t, dsn))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ran, err := ls.WithSchedulerLock(ctx, 0x504f4f4c31, func(context.Context) error {
		var one int
		return ls.db.WithContext(ctx).Raw("SELECT 1").Scan(&one).Error
	})
	require.NoError(t, err, "the job's own query must not wait on a connection pinned by its lock session")
	assert.True(t, ran)
}

// TestWithSchedulerLock_LockPool_ExactlyOneRunsAtOnce is
// TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce
// with every instance on its own lock pool, the production wiring: moving the
// lock sessions to a separate pool must keep "one runner per key across
// replicas", and a second attempt in the SAME process while the first holds the
// key must skip too (each attempt takes its own session, so the session lock is
// not re-entered).
func TestWithSchedulerLock_LockPool_ExactlyOneRunsAtOnce(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	const instances = 8
	const key = 0x504f4f4c32

	stores := make([]*LocalStorage, instances)
	for i := range stores {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
		stores[i].SetSchedulerLockDB(pgLockPool(t, dsn))
	}

	var running, maxConcurrent, acquiredCount int32
	var sameProcessRan atomic.Bool
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, ls := range stores {
		wg.Add(1)
		go func(ls *LocalStorage) {
			defer wg.Done()
			<-start
			acquired, err := ls.WithSchedulerLock(context.Background(), key, func(context.Context) error {
				n := atomic.AddInt32(&running, 1)
				for {
					m := atomic.LoadInt32(&maxConcurrent)
					if n <= m || atomic.CompareAndSwapInt32(&maxConcurrent, m, n) {
						break
					}
				}
				again, err := ls.WithSchedulerLock(context.Background(), key, func(context.Context) error { return nil })
				if err != nil {
					return err
				}
				sameProcessRan.Store(again)
				time.Sleep(150 * time.Millisecond)
				atomic.AddInt32(&running, -1)
				return nil
			})
			require.NoError(t, err)
			if acquired {
				atomic.AddInt32(&acquiredCount, 1)
			}
		}(ls)
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&maxConcurrent), "at most one replica's job may run at a time")
	assert.Equal(t, int32(1), atomic.LoadInt32(&acquiredCount), "exactly one replica may win the advisory lock for this tick")
	assert.False(t, sameProcessRan.Load(), "a second attempt in the holder's own process must skip")

	ran, err := stores[0].WithSchedulerLock(context.Background(), key, func(context.Context) error { return nil })
	require.NoError(t, err)
	assert.True(t, ran, "the lock must be released (and its session pooled clean) once the job returns")
}
