package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithNamedLock_LockPool_HolderRunsOnAOneConnectionRequestPool pins the
// NAMEDLOCK-POOL-1 property at its smallest: with the request pool capped at
// ONE connection, a named-lock holder (and a nested holder under a second key)
// can still query through that pool, because the lock session is not taken
// from it. Without the named lock pool the holder's query waits for the
// connection its own lock session pins, until the context ends.
func TestWithNamedLock_LockPool_HolderRunsOnAOneConnectionRequestPool(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	ls := NewLocalStorage(db)
	ls.SetNamedLockDB(pgLockPool(t, dsn))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = ls.WithNamedLock(ctx, "namedlock-pool-outer", func(ctx context.Context) error {
		return ls.WithNamedLock(ctx, "namedlock-pool-inner", func(ctx context.Context) error {
			var one int
			return ls.db.WithContext(ctx).Raw("SELECT 1").Scan(&one).Error
		})
	})
	require.NoError(t, err, "the holder's own query must not wait on a connection pinned by its lock session")
}

// TestWithNamedLock_LockPool_SameKeySerializesAcrossInstances keeps the lock's
// meaning with the production wiring: several instances (each its own request
// pool and its own named lock pool, i.e. replicas) on one key never overlap.
func TestWithNamedLock_LockPool_SameKeySerializesAcrossInstances(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	const instances = 4
	const perInstance = 5
	var inside, maxInside int32
	var wg sync.WaitGroup
	errs := make(chan error, instances*perInstance)
	for i := 0; i < instances; i++ {
		ls := NewLocalStorage(pgOpen(t, dsn))
		ls.SetNamedLockDB(pgLockPool(t, dsn))
		for j := 0; j < perInstance; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				errs <- ls.WithNamedLock(ctx, "namedlock-pool-same-key", func(ctx context.Context) error {
					n := atomic.AddInt32(&inside, 1)
					for {
						m := atomic.LoadInt32(&maxInside)
						if n <= m || atomic.CompareAndSwapInt32(&maxInside, m, n) {
							break
						}
					}
					time.Sleep(5 * time.Millisecond)
					atomic.AddInt32(&inside, -1)
					return nil
				})
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), maxInside, "two holders of one key overlapped")
}

// TestWithNamedLock_CancelledInsideFn_StillUnlocks: a holder whose context is
// cancelled while fn runs must not leave the key locked for other replicas. The
// unlock runs without the caller's cancellation, and a session whose unlock
// fails is discarded rather than pooled; either way the key is free afterwards.
// (Before this the unlock used the cancelled context; pgx then reported a bad
// connection and database/sql discarded the session, which also freed the key,
// so this is a behaviour guard rather than a red/green regression.)
func TestWithNamedLock_CancelledInsideFn_StillUnlocks(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	a := NewLocalStorage(pgOpen(t, dsn))
	a.SetNamedLockDB(pgLockPool(t, dsn))
	b := NewLocalStorage(pgOpen(t, dsn))
	b.SetNamedLockDB(pgLockPool(t, dsn))

	ctx, cancel := context.WithCancel(context.Background())
	_ = a.WithNamedLock(ctx, "namedlock-pool-cancel", func(context.Context) error {
		cancel()
		return nil
	})

	other, cancelOther := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelOther()
	err := b.WithNamedLock(other, "namedlock-pool-cancel", func(context.Context) error { return nil })
	require.NoError(t, err, "another replica must get the key after a cancelled holder returns")
}
