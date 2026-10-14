package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newBootstrapLockStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	return NewLocalStorage(db)
}

// On SQLite (single instance) fn always runs and its result propagates.
func TestWithBootstrapLock_SQLiteRunsAndPropagates(t *testing.T) {
	ls := newBootstrapLockStore(t)
	ctx := context.Background()

	ran := false
	err := ls.WithBootstrapLock(ctx, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ran, "fn executed")

	sentinel := errors.New("boom")
	err = ls.WithBootstrapLock(ctx, func() error { return sentinel })
	require.ErrorIs(t, err, sentinel)

	// Not held after returning: a subsequent call still runs.
	ran = false
	err = ls.WithBootstrapLock(ctx, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ran)
}

// TestWithBootstrapLock_SerializesConcurrentCallers pins the actual mechanism the
// fix for #core-auth-03 relies on: WithBootstrapLock must provide real mutual
// exclusion between two concurrent callers on the same LocalStorage instance, not
// just a documentation promise. A racer that starts second must not enter fn until
// the first racer's fn has returned and released the lock — this is the exact
// guarantee BootstrapSystem's check-then-create sequence depends on to avoid two
// callers both observing "not yet initialised" before either commits.
func TestWithBootstrapLock_SerializesConcurrentCallers(t *testing.T) {
	ls := newBootstrapLockStore(t)
	ctx := context.Background()

	var inside atomic.Int32
	var maxConcurrent int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	const racers = 20
	for range racers {
		wg.Go(func() {
			<-start
			_ = ls.WithBootstrapLock(ctx, func() error {
				cur := inside.Add(1)
				for {
					prev := atomic.LoadInt32(&maxConcurrent)
					if cur <= prev || atomic.CompareAndSwapInt32(&maxConcurrent, prev, cur) {
						break
					}
				}
				// Hold the "critical section" briefly so any missing exclusion
				// would show up as inside > 1 with high probability.
				time.Sleep(2 * time.Millisecond)
				inside.Add(-1)
				return nil
			})
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), maxConcurrent, "WithBootstrapLock must never let two callers run fn concurrently")
}
