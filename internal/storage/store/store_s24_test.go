// store_s24_test.go — coverage sweep for s24 gaps in internal/storage/store.
//
// Targets (all previously untested local paths):
//
//	local_audit_checkpoint_lock.go
//	  WithAuditCheckpointLock (23.5%)
//	    — SQLite path: fn is invoked, its result propagates
//	    — SQLite path: fn error propagates
//	    — SQLite path: lock serializes concurrent callers (mu exercised)
//
//	local_scheduler_lock.go
//	  WithSchedulerLock (9.5%)
//	    — additional SQLite paths to increase statement coverage
//	    — nil-error fn still returns (true, nil)
package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newS24Store opens a unique in-memory SQLite DB and returns a LocalStorage.
// Uses a "_s24" suffix in the DSN so test-name-based DSNs cannot collide with
// other sweeps.
func newS24Store(t *testing.T) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores24_", sqlite.Open, &gorm.Config{})
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// WithAuditCheckpointLock — SQLite (non-postgres) path
// ---------------------------------------------------------------------------

// TestWithAuditCheckpointLock_S24_SQLiteRunsFn verifies that on a non-postgres
// (SQLite) backend WithAuditCheckpointLock invokes fn and returns nil when fn
// succeeds.
func TestWithAuditCheckpointLock_S24_SQLiteRunsFn(t *testing.T) {
	ls := newS24Store(t)
	ctx := context.Background()

	called := false
	err := ls.WithAuditCheckpointLock(ctx, func() error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called, "WithAuditCheckpointLock must call fn on SQLite")
}

// TestWithAuditCheckpointLock_S24_SQLiteErrorPropagates verifies that fn's
// error is propagated unchanged to the caller.
func TestWithAuditCheckpointLock_S24_SQLiteErrorPropagates(t *testing.T) {
	ls := newS24Store(t)
	ctx := context.Background()

	sentinel := errors.New("checkpoint write failure")
	err := ls.WithAuditCheckpointLock(ctx, func() error { return sentinel })
	require.ErrorIs(t, err, sentinel,
		"WithAuditCheckpointLock must propagate fn's error")
}

// TestWithAuditCheckpointLock_S24_SQLiteSerializesConcurrent drives multiple
// goroutines through WithAuditCheckpointLock concurrently to exercise the
// auditCheckpointMu serialization path on SQLite (no advisory lock branch).
func TestWithAuditCheckpointLock_S24_SQLiteSerializesConcurrent(t *testing.T) {
	ls := newS24Store(t)
	ctx := context.Background()

	const n = 8
	var counter int
	var mu sync.Mutex // protect the counter read after Wait

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = ls.WithAuditCheckpointLock(ctx, func() error {
				mu.Lock()
				counter++
				mu.Unlock()
				return nil
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d should not error", i)
	}
	mu.Lock()
	assert.Equal(t, n, counter, "each goroutine must run fn exactly once")
	mu.Unlock()
}

// TestWithAuditCheckpointLock_S24_SQLiteReentrantAfterRelease verifies that
// the mutex is properly released after each call, so a second sequential call
// does not deadlock.
func TestWithAuditCheckpointLock_S24_SQLiteReentrantAfterRelease(t *testing.T) {
	ls := newS24Store(t)
	ctx := context.Background()

	// First call
	err := ls.WithAuditCheckpointLock(ctx, func() error { return nil })
	require.NoError(t, err, "first call must succeed")

	// Second call — would deadlock if the mutex were not released.
	err = ls.WithAuditCheckpointLock(ctx, func() error { return nil })
	require.NoError(t, err, "second sequential call must not deadlock")
}

// ---------------------------------------------------------------------------
// WithSchedulerLock — additional SQLite paths
// ---------------------------------------------------------------------------

// TestWithSchedulerLock_S24_MultipleKeys verifies that WithSchedulerLock on
// SQLite runs fn for different key values, each independently and without error.
func TestWithSchedulerLock_S24_MultipleKeys(t *testing.T) {
	ls := newS24Store(t)
	ctx := context.Background()

	// Each different key value must run fn.
	for _, key := range []int64{0, 1, -1, 999, 1<<62 - 1} {
		ran := false
		got, err := ls.WithSchedulerLock(ctx, key, func() error {
			ran = true
			return nil
		})
		require.NoError(t, err, "key=%d must not error on SQLite", key)
		assert.True(t, got, "key=%d must return ran=true on SQLite", key)
		assert.True(t, ran, "fn must be invoked for key=%d", key)
	}
}

// TestWithSchedulerLock_S24_FnErrorReturnsTrueAndError verifies that when fn
// returns an error on SQLite, WithSchedulerLock returns (true, error) — the
// "ran" bool is true because SQLite always acquires the lock.
func TestWithSchedulerLock_S24_FnErrorReturnsTrueAndError(t *testing.T) {
	ls := newS24Store(t)
	ctx := context.Background()

	sentinel := errors.New("scheduler fn error")
	got, err := ls.WithSchedulerLock(ctx, 42, func() error { return sentinel })
	assert.True(t, got, "SQLite must always return ran=true even on fn error")
	require.ErrorIs(t, err, sentinel)
}

// TestWithSchedulerLock_S24_NilFnReturnsTrueNoError verifies that a fn that
// returns nil is treated as a success on SQLite.
func TestWithSchedulerLock_S24_NilFnReturnsTrueNoError(t *testing.T) {
	ls := newS24Store(t)
	ctx := context.Background()

	got, err := ls.WithSchedulerLock(ctx, 7, func() error { return nil })
	assert.True(t, got)
	require.NoError(t, err)
}
