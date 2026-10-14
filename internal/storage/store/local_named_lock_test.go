package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newNamedLockTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	return NewLocalStorage(db)
}

// A same-key nested WithNamedLock call must be skipped (not re-acquired) --
// this is the original #1646 self-deadlock guard, and must still hold after
// FIX-5 keys the guard on lockKey.
func TestWithNamedLock_ReentrantSameKey_DoesNotDeadlock(t *testing.T) {
	ls := newNamedLockTestStore(t)
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- ls.WithNamedLock(ctx, "same-key", func(ctx context.Context) error {
			return ls.WithNamedLock(ctx, "same-key", func(ctx context.Context) error {
				return nil
			})
		})
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("same-key reentrant WithNamedLock call deadlocked")
	}
}

// FIX-5 (adversarial review run 2): a nested WithNamedLock call under a
// DIFFERENT key from the one already held must actually acquire its own
// lock, not silently skip acquisition because SOME lock (a different one) is
// already held by this call chain. Before this fix, the reentrancy guard was
// a single untyped boolean keyed on "is any lock held at all" -- so
// SetProjectMemberRole holding projectAdminGuardLockKey(projectID) and then
// calling AssignUserRole, which needs its own sodGrantLockKey("user", userID),
// never actually took the second lock, losing AssignUserRole's cross-replica
// SoD check-then-act serialization entirely whenever reached through that
// call chain.
//
// Proven here by holding "key-B" open in one goroutine and confirming a
// nested WithNamedLock(ctx, "key-B", ...) call -- issued from inside an outer
// WithNamedLock(ctx, "key-A", ...) closure on a SEPARATE call chain -- blocks
// until the first goroutine releases it. Under the old bug, the nested call
// would return immediately (wrongly treating key-B as already covered by
// key-A's own lock), which this test's ordering assertion would catch.
func TestWithNamedLock_NestedDifferentKey_StillSerializesAgainstOtherHolder(t *testing.T) {
	ls := newNamedLockTestStore(t)
	ctx := context.Background()

	const holdKey = "key-B"
	holderEntered := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan error, 1)

	go func() {
		holderDone <- ls.WithNamedLock(context.Background(), holdKey, func(ctx context.Context) error {
			close(holderEntered)
			<-releaseHolder
			return nil
		})
	}()

	select {
	case <-holderEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("holder goroutine never entered its critical section")
	}

	var releasedBeforeNestedAcquired bool
	nestedDone := make(chan error, 1)
	go func() {
		nestedDone <- ls.WithNamedLock(ctx, "key-A", func(ctx context.Context) error {
			// A DIFFERENT call chain (this goroutine) than the holder above is
			// currently blocking on holdKey. This nested call, under a
			// different key than "key-A", must still contend for holdKey's
			// own lock rather than skipping acquisition.
			return ls.WithNamedLock(ctx, holdKey, func(ctx context.Context) error {
				releasedBeforeNestedAcquired = true
				return nil
			})
		})
	}()

	// Give the nested call every opportunity to (wrongly) complete early if
	// the reentrancy guard were still skipping on "any lock held" rather than
	// "this exact key held" -- it must NOT have finished yet.
	select {
	case <-nestedDone:
		t.Fatal("nested WithNamedLock(key-B) returned before the other holder released it -- " +
			"the different-key lock was skipped instead of actually acquired")
	case <-time.After(200 * time.Millisecond):
	}

	close(releaseHolder)

	select {
	case err := <-holderDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("holder goroutine never completed")
	}

	select {
	case err := <-nestedDone:
		require.NoError(t, err)
		require.True(t, releasedBeforeNestedAcquired)
	case <-time.After(5 * time.Second):
		t.Fatal("nested WithNamedLock(key-B) never completed after the holder released")
	}
}

// namedLockKey must be a pure, stable function of its input: the Postgres
// path (local_named_lock.go's WithNamedLock) relies on the same lockKey
// string always hashing to the same advisory-lock key, on every connection,
// every process, every run -- otherwise two replicas naming the "same" lock
// key would take out advisory locks on two DIFFERENT Postgres keys and never
// actually serialize against each other.
func TestNamedLockKey_StableAndKeyDependent(t *testing.T) {
	require.Equal(t, namedLockKey("project-admin-guard"), namedLockKey("project-admin-guard"),
		"the same lockKey string must always hash to the same advisory-lock key")
	require.NotEqual(t, namedLockKey("key-A"), namedLockKey("key-B"),
		"different lockKey strings should (in practice) hash to different keys")
	require.NotEqual(t, int64(0), namedLockKey(""), "even an empty lockKey must produce a deterministic, usable key")
}

// TestWithNamedLock_RegistryReclaimsEntriesAfterUse is the #1690 regression
// pin (Part 2 regression audit, 2026-09-04): FIX-5's namedLockRegistry map
// grew by one entry per distinct lockKey ever seen and never shrank -- an
// unbounded-memory-growth surface on any long-uptime SQLite/single-process
// deployment (lockKey's key space is per-entity: one lock per user/group/
// project ID ever role-managed). After each WithNamedLock call fully
// completes and no other caller is contending for that same key, the
// registry must not still be holding that key's entry.
func TestWithNamedLock_RegistryReclaimsEntriesAfterUse(t *testing.T) {
	ls := newNamedLockTestStore(t)
	ctx := context.Background()

	for i := range 500 {
		key := fmt.Sprintf("entity-%d", i)
		require.NoError(t, ls.WithNamedLock(ctx, key, func(ctx context.Context) error {
			return nil
		}))
	}

	ls.namedLockMu.mu.Lock()
	size := len(ls.namedLockMu.locks)
	ls.namedLockMu.mu.Unlock()
	assert.Equal(t, 0, size, "the registry must reclaim each key's entry once its last holder releases it, not retain one entry per distinct key forever")
}

// TestWithNamedLock_ConcurrentSameKey_MutualExclusionSurvivesReclamation
// proves the refcounted-reclamation fix (#1690) did not reopen the mutual-
// exclusion guarantee WithNamedLock exists for: many goroutines racing
// acquire/release on the SAME key, including races that land exactly on a
// reclaim-and-recreate boundary, must never observe two goroutines inside the
// critical section at once. Run with -race to also catch a data race on the
// shared counter if two goroutines ever held two DIFFERENT mutex objects for
// what should be one logical key.
func TestWithNamedLock_ConcurrentSameKey_MutualExclusionSurvivesReclamation(t *testing.T) {
	ls := newNamedLockTestStore(t)

	const goroutines = 50
	const itersPerGoroutine = 20
	var inCriticalSection int32
	var overlapDetected bool
	var mu sync.Mutex // guards overlapDetected only

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range itersPerGoroutine {
				err := ls.WithNamedLock(context.Background(), "shared-key", func(ctx context.Context) error {
					n := inCriticalSection + 1
					inCriticalSection = n
					if n != 1 {
						mu.Lock()
						overlapDetected = true
						mu.Unlock()
					}
					inCriticalSection--
					return nil
				})
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()

	assert.False(t, overlapDetected, "two goroutines observed inside WithNamedLock's critical section for the same key at once -- reclamation raced ahead of an active holder")

	ls.namedLockMu.mu.Lock()
	size := len(ls.namedLockMu.locks)
	ls.namedLockMu.mu.Unlock()
	assert.Equal(t, 0, size, "the registry must end empty once every goroutine has released the shared key")
}
