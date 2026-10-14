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

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newSchedLockLeaseStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SchedulerLockLease{}))
	return NewLocalStorage(db)
}

// A fresh key is acquired on the very first attempt.
func TestTryAcquireSchedulerLock_FirstAcquireSucceeds(t *testing.T) {
	ls := newSchedLockLeaseStore(t)
	ctx := context.Background()

	acquired, err := ls.TryAcquireSchedulerLock(ctx, 42, "holder-a", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

// A second, different holder cannot acquire a lock that's still within its TTL.
func TestTryAcquireSchedulerLock_ContendedLockRejectsOtherHolder(t *testing.T) {
	ls := newSchedLockLeaseStore(t)
	ctx := context.Background()

	acquired, err := ls.TryAcquireSchedulerLock(ctx, 42, "holder-a", time.Minute)
	require.NoError(t, err)
	require.True(t, acquired)

	acquired, err = ls.TryAcquireSchedulerLock(ctx, 42, "holder-b", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired, "a live, differently-held lease must reject a competing holder")
}

// Calling TryAcquireSchedulerLock again with the SAME holder renews the lease
// (the heartbeat path) rather than being rejected as contended.
func TestTryAcquireSchedulerLock_SameHolderRenews(t *testing.T) {
	ls := newSchedLockLeaseStore(t)
	ctx := context.Background()

	acquired, err := ls.TryAcquireSchedulerLock(ctx, 42, "holder-a", time.Minute)
	require.NoError(t, err)
	require.True(t, acquired)

	acquired, err = ls.TryAcquireSchedulerLock(ctx, 42, "holder-a", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired, "the same holder renewing its own still-live lease must succeed")
}

// An expired lease is reclaimable by a different holder — the crash/partition
// self-heal property.
func TestTryAcquireSchedulerLock_ExpiredLeaseIsReclaimable(t *testing.T) {
	ls := newSchedLockLeaseStore(t)
	ctx := context.Background()

	acquired, err := ls.TryAcquireSchedulerLock(ctx, 42, "holder-a", -time.Second) // already expired
	require.NoError(t, err)
	require.True(t, acquired)

	acquired, err = ls.TryAcquireSchedulerLock(ctx, 42, "holder-b", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired, "an expired lease must be reclaimable by a different holder")
}

// ReleaseSchedulerLock is a conditional delete: it only removes the row when
// holder still matches, and is a silent no-op otherwise (never an error).
func TestReleaseSchedulerLock_OwnershipMismatchIsNoop(t *testing.T) {
	ls := newSchedLockLeaseStore(t)
	ctx := context.Background()

	acquired, err := ls.TryAcquireSchedulerLock(ctx, 42, "holder-a", time.Minute)
	require.NoError(t, err)
	require.True(t, acquired)

	// A DIFFERENT holder attempting to release must be a silent no-op, not an error.
	require.NoError(t, ls.ReleaseSchedulerLock(ctx, 42, "holder-b"))

	// holder-a's lease must still be intact — a second holder can't acquire it.
	acquired, err = ls.TryAcquireSchedulerLock(ctx, 42, "holder-b", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired, "release by the wrong holder must not have cleared the lease")

	// The real owner CAN release it, and the key becomes immediately acquirable.
	require.NoError(t, ls.ReleaseSchedulerLock(ctx, 42, "holder-a"))
	acquired, err = ls.TryAcquireSchedulerLock(ctx, 42, "holder-c", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired, "a genuine release must free the key for the next acquirer")
}

// Releasing a lock that was never acquired is a no-op, not an error.
func TestReleaseSchedulerLock_NeverAcquiredIsNoop(t *testing.T) {
	ls := newSchedLockLeaseStore(t)
	require.NoError(t, ls.ReleaseSchedulerLock(context.Background(), 999, "nobody"))
}

// Concurrent first-time acquire attempts on the SAME key must serialize to
// exactly one winner — the core exclusivity guarantee this whole primitive
// exists for. Uses a real file-backed SQLite DB with WAL + a busy timeout
// (concurrentDB, same helper local_break_glass_test.go's equivalent race test
// uses) so connections genuinely contend; a single shared in-memory connection
// would serialize every statement and mask the race this test exists to
// catch. The real-HTTP version of this race (proving it survives a
// storage.type: remote HTTP hop, not just an in-process DB transaction) lives
// in server/http/remote_storage_scheduler_lock_test.go.
func TestTryAcquireSchedulerLock_ConcurrentFirstAcquireHasExactlyOneWinner(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.SchedulerLockLease{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	const racers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Each racer uses its OWN distinct holder token, exactly as the real
			// RemoteStorage.WithSchedulerLock caller does (newSchedulerLockHolderToken
			// mints a fresh one per attempt) — using the same token for every
			// racer would make every attempt after the first look like that
			// SAME holder legitimately renewing its own lease, masking the
			// exclusivity race this test exists to catch.
			holder := fmt.Sprintf("holder-%d", i)
			acquired, err := ls.TryAcquireSchedulerLock(ctx, 7, holder, time.Minute)
			assert.NoError(t, err)
			if acquired {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}(i)
	}
	close(start) // release all racers at once
	wg.Wait()

	assert.Equal(t, 1, winners, "exactly one concurrent first-time acquire attempt may win")
}
