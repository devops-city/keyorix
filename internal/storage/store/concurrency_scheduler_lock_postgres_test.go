package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce
// exercises WithSchedulerLock's pg_try_advisory_lock (local_scheduler_lock.go)
// across genuinely independent connections — a single-connection test cannot
// say anything about it: pg_try_advisory_lock is scoped to the SESSION taking
// it, so one connection calling it twice would just re-acquire its own lock.
// This drives many independent LocalStorage instances (own *gorm.DB, own
// Postgres backend connection) at the SAME advisory-lock key concurrently:
// exactly one may run its job at a time, every other concurrent attempt must
// see the lock held and skip the tick (acquired=false) rather than running
// alongside the winner — the "only one replica runs this periodic job" ADR-039
// guarantee this function exists to provide.
func TestConcurrency_WithSchedulerLock_MultiInstancePostgres_ExactlyOneRunsAtOnce(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	const instances = 8
	const key = 0x5343484544 // arbitrary, namespaced to this test

	stores := make([]*LocalStorage, instances)
	for i := range instances {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}

	var running atomic.Int32
	var maxConcurrent atomic.Int32
	var acquiredCount atomic.Int32

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range instances {
		wg.Add(1)
		go func(ls *LocalStorage) {
			defer wg.Done()
			<-start
			acquired, err := ls.WithSchedulerLock(context.Background(), key, func(context.Context) error {
				n := running.Add(1)
				for {
					m := maxConcurrent.Load()
					if n <= m || maxConcurrent.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(150 * time.Millisecond) // hold the lock long enough for every racer to attempt while it's held
				running.Add(-1)
				return nil
			})
			require.NoError(t, err)
			if acquired {
				acquiredCount.Add(1)
			}
		}(stores[i])
	}
	close(start) // release every instance's attempt at once
	wg.Wait()

	assert.Equal(t, int32(1), maxConcurrent.Load(), "at most one replica's job may run at a time")
	assert.Equal(t, int32(1), acquiredCount.Load(), "exactly one replica may win the advisory lock for this tick")
}

// TestConcurrency_SchedulerLockLease_MultiInstancePostgres exercises the
// row-based lease (local_scheduler_lock_lease.go) used by RemoteStorage's
// WithSchedulerLock, which is deliberately independent of the advisory-lock
// mechanism above — its own FOR UPDATE row lock, tested here the same way:
// genuinely independent connections, not one connection racing itself.
//
// Two properties, matching the task: (a) under concurrent contention on a
// BRAND-NEW key (never acquired before — the race that matters, and the one
// this test used to avoid), exactly one holder wins; (b) after the winner's
// lease TTL expires without renewal, a DIFFERENT holder can reclaim the SAME
// key — and at every point in between there is at most one lease row for
// that key, so no two holders are ever simultaneously valid.
//
// (a) used to seed the row with one uncontended acquire before racing
// contenders against it, deliberately avoiding a brand-new-key race: prior to
// the ON CONFLICT DO NOTHING fix (local_scheduler_lock_lease.go), a
// concurrent first-time INSERT's unique-constraint violation aborted the
// whole enclosing Postgres transaction, and the Go recovery code
// (`if isUniqueViolation(createErr) { return nil }`) never got a chance to
// run — GORM's COMMIT on the already-aborted transaction was silently
// downgraded to a ROLLBACK, surfacing as a caller-facing error instead of
// (false, nil). See this campaign's report for the original repro. Now that
// the conflict is prevented rather than caught, this races the brand-new key
// directly — that race is the acceptance criterion.
func TestConcurrency_SchedulerLockLease_MultiInstancePostgres(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.SchedulerLockLease{}))

	const instances = 8
	const key = 0x4C454153450 // arbitrary, namespaced to this test; never acquired before this race

	stores := make([]*LocalStorage, instances)
	for i := range instances {
		stores[i] = NewLocalStorage(pgOpen(t, dsn))
	}

	// (a) contention: every instance races to be the FIRST-EVER acquirer of
	// this key, with a distinct holder id. Exactly one may win; every other
	// attempt must return cleanly (false, nil) — none may error.
	var wonCount atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	winners := make(chan string, instances)
	for i := range instances {
		wg.Add(1)
		go func(idx int, ls *LocalStorage) {
			defer wg.Done()
			holder := "replica-" + string(rune('A'+idx))
			<-start
			acquired, err := ls.TryAcquireSchedulerLock(context.Background(), key, holder, 5*time.Second)
			require.NoError(t, err, "a losing racer on a brand-new key must return (false, nil), never an error")
			if acquired {
				wonCount.Add(1)
				winners <- holder
			}
		}(i, stores[i])
	}
	close(start)
	wg.Wait()
	close(winners)

	assert.Equal(t, int32(1), wonCount.Load(), "exactly one of the eight racing first-time acquirers may win")
	require.Len(t, winners, 1)
	winner := <-winners

	verifier := NewLocalStorage(pgOpen(t, dsn))
	assertExactlyOneLease(t, verifier, key, winner)

	// (b) expiry handover: a SHORT-TTL lease from a fresh holder, left
	// unrenewed past expiry, must become reclaimable by a different holder —
	// and only by one at a time, same as above.
	const handoverKey = key + 1
	// handoverTTL must comfortably exceed the time it takes holder-B to open its own
	// Postgres connection and attempt the acquire below: at 100ms a slow CI runner
	// let holder-A's lease expire first and holder-B legitimately won (flaked in the
	// #2319 merge group, 2026-09-29). 1s keeps the expiry-handover assertion intact.
	const handoverTTL = time.Second
	holderA := NewLocalStorage(pgOpen(t, dsn))
	acquiredA, err := holderA.TryAcquireSchedulerLock(context.Background(), handoverKey, "holder-A", handoverTTL)
	require.NoError(t, err)
	require.True(t, acquiredA)

	// While still valid, a different holder must be refused.
	holderB := NewLocalStorage(pgOpen(t, dsn))
	acquiredB, err := holderB.TryAcquireSchedulerLock(context.Background(), handoverKey, "holder-B", 5*time.Second)
	require.NoError(t, err)
	assert.False(t, acquiredB, "holder-B must not acquire while holder-A's lease is still valid")

	time.Sleep(handoverTTL + 500*time.Millisecond) // past holder-A's TTL, never renewed (simulates a crashed replica)

	// Multiple late claimants race the now-expired lease; exactly one may
	// reclaim it.
	var reclaimWon atomic.Int32
	var wg2 sync.WaitGroup
	claimants := []*LocalStorage{holderB, NewLocalStorage(pgOpen(t, dsn)), NewLocalStorage(pgOpen(t, dsn))}
	names := []string{"holder-B", "holder-C", "holder-D"}
	start2 := make(chan struct{})
	reclaimWinner := make(chan string, len(claimants))
	for i, ls := range claimants {
		wg2.Add(1)
		go func(idx int, ls *LocalStorage) {
			defer wg2.Done()
			<-start2
			ok, err := ls.TryAcquireSchedulerLock(context.Background(), handoverKey, names[idx], 5*time.Second)
			require.NoError(t, err)
			if ok {
				reclaimWon.Add(1)
				reclaimWinner <- names[idx]
			}
		}(i, ls)
	}
	close(start2)
	wg2.Wait()
	close(reclaimWinner)

	assert.Equal(t, int32(1), reclaimWon.Load(), "exactly one late claimant may reclaim an expired lease")
	newHolder := <-reclaimWinner
	assertExactlyOneLease(t, verifier, handoverKey, newHolder)
}

// assertExactlyOneLease checks there is exactly one lease row for key and
// that its holder is exactly want — the structural check that no two
// holders are ever simultaneously valid for the same key.
func assertExactlyOneLease(t *testing.T, verifier *LocalStorage, key int64, want string) {
	t.Helper()
	var leases []models.SchedulerLockLease
	require.NoError(t, verifier.DB().Where("key = ?", key).Find(&leases).Error)
	require.Len(t, leases, 1, "exactly one lease row must exist for this key")
	assert.Equal(t, want, leases[0].Holder)
}
