package store

// audit_retention_prefix_test.go — INV-STORE-22 (#2633): the audit retention
// purge (DeleteAuditLogsBefore) deletes only a contiguous id prefix of
// audit_events, and runs under the same KEYAUDIT advisory lock the append path
// (LogAuditEvent) uses.
//
// The hash chain is ordered by id, but the purge's cutoff is on event_time.
// The two orders disagree whenever a row with a higher id carries an older
// event_time than a lower-id row: LogAuditEvent stamps event_time BEFORE it
// takes the append lock, so two concurrent writers can commit in the opposite
// order to their timestamps, and HA replicas with skewed clocks do the same at
// a larger scale. A purge that deletes every `event_time < cutoff` row then
// removes a row from the MIDDLE of the chain, and VerifyAuditChain reports the
// trail as tampered. These tests build exactly that shape with the real append
// path (real hashes, real prev_hash linkage) and assert the chain still
// verifies after the purge.

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// appendAuditAt appends one chained audit event with the given event_time via
// the real LogAuditEvent path and returns its id.
func appendAuditAt(t *testing.T, ls *LocalStorage, at time.Time, label string) uint {
	t.Helper()
	e := &models.AuditEvent{EventType: "secret.read", Description: label, EventTime: at}
	require.NoError(t, ls.LogAuditEvent(context.Background(), e))
	require.NotZero(t, e.ID)
	return e.ID
}

// purgeLikeCore runs DeleteAuditLogsBefore inside WithTransaction, the way its
// only production caller (core.PurgeAuditLogs) does.
func purgeLikeCore(t *testing.T, ls *LocalStorage, cutoff time.Time) (int64, *storage.AuditChainAnchor) {
	t.Helper()
	var (
		n      int64
		anchor *storage.AuditChainAnchor
	)
	require.NoError(t, ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
		var err error
		n, anchor, err = tx.DeleteAuditLogsBefore(context.Background(), cutoff)
		return err
	}))
	return n, anchor
}

func survivingAuditIDs(t *testing.T, ls *LocalStorage) []uint {
	t.Helper()
	var ids []uint
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Order("id ASC").Pluck("id", &ids).Error)
	return ids
}

// assertInvertedPairPurgeKeepsChainVerifiable is the shared body of the
// SQLite and Postgres variants. Chain (by id):
//
//	old1  old   (before cutoff)
//	newA  NEW   (after cutoff)   <- lower id, newer event_time
//	oldB  old   (before cutoff)  <- higher id, older event_time: the inversion
//	new2  NEW   (after cutoff)
//
// The pre-fix purge deletes old1 AND oldB, leaving newA -> [gap] -> new2: new2's
// prev_hash points at the deleted oldB, so the chain fails to verify. The
// contiguous-prefix purge deletes only old1, keeps everything from newA on, and
// re-anchors on newA.
func assertInvertedPairPurgeKeepsChainVerifiable(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	cutoff := now.Add(-24 * time.Hour)
	old := cutoff.Add(-time.Hour)

	appendAuditAt(t, ls, old, "old1")
	newA := appendAuditAt(t, ls, now, "newA")
	oldB := appendAuditAt(t, ls, old.Add(time.Minute), "oldB (older event_time, higher id)")
	new2 := appendAuditAt(t, ls, now.Add(time.Second), "new2")

	pre, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	require.True(t, pre.Valid, "fixture chain must verify before the purge: %s", pre.Reason)

	n, anchor := purgeLikeCore(t, ls, cutoff)

	assert.Equal(t, int64(1), n, "only the contiguous old prefix (old1) may be deleted")
	assert.Equal(t, []uint{newA, oldB, new2}, survivingAuditIDs(t, ls),
		"the newer row that breaks the prefix and everything after it must survive")
	require.NotNil(t, anchor, "the purge reached into the chained region, so it must hand back a re-anchor")
	assert.Equal(t, newA, anchor.RowID, "anchor must be the first surviving id")

	post, err := ls.VerifyAuditChain(ctx, anchor)
	require.NoError(t, err)
	assert.True(t, post.Valid, "chain must verify after the purge; first broken id %v: %s", post.FirstBrokenID, post.Reason)
	assert.Equal(t, int64(3), post.ChainedEvents)
}

// TestDeleteAuditLogsBefore_InvertedEventTime_DeletesOnlyContiguousIDPrefix is
// INV-STORE-22's primary guard (SQLite).
func TestDeleteAuditLogsBefore_InvertedEventTime_DeletesOnlyContiguousIDPrefix(t *testing.T) {
	assertInvertedPairPurgeKeepsChainVerifiable(t, newAuditRetentionTestStore(t))
}

// TestDeleteAuditLogsBefore_InvertedEventTime_Postgres is the Postgres variant
// of the same guard (pg-gated: skips without KEYORIX_TEST_PG_DSN).
func TestDeleteAuditLogsBefore_InvertedEventTime_Postgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	assertInvertedPairPurgeKeepsChainVerifiable(t, NewLocalStorage(db))
}

// TestDeleteAuditLogsBefore_NeverDeletesMoreThanEventTimeCutoff checks the
// two halves of INV-STORE-22 over randomized event_time orders, against an
// oracle computed in Go from the rows as appended:
//
//   - the deleted set is exactly the longest id prefix whose rows all have
//     event_time < cutoff (so it is always a SUBSET of the pre-fix
//     `event_time < cutoff` set — the purge never deletes more than it did
//     before #2633), and
//   - the surviving chain verifies against the returned anchor.
func TestDeleteAuditLogsBefore_NeverDeletesMoreThanEventTimeCutoff(t *testing.T) {
	rng := rand.New(rand.NewSource(2633)) // #nosec G404 -- deterministic test fixture, not security-sensitive
	now := time.Now().UTC().Truncate(time.Second)
	cutoff := now.Add(-24 * time.Hour)

	for iter := range 40 {
		t.Run(fmt.Sprintf("seed_iter_%d", iter), func(t *testing.T) {
			ls := newAuditRetentionTestStore(t)
			rows := 1 + rng.Intn(12)
			type appended struct {
				id  uint
				old bool
			}
			var all []appended
			for i := range rows {
				// Mostly-old leading rows with random inversions, so the prefix
				// boundary lands at varied positions (including "all old" and
				// "first row new").
				isOld := rng.Intn(10) < 7
				at := now.Add(time.Duration(rng.Intn(3600)) * time.Second)
				if isOld {
					at = cutoff.Add(-time.Duration(1+rng.Intn(3600)) * time.Second)
				}
				all = append(all, appended{appendAuditAt(t, ls, at, fmt.Sprintf("row%d", i)), isOld})
			}

			var wantDeleted, eventTimeOld []uint
			prefix := true
			for _, r := range all {
				if r.old {
					eventTimeOld = append(eventTimeOld, r.id)
				} else {
					prefix = false
				}
				if prefix && r.old {
					wantDeleted = append(wantDeleted, r.id)
				}
			}

			before := survivingAuditIDs(t, ls)
			n, anchor := purgeLikeCore(t, ls, cutoff)
			after := survivingAuditIDs(t, ls)

			deleted := diffIDs(before, after)
			assert.Equal(t, wantDeleted, deleted, "deleted set must be exactly the contiguous old id prefix")
			assert.Equal(t, int64(len(wantDeleted)), n)
			assert.Subset(t, eventTimeOld, deleted,
				"never delete a row the pre-fix `event_time < cutoff` purge would have kept")

			res, err := ls.VerifyAuditChain(context.Background(), anchor)
			require.NoError(t, err)
			assert.True(t, res.Valid, "chain must verify after the purge; first broken id %v: %s", res.FirstBrokenID, res.Reason)
			if len(after) > 0 && len(deleted) > 0 {
				require.NotNil(t, anchor)
				assert.Equal(t, after[0], anchor.RowID, "anchor must be the first surviving id")
			}
		})
	}
}

func diffIDs(before, after []uint) []uint {
	keep := make(map[uint]bool, len(after))
	for _, id := range after {
		keep[id] = true
	}
	var out []uint
	for _, id := range before {
		if !keep[id] {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// TestDeleteAuditLogsBefore_HoldsKEYAUDITUntilCommit_Postgres asserts the
// purge takes the SAME advisory lock LogAuditEvent appends under, and holds it
// until the enclosing transaction (core.PurgeAuditLogs') commits — so no
// replica can append between the purge choosing its id prefix, deleting it,
// and the caller persisting the re-anchor. A second, independent connection
// (a separate "replica") must fail pg_try_advisory_xact_lock(KEYAUDIT) while
// the purge transaction is still open, and succeed once it has committed.
func TestDeleteAuditLogsBefore_HoldsKEYAUDITUntilCommit_Postgres(t *testing.T) {
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	purgeDB := pgOpen(t, dsn)
	otherDB := pgOpen(t, dsn)
	require.NoError(t, purgeDB.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(purgeDB)

	now := time.Now().UTC().Truncate(time.Second)
	cutoff := now.Add(-24 * time.Hour)
	appendAuditAt(t, ls, cutoff.Add(-time.Hour), "old")
	appendAuditAt(t, ls, now, "new")

	tryLock := func() bool {
		var got bool
		require.NoError(t, otherDB.Transaction(func(tx *gorm.DB) error {
			return tx.Raw("SELECT pg_try_advisory_xact_lock(?)", int64(auditAdvisoryLockKey)).Scan(&got).Error
		}))
		return got
	}

	require.True(t, tryLock(), "precondition: KEYAUDIT is free before the purge")
	require.NoError(t, ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
		n, _, err := tx.DeleteAuditLogsBefore(context.Background(), cutoff)
		require.NoError(t, err)
		require.Equal(t, int64(1), n)
		assert.False(t, tryLock(), "KEYAUDIT must be held by the purge until its transaction commits")
		return nil
	}))
	assert.True(t, tryLock(), "KEYAUDIT must be released once the purge transaction commits")
}

// TestDeleteAuditLogsBefore_ConcurrentAppendNotStalledOrDropped_SQLite pins
// the lock-ORDER half of INV-STORE-22 on a production-shaped SQLite database
// (file-backed, WAL, _txlock=immediate, several pooled connections — the same
// pragmas internal/storage/factory.go's sqliteDSN sets).
//
// LogAuditEvent acquires auditChainMu and THEN opens its transaction (claiming
// SQLite's writer lock up front under _txlock=immediate). The purge already
// runs inside core.PurgeAuditLogs' transaction, which holds that writer lock
// from BEGIN. If DeleteAuditLogsBefore also took auditChainMu, the two would
// acquire the same pair of locks in opposite orders: an append that grabbed the
// mutex just after the purge transaction began would sit on it, retrying
// SQLITE_BUSY until its 10s auditWriteContext deadline, while the purge waited
// on the mutex — and the append would then be DROPPED (emitAudit logs and
// discards a failed write). On SQLite the KEYAUDIT step in the append path is
// itself a no-op; the writer lock is what serializes a purge against appends.
// This test forces exactly that interleaving and asserts the append lands
// promptly and the chain still verifies.
func TestDeleteAuditLogsBefore_ConcurrentAppendNotStalledOrDropped_SQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	dsn := path + "?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate&_synchronous=FULL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	ls := NewLocalStorage(db)

	now := time.Now().UTC().Truncate(time.Second)
	cutoff := now.Add(-24 * time.Hour)
	appendAuditAt(t, ls, cutoff.Add(-time.Hour), "old")
	appendAuditAt(t, ls, now, "new")

	var (
		wg        sync.WaitGroup
		appendErr error
		appended  = &models.AuditEvent{EventType: "secret.read", Description: "concurrent", EventTime: now.Add(time.Second)}
	)
	start := time.Now()
	var anchor *storage.AuditChainAnchor
	require.NoError(t, ls.WithTransaction(context.Background(), func(tx storage.Storage) error {
		// The purge transaction now holds SQLite's writer lock. Start an append
		// and give it time to take auditChainMu and block on BEGIN IMMEDIATE.
		wg.Go(func() {
			appendErr = ls.LogAuditEvent(context.Background(), appended)
		})
		time.Sleep(200 * time.Millisecond)
		var err error
		_, anchor, err = tx.DeleteAuditLogsBefore(context.Background(), cutoff)
		return err
	}))
	wg.Wait()
	elapsed := time.Since(start)

	require.NoError(t, appendErr, "an append racing the purge must not be dropped")
	assert.Less(t, elapsed, 5*time.Second, "purge and a racing append must not stall on an inverted lock order")
	assert.NotZero(t, appended.ID)

	res, err := ls.VerifyAuditChain(context.Background(), anchor)
	require.NoError(t, err)
	assert.True(t, res.Valid, "chain must verify; first broken id %v: %s", res.FirstBrokenID, res.Reason)
	assert.Equal(t, int64(2), res.ChainedEvents)
}
