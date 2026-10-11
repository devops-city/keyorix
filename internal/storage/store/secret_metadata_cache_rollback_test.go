// secret_metadata_cache_rollback_test.go — coordinator review of #2764,
// 2026-10-05. Two defect classes, one file, because they share a mechanism:
// a cache entry that is valid-looking but describes state that was never
// committed (rollback), or state that a later write replaced without moving
// the stamp (timestamp tie).
//
// ROLLBACK. WithTransaction hands fn a transaction-scoped LocalStorage that
// shares the parent's cache POINTER, and inside the transaction every query —
// the generation read included — runs through the transaction handle, so it
// sees UNCOMMITTED values. A cached read inside such a transaction writes an
// uncommitted answer, stamped with an uncommitted generation, into a cache that
// outlives the transaction. On rollback that entry stays; the moment a
// COMMITTED write reproduces the same generation value, it validates and is
// served. For the latest-version cache that means serving a version row that
// never committed — wrong ID, wrong ciphertext — and on SQLite the row id can
// even repeat, because sqlite_sequence is rolled back too.
// Fix: LocalStorage.cacheEnabled, set only by NewLocalStorage.
//
// TIE. `updated_at` is computed in Go by the writer and stored at microsecond
// precision on PostgreSQL, so two writes to one row can carry the same value
// and a warm entry stays "valid" across a real content change. The review
// refused a probability argument, so the stamps now carry a non-clock
// component: the row's own content (nodeGeneration, scheduleGeneration — see
// secret_metadata_cache_fieldledger_test.go for the machine-checked ledger of
// what is and is not covered).
package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestGetLatestSecretVersion_RolledBackVersionIsNotServed is the red/green
// case for the version cache. Red on 4b31a9d6b: the final read returns the
// version row the rolled-back transaction created.
func TestGetLatestSecretVersion_RolledBackVersionIsNotServed(t *testing.T) {
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: created.ID, VersionNumber: 1, EncryptedValue: []byte("v1"), CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	sentinel := errors.New("roll back on purpose")
	txErr := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.CreateSecretVersion(ctx, &models.SecretVersion{
			SecretNodeID: created.ID, VersionNumber: 2, EncryptedValue: []byte("ROLLED-BACK"), CreatedAt: time.Now(),
		}); err != nil {
			return err
		}
		// Resolving the latest version inside the transaction is what would
		// publish the uncommitted row into the shared cache.
		latest, err := tx.GetLatestSecretVersion(ctx, created.ID)
		if err != nil {
			return err
		}
		require.Equal(t, []byte("ROLLED-BACK"), latest.EncryptedValue,
			"the transaction must see its own uncommitted version (read-your-own-writes)")
		return sentinel
	})
	require.ErrorIs(t, txErr, sentinel)

	// Now a COMMITTED version 2 with different content. Its aggregate stamp
	// (count=2, max=2, sum(read_count)=0) is IDENTICAL to the rolled-back
	// transaction's, which is what makes the stale entry validate.
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: created.ID, VersionNumber: 2, EncryptedValue: []byte("COMMITTED"), CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	got, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, []byte("COMMITTED"), got.EncryptedValue,
		"a version row from a ROLLED-BACK transaction is being served: it was cached under the transaction's uncommitted aggregate, which the next committed version reproduced exactly")

	requireRootStoreFillsAndHits(t, ctx, ls, created.ID, false, true, false)
}

// TestGetSecret_RolledBackUpdateIsNotServed is the node cache's form. The
// committed write deliberately reuses the SAME updated_at, so this is red on
// 4b31a9d6b for both reasons at once: the entry should never have been
// published from inside the transaction, AND (updated_at, read_count) alone
// cannot tell the two rows apart.
func TestGetSecret_RolledBackUpdateIsNotServed(t *testing.T) {
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// One fixed timestamp both writes use, so updated_at cannot distinguish
	// them — the microsecond collision, made deterministic.
	tick := time.Now().Add(time.Second).UTC().Truncate(time.Millisecond)

	sentinel := errors.New("roll back on purpose")
	txErr := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.(*LocalStorage).db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
			Updates(map[string]any{"description": "ROLLED-BACK", "updated_at": tick}).Error; err != nil {
			return err
		}
		row, err := tx.GetSecret(ctx, created.ID)
		if err != nil {
			return err
		}
		require.Equal(t, "ROLLED-BACK", row.Description, "the transaction must see its own uncommitted update")
		return sentinel
	})
	require.ErrorIs(t, txErr, sentinel)

	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
		Updates(map[string]any{"description": "COMMITTED", "updated_at": tick}).Error)

	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "COMMITTED", got.Description,
		"a secret row from a ROLLED-BACK transaction is being served under a tied updated_at")

	requireRootStoreFillsAndHits(t, ctx, ls, created.ID, true, false, false)
}

// TestSecretMetadataCache_TransactionScopedStoreNeverTouchesTheSharedCache
// guards the mechanism rather than either symptom: no read inside a
// transaction may write the shared cache, whether the transaction commits or
// rolls back. Pinning it directly means a change that re-enables caching
// inside a transaction fails here even when it happens not to reproduce an
// exact stamp collision.
func TestSecretMetadataCache_TransactionScopedStoreNeverTouchesTheSharedCache(t *testing.T) {
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{
		SecretNodeID: created.ID, AllowedDays: "1,2,3", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}))

	// A COMMITTING transaction, so this is not about rollback: the rule is that
	// a tx-scoped store never writes the shared cache at all.
	require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.GetSecret(ctx, created.ID); err != nil {
			return err
		}
		if _, err := tx.GetLatestSecretVersion(ctx, created.ID); err != nil {
			return err
		}
		_, err := tx.GetSecretAccessSchedule(ctx, created.ID)
		return err
	}))

	_, node := ls.secretMetaCache.getNode(created.ID)
	_, version := ls.secretMetaCache.getVersion(created.ID)
	_, schedule := ls.secretMetaCache.getSchedule(created.ID)
	require.False(t, node, "GetSecret inside a transaction populated the shared node cache")
	require.False(t, version, "GetLatestSecretVersion inside a transaction populated the shared version cache")
	require.False(t, schedule, "GetSecretAccessSchedule inside a transaction populated the shared schedule cache")

	// The three assertions above are all negative, and all three would hold if
	// the cache simply did not work. Same three reads from the ROOT store must
	// fill AND hit, which is what makes "the tx-scoped store did not" a fact
	// about the transaction rather than about the feature.
	requireRootStoreFillsAndHits(t, ctx, ls, created.ID, true, true, true)
}

// TestGetSecret_TwoUpdatesOnOneTimestampTickAreNotTied is the pure tie case
// for the node stamp — no transaction involved, two ordinary committed writes
// that happen to carry the same updated_at (the cross-replica microsecond
// collision, made deterministic by writing the column directly). Red on
// 4b31a9d6b, where the stamp is (updated_at, read_count) and read_count did
// not move.
func TestGetSecret_TwoUpdatesOnOneTimestampTickAreNotTied(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	tick := time.Now().Add(time.Second).UTC().Truncate(time.Millisecond)
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
		Updates(map[string]any{"classification": "public", "updated_at": tick}).Error)

	warm, err := ls.GetSecret(ctx, created.ID) // caches under (tick, 0, …, classification=public)
	require.NoError(t, err)
	require.Equal(t, "public", warm.Classification)

	// A second write on the SAME tick, changing a read-gate input.
	require.NoError(t, ls.db.Model(&models.SecretNode{}).Where(sqlWhereID, created.ID).
		Updates(map[string]any{"classification": "restricted", "updated_at": tick}).Error)

	got, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "restricted", got.Classification,
		"two writes tied on updated_at served the earlier row: the stamp needs a non-clock component (the row's own content)")
}

// TestGetSecretAccessSchedule_TwoWritesOnOneTimestampTickAreNotTied is the same
// for the schedule stamp. An access schedule is a read GATE, so a stale one
// keeps a closed read window open — the review flagged this one specifically.
func TestGetSecretAccessSchedule_TwoWritesOnOneTimestampTickAreNotTied(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{
		SecretNodeID: created.ID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC",
	}))

	tick := time.Now().Add(time.Second).UTC().Truncate(time.Millisecond)
	require.NoError(t, ls.db.Model(&models.SecretAccessSchedule{}).Where(sqlWhereSecretNodeID, created.ID).
		Updates(map[string]any{"allowed_days": "*", "start_hour": 0, "end_hour": 24, "updated_at": tick}).Error)

	warm, err := ls.GetSecretAccessSchedule(ctx, created.ID) // caches the wide-open window
	require.NoError(t, err)
	require.NotNil(t, warm)
	require.Equal(t, 24, warm.EndHour)

	// The window closes, on the SAME tick.
	require.NoError(t, ls.db.Model(&models.SecretAccessSchedule{}).Where(sqlWhereSecretNodeID, created.ID).
		Updates(map[string]any{"allowed_days": "1", "start_hour": 9, "end_hour": 10, "updated_at": tick}).Error)

	got, err := ls.GetSecretAccessSchedule(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, 10, got.EndHour,
		"a closed read window is still serving the previous wide-open schedule: two schedule writes tied on updated_at")
	require.Equal(t, "1", got.AllowedDays)
}

// requireRootStoreFillsAndHits is the anti-vacuity control for every test in
// this file (coordinator review of #2764, item 5).
//
// All of these tests assert that something is NOT served from cache. Every one
// of them therefore passes trivially if the cache is off — if cacheEnabled were
// dropped, if the trigger probe went permanently false, if the whole feature
// were reverted. A test that cannot distinguish "the bug is fixed" from "the
// feature is gone" is not evidence for the fix.
//
// So each test also pins the positive direction on the SAME read: the root
// store must FILL its cache and then HIT it. The hit is asserted through the
// real read-path predicate (getCachedSecret/getCachedLatestVersion/
// getCachedSchedule), not inferred from an entry existing — an entry whose
// generation check fails is present and useless, which is precisely the state a
// broken stamp would leave behind.
func requireRootStoreFillsAndHits(t *testing.T, ctx context.Context, ls *LocalStorage, secretID uint, node, version, schedule bool) {
	t.Helper()
	if node {
		if _, err := ls.GetSecret(ctx, secretID); err != nil {
			t.Fatalf("root GetSecret: %v", err)
		}
		_, filled := ls.secretMetaCache.getNode(secretID)
		require.True(t, filled, "the root store did not FILL the node cache — every not-served assertion in this test would pass with caching off")
		_, hit := ls.getCachedSecret(ctx, secretID)
		require.True(t, hit, "the root store filled the node cache but cannot HIT it: the stamp written on store does not validate on read, so the cache is dead weight and this test's negative assertions prove nothing")
	}
	if version {
		if _, err := ls.GetLatestSecretVersion(ctx, secretID); err != nil {
			t.Fatalf("root GetLatestSecretVersion: %v", err)
		}
		_, filled := ls.secretMetaCache.getVersion(secretID)
		require.True(t, filled, "the root store did not FILL the version cache")
		_, hit := ls.getCachedLatestVersion(ctx, secretID)
		require.True(t, hit, "the root store filled the version cache but cannot HIT it")
	}
	if schedule {
		if _, err := ls.GetSecretAccessSchedule(ctx, secretID); err != nil {
			t.Fatalf("root GetSecretAccessSchedule: %v", err)
		}
		_, filled := ls.secretMetaCache.getSchedule(secretID)
		require.True(t, filled, "the root store did not FILL the schedule cache")
		_, hit := ls.getCachedSchedule(ctx, secretID)
		require.True(t, hit, "the root store filled the schedule cache but cannot HIT it")
	}
}
