// secret_metadata_cache_test.go — correctness tests for the read-path
// metadata cache (PERF-3, docs/specs/read-path-caching.md): GetSecret,
// GetLatestSecretVersion, and GetSecretAccessSchedule must reflect every
// known write to the underlying row on the very next call, never a stale
// cached snapshot, and a generation-check error must fall through to a live
// read rather than serving a stale value or panicking.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newCacheTestStorage(t testing.TB) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{},
		&models.ShareRecord{}, &models.SecretACL{},
	))
	// cache_epoch and its trigger are NOT model fields, so AutoMigrate cannot
	// create them (see secret_node_cache_epoch.go). Without this the node
	// cache's stamp would never move and every test in this file that asserts
	// the cache reflects a write would pass vacuously — the production
	// migration calls exactly this function, so there is one definition.
	require.NoError(t, EnsureSecretNodeCacheEpoch(db))
	return NewLocalStorage(db)
}

// TestGetSecret_CacheReflectsUpdateSecret covers the most common write path
// (Save on a full struct) — the one whose Save()-bypasses-hook-SetColumn
// behavior originally broke this cache's design; see secret_metadata_cache.go's
// own header for the full story.
func TestGetSecret_CacheReflectsUpdateSecret(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)

	// Warm the cache.
	first, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "", first.Description)

	// Mutate via UpdateSecret (Save) — the path that silently didn't bump a
	// hand-added generation column.
	first.Description = "updated"
	first.UpdatedAt = time.Now()
	_, err = ls.UpdateSecret(ctx, first)
	require.NoError(t, err)

	second, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "updated", second.Description, "cache served a stale pre-update snapshot")
}

// TestGetSecret_CacheReflectsTransitionSecretStatus covers the conditional
// Select("*").Updates(secret) write path (TransitionSecretStatus).
func TestGetSecret_CacheReflectsTransitionSecretStatus(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	first, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "active", first.Status)

	first.Status = "suspended"
	first.UpdatedAt = time.Now()
	ok, err := ls.TransitionSecretStatus(ctx, first, "active")
	require.NoError(t, err)
	require.True(t, ok)

	second, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "suspended", second.Status, "cache served a stale pre-transition snapshot")
}

// TestGetSecret_CacheReflectsSetSecretCertNotAfter covers the single-column
// .Update("col", val) write path.
func TestGetSecret_CacheReflectsSetSecretCertNotAfter(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)

	_, err = ls.GetSecret(ctx, created.ID) // warm
	require.NoError(t, err)

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, ls.SetSecretCertNotAfter(ctx, created.ID, &notAfter))

	second, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, second.CertNotAfter)
	require.True(t, second.CertNotAfter.Equal(notAfter), "cache served a stale pre-SetSecretCertNotAfter snapshot")
}

// TestGetSecret_CacheReflectsDeleteSecret: a soft-deleted secret must never
// be served from cache after the delete, even though DeleteSecret does not
// itself advance UpdatedAt (confirmed empirically) — the generation-check
// query's own soft-delete scope is what makes this correct regardless.
func TestGetSecret_CacheReflectsDeleteSecret(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)

	_, err = ls.GetSecret(ctx, created.ID) // warm
	require.NoError(t, err)

	require.NoError(t, ls.DeleteSecret(ctx, created.ID))

	_, err = ls.GetSecret(ctx, created.ID)
	require.Error(t, err, "cache served a stale pre-delete snapshot for a now soft-deleted secret")
}

// TestGetLatestSecretVersion_CacheReflectsRotate covers RotateSecret's
// version-creation path (storeSecretVersion + tx.UpdateSecret in one
// transaction) — the version cache shares its generation signal with the
// node cache precisely because this path touches both together.
func TestGetLatestSecretVersion_CacheReflectsNewVersion(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now()})
	require.NoError(t, err)

	v1, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 1, v1.VersionNumber)

	// Version 2 lands together with a node touch, mirroring
	// updateSecretWithNewVersion's real transaction shape.
	require.NoError(t, ls.db.Transaction(func(tx *gorm.DB) error {
		txStore := &LocalStorage{db: tx, secretMetaCache: ls.secretMetaCache}
		if _, err := txStore.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 2, CreatedAt: time.Now()}); err != nil {
			return err
		}
		created.UpdatedAt = time.Now()
		_, err := txStore.UpdateSecret(ctx, created)
		return err
	}))

	v2, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 2, v2.VersionNumber, "cache served a stale pre-rotate version snapshot")
}

// TestGetSecretAccessSchedule_CacheReflectsSetAndDelete covers the
// schedule's own independent generation signal (a different table from
// secret_nodes).
func TestGetSecretAccessSchedule_CacheReflectsSetAndDelete(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)

	none, err := ls.GetSecretAccessSchedule(ctx, created.ID)
	require.NoError(t, err)
	require.Nil(t, none)

	require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{
		SecretNodeID: created.ID, AllowedDays: "1,2,3,4,5", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}))
	got, err := ls.GetSecretAccessSchedule(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "1,2,3,4,5", got.AllowedDays)

	// Update the existing schedule (the FirstOrCreate-then-Save branch).
	require.NoError(t, ls.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{
		SecretNodeID: created.ID, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC",
	}))
	updated, err := ls.GetSecretAccessSchedule(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.Equal(t, "*", updated.AllowedDays, "cache served a stale pre-update schedule snapshot")

	require.NoError(t, ls.DeleteSecretAccessSchedule(ctx, created.ID))
	gone, err := ls.GetSecretAccessSchedule(ctx, created.ID)
	require.NoError(t, err)
	require.Nil(t, gone, "cache served a stale pre-delete schedule snapshot")
}

// TestGetCachedSecret_GenerationCheckError_FailsClosed: once the
// generation-check query itself can no longer succeed (table gone), a WARM
// cache entry must never be served — getCachedSecret must report a miss,
// not panic and not return the stale cached node.
func TestGetCachedSecret_GenerationCheckError_FailsClosed(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	_, err = ls.GetSecret(ctx, created.ID) // warm the cache
	require.NoError(t, err)

	// Confirm it's actually warm before breaking the DB.
	_, ok := ls.secretMetaCache.getNode(created.ID)
	require.True(t, ok, "expected cache to be warm before the DB is broken")

	require.NoError(t, ls.db.Migrator().DropTable(&models.SecretNode{}))

	got, hit := ls.getCachedSecret(ctx, created.ID)
	require.False(t, hit, "a generation-check error must never be reported as a cache hit")
	require.Nil(t, got)
}

// TestGetSecret_DifferentLocalStorageInstances_DoNotShareACache guards the
// per-instance cache design decision itself (secret_metadata_cache.go's own
// header: a package-level cache would make a cross-replica test vacuous).
// Two independent LocalStorage instances over the SAME underlying *gorm.DB
// must each do their own generation check — warming one's cache must not
// let the other skip its own live verification.
func TestSecretMetadataCache_IsPerInstanceNotPackageGlobal(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{}, &models.SecretACL{}))
	require.NoError(t, EnsureSecretNodeCacheEpoch(db)) // see newCacheTestStorage
	a := NewLocalStorage(db)
	b := NewLocalStorage(db)
	require.NotSame(t, a.secretMetaCache, b.secretMetaCache)

	created, err := a.CreateSecret(context.Background(), &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	_, err = a.GetSecret(context.Background(), created.ID) // warm a's cache only
	require.NoError(t, err)

	_, aHas := a.secretMetaCache.getNode(created.ID)
	_, bHas := b.secretMetaCache.getNode(created.ID)
	require.True(t, aHas)
	require.False(t, bHas, "b's cache must not have been populated by a's read")
}

// Coordinator review of #2764: a rotation committing BETWEEN GetLatestSecretVersion's
// version query and its generation read must not leave the pre-rotation version cached
// under the post-rotation generation (a rotated, possibly compromised value would keep
// being served). The callback commits version 2 right after the version query.
func TestGetLatestSecretVersion_RotationDuringResolveIsNotCachedStale(t *testing.T) {
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now()})
	require.NoError(t, err)

	armed := true
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("test:rotate-after-version-read", func(tx *gorm.DB) {
		if armed && tx.Statement.Table == "secret_versions" {
			armed = false
			time.Sleep(2 * time.Millisecond) // distinct updated_at
			require.NoError(t, ls.db.Transaction(func(inner *gorm.DB) error {
				txStore := &LocalStorage{db: inner, secretMetaCache: ls.secretMetaCache}
				if _, err := txStore.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 2, CreatedAt: time.Now()}); err != nil {
					return err
				}
				created.UpdatedAt = time.Now()
				_, err := txStore.UpdateSecret(ctx, created)
				return err
			}))
		}
	}))

	_, err = ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.False(t, armed, "the rotation never fired inside the resolve window")

	v, err := ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 2, v.VersionNumber, "the pre-rotation version was cached under the post-rotation generation")
}
