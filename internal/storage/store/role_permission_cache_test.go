// role_permission_cache_test.go — correctness tests for the read-path
// "principal permissions" cache (PERF-3, docs/specs/read-path-caching.md
// PR-2): RoleSetHasPermission must reflect a permission grant/revoke on the
// very next call, never a stale cached decision, and a generation-check
// error must fall through to a live read rather than serving a stale value
// or panicking.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newRolePermCacheTestStorage(t testing.TB) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.SystemMetadata{},
		&models.UserRole{}, &models.GroupRole{}, &models.MachineIdentityRole{}, &models.ConnectRefGrant{},
	))
	// The generation triggers (#3259): without them the cache is bypassed by
	// design, and every hit-path test here would pass vacuously.
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
	return NewLocalStorage(db)
}

func TestRoleSetHasPermission_CacheReflectsGrant(t *testing.T) {
	t.Parallel()
	ls := newRolePermCacheTestStorage(t)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "r1"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)

	before, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.False(t, before, "role should not have the permission yet")

	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	after, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.True(t, after, "cache served a stale pre-grant decision")
}

func TestRoleSetHasPermission_CacheReflectsRevoke(t *testing.T) {
	t.Parallel()
	ls := newRolePermCacheTestStorage(t)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "r1"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	before, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.True(t, before)

	require.NoError(t, ls.RemovePermissionFromRole(ctx, role.ID, perm.ID))

	after, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.False(t, after, "a permission removal must take effect immediately — cache served a stale pre-revoke decision")
}

func TestRoleSetHasPermission_CacheReflectsDeleteRole(t *testing.T) {
	t.Parallel()
	ls := newRolePermCacheTestStorage(t)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "r1"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	before, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.True(t, before)

	_, err = ls.DeleteRole(ctx, role.ID)
	require.NoError(t, err)

	after, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.False(t, after, "cache served a stale pre-delete decision for a now-deleted role")
}

// TestRoleSetHasPermission_KeyIsOrderIndependent proves rolePermKey treats
// [A,B] and [B,A] as the SAME cache entry — the roleIDs slice order a
// caller happens to produce must not create spurious cache misses or,
// worse, two independent entries that could disagree.
func TestRoleSetHasPermission_KeyIsOrderIndependent(t *testing.T) {
	t.Parallel()
	require.Equal(t, rolePermKey([]uint{5, 2, 9}, "x"), rolePermKey([]uint{9, 5, 2}, "x"))
	require.NotEqual(t, rolePermKey([]uint{5, 2}, "x"), rolePermKey([]uint{5, 2, 9}, "x"))
	require.NotEqual(t, rolePermKey([]uint{5, 2}, "x"), rolePermKey([]uint{5, 2}, "y"))
}

// TestGetCachedRolePermission_GenerationCheckError_FailsClosed: once the
// generation-check query itself can no longer succeed (system_metadata
// table gone), a WARM cache entry must never be served.
func TestGetCachedRolePermission_GenerationCheckError_FailsClosed(t *testing.T) {
	t.Parallel()
	ls := newRolePermCacheTestStorage(t)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "r1"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	_, err = ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read") // warm
	require.NoError(t, err)

	key := rolePermKey([]uint{role.ID}, "secrets.read")
	_, ok := ls.rolePermCache.get(key)
	require.True(t, ok, "expected cache to be warm before the DB is broken")

	require.NoError(t, ls.db.Migrator().DropTable(&models.SystemMetadata{}))

	allowed, hit := ls.getCachedRolePermission(ctx, key)
	require.False(t, hit, "a generation-check error must never be reported as a cache hit")
	require.False(t, allowed)
}

func mustFoldedName(t testing.TB, name string) identity.FoldedName {
	t.Helper()
	fn, err := identity.NewFoldedName(name)
	require.NoError(t, err)
	return fn
}

// Coordinator review of #2767: a revoke that commits BETWEEN RoleSetHasPermission's
// live join and its cache write must not leave the pre-revoke "allowed" cached
// under the post-revoke generation. The in-flight call may still answer true
// (it read before the revoke), but the very next call must see the revoke.
// The callback fires the revoke right after the permissions join, i.e. exactly
// in that window.
func TestRoleSetHasPermission_RevokeDuringResolveIsNotCachedStale(t *testing.T) {
	ls := newRolePermCacheTestStorage(t)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "r1"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	armed := true
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register("test:revoke-after-join", func(tx *gorm.DB) {
		if armed && tx.Statement.Table == "permissions" {
			armed = false
			require.NoError(t, ls.RemovePermissionFromRole(ctx, role.ID, perm.ID))
		}
	}))

	_, err = ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.False(t, armed, "the revoke never fired inside the resolve window")

	after, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.False(t, after, "a revoked permission is still authorizing: the pre-revoke decision was cached under the post-revoke generation")
}
