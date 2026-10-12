// role_permission_cache.go — the read-path "principal permissions" cache
// (PERF-3, docs/specs/read-path-caching.md PR-2): caches
// RoleSetHasPermission's own result ("does this exact role-ID set grant
// permission P"), not role MEMBERSHIP. Role membership (which role IDs a
// principal currently holds — GetMachineRoleIDsAt, scopedRoleIDs,
// GetUserGroupRoleIDsAt) is deliberately left uncached: a role grant/revoke
// is exactly the #G18 "stop authorizing on the very next request" case, and
// keeping membership resolution live means a bug in this cache can at most
// make a permission check for a role a principal legitimately and
// CURRENTLY holds briefly stale by one generation-check round trip — it
// cannot let a revoked role keep authorizing, because the role list itself
// is never cached here.
//
// ResolveUserPermissionAt / ResolveMachinePermissionAt
// (local_principal_permission.go) read the generation in the SAME statement as
// the role ids and use the same entries under the same rules.
//
// Unlike secret_metadata_cache.go's per-row generation (one column per
// secret), role_permissions edits are rare, install-wide, admin-only
// actions (grant/revoke a permission on a role) — a single GLOBAL
// generation signal is simplest and safest: no per-role invalidation key
// can under-invalidate when there's only one key. Stored as a
// system_metadata row (rolePermissionsGenerationKey) rather than a new
// table/column — reuses the existing generic key/value store, no migration
// needed. Value is a monotonic integer counter incremented by the database
// inside the same transaction as the role_permissions write — deliberately
// NOT a clock- or randomness-derived string; see
// bumpRolePermissionsGenerationTx's doc comment for the three reasons,
// including the fuzz-oracle failure a nondeterministic value caused on this
// PR's own CI. The only property a reader needs is "did this change since I
// last looked," never "by how much."
//
// Same per-LocalStorage-instance-not-package-global design as
// secret_metadata_cache.go, for the identical reason (see that file's
// header) — this cache is a field on *LocalStorage, shared with a
// transaction-scoped copy, never a package-level var.
package store

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const rolePermissionsGenerationKey = "role_permissions_generation"

type rolePermCacheEntry struct {
	generation string
	allowed    bool
}

type rolePermissionCache struct {
	mu      sync.Mutex
	entries map[string]rolePermCacheEntry
}

func newRolePermissionCache() *rolePermissionCache {
	return &rolePermissionCache{entries: make(map[string]rolePermCacheEntry)}
}

// rolePermKey builds the cache key for a (roleIDs, permission) pair,
// sorting a COPY of roleIDs so this never mutates the caller's slice (which
// may be shared/reused elsewhere up the call chain).
func rolePermKey(roleIDs []uint, permission string) string {
	ids := make([]uint, len(roleIDs))
	copy(ids, roleIDs)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var b strings.Builder
	for _, id := range ids {
		b.WriteString(strconv.FormatUint(uint64(id), 10))
		b.WriteByte(',')
	}
	b.WriteByte('|')
	b.WriteString(permission)
	return b.String()
}

func (c *rolePermissionCache) get(key string) (rolePermCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e, ok
}

func (c *rolePermissionCache) set(key string, e rolePermCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = e
}

// liveRolePermissionsGeneration reads the current global generation value.
// A never-bumped install reads as ("", nil) — "" is a perfectly valid
// generation value (every cache entry recorded before the first-ever bump
// shares it), not a sentinel error.
func liveRolePermissionsGeneration(ctx context.Context, ls *LocalStorage) (string, error) {
	val, _, err := ls.GetSystemMetadata(ctx, rolePermissionsGenerationKey)
	if err != nil {
		return "", err
	}
	return val, nil
}

// bumpRolePermissionsGenerationTx advances the global generation using tx, so
// the bump commits atomically with whatever role_permissions write it's paired
// with (AssignPermissionToRole, RemovePermissionFromRole, DeleteRole's
// cascade) — a reader can never observe the new role_permissions row with the
// old generation, or vice versa. A bump failure must fail the write it is
// paired with: returning an error here rolls the whole transaction back, so
// there is no path that grants or revokes a permission without invalidating
// the cache that answers for it.
//
// The value is a DETERMINISTIC monotonic integer incremented by the database
// itself, not a timestamp plus a random suffix. Three reasons, the first found
// the hard way on this PR's own CI:
//
//   - server/faultops' FuzzStorageFaultOperations state oracles compare the
//     whole system_metadata table between a fault-free REFERENCE run and a
//     faulted run of the same operation sequence (snapshot_test.go excludes
//     every time.Time field structurally, but Value is a string and is
//     compared byte-for-byte). A clock- or randomness-derived value differs
//     between two independently bootstrapped worlds even when nothing is
//     wrong, which reported "ORACLE (a) VIOLATION — Differing tables:
//     [SystemMetadata]" on operations that never touch role_permissions at
//     all: the bootstrap's own ReconcileRBAC grants had already written a
//     different value into each world.
//   - A clock-derived value is not monotonic across replicas under clock skew,
//     which is why the random suffix had to exist at all; a counter the
//     database increments needs neither a clock nor randomness.
//   - A read-then-write counter in Go would NOT be safe: two concurrent bumps
//     could both read N and both write N+1, so a reader that cached under N+1
//     between the two commits would keep hitting that entry while the second
//     writer's change stayed invisible. Evaluating the increment inside a
//     single UPDATE statement makes that impossible — the row is write-locked
//     for the duration, so the two bumps serialize into N+1 and N+2.
func bumpRolePermissionsGenerationTx(ctx context.Context, tx *LocalStorage) error {
	// Seed the counter if this install has never bumped. ON CONFLICT DO NOTHING
	// (never DoUpdates) so a row that already exists is left at its current
	// value rather than reset to zero — a reset would make a cache entry stamped
	// with an earlier, higher value start matching again.
	if err := tx.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&models.SystemMetadata{
		Key: rolePermissionsGenerationKey, Value: "0", UpdatedAt: time.Now(),
	}).Error; err != nil {
		return err
	}
	// CAST(... AS TEXT) on both sides keeps this one statement valid on SQLite
	// and PostgreSQL alike: Postgres rejects assigning an integer expression to
	// a text column without the outer cast, and SQLite has no ::text syntax.
	res := tx.db.WithContext(ctx).Model(&models.SystemMetadata{}).
		Where("key = ?", rolePermissionsGenerationKey).
		UpdateColumn("value", gorm.Expr("CAST(CAST(value AS INTEGER) + 1 AS TEXT)"))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		// The seed above guarantees the row exists inside this transaction, so
		// zero rows affected means something else removed it concurrently. Fail
		// the paired write rather than leave a stale cache authorizing.
		return fmt.Errorf("role-permission cache generation bump matched %d rows, want 1", res.RowsAffected)
	}
	return nil
}
