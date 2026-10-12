// local_principal_permission.go — ResolveUserPermissionAt /
// ResolveMachinePermissionAt (PERF-FIX-6, collapse C4 of SESSION-PERF-FIX-3's
// plan).
//
// A role-based decision (core.Authorize, AuthorizePrincipal's machine branch)
// used to read the principal's roles in several statements: for a user
// GetUserRoleIDsAt, GetUserGroupRoleIDsAt, RoleSetBypassesPermissionChecks and
// then RoleSetHasPermission's generation probe (liveRolePermissionsGeneration);
// for a machine GetMachineRoleIDsAt and the generation probe. Each principal
// kind now reads all of that in ONE statement:
//
//   - the role ids: the same WHERE clauses as GetUserRoleIDsAt and
//     GetUserGroupRoleIDsAt (UNION, which also de-duplicates, as scopedRoleIDs
//     did), or GetMachineRoleIDsAt's, verbatim;
//   - the ADR-084 bypass flag of each of those roles (users only — a machine
//     never bypasses, so its statement does not read the flag at all);
//   - the role->permission cache generation (system_metadata), in the SAME
//     statement as the role ids, so the generation that validates a cached
//     answer is never older than the role set it is validated for.
//
// The role->permission cache is then consulted under that generation with
// RoleSetHasPermission's rules (role_permission_cache.go): a hit needs an
// entry with exactly that generation; a miss runs the live join and publishes
// under the generation read BEFORE the join; a transaction-scoped store
// (cacheEnabled false) neither reads nor publishes. Role membership is still
// never cached. Invalidation (bumpRolePermissionsGenerationTx) is unchanged.
//
// If the combined statement fails, both methods fall back to the classic
// per-statement reads (storage.Compose*PermissionAt), so every failure mode
// answers exactly as before: a role-id or bypass read error is returned (fail
// closed), and a failed generation read only skips the cache, as
// RoleSetHasPermission always did. The schema every real deployment migrates
// has system_metadata; many test fixtures migrate a subset without it.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// userPrincipalPermissionSQL: the two role-id subqueries are GetUserRoleIDsAt's
// and GetUserGroupRoleIDsAt's WHERE clauses verbatim (sqlJoin*/sqlWhere*
// constants spelled out), and the bypass expression is
// RoleSetBypassesPermissionChecks' predicate. A role id with no roles row
// (cannot happen with the FK, but) reads as not bypassing, as the COUNT did.
const userPrincipalPermissionSQL = `SELECT ids.role_id AS role_id,
 CASE WHEN r.bypasses_permission_checks = ? THEN 1 ELSE 0 END AS bypass,
 gen.value AS generation
FROM (
 SELECT user_roles.role_id AS role_id FROM user_roles
  LEFT JOIN projects ON projects.id = user_roles.project_id
  LEFT JOIN environments ON environments.id = user_roles.environment_id
  WHERE user_roles.user_id = ?
   AND (user_roles.project_id = 0 OR (user_roles.project_id = ? AND projects.deleted_at IS NULL))
   AND (user_roles.environment_id = 0 OR (user_roles.environment_id = ? AND environments.deleted_at IS NULL))
   AND (user_roles.expires_at IS NULL OR user_roles.expires_at > ?)
 UNION
 SELECT group_roles.role_id AS role_id FROM group_roles
  JOIN user_groups ON user_groups.group_id = group_roles.group_id
  JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL
  LEFT JOIN projects ON projects.id = group_roles.project_id
  LEFT JOIN environments ON environments.id = group_roles.environment_id
  WHERE user_groups.user_id = ?
   AND (user_groups.project_id = 0 OR user_groups.project_id = ?)
   AND (group_roles.project_id = 0 OR (group_roles.project_id = ? AND projects.deleted_at IS NULL))
   AND (group_roles.environment_id = 0 OR (group_roles.environment_id = ? AND environments.deleted_at IS NULL))
   AND (group_roles.expires_at IS NULL OR group_roles.expires_at > ?)
) ids
LEFT JOIN roles r ON r.id = ids.role_id
LEFT JOIN system_metadata gen ON gen.key = ?`

// machinePrincipalPermissionSQL: GetMachineRoleIDsAt's WHERE clauses verbatim.
// No bypass column: a machine never bypasses (ADR-030).
const machinePrincipalPermissionSQL = `SELECT ids.role_id AS role_id, 0 AS bypass, gen.value AS generation
FROM (
 SELECT DISTINCT machine_identity_roles.role_id AS role_id FROM machine_identity_roles
  LEFT JOIN projects ON projects.id = machine_identity_roles.project_id
  LEFT JOIN environments ON environments.id = machine_identity_roles.environment_id
  WHERE machine_identity_roles.machine_identity_id = ?
   AND (machine_identity_roles.project_id = 0 OR (machine_identity_roles.project_id = ? AND projects.deleted_at IS NULL))
   AND (machine_identity_roles.environment_id = 0 OR (machine_identity_roles.environment_id = ? AND environments.deleted_at IS NULL))
) ids
LEFT JOIN system_metadata gen ON gen.key = ?`

type principalPermissionRow struct {
	RoleID     uint
	Bypass     int
	Generation *string
}

// ResolveUserPermissionAt: see the storage.Storage interface doc and this
// file's header.
func (ls *LocalStorage) ResolveUserPermissionAt(ctx context.Context, userID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	now := ls.rbacEffectiveNow(time.Now().UTC())
	var rows []principalPermissionRow
	if err := ls.db.WithContext(ctx).Raw(userPrincipalPermissionSQL,
		true,
		userID, scope.ProjectID, scope.EnvironmentID, now,
		userID, scope.ProjectID, scope.ProjectID, scope.EnvironmentID, now,
		rolePermissionsGenerationKey,
	).Scan(&rows).Error; err != nil {
		// See the file header: answer exactly as the classic reads would.
		return storage.ComposeUserPermissionAt(ctx, ls, userID, scope, permission)
	}
	return ls.resolvePrincipalPermission(ctx, rows, permission, true)
}

// ResolveMachinePermissionAt: see the storage.Storage interface doc and this
// file's header.
func (ls *LocalStorage) ResolveMachinePermissionAt(ctx context.Context, machineID uint, scope storage.Scope, permission string) (*storage.PrincipalPermission, error) {
	var rows []principalPermissionRow
	if err := ls.db.WithContext(ctx).Raw(machinePrincipalPermissionSQL,
		machineID, scope.ProjectID, scope.EnvironmentID,
		rolePermissionsGenerationKey,
	).Scan(&rows).Error; err != nil {
		return storage.ComposeMachinePermissionAt(ctx, ls, machineID, scope, permission)
	}
	return ls.resolvePrincipalPermission(ctx, rows, permission, false)
}

// resolvePrincipalPermission turns the one-statement rows into the result and,
// when the set is non-empty and does not bypass, answers the permission under
// the generation those rows carry. A never-bumped install has no generation
// row: "" (liveRolePermissionsGeneration's value for that case).
func (ls *LocalStorage) resolvePrincipalPermission(ctx context.Context, rows []principalPermissionRow, permission string, userBypass bool) (*storage.PrincipalPermission, error) {
	out := &storage.PrincipalPermission{}
	if len(rows) == 0 {
		return out, nil
	}
	seen := make(map[uint]struct{}, len(rows))
	for _, r := range rows {
		if _, dup := seen[r.RoleID]; dup {
			continue
		}
		seen[r.RoleID] = struct{}{}
		out.RoleIDs = append(out.RoleIDs, r.RoleID)
		if userBypass && r.Bypass != 0 {
			out.BypassesPermissionChecks = true
		}
	}
	if out.BypassesPermissionChecks {
		return out, nil
	}
	gen := ""
	if rows[0].Generation != nil {
		gen = *rows[0].Generation
	}
	allowed, err := ls.roleSetHasPermissionUnderGeneration(ctx, out.RoleIDs, permission, gen)
	if err != nil {
		return nil, err
	}
	out.HasPermission = allowed
	return out, nil
}

// roleSetHasPermissionUnderGeneration is RoleSetHasPermission with the
// generation already read (in the statement that read roleIDs, i.e. before
// the live join below): a hit needs an entry stamped with exactly gen; a miss
// runs the live join and publishes under gen. Never reads or publishes the
// shared cache from a transaction-scoped store (cacheEnabled).
func (ls *LocalStorage) roleSetHasPermissionUnderGeneration(ctx context.Context, roleIDs []uint, permission, gen string) (bool, error) {
	key := rolePermKey(roleIDs, permission)
	if ls.cacheEnabled {
		if cached, ok := ls.rolePermCache.get(key); ok && cached.generation == gen {
			return cached.allowed, nil
		}
	}
	allowed, err := ls.liveRoleSetHasPermission(ctx, roleIDs, permission)
	if err != nil {
		return false, err
	}
	if ls.cacheEnabled {
		ls.rolePermCache.set(key, rolePermCacheEntry{generation: gen, allowed: allowed})
	}
	return allowed, nil
}
