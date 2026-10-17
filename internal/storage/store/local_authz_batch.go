// local_authz_batch.go — the reads behind core's batch secret authoriser
// (SHARES-BATCH-AUTHZ-1).
//
// core.AuthorizeSecretsBatch decides a page of secrets with the same rules as the
// per-row AuthorizeSecret, from a fixed number of statements. Each read here is the
// set-at-once form of a per-row read and keeps that read's predicates verbatim:
//
//   - ProjectMembershipsAmong: IsProjectMember for many projects;
//   - ListUserRoleGrants: the two role-id subqueries of ResolveUserPermissionAt, with
//     the scope-dependent tests moved out so one listing serves every scope;
//   - ListUserLiveGroupMemberships: GetUserGroupsAt without its scope filter.
//
// core's equivalence test (TestAuthorizeSecretsBatch_EqualsPerRow) pins the batch
// against the per-row decision over a generated matrix of states.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ProjectMembershipsAmong: see the storage.Storage interface doc. IsProjectMember's
// two counts (a direct user_roles grant, then a group_roles grant through a live
// group), as one DISTINCT project listing per chunk.
func (ls *LocalStorage) ProjectMembershipsAmong(ctx context.Context, userID uint, projectIDs []uint) (map[uint]bool, error) {
	out := make(map[uint]bool, len(projectIDs))
	now := ls.rbacEffectiveNow(time.Now().UTC())
	err := forEachIDChunk(projectIDs, func(chunk []uint) error {
		live := make([]uint, 0, len(chunk))
		for _, id := range chunk {
			if id != 0 { // IsProjectMember: project 0 is never a membership
				live = append(live, id)
			}
		}
		if len(live) == 0 {
			return nil
		}
		var direct []uint
		if err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
			Where("user_id = ? AND project_id IN ?", userID, live).
			Where(sqlWhereURNotExpired, now).
			Distinct().Pluck("project_id", &direct).Error; err != nil {
			return lookupErr(err)
		}
		for _, id := range direct {
			out[id] = true
		}
		var viaGroup []uint
		if err := ls.db.WithContext(ctx).Table("group_roles").
			Joins(sqlJoinUserGroups).
			Joins(sqlJoinGroups).
			Where("user_groups.user_id = ? AND group_roles.project_id IN ?", userID, live).
			Where(sqlWhereGRNotExpired, now).
			Distinct().Pluck("group_roles.project_id", &viaGroup).Error; err != nil {
			return lookupErr(err)
		}
		for _, id := range viaGroup {
			out[id] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// userRoleGrantsSQL is userPrincipalPermissionSQL's two subqueries with each grant's
// own project and environment returned instead of compared to one target scope. The
// liveness tests (LEFT JOIN ... deleted_at IS NULL, so a missing row counts as live),
// the expiry tests and the live-group join are verbatim.
const userRoleGrantsSQL = `SELECT 0 AS via_group, user_roles.project_id AS project_id,
 user_roles.environment_id AS environment_id, 0 AS member_project_id,
 user_roles.role_id AS role_id,
 CASE WHEN r.bypasses_permission_checks = ? THEN 1 ELSE 0 END AS bypass
FROM user_roles
 LEFT JOIN projects ON projects.id = user_roles.project_id
 LEFT JOIN environments ON environments.id = user_roles.environment_id
 LEFT JOIN roles r ON r.id = user_roles.role_id
WHERE user_roles.user_id = ?
 AND (user_roles.project_id = 0 OR projects.deleted_at IS NULL)
 AND (user_roles.environment_id = 0 OR environments.deleted_at IS NULL)
 AND (user_roles.expires_at IS NULL OR user_roles.expires_at > ?)
UNION ALL
SELECT 1 AS via_group, group_roles.project_id AS project_id,
 group_roles.environment_id AS environment_id, user_groups.project_id AS member_project_id,
 group_roles.role_id AS role_id,
 CASE WHEN r.bypasses_permission_checks = ? THEN 1 ELSE 0 END AS bypass
FROM group_roles
 JOIN user_groups ON user_groups.group_id = group_roles.group_id
 JOIN groups ON groups.id = group_roles.group_id AND groups.deleted_at IS NULL
 LEFT JOIN projects ON projects.id = group_roles.project_id
 LEFT JOIN environments ON environments.id = group_roles.environment_id
 LEFT JOIN roles r ON r.id = group_roles.role_id
WHERE user_groups.user_id = ?
 AND (group_roles.project_id = 0 OR projects.deleted_at IS NULL)
 AND (group_roles.environment_id = 0 OR environments.deleted_at IS NULL)
 AND (group_roles.expires_at IS NULL OR group_roles.expires_at > ?)`

type userRoleGrantRow struct {
	ViaGroup        int
	ProjectID       uint
	EnvironmentID   uint
	MemberProjectID uint
	RoleID          uint
	Bypass          int
}

// ListUserRoleGrants: see the storage.Storage interface doc.
func (ls *LocalStorage) ListUserRoleGrants(ctx context.Context, userID uint) ([]storage.UserRoleGrant, error) {
	now := ls.rbacEffectiveNow(time.Now().UTC())
	var rows []userRoleGrantRow
	if err := ls.db.WithContext(ctx).Raw(userRoleGrantsSQL,
		true, userID, now,
		true, userID, now,
	).Scan(&rows).Error; err != nil {
		return nil, lookupErr(err)
	}
	out := make([]storage.UserRoleGrant, 0, len(rows))
	for _, r := range rows {
		out = append(out, storage.UserRoleGrant{
			RoleID: r.RoleID, ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
			ViaGroup: r.ViaGroup != 0, MemberProjectID: r.MemberProjectID, Bypass: r.Bypass != 0,
		})
	}
	return out, nil
}

// ListUserLiveGroupMemberships: see the storage.Storage interface doc.
func (ls *LocalStorage) ListUserLiveGroupMemberships(ctx context.Context, userID uint) ([]storage.UserGroupMembershipAt, error) {
	var rows []struct {
		GroupID   uint
		ProjectID uint
	}
	if err := ls.db.WithContext(ctx).Table("user_groups").
		Select("user_groups.group_id AS group_id, user_groups.project_id AS project_id").
		Joins("JOIN groups ON groups.id = user_groups.group_id AND groups.deleted_at IS NULL").
		Where("user_groups.user_id = ?", userID).
		Scan(&rows).Error; err != nil {
		return nil, lookupErr(err)
	}
	out := make([]storage.UserGroupMembershipAt, 0, len(rows))
	for _, r := range rows {
		out = append(out, storage.UserGroupMembershipAt{GroupID: r.GroupID, ProjectID: r.ProjectID})
	}
	return out, nil
}
