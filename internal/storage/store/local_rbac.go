// local_rbac.go — Role and RBAC operations for LocalStorage.
//
// Covers: CreatePermission, AssignPermissionToRole,
//
//	CreateRole, GetRole, GetRoleByName, UpdateRole, DeleteRole, ListRoles,
//	AssignRole, RemoveRole, GetUserRoles, GetUserPermissions.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_rbac.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// rbacEffectiveNow returns a wall-clock reading that never regresses relative
// to what this LocalStorage has already observed for RBAC permission-
// resolution queries (#1632): max(now, rbacClockWatermark), always advancing
// the watermark forward. Every expiry check in this file binds a fresh
// time.Now().UTC() directly into a SQL `expires_at > ?` bound (or an in-Go
// ExpiresAt.After comparison) with no caching layer in between — a host
// clock stepped backward past a grant's real expiry would compute that grant
// as still live, extending a permission/role assignment's validity past its
// real window.
//
// Unlike consumeClockLooksRegressed (which REFUSES a single, discrete
// action outright), this CLAMPS rather than errors. These ~14+ call sites are
// read-heavy permission-resolution queries reached on every authorized
// request across the whole application; hard-refusing all of them the moment
// a regression is detected would turn a narrow clock-integrity concern into
// a total authorization outage (every permission check failing, for every
// user, until the tolerance window passes) — a strictly worse outcome than
// the hazard being defended against. Clamping achieves the same security
// property (a backward-stepped clock can never compute a grant as MORE valid
// than the highest wall-clock time this process has already legitimately
// observed) without that availability blast radius. The two in-Go
// ExpiresAt.After checks in this file (assignUserRole, assignGroupRole) are
// already safe-direction on a regression — a backward clock makes an
// EXPIRED existing grant look live, which blocks a fresh assignment rather
// than granting anything — but are clamped too for mechanical consistency
// with every other wall-clock read in this file, not because they are
// themselves a security finding.
func (ls *LocalStorage) rbacEffectiveNow(now time.Time) time.Time {
	wm := ls.rbacClockWatermark
	wm.mu.Lock()
	defer wm.mu.Unlock()
	if now.Before(wm.time) {
		return wm.time
	}
	wm.time = now
	return now
}

// --- Permissions ---

func (ls *LocalStorage) CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error) {
	if err := ls.db.WithContext(ctx).Create(permission).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return permission, nil
}

// AssignPermissionToRole grants permissionID to roleID. Bumps the global
// role_permissions cache-invalidation generation (PERF-3, PR-2) in the SAME
// transaction as the grant, so a reader can never observe the new grant
// under a stale cached "no" decision.
func (ls *LocalStorage) AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		rp := models.RolePermission{RoleID: roleID, PermissionID: permissionID}
		if err := tx.Create(&rp).Error; err != nil {
			if isUniqueViolation(err) {
				// role_permissions' composite primary key (role_id, permission_id) is
				// already held -- see storage.ErrDuplicateRolePermission's doc comment
				// for why this needs to be distinguishable from any other storage
				// failure (a generic 500 instead of 409 Conflict).
				return fmt.Errorf("%w: %v", storage.ErrDuplicateRolePermission, err)
			}
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if err := bumpRolePermissionsGenerationTx(ctx, &LocalStorage{db: tx}); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return nil
	})
}

// --- Roles ---

func (ls *LocalStorage) CreateRole(ctx context.Context, name identity.FoldedName, description string) (*models.Role, error) {
	role := &models.Role{Name: name.Display(), NameFolded: name.Folded(), Description: description}
	if err := ls.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

// SetRoleBypassesPermissionChecks sets models.Role.BypassesPermissionChecks
// (ADR-084). See the interface doc comment for why this exists and who may
// call it -- role seeding only, never CreateRole/UpdateRole.
func (ls *LocalStorage) SetRoleBypassesPermissionChecks(ctx context.Context, roleID uint, value bool) error {
	if err := ls.db.WithContext(ctx).Model(&models.Role{}).Where("id = ?", roleID).
		Update("bypasses_permission_checks", value).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	var role models.Role
	if err := ls.db.WithContext(ctx).First(&role, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Wrap the typed sentinel so callers can distinguish "this role does
			// not exist" from a transient failure (e.g. isGlobalAdminRoleName's
			// dangling-role-reference tolerance).
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), storage.ErrRoleNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &role, nil
}

// GetRoleByName looks up a role by its exact display name.
//
// #1642 follow-up (filed, not fixed here): this queries the raw `name`
// column, not `name_folded`, so it does NOT benefit from the case-insensitive
// fold CreateRole/ensureRoleNameIndex enforce at write time — a lookup for
// "Admin" will not find a role created as "admin". This is the same
// write-without-read-fold shape already fixed for GetUserByEmail/
// GetUserByUsername, and the human-facing exposure (GET
// /api/v1/roles/by-name?name=) has the same theoretical gap. It is left
// unfixed in this change because roleSetContainsAdmin (authz.go) calls this
// method internally, on every authorization check, with the four fixed
// adminRoleNames literals — switching this query to name_folded requires
// every test fixture across the repo that seeds a `models.Role{Name: "..."}`
// row directly (bypassing CreateRole, and so leaving NameFolded empty) to
// also set NameFolded, and that pattern is used by roughly 100 call sites
// across internal/core, internal/cli, internal/storage/store,
// server/grpc/services, and server/http(/handlers) — a fixture sweep at
// least as large as the User/Group one already done for #1642, disproportionate
// to what is a UX papercut (case-variant role-name search misses a match) with
// no security stake, unlike CreateRole's charset bypass. Track as a separate
// follow-up rather than expand this change further.
func (ls *LocalStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	if err := ls.db.WithContext(ctx).Where("name = ?", name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Wraps storage.ErrRoleNotFound so a caller can tell "this role does
			// not exist" (a configuration fact) from "the lookup failed" (unknown
			// state) with errors.Is, instead of string-matching a TRANSLATABLE
			// message -- which silently stops working the moment the key is
			// actually translated. GetRole's sibling path already does this; this
			// one did not, and internal/core's SSO role reconciliation needs the
			// distinction to decide whether to skip a role or refuse the login
			// (#2839 item 1).
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), storage.ErrRoleNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &role, nil
}

func (ls *LocalStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	if err := ls.db.WithContext(ctx).Save(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

// DeleteRole hard-deletes a role and, in the SAME transaction, every row in
// another table that references it by RoleID (UserRole, GroupRole,
// MachineIdentityRole, RolePermission, ConnectRefGrant). Role has no
// DeletedAt column (it is not soft-deletable like Group/User), and none of
// these RoleID columns are GORM associations -- AutoMigrate creates no FK
// constraint on either backend -- so without this cascade a deleted role
// left every one of those tables holding an orphaned row pointing at a
// nonexistent role ID (SESSION-AT AT1 row 2). Confirmed separately that
// this was inert, not a privilege-inheritance hole (role-ID reuse is
// impossible: GORM's AUTOINCREMENT never reissues a deleted role's ID, and
// every authorization query joins against the live roles table, so an
// orphaned grant row matches nothing) -- this fix is data hygiene, not a
// security closure.
//
// Deliberately NOT cascaded, and must stay that way: BreakGlassActivation
// and AccessReviewItem both also carry a RoleID (plus a RoleName string
// snapshot), but both are history/compliance records, not live grants --
// BreakGlassActivation is the audit trail of a past emergency access
// activation, AccessReviewItem is an explicit frozen snapshot of a grant at
// the moment an access-review campaign opened (its own doc comment: "the
// live grant may change or be revoked after capture"). Deleting either on a
// role delete would destroy audit/compliance evidence that must survive the
// role being deleted (PR #2357 review). A future "complete the cascade"
// change must not add these two.
//
// The returned RoleDeleteCascadeCounts is read back by core.DeleteRole
// purely for its own audit-log message (PR #2357 review) -- the counts
// themselves carry no correctness meaning here.
func (ls *LocalStorage) DeleteRole(ctx context.Context, id uint) (storage.RoleDeleteCascadeCounts, error) {
	var counts storage.RoleDeleteCascadeCounts
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Delete(&models.Role{}, id)
		if result.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("%s", i18n.T("ErrorRoleNotFound", nil))
		}
		ur := tx.Where("role_id = ?", id).Delete(&models.UserRole{})
		if ur.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), ur.Error)
		}
		counts.UserAssignments = int(ur.RowsAffected)
		gr := tx.Where("role_id = ?", id).Delete(&models.GroupRole{})
		if gr.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), gr.Error)
		}
		counts.GroupAssignments = int(gr.RowsAffected)
		mr := tx.Where("role_id = ?", id).Delete(&models.MachineIdentityRole{})
		if mr.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), mr.Error)
		}
		counts.MachineAssignments = int(mr.RowsAffected)
		if err := tx.Where("role_id = ?", id).Delete(&models.RolePermission{}).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		// PERF-3 PR-2: a deleted role's own grants are gone too; bump the
		// global generation defensively (see AssignPermissionToRole's doc
		// comment) even though the deleted role's own membership rows are
		// also removed in this same transaction, which already keeps any
		// (roleIDs-including-this-one, permission) cache key unreachable.
		if err := bumpRolePermissionsGenerationTx(ctx, &LocalStorage{db: tx}); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if err := tx.Where("role_id = ?", id).Delete(&models.ConnectRefGrant{}).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return nil
	})
	return counts, err
}

func (ls *LocalStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	var roles []*models.Role
	if err := ls.db.WithContext(ctx).Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// --- RBAC assignment ---

// AssignRole assigns a permanent role to a user at scope; errors if already
// assigned there.
func (ls *LocalStorage) AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	return ls.assignUserRole(ctx, userID, roleID, scope, nil)
}

// AssignRoleWithExpiry assigns a time-bound role to a user at scope: the grant
// stops authorizing once expiresAt passes and is later swept by the JIT scheduler.
func (ls *LocalStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	return ls.assignUserRole(ctx, userID, roleID, scope, &expiresAt)
}

func (ls *LocalStorage) assignUserRole(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt *time.Time) error {
	if expiresAt != nil {
		utc := expiresAt.UTC()
		expiresAt = &utc
	}
	// #G21: the read (is there a stale, expired row blocking this key?), the
	// delete of that stale row, and the create of the fresh grant all run
	// inside ONE database transaction, so SQLite's single-writer locking
	// (acquired at the first write statement below, held until commit)
	// prevents a concurrent assignUserRole call from inserting its own live
	// grant at this key in between our read and our write — a plain
	// match-by-composite-key delete run outside a transaction could
	// otherwise silently destroy that concurrently-created live grant. (An
	// earlier version of this fix tried to additionally re-assert the exact
	// observed expires_at value in the delete's WHERE clause, but GORM's
	// struct-field writes and a raw driver parameter bind serialize
	// time.Time inconsistently with this driver — confirmed empirically, not
	// just suspected — so any Go-side round trip of the value risked a
	// false-negative byte mismatch even for the SAME row; transactional
	// isolation avoids depending on that comparison at all.)
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing models.UserRole
		err := tx.Where(sqlWhereUserRoleEnv,
			userID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
		switch err {
		case nil:
			// A row already exists at this exact (user, role, project, environment) key. A
			// still-live grant (no expiry, or an expiry still in the future) genuinely blocks
			// a duplicate assignment. But an EXPIRED grant is a stale, un-reaped row — e.g. a
			// prior break-glass activation whose time-bound grant naturally lapsed — and must
			// be treated as ABSENT for this check, or a second real-incident activation for
			// the same user/role/scope is permanently refused with "already assigned" even
			// though nothing live is actually being duplicated (#263). Delete the stale row
			// so the composite primary key (user_id, role_id, project_id, environment_id) is
			// free for the fresh Create below, mirroring how live-authorization queries
			// elsewhere (e.g. GetUserRoles) already exclude expired grants.
			if existing.ExpiresAt == nil || existing.ExpiresAt.After(ls.rbacEffectiveNow(time.Now().UTC())) {
				return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
			}
			if derr := tx.Where(sqlWhereUserRoleEnv,
				userID, roleID, scope.ProjectID, scope.EnvironmentID).
				Delete(&models.UserRole{}).Error; derr != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), derr)
			}
		case gorm.ErrRecordNotFound:
			// no existing row for this key — proceed to create.
		default:
			return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
		}
		userRole := models.UserRole{
			UserID:        userID,
			RoleID:        roleID,
			ProjectID:     scope.ProjectID,
			EnvironmentID: scope.EnvironmentID,
			ExpiresAt:     expiresAt,
		}
		if err := tx.Create(&userRole).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return nil
	})
}

// RemoveRole removes a role from a user at scope.
func (ls *LocalStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where(sqlWhereUserRoleEnv,
			userID, roleID, scope.ProjectID, scope.EnvironmentID).Delete(&models.UserRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotAssigned", nil), storage.ErrRoleNotAssigned)
	}
	return nil
}

// RemoveAllProjectRoleGrants deletes every user_roles row for (userID, projectID),
// regardless of environment_id — unlike RemoveRole, which only ever deletes an
// exact-scope match. Used by RemoveProjectMember to fully revoke a departing
// member's access to a project: without it, an environment-scoped grant (e.g.
// "prod-only access", project_id = P, environment_id = E) survives project-level
// removal untouched, because it was never an exact match for
// Scope{ProjectID: P} (environment_id defaults to 0) (#232).
func (ls *LocalStorage) RemoveAllProjectRoleGrants(ctx context.Context, userID, projectID uint) error {
	if err := ls.db.WithContext(ctx).
		Where("user_id = ? AND project_id = ?", userID, projectID).
		Delete(&models.UserRole{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// GetUserRoles retrieves all roles assigned to userID via the user_roles join table.
func (ls *LocalStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where(sqlWhereURUserID, userID).
		Where(sqlWhereURNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetUserRoleIDsAt returns the IDs of roles directly assigned to userID that
// apply at the target scope: a stored assignment applies when its project is
// global (0) or equal, and its environment is global (0) or equal.
//
// A scoped (non-zero) project_id/environment_id must ALSO NOT resolve to a
// soft-deleted project/environment row — mirroring the groups.deleted_at join
// GetUserGroupRoleIDsAt already applies for a group's own soft-delete state
// (#161). Without it, a role bound directly to a project/environment ID keeps
// authorizing regardless of that project's/environment's own soft-delete state,
// so deletion doesn't work as an access boundary for directly-bound roles at all.
// The LEFT JOINs (not INNER) are required because project_id/environment_id 0
// means "global" and has no corresponding row to join against — the "= 0 OR ..."
// clause short-circuits before the joined columns are consulted in that case; a
// scoped project_id/environment_id with no matching row at all (the joined column
// is SQL NULL) is treated as not-deleted, same as every other "unknown" scope ID
// this query already tolerates.
func (ls *LocalStorage) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Joins("LEFT JOIN projects ON projects.id = user_roles.project_id").
		Joins("LEFT JOIN environments ON environments.id = user_roles.environment_id").
		Where(sqlWhereURUserID, userID).
		Where("user_roles.project_id = 0 OR (user_roles.project_id = ? AND projects.deleted_at IS NULL)", scope.ProjectID).
		Where("user_roles.environment_id = 0 OR (user_roles.environment_id = ? AND environments.deleted_at IS NULL)", scope.EnvironmentID).
		Where(sqlWhereURNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Distinct().Pluck("user_roles.role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// GetUserRoleScopes returns the distinct (project, environment) scopes at which
// userID holds ANY LIVE role, directly (user_roles) or via a live (non-deleted)
// group (group_roles). See the storage.Storage interface doc for why this exists
// (#165's scope-aware admin-rank-ceiling check).
func (ls *LocalStorage) GetUserRoleScopes(ctx context.Context, userID uint) ([]storage.Scope, error) {
	type scopeRow struct {
		ProjectID     uint
		EnvironmentID uint
	}
	seen := make(map[storage.Scope]struct{})

	var direct []scopeRow
	if err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Select("project_id, environment_id").
		Where("user_id = ?", userID).
		Where(sqlWhereURNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Group("project_id, environment_id").
		Scan(&direct).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range direct {
		seen[storage.Scope{ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID}] = struct{}{}
	}

	var viaGroups []scopeRow
	if err := ls.db.WithContext(ctx).Table("group_roles").
		Select("group_roles.project_id AS project_id, group_roles.environment_id AS environment_id").
		Joins(sqlJoinUserGroups).
		Joins(sqlJoinGroups).
		Where(sqlWhereUGUserID, userID).
		Where(sqlWhereGRNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Group("group_roles.project_id, group_roles.environment_id").
		Scan(&viaGroups).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range viaGroups {
		seen[storage.Scope{ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID}] = struct{}{}
	}

	scopes := make([]storage.Scope, 0, len(seen))
	for s := range seen {
		scopes = append(scopes, s)
	}
	return scopes, nil
}

// ListProjectRoleAssignments returns every role assignment scoped to the project
// (project_id = projectID, any environment) for both users (user_roles) and groups
// (group_roles) — the raw grant rows behind a project access review. Global
// (project 0) assignments are deliberately excluded (install-level, reviewed
// separately). A principal with several roles at the project yields several rows.
func (ls *LocalStorage) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	var out []storage.RoleAssignment

	now := ls.rbacEffectiveNow(time.Now().UTC())
	var userRows []models.UserRole
	if err := ls.db.WithContext(ctx).
		Where(sqlWhereProjectID, projectID).
		Where(sqlWhereURNotExpired, now).
		Find(&userRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range userRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "user", PrincipalID: r.UserID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}

	var groupRows []models.GroupRole
	if err := ls.db.WithContext(ctx).Table("group_roles").
		Select("group_roles.*").
		// A soft-deleted group confers no roles/authority — exclude its grant rows,
		// matching GetUserGroupRoleIDsAt's authorization resolution. Without this a
		// deleted group's still-present group_roles row kept showing up as a "live"
		// project-admin assignment to callers like guardLastProjectAdmin.
		Joins(sqlJoinGroups).
		Where(sqlWhereProjectID, projectID).
		Where(sqlWhereGRNotExpired, now).
		Find(&groupRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range groupRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// ListProjectMachineRoleAssignments returns every machine-identity role grant
// scoped to the project (project_id = projectID, any environment) — the machine
// counterpart to ListProjectRoleAssignments's user/group rows.
func (ls *LocalStorage) ListProjectMachineRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	var rows []models.MachineIdentityRole
	if err := ls.db.WithContext(ctx).Where(sqlWhereProjectID, projectID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := make([]storage.RoleAssignment, 0, len(rows))
	for _, r := range rows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "machine", PrincipalID: r.MachineIdentityID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// ListGlobalAdminAssignmentsForUpdate returns every global-scope (project 0,
// environment 0) direct user and group role grant whose role is in adminRoleIDs,
// taking a row-level write lock on backends that support one (Postgres FOR
// UPDATE), mirroring LockUserForUpdate/LockWebAuthnCredentialForUpdate. See the
// Storage interface doc (#340) for why this exists: a concurrent racing removal
// must serialize against this read on Postgres/HA; the caller's own process
// mutex covers SQLite (single instance, no cross-process concern).
func (ls *LocalStorage) ListGlobalAdminAssignmentsForUpdate(ctx context.Context, adminRoleIDs []uint) ([]storage.RoleAssignment, error) {
	if len(adminRoleIDs) == 0 {
		return nil, nil
	}
	locked := ls.db.Dialector.Name() == "postgres"

	var out []storage.RoleAssignment

	userQ := ls.db.WithContext(ctx)
	if locked {
		userQ = userQ.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var userRows []models.UserRole
	if err := userQ.Where("project_id = 0 AND environment_id = 0 AND role_id IN ?", adminRoleIDs).
		Where(sqlWhereURNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Find(&userRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range userRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "user", PrincipalID: r.UserID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}

	groupQ := ls.db.WithContext(ctx)
	if locked {
		groupQ = groupQ.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var groupRows []models.GroupRole
	if err := groupQ.Where("project_id = 0 AND environment_id = 0 AND role_id IN ?", adminRoleIDs).
		Where(sqlWhereGRNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Find(&groupRows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range groupRows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// RemoveGlobalAdminRoleGuarded is the atomic, single-storage-call form of
// guardLastGlobalAdmin (#340) + RemoveRole — added for #525, replacing the two
// separate calls (ListGlobalAdminAssignmentsForUpdate then RemoveRole)
// RemoveUserRole previously made inside a WithTransaction closure. See the
// Storage interface doc for the full
// atomicity reasoning. Runs in its own transaction (mirroring WithTransaction's own
// db.Transaction wrapping) so the row lock ListGlobalAdminAssignmentsForUpdate takes
// on Postgres is actually held for the whole check-then-delete, exactly as it was
// when the caller drove both calls under its own WithTransaction.
func (ls *LocalStorage) RemoveGlobalAdminRoleGuarded(ctx context.Context, userID, roleID uint, adminRoleIDs []uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := &LocalStorage{
			db:                    tx,
			auditChainMu:          ls.auditChainMu,
			auditCheckpointMu:     ls.auditCheckpointMu,
			bootstrapMu:           ls.bootstrapMu,
			namedLockMu:           ls.namedLockMu,
			consumeClockWatermark: ls.consumeClockWatermark,
			rbacClockWatermark:    ls.rbacClockWatermark,
			auditHead:             ls.auditHead,
		}
		assignments, err := txStorage.ListGlobalAdminAssignmentsForUpdate(ctx, adminRoleIDs)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		survives := false
		for _, a := range assignments {
			// Ignore the exact assignment being removed; any OTHER global admin
			// grant that still resolves to a LIVE holder means governance survives.
			if a.PrincipalType == "user" && a.PrincipalID == userID && a.RoleID == roleID {
				continue
			}
			live, err := txStorage.globalAdminAssignmentHasLiveHolder(ctx, a)
			if err != nil {
				return err
			}
			if live {
				survives = true
				break
			}
		}
		if !survives {
			return fmt.Errorf("%w: the install would be left with no install administrator at the global scope and no one able to manage users, roles, or settings", storage.ErrWouldStrandLastAdmin)
		}
		return txStorage.RemoveRole(ctx, userID, roleID, storage.Scope{})
	})
}

// globalAdminLiveAccountStates are the account_state values that do NOT block
// login: exactly the states core.AccountLoginBlocked returns false for
// (internal/core/account_state.go). Suspended, deprovisioned and any
// unrecognized value are excluded, so a suspended admin's surviving grant row
// is never counted as a fallback admin (it cannot log in to manage anything).
// TestGlobalAdminLiveAccountStates_MatchAccountLoginBlocked (internal/core)
// fails if the two lists drift.
var globalAdminLiveAccountStates = []string{"active", "pending_first_login", "password_reset_required"}

// loginCapableAccountStates is globalAdminLiveAccountStates under the name that
// describes what the set actually IS, for the #2701 credential-owner re-check
// (requireLiveCredentialOwner, local_auth.go). Deliberately the SAME slice, not
// a copy of the values: both uses need exactly "the account_state values that do
// not block login", and TestGlobalAdminLiveAccountStates_MatchAccountLoginBlocked
// already pins that set against core.AccountLoginBlocked. A second literal would
// be a second thing to keep in step.
var loginCapableAccountStates = globalAdminLiveAccountStates

// GlobalAdminLiveAccountStates returns a copy of globalAdminLiveAccountStates,
// for the drift test in internal/core.
func GlobalAdminLiveAccountStates() []string {
	return append([]string(nil), globalAdminLiveAccountStates...)
}

// globalAdminAssignmentHasLiveHolder reports whether a global admin grant row
// returned by ListGlobalAdminAssignmentsForUpdate still confers admin authority
// on at least one usable account. A grant ROW is not a holder (#2658):
// soft-deleting a user or a group, deactivating a user, or removing a group's
// last member never deletes the user_roles/group_roles row, so counting rows
// let RemoveUserRole strip the last real admin while a dead group's leftover
// grant was counted as "another admin survives". This mirrors core's
// resolveGlobalAdminHolders/filterActiveHolders (internal/core/authz.go), the
// resolver the group-path guards already use:
//
//   - a user grant counts only if the user is not soft-deleted, IsActive, and
//     in an account_state that can log in (globalAdminLiveAccountStates);
//   - a group grant counts only if the group is not soft-deleted and has at
//     least one GLOBAL (user_groups.project_id = 0) member who is live by the
//     same test.
//
// On Postgres every row the verdict rests on (the user, the group, the
// membership rows) is read FOR UPDATE inside the caller's transaction, like
// ListGlobalAdminAssignmentsForUpdate's own grant rows. That is
// belt-and-braces: core's RemoveUserRole also holds lastAdminGuardLockKey,
// the named lock every other last-admin writer (DeleteGroup,
// RemoveUserFromGroup, RemoveRoleFromGroup, SuspendUser, DeleteUser, SCIM)
// already takes.
func (ls *LocalStorage) globalAdminAssignmentHasLiveHolder(ctx context.Context, a storage.RoleAssignment) (bool, error) {
	locked := ls.db.Dialector.Name() == "postgres"
	q := func() *gorm.DB {
		db := ls.db.WithContext(ctx)
		if locked {
			db = db.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		return db
	}
	liveUsers := func(ids []uint) (bool, error) {
		if len(ids) == 0 {
			return false, nil
		}
		var users []models.User
		if err := q().Where("id IN ? AND is_active = ? AND account_state IN ?", ids, true, globalAdminLiveAccountStates).Find(&users).Error; err != nil {
			return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		return len(users) > 0, nil
	}
	switch a.PrincipalType {
	case "user":
		return liveUsers([]uint{a.PrincipalID})
	case "group":
		var groups []models.Group
		if err := q().Where("id = ?", a.PrincipalID).Find(&groups).Error; err != nil {
			return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		if len(groups) == 0 {
			return false, nil // soft-deleted (default scope) or gone
		}
		var memberships []models.UserGroup
		if err := q().Where("group_id = ? AND project_id = 0", a.PrincipalID).Find(&memberships).Error; err != nil {
			return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		ids := make([]uint, 0, len(memberships))
		for _, m := range memberships {
			ids = append(ids, m.UserID)
		}
		return liveUsers(ids)
	default:
		return false, nil
	}
}

// GetUserRoleIDsExact returns the IDs of roles directly assigned to userID at
// exactly the given scope (no global/inherited matching). Used for full
// replacement of a user's roles at one scope.
func (ls *LocalStorage) GetUserRoleIDsExact(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Where("user_id = ? AND project_id = ? AND environment_id = ?",
			userID, scope.ProjectID, scope.EnvironmentID).
		Where(sqlWhereURNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Distinct().Pluck("role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// IsProjectMember reports whether the user holds a LIVE role grant scoped to the
// project itself (project_id = projectID), directly or via a group. A global/install-
// wide role (project_id = 0) does NOT count — break-glass and similar controls must
// distinguish a project member from any user who merely holds the install baseline.
func (ls *LocalStorage) IsProjectMember(ctx context.Context, userID, projectID uint) (bool, error) {
	if projectID == 0 {
		return false, nil
	}
	now := ls.rbacEffectiveNow(time.Now().UTC())
	var direct int64
	if err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Where("user_id = ? AND project_id = ?", userID, projectID).
		Where(sqlWhereURNotExpired, now).
		Count(&direct).Error; err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if direct > 0 {
		return true, nil
	}
	var viaGroup int64
	if err := ls.db.WithContext(ctx).Table("group_roles").
		Joins(sqlJoinUserGroups).
		Joins(sqlJoinGroups).
		Where("user_groups.user_id = ? AND group_roles.project_id = ?", userID, projectID).
		Where(sqlWhereGRNotExpired, now).
		Count(&viaGroup).Error; err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return viaGroup > 0, nil
}

// IsGroupProjectScoped reports whether groupID holds a LIVE role grant scoped to
// the project itself (group_roles.project_id = projectID) — the group-share
// counterpart to IsProjectMember above. A global/install-wide group role grant
// (project_id = 0) does NOT count, matching IsProjectMember's own global
// exclusion, and a soft-deleted group never counts (sqlJoinGroups filters it).
func (ls *LocalStorage) IsGroupProjectScoped(ctx context.Context, groupID, projectID uint) (bool, error) {
	if projectID == 0 {
		return false, nil
	}
	now := ls.rbacEffectiveNow(time.Now().UTC())
	var count int64
	if err := ls.db.WithContext(ctx).Table("group_roles").
		Joins(sqlJoinGroups).
		Where("group_roles.group_id = ? AND group_roles.project_id = ?", groupID, projectID).
		Where(sqlWhereGRNotExpired, now).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return count > 0, nil
}

// ListProjectMembers returns the users holding a LIVE role at the project's scope
// (project_id = projectID, environment_id = 0 — project-level membership per ADR-021).
// Soft-deleted users AND expired time-bound grants are excluded — the same expires_at
// filter every authorization query applies, so a lapsed (but not-yet-swept) grant (e.g.
// an expired break-glass project_admin) confers neither access NOR membership/notification
// eligibility. Without it, sensitive approver notifications would keep reaching a user
// whose grant has already lapsed.
func (ls *LocalStorage) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	var members []storage.ProjectMember
	err := ls.db.WithContext(ctx).Table("user_roles ur").
		Select("u.id AS user_id, u.username, u.display_name, u.email, r.id AS role_id, r.name AS role_name").
		Joins("JOIN users u ON u.id = ur.user_id").
		Joins("JOIN roles r ON r.id = ur.role_id").
		Where("ur.project_id = ? AND ur.environment_id = 0", projectID).
		Where("ur.expires_at IS NULL OR ur.expires_at > ?", ls.rbacEffectiveNow(time.Now().UTC())).
		Where("u.deleted_at IS NULL").
		Order("u.username").
		Scan(&members).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return members, nil
}

// GetUserGroupRoleIDsAt returns the IDs of roles userID inherits via group
// membership that apply at the target scope (same scope-matching rule as
// GetUserRoleIDsAt).
// GetUserGroupRoleIDsAt: like GetUserRoleIDsAt but for group-inherited role
// grants. A scoped (non-zero) project_id/environment_id must ALSO resolve to a
// LIVE project/environment row, same as GetUserRoleIDsAt (#161) — a group-bound
// role scoped to a since-soft-deleted project previously kept authorizing every
// group member regardless of the project's own soft-delete state.
//
// Project-scoped memberships (UserGroup.ProjectID != 0) are honoured only when
// the requested scope matches: a membership with project_id=5 does not confer
// roles when evaluating scope project_id=7.  Global memberships (project_id=0)
// continue to apply at every scope.
func (ls *LocalStorage) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Table("group_roles").
		Joins(sqlJoinUserGroups).
		// A soft-deleted group confers no roles, even though its membership/grant rows
		// are kept for restore — exclude deleted groups from authorization.
		Joins(sqlJoinGroups).
		Joins("LEFT JOIN projects ON projects.id = group_roles.project_id").
		Joins("LEFT JOIN environments ON environments.id = group_roles.environment_id").
		Where(sqlWhereUGUserID, userID).
		// Honour project-scoped memberships: global (project_id=0) always applies;
		// non-zero only when it matches the requested project.
		Where("user_groups.project_id = 0 OR user_groups.project_id = ?", scope.ProjectID).
		Where("group_roles.project_id = 0 OR (group_roles.project_id = ? AND projects.deleted_at IS NULL)", scope.ProjectID).
		Where("group_roles.environment_id = 0 OR (group_roles.environment_id = ? AND environments.deleted_at IS NULL)", scope.EnvironmentID).
		Where(sqlWhereGRNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Distinct().Pluck("group_roles.role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// RoleSetHasPermission reports whether any role in roleIDs grants the named
// permission (e.g. "secrets.read") via the role_permissions join.
// RoleSetHasPermission reports whether any role in roleIDs grants permission.
// Served from the read-path "principal permissions" cache (PERF-3,
// docs/specs/read-path-caching.md PR-2) when a live global generation check
// confirms no role_permissions edit has happened since this exact
// (roleIDs, permission) pair was last resolved; any miss (cold cache, stale
// generation, or a generation-check error) falls through to the exact live
// join this method always ran. See role_permission_cache.go's header for why
// only the role→permission MAPPING is cached here, never role membership.
func (ls *LocalStorage) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	if len(roleIDs) == 0 {
		return false, nil
	}
	key := rolePermKey(roleIDs, permission)
	if allowed, hit := ls.getCachedRolePermission(ctx, key); hit {
		return allowed, nil
	}
	// Never publish an answer resolved inside a transaction into the shared
	// cache: it was computed from UNCOMMITTED rows under an UNCOMMITTED
	// generation, so a rollback would leave it there to be validated (and
	// served) by the next committed write that reproduces the same generation
	// value. With the generation a monotonic integer, the very next committed
	// role_permissions write reproduces a rolled-back N+1 exactly. See
	// cacheEnabled's doc comment on LocalStorage. getCachedRolePermission above
	// is gated by the same flag, so a tx-scoped read is fully live.
	if !ls.cacheEnabled {
		return ls.liveRoleSetHasPermission(ctx, roleIDs, permission)
	}
	// Read the generation BEFORE the live join (coordinator review of #2767):
	// a grant/revoke committing between the join and a later generation read
	// would otherwise cache this pre-change answer under the POST-change
	// generation, and a revoked permission would keep authorizing until some
	// unrelated role_permissions edit. Read first, the worst case is a cache
	// entry under an already-stale generation, which simply never hits.
	gen, trusted, genErr := liveRolePermissionsGeneration(ctx, ls)
	allowed, err := ls.liveRoleSetHasPermission(ctx, roleIDs, permission)
	if err != nil {
		return false, err
	}
	if genErr == nil && trusted {
		ls.rolePermCache.set(key, rolePermCacheEntry{generation: gen, allowed: allowed})
	}
	return allowed, nil
}

// liveRoleSetHasPermission is the uncached join — the behaviour this method had
// before PERF-3, and what every cache miss (and every read inside a
// transaction) falls through to.
func (ls *LocalStorage) liveRoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	var count int64
	err := ls.db.WithContext(ctx).Table("permissions").
		Joins(sqlJoinRolePerms).
		Where("role_permissions.role_id IN ?", roleIDs).
		Where("permissions.name = ?", permission).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	return count > 0, nil
}

// getCachedRolePermission returns (allowed, true) on a confirmed-current
// cache hit, or (false, false) on any miss — including a generation-check
// error (fail closed: never trust the cache over a check that itself
// failed), a generation the triggers no longer maintain (#3259), and a
// transaction-scoped store, which must never read the shared
// cache (see cacheEnabled's doc comment on LocalStorage).
func (ls *LocalStorage) getCachedRolePermission(ctx context.Context, key string) (bool, bool) {
	if !ls.cacheEnabled {
		return false, false
	}
	cached, ok := ls.rolePermCache.get(key)
	if !ok {
		return false, false
	}
	liveGen, trusted, err := liveRolePermissionsGeneration(ctx, ls)
	if err != nil || !trusted || liveGen != cached.generation {
		return false, false
	}
	return cached.allowed, true
}

// RoleSetBypassesPermissionChecks reports whether any role in roleIDs has
// BypassesPermissionChecks = true (ADR-084).
func (ls *LocalStorage) RoleSetBypassesPermissionChecks(ctx context.Context, roleIDs []uint) (bool, error) {
	if len(roleIDs) == 0 {
		return false, nil
	}
	var count int64
	err := ls.db.WithContext(ctx).Model(&models.Role{}).
		Where("id IN ?", roleIDs).
		Where("bypasses_permission_checks = ?", true).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	return count > 0, nil
}

// ListAdminBypassRoleIDs enumerates every role ID with
// BypassesPermissionChecks = true (ADR-084) -- see the interface doc comment for
// why the enumeration exists alongside the membership test. Deliberately selects
// on the FLAG and nothing else: no name predicate, so a role acquires or loses
// admin-conferring status only by the flag moving, which is written in exactly
// two places (the one-time backfill in internal/storage/factory.go and role
// seeding in internal/core/auth_bootstrap.go).
//
// An empty result is a legitimate answer (a pre-bootstrap install has no roles
// at all); only a query failure is an error.
func (ls *LocalStorage) ListAdminBypassRoleIDs(ctx context.Context) ([]uint, error) {
	var ids []uint
	if err := ls.db.WithContext(ctx).Model(&models.Role{}).
		Where("bypasses_permission_checks = ?", true).
		Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	return ids, nil
}

// ListPermissions returns all permissions.
func (ls *LocalStorage) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	var permissions []*models.Permission
	if err := ls.db.WithContext(ctx).Find(&permissions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetPermission returns a single permission by ID.
func (ls *LocalStorage) GetPermission(ctx context.Context, id uint) (*models.Permission, error) {
	var permission models.Permission
	if err := ls.db.WithContext(ctx).First(&permission, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &permission, nil
}

// GetRolePermissions returns all permissions assigned to a role.
func (ls *LocalStorage) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Joins(sqlJoinRolePerms).
		Where("role_permissions.role_id = ?", roleID).
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// RemovePermissionFromRole removes a permission from a role.
// RemovePermissionFromRole revokes permissionID from roleID. Bumps the
// global role_permissions cache generation (PERF-3, PR-2) in the SAME
// transaction as the revoke — see AssignPermissionToRole's doc comment.
func (ls *LocalStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.
			Where("role_id = ? AND permission_id = ?", roleID, permissionID).
			Delete(&models.RolePermission{})
		if result.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		return bumpRolePermissionsGenerationTx(ctx, &LocalStorage{db: tx})
	})
}

// GetGroupRoles returns all roles assigned to a group.
func (ls *LocalStorage) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN group_roles ON roles.id = group_roles.role_id").
		Where("group_roles.group_id = ?", groupID).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetGroupRoleGrants is GetGroupRoles plus each grant's time-bound expiry, joined
// from group_roles.expires_at (nil = permanent).
func (ls *LocalStorage) GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*storage.GroupRoleGrant, error) {
	var grants []*storage.GroupRoleGrant
	err := ls.db.WithContext(ctx).Table("roles").
		Select("roles.id, roles.name, roles.description, group_roles.expires_at").
		Joins("JOIN group_roles ON roles.id = group_roles.role_id").
		Where("group_roles.group_id = ?", groupID).
		Scan(&grants).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return grants, nil
}

// ListGroupRoleAssignments returns every LIVE role grant held by groupID across all
// scopes, unlike GetGroupRoles/GetGroupRoleGrants which return the role but not
// which scope it was granted at. Excludes expired grants -- matching every other
// role-lookup function in this file -- since callers (validateGroupJoinRoles's
// SoD/escalation checks, the admin group-roles view) treat this as "what does the
// group currently confer," not a historical record.
func (ls *LocalStorage) ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]storage.RoleAssignment, error) {
	var rows []models.GroupRole
	if err := ls.db.WithContext(ctx).
		Where("group_id = ?", groupID).
		Where(sqlWhereGRNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := make([]storage.RoleAssignment, 0, len(rows))
	for _, r := range rows {
		out = append(out, storage.RoleAssignment{
			PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
			ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
		})
	}
	return out, nil
}

// ListAllGroupRoleGrants returns every group→role grant row in the deployment,
// including scoped (project/environment) and global (project_id=0) grants.
// Includes time-bound (JIT) grants, expired or not — the group-grant
// counterpart to ListAllUserRoleGrants; callers filter by ExpiresAt if needed.
func (ls *LocalStorage) ListAllGroupRoleGrants(ctx context.Context) ([]*models.GroupRole, error) {
	var grants []*models.GroupRole
	return grants, ls.db.WithContext(ctx).Find(&grants).Error
}

// AssignRoleToGroup assigns a permanent role to a group at scope; errors if
// already assigned there.
func (ls *LocalStorage) AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	return ls.assignGroupRole(ctx, groupID, roleID, scope, nil)
}

// AssignRoleToGroupWithExpiry assigns a time-bound role to a group at scope.
func (ls *LocalStorage) AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	return ls.assignGroupRole(ctx, groupID, roleID, scope, &expiresAt)
}

func (ls *LocalStorage) assignGroupRole(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt *time.Time) error {
	if expiresAt != nil {
		utc := expiresAt.UTC()
		expiresAt = &utc
	}
	// #G21: see assignUserRole's identical fix — the read, the stale-row
	// delete, and the fresh-grant create all run inside ONE transaction so
	// SQLite's single-writer locking prevents a concurrent
	// AssignRoleToGroup call from inserting its own live grant at this key
	// in between our read and our write, rather than trying to re-verify the
	// observed expires_at value in the delete's WHERE clause (abandoned:
	// GORM's struct-field writes and a raw driver parameter bind serialize
	// time.Time inconsistently with this driver, confirmed empirically).
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing models.GroupRole
		err := tx.Where(sqlWhereGroupRoleEnv,
			groupID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
		switch err {
		case nil:
			// A row already exists at this exact (group, role, project, environment) key. A
			// still-live grant (no expiry, or an expiry still in the future) genuinely blocks
			// a duplicate assignment. But an EXPIRED grant is a stale, un-reaped row — e.g. a
			// prior break-glass activation whose time-bound grant naturally lapsed — and must
			// be treated as ABSENT for this check, or a second real-incident activation for
			// the same group/role/scope is permanently refused with "already assigned" even
			// though nothing live is actually being duplicated (#263/#471). Delete the stale
			// row so the composite primary key (group_id, role_id, project_id, environment_id)
			// is free for the fresh Create below, mirroring assignUserRole's identical fix.
			if existing.ExpiresAt == nil || existing.ExpiresAt.After(ls.rbacEffectiveNow(time.Now().UTC())) {
				return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
			}
			if derr := tx.Where(sqlWhereGroupRoleEnv,
				groupID, roleID, scope.ProjectID, scope.EnvironmentID).
				Delete(&models.GroupRole{}).Error; derr != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), derr)
			}
		case gorm.ErrRecordNotFound:
			// no existing row for this key — proceed to create.
		default:
			return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
		}
		groupRole := models.GroupRole{
			GroupID:       groupID,
			RoleID:        roleID,
			ProjectID:     scope.ProjectID,
			EnvironmentID: scope.EnvironmentID,
			ExpiresAt:     expiresAt,
		}
		if err := tx.Create(&groupRole).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		return nil
	})
}

// DeleteExpiredRoleGrants removes user_roles and group_roles whose ExpiresAt is
// non-NULL and at or before the cutoff, returning the removed grants so the caller
// can audit each expiry. Runs in a transaction so the rows it reports are exactly
// the rows it deleted.
func (ls *LocalStorage) DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]storage.RoleAssignment, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776 // nosemgrep: keyorix-role-grant-query-missing-expiry-filter -- this IS the expiry sweep job; it intentionally selects expired rows to delete them
	cutoff := before.UTC()
	var removed []storage.RoleAssignment
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var userRows []models.UserRole
		if err := tx.Where(sqlWhereExpired, cutoff).Find(&userRows).Error; err != nil {
			return err
		}
		var groupRows []models.GroupRole
		if err := tx.Where(sqlWhereExpired, cutoff).Find(&groupRows).Error; err != nil {
			return err
		}
		if len(userRows) > 0 {
			if err := tx.Where(sqlWhereExpired, cutoff).Delete(&models.UserRole{}).Error; err != nil {
				return err
			}
		}
		if len(groupRows) > 0 {
			if err := tx.Where(sqlWhereExpired, cutoff).Delete(&models.GroupRole{}).Error; err != nil {
				return err
			}
		}
		for _, r := range userRows {
			removed = append(removed, storage.RoleAssignment{
				PrincipalType: "user", PrincipalID: r.UserID, RoleID: r.RoleID,
				ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
			})
		}
		for _, r := range groupRows {
			removed = append(removed, storage.RoleAssignment{
				PrincipalType: "group", PrincipalID: r.GroupID, RoleID: r.RoleID,
				ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return removed, nil
}

// RemoveRoleFromGroup removes a role from a group at scope.
func (ls *LocalStorage) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where(sqlWhereGroupRoleEnv,
			groupID, roleID, scope.ProjectID, scope.EnvironmentID).
		Delete(&models.GroupRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotAssigned", nil))
	}
	return nil
}

// GetUserPermissions retrieves all distinct permissions for userID via role membership.
func (ls *LocalStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	var permissions []*storage.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Select("permissions.id, permissions.name, permissions.description, permissions.resource, permissions.action").
		Joins(sqlJoinRolePerms).
		Joins("JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where(sqlWhereURUserID, userID).
		Where(sqlWhereURNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Group("permissions.id").
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetUserGroupPermissions returns the permissions a user holds via group
// membership, scope-agnostically across all their groups. Mirrors
// GetUserPermissions but resolves through group_roles/user_groups, excluding
// soft-deleted groups and expired grants (matching GetUserGroupRoleIDsAt).
func (ls *LocalStorage) GetUserGroupPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	var permissions []*storage.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Select("permissions.id, permissions.name, permissions.description, permissions.resource, permissions.action").
		Joins(sqlJoinRolePerms).
		Joins("JOIN group_roles ON role_permissions.role_id = group_roles.role_id").
		Joins(sqlJoinUserGroups).
		// A soft-deleted group confers no permissions (matches authz resolution).
		Joins(sqlJoinGroups).
		Where(sqlWhereUGUserID, userID).
		Where(sqlWhereGRNotExpired, ls.rbacEffectiveNow(time.Now().UTC())).
		Group("permissions.id").
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// ListAllUserRoleGrants returns every user→role grant row in the deployment,
// including scoped (project/environment) and global (project_id=0) grants.
// Includes time-bound (JIT) grants; callers filter by ExpiresAt if needed.
func (ls *LocalStorage) ListAllUserRoleGrants(ctx context.Context) ([]*models.UserRole, error) {
	var grants []*models.UserRole
	return grants, ls.db.WithContext(ctx).Find(&grants).Error
}
