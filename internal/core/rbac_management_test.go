package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newRBACManagementCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.PendingAuditEvent{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		// SystemMetadata holds the role_permissions cache-invalidation generation
		// (PERF-3 PR-2): every role_permissions write bumps it in the same
		// transaction, so a setup that migrates RolePermission must migrate this
		// too or the grant fails closed — which is the intended safety behaviour,
		// not something to relax in the writer. See role_permission_cache.go.
		&models.SystemMetadata{},
		&models.User{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SoDPolicy{}, &models.Session{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// #169: an actor with NO permissions at all — the CVE's own escalation shape (a
// roles.write holder with nothing else) — must not be able to bundle ANY permission
// into a role's definition, including a low-privilege one they don't personally hold.
func TestAssignPermissionToRole_RequiresActorHoldPermission(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)

	const attacker = uint(9) // holds ONLY roles.write in the real exploit scenario, no roles at all here
	err := c.AssignPermissionToRole(ctx, attacker, 1, 1, false)
	require.Error(t, err, "an actor who doesn't hold system.write must not be able to bundle it into a role")
	assert.Contains(t, err.Error(), "do not hold it yourself")

	var count int64
	require.NoError(t, db.Model(&models.RolePermission{}).Count(&count).Error)
	assert.Zero(t, count, "the permission must not have been assigned")
}

// #1545: a machine identity presents actorID==0 by construction (ADR-030, no
// UserID), the same value the actorID==0 exemption was written for a true
// "no authenticated principal" system caller (ReconcileRBACPermissions).
// Before this fix, AssignPermissionToRole's `if actorID != 0` gate silently
// exempted a machine caller from the #169 self-permission check right
// alongside that trusted system caller — a machine identity holding nothing
// but roles.write (a legitimate, grantable, non-admin permission) could
// bundle system.write into ANY role's definition without holding it itself.
// Exploit-shaped: this is the exact attacker shape (actorID==0, actorIsMachine
// true, no roles at all) — must be denied, not silently trusted. Verified red
// before the actorIsMachine fix (temporarily reverted the `|| actorIsMachine`
// clause locally and confirmed this test failed with the assignment
// succeeding), green after.
func TestAssignPermissionToRole_MachineActorRequiresHoldPermission(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)

	err := c.AssignPermissionToRole(ctx, 0, 1, 1, true)
	require.Error(t, err, "a machine actor (actorID==0, actorIsMachine=true) who doesn't hold system.write must not be able to bundle it into a role")
	assert.Contains(t, err.Error(), "do not hold it yourself")

	var count int64
	require.NoError(t, db.Model(&models.RolePermission{}).Count(&count).Error)
	assert.Zero(t, count, "the permission must not have been assigned")
}

// Positive control: the true "no authenticated principal" system caller
// (actorID==0, actorIsMachine=false — e.g. ReconcileRBACPermissions's startup
// top-up, #293) must remain exempt from the #169 check exactly as before —
// the fix narrows the exemption to that genuine case, it does not remove it.
func TestAssignPermissionToRole_SystemPseudoActorStillExempt(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)

	require.NoError(t, c.AssignPermissionToRole(ctx, 0, 1, 1, false))

	var count int64
	require.NoError(t, db.Model(&models.RolePermission{}).Where("role_id = ? AND permission_id = ?", 1, 1).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// The escalation path the finding describes: attacker holds roles.write (only)
// PLUS the target permission at project scope, but not globally — bundling into a
// role (a global catalog object) must still require GLOBAL authority, not just
// scoped authority, since the resulting role could be granted anywhere.
func TestAssignPermissionToRole_ScopedHolderCannotBundleGlobally(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "scoped-holder"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	const attacker = uint(9)
	// attacker holds "system.write" only at project 3, not globally.
	require.NoError(t, db.Create(&models.UserRole{UserID: attacker, RoleID: 2, ProjectID: 3}).Error)

	err := c.AssignPermissionToRole(ctx, attacker, 1, 1, false)
	require.Error(t, err, "a project-scoped holder of system.write must not bundle it into a role, which is a global object")
}

// An actor who genuinely holds the permission (directly, at global scope) may bundle
// it into a role — the fix must not block the legitimate case.
func TestAssignPermissionToRole_HolderMaySelfBundle(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "holder"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	const holder = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: holder, RoleID: 2}).Error) // global grant

	require.NoError(t, c.AssignPermissionToRole(ctx, holder, 1, 1, false))

	var count int64
	require.NoError(t, db.Model(&models.RolePermission{}).Where("role_id = ? AND permission_id = ?", 1, 1).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// A global admin bypasses the self-permission check (matching every other authz gate
// in this codebase) — an admin can bundle any permission into any role.
func TestAssignPermissionToRole_AdminBypasses(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)

	const admin = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: admin, RoleID: 2}).Error)

	require.NoError(t, c.AssignPermissionToRole(ctx, admin, 1, 1, false))
}

// TestAssignPermissionToRole_DuplicateAssignment_ReturnsConflictNotStorageFailure
// is SESSION-I's regression: role_permissions' composite primary key
// (role_id, permission_id) rejects a duplicate insert at the real SQLite
// layer, and before storage.ErrDuplicateRolePermission existed, that
// primary-key violation surfaced from AssignPermissionToRole as a generic
// "Storage operation failed" error indistinguishable from any other DB
// failure — server/http/handlers/rbac.go's handler could not classify it,
// so a re-assign of an already-held permission 500ed instead of the correct
// 409 Conflict. Runs against a real SQLite database (newRBACManagementCore),
// not a mock, so the actual UNIQUE constraint fires.
func TestAssignPermissionToRole_DuplicateAssignment_ReturnsConflictNotStorageFailure(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)

	const admin = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: admin, RoleID: 1}).Error)

	// First assignment succeeds.
	require.NoError(t, c.AssignPermissionToRole(ctx, admin, 1, 1, false))

	// Second, identical assignment must fail with a message the handler can
	// classify as 409 (strings.Contains(err.Error(), "already has permission")),
	// NOT the generic i18n.T("ErrorStorageFailed") wrapper every other,
	// genuinely-unexpected storage error still falls through to.
	err := c.AssignPermissionToRole(ctx, admin, 1, 1, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already has permission",
		"a duplicate role-permission assignment must be classifiable as a conflict, not a generic storage failure")
	assert.NotContains(t, err.Error(), "Storage operation failed",
		"must not fall through to the generic default-case wrapper the handler maps to 500")

	var count int64
	require.NoError(t, db.Model(&models.RolePermission{}).Where("role_id = ? AND permission_id = ?", 1, 1).Count(&count).Error)
	assert.Equal(t, int64(1), count, "the duplicate attempt must not have inserted a second row")
}

// RemovePermissionFromRole is purely subtractive (weakens a role) — it must NOT
// require the actor hold the permission being removed, unlike assignment.
func TestRemovePermissionFromRole_NoSelfPermissionRequired(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)

	const actor = uint(9) // holds nothing
	require.NoError(t, c.RemovePermissionFromRole(ctx, actor, 1, 1))
}

// lastRBACEventDetail fetches the most recent audit event of the given type
// and decodes its structured Diff, for asserting on rbacAuditDetail fields
// (unexported, but this test file is in package core) that ListRBACAuditLogs
// doesn't currently surface — #1500's BuiltinRoleTarget among them.
func lastRBACEventDetail(t *testing.T, c *KeyorixCore, eventType string) (*models.AuditEvent, rbacAuditDetail) {
	t.Helper()
	events, _, err := c.storage.GetAuditLogs(context.Background(), &storage.AuditFilter{
		Actions: []string{eventType}, Page: 1, PageSize: 50,
	})
	require.NoError(t, err)
	require.NotEmpty(t, events, "expected at least one %s event", eventType)
	event := events[0]
	var detail rbacAuditDetail
	require.NoError(t, json.Unmarshal([]byte(event.Diff), &detail))
	return event, detail
}

// #1500: removing a permission from a built-in role stays PERMITTED (ADR-044) —
// this only asserts the operation succeeds and its audit event carries the
// distinct built-in signal, not that it's refused.
func TestRemovePermissionFromRole_BuiltinRoleTarget_SignalsInAudit(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error) // builtin
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)

	logOutput := captureLog(t, func() {
		require.NoError(t, c.RemovePermissionFromRole(ctx, 9, 1, 1))
	})

	event, detail := lastRBACEventDetail(t, c, EventPermissionRemoved)
	assert.Contains(t, event.Description, "reason=builtin_role_target")
	assert.True(t, detail.BuiltinRoleTarget)
	assert.Equal(t, uint(1), detail.RoleID)
	assert.Equal(t, uint(1), detail.PermissionID)

	assert.Contains(t, logOutput, "SECURITY", "expected a log warning naming the role and permission")
	assert.Contains(t, logOutput, "admin", "log warning must name the built-in role")
	assert.Contains(t, logOutput, "system.write", "log warning must name the permission")
}

// A non-built-in role produces the ordinary event: no reason= token, no
// structured flag, no SECURITY log line.
func TestRemovePermissionFromRole_NonBuiltinRole_NoSignal(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)

	logOutput := captureLog(t, func() {
		require.NoError(t, c.RemovePermissionFromRole(ctx, 9, 1, 1))
	})

	event, detail := lastRBACEventDetail(t, c, EventPermissionRemoved)
	assert.NotContains(t, event.Description, "reason=")
	assert.False(t, detail.BuiltinRoleTarget)
	assert.Empty(t, strings.TrimSpace(logOutput), "no SECURITY warning expected for a non-built-in target")
}

// #1500: assigning a permission to a built-in role also stays PERMITTED and
// must carry the same signal — the inverse of RemovePermissionFromRole above.
func TestAssignPermissionToRole_BuiltinRoleTarget_SignalsInAudit(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error) // builtin
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)
	// Actor must already hold the permission (#169) — make them a global admin.
	const actor = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: actor, RoleID: 1}).Error)

	logOutput := captureLog(t, func() {
		require.NoError(t, c.AssignPermissionToRole(ctx, actor, 1, 1, false))
	})

	event, detail := lastRBACEventDetail(t, c, EventPermissionAdded)
	assert.Contains(t, event.Description, "reason=builtin_role_target")
	assert.True(t, detail.BuiltinRoleTarget)

	assert.Contains(t, logOutput, "SECURITY")
	assert.Contains(t, logOutput, "admin")
	assert.Contains(t, logOutput, "system.write")
}

// A non-built-in role produces the ordinary event on assignment too.
func TestAssignPermissionToRole_NonBuiltinRole_NoSignal(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "holder"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	const holder = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: holder, RoleID: 2}).Error)

	logOutput := captureLog(t, func() {
		require.NoError(t, c.AssignPermissionToRole(ctx, holder, 1, 1, false))
	})

	event, detail := lastRBACEventDetail(t, c, EventPermissionAdded)
	assert.NotContains(t, event.Description, "reason=")
	assert.False(t, detail.BuiltinRoleTarget)
	assert.Empty(t, strings.TrimSpace(logOutput), "no SECURITY warning expected for a non-built-in target")
}

// RemoveUserRole must evict the target user's cached sessions from the HTTP auth
// cache, matching every other credential-lifecycle event in this package (password
// change, suspend/deactivate/delete, PAT revoke, machine-identity suspend/revoke) —
// otherwise a just-revoked role keeps authorizing requests for up to the positive
// auth-cache TTL. Unlike those stronger events, the user's sessions themselves must
// NOT be deleted (they stay logged in; only the cached authorization decision is
// forced to re-resolve from storage on the next request).
//
// Uses SetTokenCacheClearer, not SetTokenCacheInvalidator: evictUserSessionCache
// (#2402, FuzzAuthCacheDifferential) switched to the delete-only-if-cached primitive
// specifically so a session that was never actually cached yet (e.g. a fresh login,
// immediately followed by a role grant+removal before its first authenticated
// request) does not get spuriously tombstoned as a false negative — the credential
// itself is still valid here, only its privileges may have changed.
func TestRemoveUserRole_EvictsSessionCacheWithoutLoggingOut(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)

	const userID = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: 1, ProjectID: 5}).Error)
	require.NoError(t, db.Create(&models.Session{UserID: userID, SessionToken: "session-hash-a"}).Error)
	require.NoError(t, db.Create(&models.Session{UserID: userID, SessionToken: "session-hash-b"}).Error)

	var cleared []string
	c.SetTokenCacheClearer(func(h string) { cleared = append(cleared, h) })

	require.NoError(t, c.RemoveUserRole(ctx, 0, userID, 1, Scope{ProjectID: 5}))

	assert.ElementsMatch(t, []string{"session-hash-a", "session-hash-b"}, cleared,
		"every one of the user's session hashes must be cleared from the auth cache")

	var remaining int64
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", userID).Count(&remaining).Error)
	assert.Equal(t, int64(2), remaining, "sessions must NOT be deleted — the user stays logged in")
}
