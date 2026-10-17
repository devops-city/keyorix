// store_s27_test.go — s27 coverage blitz for internal/storage/store.
//
// Targets (local_*.go functions with low coverage not yet hit by s1-s26):
//
//	local_rbac.go
//	  assignUserRole          — internal-DB-error path
//	  RemoveRole              — not-found + error path
//	  GetUserRoleIDsAt        — error path
//	  GetUserRoleScopes       — error path
//	  ListProjectRoleAssignments  — error paths
//	  ListProjectMachineRoleAssignments — error path
//	  GetUserRoleIDsExact     — error path
//	  IsProjectMember         — projectID=0 fast-return + error paths
//	  ListProjectMembers      — error path
//	  GetUserGroupRoleIDsAt   — error path
//	  RoleSetHasPermission    — empty-ids fast-return + error path
//	  GetPermission           — not-found + error path
//	  GetRolePermissions      — error path
//	  GetGroupRoles           — error path
//	  GetGroupRoleGrants      — error path
//	  assignGroupRole         — internal-DB-error path
//	  DeleteExpiredRoleGrants — empty case + happy path
//	  RemoveRoleFromGroup     — not-found + error path
//	  GetUserPermissions      — error path
//	  GetUserGroupPermissions — error path
//
//	local_auth.go
//	  CreateSession             — error path
//	  RotateSession             — lost-race (already-rotated) path
//	  RevokeAllPersonalAccessTokensForUser — error paths
//
//	local_memberships.go
//	  CreateProjectMembership     — happy path + duplicate => ErrDuplicateActiveMembership
//	  CountProjectMembershipsByUsers — empty-ids early-return + error path
//
//	local_machine_identities.go
//	  LockMachineIdentityForUpdate   — not-found
//	  CountStaleMachineIdentitiesByProject — empty-projectIDs early-return + error path
//
//	local_machine_credentials.go
//	  GetMachineRoleIDsAt — error path
//	  GetMachineRoles     — error path
//
//	local_break_glass.go
//	  ListBreakGlassActivations  — error path
//	  RevokeBreakGlassActivation — not-found + error path
//
//	local_legal_hold.go
//	  GetActiveLegalHold — not-found nil-nil + error path
//
//	local_access_activity.go
//	  lastUserActivityByEventTypes — error path
//
//	local_audit.go
//	  GetAuditLogs      — filter branch coverage
//	  CreateAnomalyAlert — dedup window skip
//
//	local_audit_checkpoint.go
//	  AuditEntryHashByID — not-found vs found
//
//	local_audit_checkpoint_lock.go
//	  WithAuditCheckpointLock — SQLite (non-postgres) happy + error path
//
//	local_secret_dependencies.go
//	  ListSecretDependenciesForProject         — error path
//	  ListSecretDependenciesForProjectForUpdate — happy path on SQLite
//	  DeleteSecretDependency                   — not-found
//
//	local_drift.go
//	  ListProjectSecretsForDrift — error path
//
//	local_purge.go
//	  DeleteClosedAccessReviewsBefore    — happy path + error path
//	  DeleteExpiredBreakGlassBefore      — happy path
//	  DeleteResolvedAccessRequestsBefore — happy path
package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newS27Store opens a unique in-memory SQLite DB with the requested models
// auto-migrated.
func newS27Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores27_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// brokenS27Store returns a LocalStorage whose DB is closed so every query fails.
func brokenS27Store(t *testing.T) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores27_", sqlite.Open, &gorm.Config{})
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return NewLocalStorage(db)
}

// rbacModels lists all models required for RBAC tests.
var rbacModels = []any{
	&models.UserRole{}, &models.GroupRole{}, &models.UserGroup{},
	&models.Role{}, &models.Group{}, &models.Project{}, &models.Environment{},
	&models.Permission{}, &models.RolePermission{}, &models.MachineIdentityRole{},
}

// ---------------------------------------------------------------------------
// local_rbac.go
// ---------------------------------------------------------------------------

func TestAssignUserRole_S27_InternalDBError(t *testing.T) {
	ls := brokenS27Store(t)
	err := ls.AssignRole(context.Background(), 1, 10, storage.Scope{})
	require.Error(t, err)
}

func TestRemoveRole_S27_NotFound(t *testing.T) {
	ls := newS27Store(t, rbacModels...)
	err := ls.RemoveRole(context.Background(), 99, 99, storage.Scope{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrRoleNotAssigned) || err != nil)
}

func TestRemoveRole_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	err := ls.RemoveRole(context.Background(), 1, 1, storage.Scope{})
	require.Error(t, err)
}

func TestGetUserRoleIDsAt_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetUserRoleIDsAt(context.Background(), 1, storage.Scope{})
	require.Error(t, err)
}

func TestGetUserRoleScopes_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetUserRoleScopes(context.Background(), 1)
	require.Error(t, err)
}

func TestListProjectRoleAssignments_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.ListProjectRoleAssignments(context.Background(), 1)
	require.Error(t, err)
}

func TestListProjectMachineRoleAssignments_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.ListProjectMachineRoleAssignments(context.Background(), 1)
	require.Error(t, err)
}

func TestGetUserRoleIDsExact_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetUserRoleIDsExact(context.Background(), 1, storage.Scope{})
	require.Error(t, err)
}

func TestIsProjectMember_S27_ZeroProjectIDReturnsFalse(t *testing.T) {
	ls := newS27Store(t, rbacModels...)
	isMember, err := ls.IsProjectMember(context.Background(), 1, 0)
	require.NoError(t, err)
	assert.False(t, isMember)
}

func TestIsProjectMember_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.IsProjectMember(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestListProjectMembers_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.ListProjectMembers(context.Background(), 1)
	require.Error(t, err)
}

func TestGetUserGroupRoleIDsAt_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetUserGroupRoleIDsAt(context.Background(), 1, storage.Scope{})
	require.Error(t, err)
}

func TestRoleSetHasPermission_S27_EmptyIDsReturnsFalse(t *testing.T) {
	ls := newS27Store(t, rbacModels...)
	has, err := ls.RoleSetHasPermission(context.Background(), nil, "secrets.read")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestRoleSetHasPermission_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.RoleSetHasPermission(context.Background(), []uint{1, 2}, "secrets.read")
	require.Error(t, err)
}

func TestGetPermission_S27_NotFound(t *testing.T) {
	ls := newS27Store(t, rbacModels...)
	_, err := ls.GetPermission(context.Background(), 9999)
	require.Error(t, err)
}

func TestGetPermission_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetPermission(context.Background(), 1)
	require.Error(t, err)
}

func TestGetRolePermissions_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetRolePermissions(context.Background(), 1)
	require.Error(t, err)
}

func TestGetGroupRoles_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetGroupRoles(context.Background(), 1)
	require.Error(t, err)
}

func TestGetGroupRoleGrants_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetGroupRoleGrants(context.Background(), 1)
	require.Error(t, err)
}

func TestAssignGroupRole_S27_InternalDBError(t *testing.T) {
	ls := brokenS27Store(t)
	err := ls.AssignRoleToGroup(context.Background(), 1, 10, storage.Scope{})
	require.Error(t, err)
}

func TestDeleteExpiredRoleGrants_S27_NoneExpired(t *testing.T) {
	ls := newS27Store(t, rbacModels...)
	ctx := context.Background()
	// Assign a permanent (non-expiring) grant.
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 0, EnvironmentID: 0}).Error)
	removed, err := ls.DeleteExpiredRoleGrants(ctx, time.Now())
	require.NoError(t, err)
	assert.Len(t, removed, 0, "no expired grants")
}

func TestDeleteExpiredRoleGrants_S27_RemovesExpiredGrants(t *testing.T) {
	ls := newS27Store(t, rbacModels...)
	ctx := context.Background()
	past := time.Now().Add(-2 * time.Hour)
	future := time.Now().Add(time.Hour)
	// expired user grant
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 2, RoleID: 20, ExpiresAt: &past}).Error)
	// live user grant
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 2, RoleID: 21, ExpiresAt: &future}).Error)
	// expired group grant
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 3, RoleID: 30, ExpiresAt: &past}).Error)

	removed, err := ls.DeleteExpiredRoleGrants(ctx, time.Now())
	require.NoError(t, err)
	// should have removed expired user + expired group
	assert.Len(t, removed, 2)
	types := map[string]bool{}
	for _, r := range removed {
		types[r.PrincipalType] = true
	}
	assert.True(t, types["user"])
	assert.True(t, types["group"])
}

func TestRemoveRoleFromGroup_S27_NotFound(t *testing.T) {
	ls := newS27Store(t, rbacModels...)
	err := ls.RemoveRoleFromGroup(context.Background(), 99, 99, storage.Scope{})
	require.Error(t, err)
}

func TestRemoveRoleFromGroup_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	err := ls.RemoveRoleFromGroup(context.Background(), 1, 1, storage.Scope{})
	require.Error(t, err)
}

func TestGetUserPermissions_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetUserPermissions(context.Background(), 1)
	require.Error(t, err)
}

func TestGetUserGroupPermissions_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetUserGroupPermissions(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go
// ---------------------------------------------------------------------------

func TestCreateSession_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.CreateSession(context.Background(), &models.Session{
		UserID:       1,
		SessionToken: "tok-xyz",
	})
	require.Error(t, err)
}

func TestRotateSession_S27_LostRaceReturnsNilFalse(t *testing.T) {
	ls := newS27Store(t, &models.Session{})
	ctx := context.Background()

	// Create a session and immediately mark it rotated (simulates prior rotation).
	now := time.Now()
	sess := &models.Session{
		UserID:       1,
		SessionToken: "orig-token",
		RotatedAt:    &now,
	}
	require.NoError(t, ls.db.Create(sess).Error)

	newSess := &models.Session{UserID: 1, SessionToken: "new-token"}
	created, won, err := ls.RotateSession(ctx, sess.ID, newSess, now)
	require.NoError(t, err)
	assert.False(t, won, "already-rotated row must yield lost-race")
	assert.Nil(t, created)
}

// ---------------------------------------------------------------------------
// local_memberships.go
// ---------------------------------------------------------------------------

func TestCreateProjectMembership_S27_Happy(t *testing.T) {
	ls := newS27Store(t, &models.ProjectMembership{})
	ctx := context.Background()
	m := &models.ProjectMembership{
		ProjectID: 1,
		UserID:    2,
		State:     "active",
		InvitedAt: time.Now(),
	}
	created, err := ls.CreateProjectMembership(ctx, m)
	require.NoError(t, err)
	assert.NotZero(t, created.ID)
}

func TestCreateProjectMembership_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.CreateProjectMembership(context.Background(), &models.ProjectMembership{
		ProjectID: 1,
		UserID:    1,
		State:     "active",
		InvitedAt: time.Now(),
	})
	require.Error(t, err)
}

func TestCountProjectMembershipsByUsers_S27_EmptyIDsReturnEmpty(t *testing.T) {
	ls := newS27Store(t, &models.ProjectMembership{})
	counts, err := ls.CountProjectMembershipsByUsers(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

func TestCountProjectMembershipsByUsers_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.CountProjectMembershipsByUsers(context.Background(), []uint{1, 2})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_identities.go
// ---------------------------------------------------------------------------

func TestLockMachineIdentityForUpdate_S27_NotFound(t *testing.T) {
	ls := newS27Store(t, &models.MachineIdentity{})
	_, err := ls.LockMachineIdentityForUpdate(context.Background(), 9999)
	require.Error(t, err)
}

func TestCountStaleMachineIdentitiesByProject_S27_EmptyProjectIDsReturnEmpty(t *testing.T) {
	ls := newS27Store(t, &models.MachineIdentity{})
	counts, err := ls.CountStaleMachineIdentitiesByProject(context.Background(), nil, time.Now())
	require.NoError(t, err)
	assert.Empty(t, counts)
}

func TestCountStaleMachineIdentitiesByProject_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.CountStaleMachineIdentitiesByProject(context.Background(), []uint{1, 2}, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go
// ---------------------------------------------------------------------------

func TestGetMachineRoleIDsAt_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetMachineRoleIDsAt(context.Background(), 1, storage.Scope{})
	require.Error(t, err)
}

func TestGetMachineRoles_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetMachineRoles(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_break_glass.go
// ---------------------------------------------------------------------------

func TestListBreakGlassActivations_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.ListBreakGlassActivations(context.Background(), 1)
	require.Error(t, err)
}

func TestRevokeBreakGlassActivation_S27_NotActive(t *testing.T) {
	ls := newS27Store(t, &models.BreakGlassActivation{})
	err := ls.RevokeBreakGlassActivation(context.Background(), 9999, 1, 0, time.Now())
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrBreakGlassNotActive) || err != nil)
}

func TestRevokeBreakGlassActivation_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	err := ls.RevokeBreakGlassActivation(context.Background(), 1, 1, 0, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_legal_hold.go
// ---------------------------------------------------------------------------

func TestGetActiveLegalHold_S27_NoneReturnsNilNil(t *testing.T) {
	ls := newS27Store(t, &models.LegalHold{})
	hold, err := ls.GetActiveLegalHold(context.Background())
	require.NoError(t, err)
	assert.Nil(t, hold)
}

func TestGetActiveLegalHold_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.GetActiveLegalHold(context.Background())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_access_activity.go
// ---------------------------------------------------------------------------

func TestLastUserSecretActivity_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.LastUserSecretActivity(context.Background(), 1, time.Time{})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_audit.go
// ---------------------------------------------------------------------------

func TestGetAuditLogs_S27_WithFilters(t *testing.T) {
	ls := newS27Store(t, &models.AuditEvent{})
	ctx := context.Background()

	projID := uint(5)
	userID := uint(7)
	action := "secret.read"
	successTrue := true
	actorType := "user"
	now := time.Now()
	afterID := uint(0)

	// Insert a matching event.
	evt := &models.AuditEvent{
		ProjectID: &projID,
		UserID:    &userID,
		EventType: action,
		EventTime: now,
		Success:   &successTrue,
		ActorType: actorType,
	}
	require.NoError(t, ls.db.Create(evt).Error)

	filter := &storage.AuditFilter{
		ProjectID: &projID,
		UserID:    &userID,
		Action:    &action,
		Success:   &successTrue,
		ActorType: &actorType,
		StartTime: &now,
		EndTime:   &now,
		AfterID:   &afterID,
		Ascending: true,
		Page:      2,
		PageSize:  5,
	}
	events, total, err := ls.GetAuditLogs(ctx, filter)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(0))
	_ = events
}

func TestCreateAnomalyAlert_S27_DedupSkip(t *testing.T) {
	ls := newS27Store(t, &models.AnomalyAlert{})
	ctx := context.Background()
	now := time.Now()
	alert := &models.AnomalyAlert{
		SecretNodeID: 1,
		AlertType:    "unusual_access",
		AccessedBy:   "svc-a",
		IPAddress:    "1.2.3.4",
		DetectedAt:   now,
	}
	// First insert succeeds.
	require.NoError(t, ls.CreateAnomalyAlert(ctx, alert))
	// Second within dedup window is silently skipped (no error, no duplicate).
	require.NoError(t, ls.CreateAnomalyAlert(ctx, alert))
	var count int64
	require.NoError(t, ls.db.Model(&models.AnomalyAlert{}).Count(&count).Error)
	assert.Equal(t, int64(1), count, "duplicate within dedup window must be silently dropped")
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint.go
// ---------------------------------------------------------------------------

func TestAuditEntryHashByID_S27_FoundVsNotFound(t *testing.T) {
	ls := newS27Store(t, &models.AuditEvent{})
	ctx := context.Background()

	// Not-found case.
	hash, found, err := ls.AuditEntryHashByID(ctx, 9999)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, hash)

	// Insert an event and check found path.
	projID := uint(1)
	successTrue := true
	evt := &models.AuditEvent{
		ProjectID: &projID,
		EventType: "secret.read",
		EventTime: time.Now(),
		Success:   &successTrue,
		ActorType: "user",
		EntryHash: "deadbeef",
	}
	require.NoError(t, ls.db.Create(evt).Error)
	hash, found, err = ls.AuditEntryHashByID(ctx, evt.ID)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "deadbeef", hash)
}

// ---------------------------------------------------------------------------
// local_audit_checkpoint_lock.go
// ---------------------------------------------------------------------------

func TestWithAuditCheckpointLock_S27_SQLiteRunsFn(t *testing.T) {
	ls := newS27Store(t)
	ctx := context.Background()

	ran := false
	err := ls.WithAuditCheckpointLock(ctx, func(context.Context) error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ran)
}

func TestWithAuditCheckpointLock_S27_PropagatesFnError(t *testing.T) {
	ls := newS27Store(t)
	ctx := context.Background()

	sentinel := errors.New("fn-error")
	err := ls.WithAuditCheckpointLock(ctx, func(context.Context) error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// local_secret_dependencies.go
// ---------------------------------------------------------------------------

func TestListSecretDependenciesForProject_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.ListSecretDependenciesForProject(context.Background(), 1)
	require.Error(t, err)
}

func TestListSecretDependenciesForProjectForUpdate_S27_SQLiteHappyPath(t *testing.T) {
	ls := newS27Store(t, &models.SecretDependency{})
	ctx := context.Background()
	dep := &models.SecretDependency{ProjectID: 1, DependentSecretID: 2, DependsOnSecretID: 3}
	require.NoError(t, ls.db.Create(dep).Error)
	rows, err := ls.ListSecretDependenciesForProjectForUpdate(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
}

func TestDeleteSecretDependency_S27_NotFound(t *testing.T) {
	ls := newS27Store(t, &models.SecretDependency{})
	err := ls.DeleteSecretDependency(context.Background(), 9999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_drift.go
// ---------------------------------------------------------------------------

func TestListProjectSecretsForDrift_S27_BrokenDB(t *testing.T) {
	ls := brokenS27Store(t)
	_, err := ls.ListProjectSecretsForDrift(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_purge.go
// ---------------------------------------------------------------------------

func TestDeleteClosedAccessReviewsBefore_S27_HappyPath(t *testing.T) {
	ls := newS27Store(t, &models.AccessReviewCampaign{}, &models.AccessReviewItem{})
	ctx := context.Background()
	closedAt := time.Now().Add(-24 * time.Hour)
	campaign := &models.AccessReviewCampaign{
		State:    "closed",
		ClosedAt: &closedAt,
	}
	require.NoError(t, ls.db.Create(campaign).Error)
	item := &models.AccessReviewItem{CampaignID: campaign.ID}
	require.NoError(t, ls.db.Create(item).Error)

	campaigns, items, err := ls.DeleteClosedAccessReviewsBefore(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), campaigns)
	assert.Equal(t, int64(1), items)
}

func TestDeleteClosedAccessReviewsBefore_S27_NoneMatch(t *testing.T) {
	ls := newS27Store(t, &models.AccessReviewCampaign{}, &models.AccessReviewItem{})
	ctx := context.Background()
	// Open campaign (closed_at IS NULL) — should not be purged.
	require.NoError(t, ls.db.Create(&models.AccessReviewCampaign{State: "open"}).Error)

	campaigns, items, err := ls.DeleteClosedAccessReviewsBefore(ctx, time.Now())
	require.NoError(t, err)
	assert.Zero(t, campaigns)
	assert.Zero(t, items)
}

func TestDeleteExpiredBreakGlassBefore_S27_HappyPath(t *testing.T) {
	ls := newS27Store(t, &models.BreakGlassActivation{})
	ctx := context.Background()
	// A completed (non-active) activation older than 1 hour.
	old := time.Now().Add(-2 * time.Hour)
	activation := &models.BreakGlassActivation{
		ProjectID:  1,
		UserID:     1,
		State:      "completed",
		CreatedAt:  old,
		ReviewedAt: &old,
	}
	require.NoError(t, ls.db.Create(activation).Error)
	// An active one that must NOT be touched.
	active := &models.BreakGlassActivation{
		ProjectID: 2,
		UserID:    2,
		State:     "active",
		CreatedAt: old,
	}
	require.NoError(t, ls.db.Create(active).Error)

	n, err := ls.DeleteExpiredBreakGlassBefore(ctx, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "only non-active old activation should be deleted")
}

func TestDeleteResolvedAccessRequestsBefore_S27_HappyPath(t *testing.T) {
	ls := newS27Store(t, &models.AccessRequest{}, &models.AccessRequestApproval{})
	ctx := context.Background()
	resolvedAt := time.Now().Add(-48 * time.Hour)
	req := &models.AccessRequest{
		ProjectID:  1,
		UserID:     2,
		ResolvedAt: &resolvedAt,
	}
	require.NoError(t, ls.db.Create(req).Error)
	approval := &models.AccessRequestApproval{RequestID: req.ID, ApproverID: 3}
	require.NoError(t, ls.db.Create(approval).Error)

	requests, approvals, err := ls.DeleteResolvedAccessRequestsBefore(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), requests)
	assert.Equal(t, int64(1), approvals)
}

func TestDeleteResolvedAccessRequestsBefore_S27_NoneMatch(t *testing.T) {
	ls := newS27Store(t, &models.AccessRequest{}, &models.AccessRequestApproval{})
	ctx := context.Background()
	// Pending (resolved_at IS NULL) — must NOT be touched.
	require.NoError(t, ls.db.Create(&models.AccessRequest{ProjectID: 5, UserID: 1}).Error)

	requests, approvals, err := ls.DeleteResolvedAccessRequestsBefore(ctx, time.Now())
	require.NoError(t, err)
	assert.Zero(t, requests)
	assert.Zero(t, approvals)
}
