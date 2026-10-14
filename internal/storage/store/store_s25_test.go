// store_s25_test.go — s25 coverage blitz for internal/storage/store.
//
// Targets (local_*.go functions with ≤85% coverage in the full CI run):
//
//	local_auth.go
//	  ListSessionTokenHashesByFamily — error path
//	  DeleteSessionsByFamily         — empty-familyID no-op + error path
//	  ListSessionsByUser             — error path
//	  DeleteSession                  — happy path (no-op on missing ID) + error path
//	  EnforceSessionLimit            — keep≤0 no-op, under-cap no-op, error path
//	  DeleteSessionsForUserExcept    — error path
//	  ListSessionTokenHashesForUser  — error path
//	  ListPersonalAccessTokensByUser — error path
//	  ListActivePersonalAccessTokens — error path
//	  RevokePersonalAccessToken      — not-found + error path
//	  RevokeAllPersonalAccessTokensForUser — none-exist + error path
//	  MarkSetupTokenConsumed         — already-consumed + error path
//	  CountSetupTokensSince          — error path
//
//	local_notifications.go
//	  HasUnreadNotification       — error path
//	  GetUnreadNotification       — not-found nil-nil + error path
//	  UpdateNotification          — not-found error + error path
//	  CountUnreadNotifications    — error path
//	  MarkNotificationRead        — not-found error + error path
//	  ListNotifications           — unreadOnly=true branch + error path
//
//	local_connect_ref_grants.go
//	  ListConnectRefGrantsByConnector — error path
//	  ListConnectRefGrants            — error path
//
//	local_invitations.go
//	  UpdateProjectInvitation     — zero-rows (false) + error path
//	  ListProjectInvitations      — error path
//	  UpdateAccessRequest         — zero-rows (false) + error path
//	  ListAccessRequests          — error path
//	  ListAccessRequestApprovals  — error path
//
//	local_dynamic.go
//	  ListDynamicSecretConfigs    — environmentID filter branch + error path
//	  ListDynamicSecretLeases     — error path
//	  ListExpiredActiveLeases     — error path
//
//	local_memberships.go
//	  ListProjectMemberships      — error path
//	  ListStaleInvitedMemberships — error path
//	  ListUserProjectMemberships  — error path
//
//	local_machine_credentials.go
//	  ListMachineIdentityCredentials       — error path
//	  ListActiveMachineIdentityCredentials — error path
//	  RevokeMachineIdentityCredential      — not-found + error path
//	  AssignMachineRole                    — error path
//	  RemoveMachineRole                    — not-found + error path
//	  ListOIDCBindings                     — error path
//	  DeleteOIDCBinding                    — not-found + error path
package store

import (
	"context"
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

// newS25Store opens a fresh in-memory SQLite DB, runs AutoMigrate on the
// supplied model types, and returns the LocalStorage. Using a "_s25" DSN
// suffix prevents collisions with other sweeps' test-name-keyed DSNs.
func newS25Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores25_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_auth.go — ListSessionTokenHashesByFamily error path
// ---------------------------------------------------------------------------

func TestListSessionTokenHashesByFamily_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListSessionTokenHashesByFamily(context.Background(), "fam-x")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — DeleteSessionsByFamily: empty no-op + error path
// ---------------------------------------------------------------------------

// TestDeleteSessionsByFamily_S25_EmptyFamilyNoop verifies the early-return
// guard: an empty familyID must return nil without touching the DB.
func TestDeleteSessionsByFamily_S25_EmptyFamilyNoop(t *testing.T) {
	ls := newBrokenDB(t) // broken DB — would error if the DB were touched
	err := ls.DeleteSessionsByFamily(context.Background(), "")
	require.NoError(t, err, "empty familyID must be a no-op, not a DB error")
}

func TestDeleteSessionsByFamily_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteSessionsByFamily(context.Background(), "some-family")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — ListSessionsByUser error path
// ---------------------------------------------------------------------------

func TestListSessionsByUser_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListSessionsByUser(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — DeleteSession: happy path + error path
// ---------------------------------------------------------------------------

// TestDeleteSession_S25_HappyPath verifies DeleteSession on a missing ID
// succeeds (GORM Delete with a model that has no DeletedAt is a no-error
// hard-delete returning RowsAffected 0, not an error).
func TestDeleteSession_S25_HappyPath(t *testing.T) {
	ls := newS25Store(t, &models.Session{})
	require.NoError(t, ls.DeleteSession(context.Background(), 999))
}

func TestDeleteSession_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteSession(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — EnforceSessionLimit
// ---------------------------------------------------------------------------

// TestEnforceSessionLimit_S25_ZeroKeepNoop verifies keep ≤ 0 early-return.
func TestEnforceSessionLimit_S25_ZeroKeepNoop(t *testing.T) {
	ls := newBrokenDB(t) // broken DB — must not be touched
	require.NoError(t, ls.EnforceSessionLimit(context.Background(), 1, 0))
	require.NoError(t, ls.EnforceSessionLimit(context.Background(), 1, -1))
}

// TestEnforceSessionLimit_S25_BrokenDB exercises the first DB call error path.
func TestEnforceSessionLimit_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.EnforceSessionLimit(context.Background(), 1, 3)
	require.Error(t, err)
}

// TestEnforceSessionLimit_S25_UnderCapIsNoop verifies that when the user has
// fewer sessions than keep, the prune DELETE is skipped without error.
func TestEnforceSessionLimit_S25_UnderCapIsNoop(t *testing.T) {
	ls := newS25Store(t, &models.Session{})
	ctx := context.Background()

	// Insert 2 sessions for user 1.
	for i := range 2 {
		require.NoError(t, ls.db.Create(&models.Session{
			UserID:       1,
			SessionToken: "tok" + string(rune('a'+i)),
			FamilyID:     "f1",
		}).Error)
	}

	// keep=10 is above the session count — must be a no-op.
	require.NoError(t, ls.EnforceSessionLimit(ctx, 1, 10))
}

// ---------------------------------------------------------------------------
// local_auth.go — DeleteSessionsForUserExcept error path
// ---------------------------------------------------------------------------

func TestDeleteSessionsForUserExcept_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteSessionsForUserExcept(context.Background(), 1, 2)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — ListSessionTokenHashesForUser error path
// ---------------------------------------------------------------------------

func TestListSessionTokenHashesForUser_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListSessionTokenHashesForUser(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — ListPersonalAccessTokensByUser error path
// ---------------------------------------------------------------------------

func TestListPersonalAccessTokensByUser_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListPersonalAccessTokensByUser(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — ListActivePersonalAccessTokens error path
// ---------------------------------------------------------------------------

func TestListActivePersonalAccessTokens_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListActivePersonalAccessTokens(context.Background())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — RevokePersonalAccessToken
// ---------------------------------------------------------------------------

// TestRevokePersonalAccessToken_S25_NotFound verifies the RowsAffected == 0
// branch: revoking a non-existent PAT must return a "not found" error.
func TestRevokePersonalAccessToken_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.PersonalAccessToken{})
	err := ls.RevokePersonalAccessToken(context.Background(), 9999)
	require.Error(t, err, "revoking a non-existent PAT must return an error")
}

func TestRevokePersonalAccessToken_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.RevokePersonalAccessToken(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — RevokeAllPersonalAccessTokensForUser
// ---------------------------------------------------------------------------

// TestRevokeAllPersonalAccessTokensForUser_S25_NoneExist verifies the
// "no active PATs" early-return path: must return (nil, nil).
func TestRevokeAllPersonalAccessTokensForUser_S25_NoneExist(t *testing.T) {
	ls := newS25Store(t, &models.PersonalAccessToken{})
	hashes, err := ls.RevokeAllPersonalAccessTokensForUser(context.Background(), 42)
	require.NoError(t, err)
	assert.Nil(t, hashes, "no active PATs should return nil slice, not an error")
}

func TestRevokeAllPersonalAccessTokensForUser_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.RevokeAllPersonalAccessTokensForUser(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — MarkSetupTokenConsumed
// ---------------------------------------------------------------------------

// TestMarkSetupTokenConsumed_S25_NoActiveRowReturnsFalse verifies the
// RowsAffected == 0 path: a non-active (or non-existent) token returns
// (false, nil).
func TestMarkSetupTokenConsumed_S25_NoActiveRowReturnsFalse(t *testing.T) {
	ls := newS25Store(t, &models.SetupToken{})
	consumed, err := ls.MarkSetupTokenConsumed(context.Background(), 9999, time.Now())
	require.NoError(t, err)
	assert.False(t, consumed, "a non-existent token must return false without error")
}

func TestMarkSetupTokenConsumed_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.MarkSetupTokenConsumed(context.Background(), 1, time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_auth.go — CountSetupTokensSince error path
// ---------------------------------------------------------------------------

func TestCountSetupTokensSince_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CountSetupTokensSince(context.Background(), "invite", "a@b.com", time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_notifications.go — HasUnreadNotification error path
// ---------------------------------------------------------------------------

func TestHasUnreadNotification_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.HasUnreadNotification(context.Background(), 1, "rotation.reminder", 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_notifications.go — GetUnreadNotification
// ---------------------------------------------------------------------------

// TestGetUnreadNotification_S25_NotFoundReturnsNil verifies the
// ErrRecordNotFound branch returns (nil, nil).
func TestGetUnreadNotification_S25_NotFoundReturnsNil(t *testing.T) {
	ls := newS25Store(t, &models.Notification{})
	n, err := ls.GetUnreadNotification(context.Background(), 99, "info", 1)
	require.NoError(t, err)
	assert.Nil(t, n, "a missing unread notification must return (nil, nil)")
}

func TestGetUnreadNotification_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetUnreadNotification(context.Background(), 1, "info", 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_notifications.go — UpdateNotification
// ---------------------------------------------------------------------------

// TestUpdateNotification_S25_NotFound verifies the RowsAffected == 0 branch:
// updating a notification for a wrong user/id must return a "not found" error.
func TestUpdateNotification_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.Notification{})
	err := ls.UpdateNotification(context.Background(), &models.Notification{
		ID:     9999,
		UserID: 1,
		Title:  "New title",
	})
	require.Error(t, err, "updating a non-existent notification must return an error")
}

func TestUpdateNotification_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.UpdateNotification(context.Background(), &models.Notification{
		ID: 1, UserID: 1, Title: "t",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_notifications.go — CountUnreadNotifications error path
// ---------------------------------------------------------------------------

func TestCountUnreadNotifications_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CountUnreadNotifications(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_notifications.go — MarkNotificationRead
// ---------------------------------------------------------------------------

// TestMarkNotificationRead_S25_NotFound verifies the RowsAffected == 0 branch.
func TestMarkNotificationRead_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.Notification{})
	err := ls.MarkNotificationRead(context.Background(), 9999, 1)
	require.Error(t, err, "marking a non-existent notification read must return an error")
}

func TestMarkNotificationRead_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.MarkNotificationRead(context.Background(), 1, 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_notifications.go — ListNotifications: unreadOnly branch + error path
// ---------------------------------------------------------------------------

// TestListNotifications_S25_UnreadOnlyFilter verifies that unreadOnly=true adds
// the is_read=false WHERE clause (exercises the unreadOnly branch).
func TestListNotifications_S25_UnreadOnlyFilter(t *testing.T) {
	ls := newS25Store(t, &models.Notification{})
	ctx := context.Background()
	pid := uint(1)

	// Insert one read and one unread notification for user 5.
	n1, err := ls.CreateNotification(ctx, &models.Notification{
		UserID: 5, ProjectID: &pid, Type: "info", Title: "read-me", Message: "x",
	})
	require.NoError(t, err)
	require.NoError(t, ls.MarkNotificationRead(ctx, n1.ID, 5))

	_, err = ls.CreateNotification(ctx, &models.Notification{
		UserID: 5, ProjectID: &pid, Type: "info", Title: "unread-me", Message: "y",
	})
	require.NoError(t, err)

	rows, err := ls.ListNotifications(ctx, 5, true, 10)
	require.NoError(t, err)
	assert.Len(t, rows, 1, "unreadOnly=true must return only unread notifications")
	assert.Equal(t, "unread-me", rows[0].Title)
}

func TestListNotifications_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListNotifications(context.Background(), 1, false, 10)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_connect_ref_grants.go — error paths
// ---------------------------------------------------------------------------

func TestListConnectRefGrantsByConnector_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListConnectRefGrantsByConnector(context.Background(), "pg-connector")
	require.Error(t, err)
}

func TestListConnectRefGrants_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListConnectRefGrants(context.Background())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_invitations.go — UpdateProjectInvitation
// ---------------------------------------------------------------------------

// TestUpdateProjectInvitation_S25_NoMatchReturnsFalse verifies the
// RowsAffected == 0 path when no "pending" row matches.
func TestUpdateProjectInvitation_S25_NoMatchReturnsFalse(t *testing.T) {
	ls := newS25Store(t, &models.ProjectInvitation{})
	updated, err := ls.UpdateProjectInvitation(context.Background(),
		&models.ProjectInvitation{ID: 9999})
	require.NoError(t, err)
	assert.False(t, updated)
}

func TestUpdateProjectInvitation_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.UpdateProjectInvitation(context.Background(),
		&models.ProjectInvitation{ID: 1})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_invitations.go — ListProjectInvitations error path
// ---------------------------------------------------------------------------

func TestListProjectInvitations_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListProjectInvitations(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_invitations.go — UpdateAccessRequest
// ---------------------------------------------------------------------------

// TestUpdateAccessRequest_S25_NoMatchReturnsFalse verifies RowsAffected == 0.
func TestUpdateAccessRequest_S25_NoMatchReturnsFalse(t *testing.T) {
	ls := newS25Store(t, &models.AccessRequest{})
	updated, err := ls.UpdateAccessRequest(context.Background(),
		&models.AccessRequest{ID: 9999})
	require.NoError(t, err)
	assert.False(t, updated)
}

func TestUpdateAccessRequest_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.UpdateAccessRequest(context.Background(),
		&models.AccessRequest{ID: 1})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_invitations.go — ListAccessRequests error path
// ---------------------------------------------------------------------------

func TestListAccessRequests_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListAccessRequests(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_invitations.go — ListAccessRequestApprovals error path
// ---------------------------------------------------------------------------

func TestListAccessRequestApprovals_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListAccessRequestApprovals(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_dynamic.go — ListDynamicSecretConfigs
// ---------------------------------------------------------------------------

// TestListDynamicSecretConfigs_S25_WithEnvironmentFilter verifies the
// environmentID != 0 branch adds the WHERE clause without error.
func TestListDynamicSecretConfigs_S25_WithEnvironmentFilter(t *testing.T) {
	ls := newS25Store(t, &models.DynamicSecretConfig{})
	rows, err := ls.ListDynamicSecretConfigs(context.Background(), 1, 2)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestListDynamicSecretConfigs_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListDynamicSecretConfigs(context.Background(), 1, 0)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_dynamic.go — ListDynamicSecretLeases error path
// ---------------------------------------------------------------------------

func TestListDynamicSecretLeases_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListDynamicSecretLeases(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_dynamic.go — ListExpiredActiveLeases error path
// ---------------------------------------------------------------------------

func TestListExpiredActiveLeases_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListExpiredActiveLeases(context.Background(), time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_memberships.go — error paths
// ---------------------------------------------------------------------------

func TestListProjectMemberships_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListProjectMemberships(context.Background(), 1)
	require.Error(t, err)
}

func TestListStaleInvitedMemberships_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListStaleInvitedMemberships(context.Background(), time.Now())
	require.Error(t, err)
}

func TestListUserProjectMemberships_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListUserProjectMemberships(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — ListMachineIdentityCredentials error path
// ---------------------------------------------------------------------------

func TestListMachineIdentityCredentials_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListMachineIdentityCredentials(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — ListActiveMachineIdentityCredentials error path
// ---------------------------------------------------------------------------

func TestListActiveMachineIdentityCredentials_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListActiveMachineIdentityCredentials(context.Background())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — RevokeMachineIdentityCredential
// ---------------------------------------------------------------------------

// TestRevokeMachineIdentityCredential_S25_NotFound verifies the
// RowsAffected == 0 branch: revoking a non-existent credential returns an error.
func TestRevokeMachineIdentityCredential_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.MachineIdentity{}, &models.MachineIdentityCredential{})
	err := ls.RevokeMachineIdentityCredential(context.Background(), 1, 9999)
	require.Error(t, err, "revoking a non-existent credential must return an error")
}

func TestRevokeMachineIdentityCredential_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.RevokeMachineIdentityCredential(context.Background(), 1, 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — AssignMachineRole error path
// ---------------------------------------------------------------------------

// TestAssignMachineRole_S25_BrokenDB exercises the first DB call error in
// AssignMachineRole (the First that checks for an existing grant).
func TestAssignMachineRole_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.AssignMachineRole(context.Background(), 1, 2,
		storage.Scope{ProjectID: 1, EnvironmentID: 0})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — RemoveMachineRole
// ---------------------------------------------------------------------------

// TestRemoveMachineRole_S25_NotFound verifies the RowsAffected == 0 branch:
// removing a non-existent machine role grant must return an error.
func TestRemoveMachineRole_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.MachineIdentityRole{})
	err := ls.RemoveMachineRole(context.Background(), 1, 99,
		storage.Scope{ProjectID: 1})
	require.Error(t, err, "removing a non-existent machine role must return an error")
}

func TestRemoveMachineRole_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.RemoveMachineRole(context.Background(), 1, 2, storage.Scope{ProjectID: 1})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — ListOIDCBindings error path
// ---------------------------------------------------------------------------

func TestListOIDCBindings_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListOIDCBindings(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials.go — DeleteOIDCBinding
// ---------------------------------------------------------------------------

// TestDeleteOIDCBinding_S25_NotFound verifies the RowsAffected == 0 branch:
// deleting a non-existent OIDC binding must return a "not found" error.
func TestDeleteOIDCBinding_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.MachineIdentityOIDCBinding{})
	err := ls.DeleteOIDCBinding(context.Background(), 9999)
	require.Error(t, err, "deleting a non-existent OIDC binding must return an error")
}

func TestDeleteOIDCBinding_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteOIDCBinding(context.Background(), 1)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_login_attempts.go — CountRecentLoginAttempts error path
// ---------------------------------------------------------------------------

func TestCountRecentLoginAttempts_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.CountRecentLoginAttempts(context.Background(), "1.2.3.4", time.Now())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_mfa.go — MarkTOTPStepUsed, DeleteMFAForUser, ConsumeMFARecoveryCode
// ---------------------------------------------------------------------------

func TestMarkTOTPStepUsed_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.MarkTOTPStepUsed(context.Background(), 1, 12345)
	require.Error(t, err)
}

// TestMarkTOTPStepUsed_S25_ZeroRowsReturnsFalse verifies the RowsAffected == 0
// branch: when the step is not newer than the stored step, returns (false, nil).
func TestMarkTOTPStepUsed_S25_ZeroRowsReturnsFalse(t *testing.T) {
	ls := newS25Store(t, &models.MFASecret{})
	// No row for userID 9999 → RowsAffected == 0 → (false, nil).
	advanced, err := ls.MarkTOTPStepUsed(context.Background(), 9999, 100)
	require.NoError(t, err)
	assert.False(t, advanced, "no matching row must return false without error")
}

func TestDeleteMFAForUser_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.DeleteMFAForUser(context.Background(), 1)
	require.Error(t, err)
}

func TestConsumeMFARecoveryCode_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ConsumeMFARecoveryCode(context.Background(), 1, "hash", time.Now())
	require.Error(t, err)
}

// TestConsumeMFARecoveryCode_S25_ZeroRowsReturnsFalse verifies that when no
// unused matching code is found, returns (false, nil).
func TestConsumeMFARecoveryCode_S25_ZeroRowsReturnsFalse(t *testing.T) {
	ls := newS25Store(t, &models.MFARecoveryCode{})
	consumed, err := ls.ConsumeMFARecoveryCode(context.Background(), 1, "nonexistent", time.Now())
	require.NoError(t, err)
	assert.False(t, consumed)
}

// ---------------------------------------------------------------------------
// local_machine_identities.go — TransitionMachineIdentityState, List functions
// ---------------------------------------------------------------------------

// TestTransitionMachineIdentityState_S25_BrokenDB exercises the DB-error path.
func TestTransitionMachineIdentityState_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.TransitionMachineIdentityState(context.Background(),
		&models.MachineIdentity{ID: 1}, "active")
	require.Error(t, err)
}

// TestTransitionMachineIdentityState_S25_NoMatchReturnsFalse verifies the
// RowsAffected == 0 path when no row matches the fromState.
func TestTransitionMachineIdentityState_S25_NoMatchReturnsFalse(t *testing.T) {
	ls := newS25Store(t, &models.MachineIdentity{})
	updated, err := ls.TransitionMachineIdentityState(context.Background(),
		&models.MachineIdentity{ID: 9999}, "active")
	require.NoError(t, err)
	assert.False(t, updated)
}

func TestListMachineIdentities_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListMachineIdentities(context.Background(), 1)
	require.Error(t, err)
}

func TestListAllMachineIdentities_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListAllMachineIdentities(context.Background())
	require.Error(t, err)
}

// TestTransitionDynamicSecretConfigDisabled_S25_BrokenDB exercises the DB-error
// path (StateTransitionMissingCAS fix), mirroring
// TestTransitionMachineIdentityState_S25_BrokenDB above.
func TestTransitionDynamicSecretConfigDisabled_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.TransitionDynamicSecretConfigDisabled(context.Background(),
		&models.DynamicSecretConfig{ID: 1, Disabled: true}, false)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rbac.go — error paths for simple functions
// ---------------------------------------------------------------------------

func TestListRoles_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListRoles(context.Background())
	require.Error(t, err)
}

func TestAssignPermissionToRole_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.AssignPermissionToRole(context.Background(), 1, 2)
	require.Error(t, err)
}

func TestListPermissions_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.ListPermissions(context.Background())
	require.Error(t, err)
}

// TestRemovePermissionFromRole_S25_NotFound verifies the RowsAffected == 0 branch.
func TestRemovePermissionFromRole_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.RolePermission{})
	err := ls.RemovePermissionFromRole(context.Background(), 1, 99)
	require.Error(t, err, "removing a non-existent permission from role must return an error")
}

func TestRemovePermissionFromRole_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.RemovePermissionFromRole(context.Background(), 1, 2)
	require.Error(t, err)
}

func TestRemoveAllProjectRoleGrants_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	err := ls.RemoveAllProjectRoleGrants(context.Background(), 1, 2)
	require.Error(t, err)
}

// TestGetRole_S25_BrokenDB exercises the non-RecordNotFound error branch in
// GetRole (the broken DB returns a generic table-absent error, not ErrRecordNotFound).
func TestGetRole_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetRole(context.Background(), 1)
	require.Error(t, err)
}

// TestGetRoleByName_S25_BrokenDB exercises the non-RecordNotFound error branch.
func TestGetRoleByName_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetRoleByName(context.Background(), "admin")
	require.Error(t, err)
}

// TestDeleteRole_S25_NotFound verifies the RowsAffected == 0 branch.
func TestDeleteRole_S25_NotFound(t *testing.T) {
	ls := newS25Store(t, &models.Role{})
	_, err := ls.DeleteRole(context.Background(), 9999)
	require.Error(t, err, "deleting a non-existent role must return an error")
}

func TestDeleteRole_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.DeleteRole(context.Background(), 1)
	require.Error(t, err)
}

func TestGetUserRoles_S25_BrokenDB(t *testing.T) {
	ls := newBrokenDB(t)
	_, err := ls.GetUserRoles(context.Background(), 1)
	require.Error(t, err)
}
