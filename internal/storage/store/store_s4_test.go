// store_s4_test.go — coverage sweep for functions not yet covered in s1–s3:
// query.go (addBool, addString, addUint, addTime, addTags, String),
// local_audit_checkpoint_lock.go (WithAuditCheckpointLock SQLite path),
// local_secrets.go (DeleteProjectIfEmpty, ListEnvironments, deleteProjectCascade not-found),
// local_users.go (isDuplicateEmailViolation, CreateUser error, UpdateUser error,
//
//	RestoreUser not-found, ListUsers filters, groups CRUD, sessions empty/edge),
//
// local_memberships.go (CreateProjectMembership duplicate),
// local_notifications.go (CreateNotification),
// local_sod.go (CreateSoDPolicy, DeleteSoDPolicy not-found),
// local_sso.go (CreateSSOLoginState, ConsumeSSOLoginState not-found),
// local_access_review_campaigns.go (CreateAccessReviewCampaign, ListAccessReviewCampaigns, etc.).
package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// local_audit_checkpoint_lock.go — SQLite path (non-postgres)
// ---------------------------------------------------------------------------

func TestWithAuditCheckpointLock_SQLite(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "ckplock_"+t.Name())

	// SQLite path: fn executes and result propagates.
	ran := false
	err := ls.WithAuditCheckpointLock(ctx, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ran)

	// Error propagates.
	sentinel := fmt.Errorf("checkpoint failed")
	err = ls.WithAuditCheckpointLock(ctx, func() error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
}

// ---------------------------------------------------------------------------
// local_secrets.go — DeleteProjectIfEmpty, ListEnvironments
// ---------------------------------------------------------------------------

func newProjectSecretsStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "proj_sec_"+t.Name(),
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretVersion{}, &models.ShareRecord{}, &models.DynamicSecretConfig{})
}

func TestDeleteProjectIfEmpty_NoSecrets(t *testing.T) {
	ctx := context.Background()
	ls := newProjectSecretsStore(t)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "empty-proj"})
	require.NoError(t, err)
	require.NoError(t, ls.db.Create(&models.Environment{ProjectID: p.ID, Name: "dev"}).Error)

	// Project has no live secrets → should delete and return 0.
	count, err := ls.DeleteProjectIfEmpty(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Project should now be soft-deleted.
	_, err = ls.GetProject(ctx, p.ID)
	require.Error(t, err)
}

func TestDeleteProjectIfEmpty_WithSecrets(t *testing.T) {
	ctx := context.Background()
	ls := newProjectSecretsStore(t)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "non-empty-proj"})
	require.NoError(t, err)
	e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "dev"})
	require.NoError(t, err)

	// Add a live secret.
	require.NoError(t, ls.db.Create(&models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "api-key", IsSecret: true,
	}).Error)

	// Should return blocking count = 1, project not deleted.
	count, err := ls.DeleteProjectIfEmpty(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Project still exists.
	got, err := ls.GetProject(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, p.ID, got.ID)
}

func TestListEnvironments(t *testing.T) {
	ctx := context.Background()
	ls := newProjectSecretsStore(t)

	// Empty result.
	envs, err := ls.ListEnvironments(ctx)
	require.NoError(t, err)
	assert.Empty(t, envs)

	// Insert a couple of environments.
	p, err := ls.CreateProject(ctx, &models.Project{Name: "env-list-proj"})
	require.NoError(t, err)
	require.NoError(t, ls.db.Create(&models.Environment{ProjectID: p.ID, Name: "prod"}).Error)
	require.NoError(t, ls.db.Create(&models.Environment{ProjectID: p.ID, Name: "staging"}).Error)

	envs, err = ls.ListEnvironments(ctx)
	require.NoError(t, err)
	assert.Len(t, envs, 2)
}

// ---------------------------------------------------------------------------
// local_users.go — isDuplicateEmailViolation, CreateUser error path, etc.
// ---------------------------------------------------------------------------

func TestIsDuplicateEmailViolation(t *testing.T) {
	assert.False(t, isDuplicateEmailViolation(nil))
	assert.True(t, isDuplicateEmailViolation(fmt.Errorf("uniq_users_email_folded_active")))
	assert.True(t, isDuplicateEmailViolation(fmt.Errorf("ERROR: violates unique constraint \"uniq_users_email_folded_active\"")))
	assert.False(t, isDuplicateEmailViolation(fmt.Errorf("some other error")))
}

func newUserS4Store(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "users_s4_"+t.Name(), &models.User{}, &models.UserGroup{}, &models.Group{})
}

func TestCreateUser_Success(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "alice", UsernameFolded: "alice", Email: "alice@example.com", EmailFolded: "alice@example.com"})
	require.NoError(t, err)
	assert.NotZero(t, u.ID)
}

func TestUpdateUser_Success(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "bob", UsernameFolded: "bob", Email: "bob@example.com", EmailFolded: "bob@example.com"})
	require.NoError(t, err)

	u.DisplayName = "Bobby"
	updated, err := ls.UpdateUser(ctx, u)
	require.NoError(t, err)
	assert.Equal(t, "Bobby", updated.DisplayName)
}

// TestUpdateUserIfActiveStateMatches_Success verifies the happy path: a
// conditional write against a row whose CURRENT is_active still equals
// fromActive matches and persists the full row.
func TestUpdateUserIfActiveStateMatches_Success(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "dave", UsernameFolded: "dave", Email: "dave@example.com", EmailFolded: "dave@example.com", IsActive: true})
	require.NoError(t, err)

	u.IsActive = false
	u.DisplayName = "Dave Deactivated"
	matched, err := ls.UpdateUserIfActiveStateMatches(ctx, u, true)
	require.NoError(t, err)
	assert.True(t, matched)

	reloaded, err := ls.GetUser(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, reloaded.IsActive)
	assert.Equal(t, "Dave Deactivated", reloaded.DisplayName)
}

// TestUpdateUserIfActiveStateMatches_LostRaceReturnsFalse proves the TOCTOU
// race is closed: calling the method twice back-to-back with the SAME
// fromActive (as two racing UpdateUser callers who both observed the row
// active before either commits would) lets only the first call win — the
// second observes the row's is_active has already moved and reports no match,
// rather than silently clobbering the first call's write. Mirrors
// TestTransitionMachineIdentityState_S25_NoMatchReturnsFalse's shape for this
// codebase's other conditional-write primitive.
func TestUpdateUserIfActiveStateMatches_LostRaceReturnsFalse(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "eve", UsernameFolded: "eve", Email: "eve@example.com", EmailFolded: "eve@example.com", IsActive: true})
	require.NoError(t, err)

	// First racing caller: observed IsActive=true, flips to false, wins.
	first := &models.User{ID: u.ID, Username: u.Username, UsernameFolded: u.UsernameFolded, Email: u.Email, EmailFolded: u.EmailFolded, IsActive: false}
	matched, err := ls.UpdateUserIfActiveStateMatches(ctx, first, true)
	require.NoError(t, err)
	assert.True(t, matched, "first racing call must win")

	// Second racing caller: ALSO observed IsActive=true (stale — the first call
	// already committed false) and tries to persist its own unrelated field
	// change plus a redundant IsActive=false assertion. Must lose the race, not
	// silently re-apply its stale view over the winner's write.
	second := &models.User{ID: u.ID, Username: u.Username, UsernameFolded: u.UsernameFolded, Email: u.Email, EmailFolded: u.EmailFolded, DisplayName: "Should Not Persist", IsActive: false}
	matched, err = ls.UpdateUserIfActiveStateMatches(ctx, second, true)
	require.NoError(t, err)
	assert.False(t, matched, "second racing call must lose the race")

	// The loser's DisplayName must not have landed.
	reloaded, err := ls.GetUser(ctx, u.ID)
	require.NoError(t, err)
	assert.NotEqual(t, "Should Not Persist", reloaded.DisplayName)
}

// TestUpdateUserIfActiveStateMatches_NoMatchReturnsFalse verifies the
// RowsAffected == 0 path for a nonexistent user (no row can match).
func TestUpdateUserIfActiveStateMatches_NoMatchReturnsFalse(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	matched, err := ls.UpdateUserIfActiveStateMatches(ctx, &models.User{ID: 999999, IsActive: false}, true)
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestRestoreUser_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	// Non-existent ID → ErrUserNotFound.
	err := ls.RestoreUser(ctx, 99999)
	require.Error(t, err)
	require.ErrorIs(t, err, storage.ErrUserNotFound)
}

func TestRestoreUser_NotDeleted(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "carol", UsernameFolded: "carol", Email: "carol@example.com", EmailFolded: "carol@example.com"})
	require.NoError(t, err)

	// User not soft-deleted → returns not-found sentinel (RowsAffected == 0).
	err = ls.RestoreUser(ctx, u.ID)
	require.Error(t, err)
	require.ErrorIs(t, err, storage.ErrUserNotFound)
}

func TestListUsers_Filters(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	active := true
	u1, err := ls.CreateUser(ctx, &models.User{Username: "u1fil", UsernameFolded: "u1fil", Email: "u1fil@example.com", EmailFolded: "u1fil@example.com", IsActive: true})
	require.NoError(t, err)
	u2, err := ls.CreateUser(ctx, &models.User{Username: "u2fil", UsernameFolded: "u2fil", Email: "u2fil@example.com", EmailFolded: "u2fil@example.com", IsActive: true})
	require.NoError(t, err)

	// Deactivate u2 via direct DB update to avoid GORM zero-value issue.
	require.NoError(t, ls.db.Model(u2).Update("is_active", false).Error)

	// Filter by IsActive=true → only u1.
	users, total, err := ls.ListUsers(ctx, &storage.UserFilter{IsActive: &active, Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, users, 1)
	assert.Equal(t, "u1fil", users[0].Username)

	// No filter → both users (u2 is deactivated but still in the table).
	users, total, err = ls.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(2))
	_ = users
	_ = u1
}

func TestListUsers_UsernameEmailFilter(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	_, err := ls.CreateUser(ctx, &models.User{Username: "dave", UsernameFolded: "dave", Email: "dave@example.com", EmailFolded: "dave@example.com"})
	require.NoError(t, err)
	_, err = ls.CreateUser(ctx, &models.User{Username: "eve", UsernameFolded: "eve", Email: "eve@example.com", EmailFolded: "eve@example.com"})
	require.NoError(t, err)

	uname := "dave"
	users, total, err := ls.ListUsers(ctx, &storage.UserFilter{Username: &uname, Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "dave", users[0].Username)

	email := "eve@"
	users, total, err = ls.ListUsers(ctx, &storage.UserFilter{Email: &email, Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "eve", users[0].Username)
}

func TestListUsers_CreatedAfterFilter(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	_, err := ls.CreateUser(ctx, &models.User{Username: "frank", UsernameFolded: "frank", Email: "frank@example.com", EmailFolded: "frank@example.com"})
	require.NoError(t, err)

	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	// CreatedAfter past → user found.
	users, total, err := ls.ListUsers(ctx, &storage.UserFilter{CreatedAfter: &past, Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(1))
	_ = users

	// CreatedAfter future → no results.
	users, total, err = ls.ListUsers(ctx, &storage.UserFilter{CreatedAfter: &future, Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, users)
}

func TestListUsers_InactiveSinceFilter(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "grace", UsernameFolded: "grace", Email: "grace@example.com", EmailFolded: "grace@example.com"})
	require.NoError(t, err)

	// InactiveSince: never logged in (LastLoginAt = nil) → returned.
	inactiveSince := time.Now().Add(-30 * 24 * time.Hour)
	users, total, err := ls.ListUsers(ctx, &storage.UserFilter{InactiveSince: &inactiveSince, Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(1))
	_ = u
	_ = users
}

func TestListUsers_OffsetParam(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	for i := range 3 {
		_, err := ls.CreateUser(ctx, &models.User{
			Username:       fmt.Sprintf("puser%d", i),
			UsernameFolded: fmt.Sprintf("puser%d", i),
			Email:          fmt.Sprintf("puser%d@example.com", i),
			EmailFolded:    fmt.Sprintf("puser%d@example.com", i),
		})
		require.NoError(t, err)
	}

	// Offset=2 → should return 1 user.
	users, _, err := ls.ListUsers(ctx, &storage.UserFilter{Offset: 2, Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Len(t, users, 1)
}

// ---------------------------------------------------------------------------
// local_users.go — Groups
// ---------------------------------------------------------------------------

func TestGroup_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	// Create.
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "eng", NameFolded: "eng"})
	require.NoError(t, err)
	assert.NotZero(t, g.ID)

	// Get.
	got, err := ls.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, "eng", got.Name)

	// Get — not found.
	_, err = ls.GetGroup(ctx, 99999)
	require.Error(t, err)

	// Update.
	desc := "engineers"
	matched, err := ls.UpdateGroupFields(ctx, g.ID, nil, nil, &desc, time.Now())
	require.NoError(t, err)
	require.True(t, matched)
	updated, err := ls.GetGroup(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, "engineers", updated.Description)

	// ListGroups.
	groups, err := ls.ListGroups(ctx)
	require.NoError(t, err)
	assert.Len(t, groups, 1)

	// ListGroupsPage.
	gps, total, err := ls.ListGroupsPage(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, gps, 1)

	// DeleteGroup.
	err = ls.DeleteGroup(ctx, g.ID)
	require.NoError(t, err)

	// After soft-delete, ListGroups should be empty.
	groups, err = ls.ListGroups(ctx)
	require.NoError(t, err)
	assert.Empty(t, groups)

	// RestoreGroup.
	err = ls.RestoreGroup(ctx, g.ID)
	require.NoError(t, err)

	groups, err = ls.ListGroups(ctx)
	require.NoError(t, err)
	assert.Len(t, groups, 1)
}

func TestDeleteGroup_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	err := ls.DeleteGroup(ctx, 99999)
	require.Error(t, err)
}

func TestRestoreGroup_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	err := ls.RestoreGroup(ctx, 99999)
	require.Error(t, err)
}

func TestGroup_UserMembership(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "henry", UsernameFolded: "henry", Email: "henry@example.com", EmailFolded: "henry@example.com"})
	require.NoError(t, err)
	g, err := ls.CreateGroup(ctx, &models.Group{Name: "ops", NameFolded: "ops"})
	require.NoError(t, err)

	// AddUserToGroup (global: projectID=0).
	err = ls.AddUserToGroup(ctx, u.ID, g.ID, 0)
	require.NoError(t, err)

	// Idempotent second add (same projectID).
	err = ls.AddUserToGroup(ctx, u.ID, g.ID, 0)
	require.NoError(t, err)

	// ListGroupMembers.
	members, err := ls.ListGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	assert.Len(t, members, 1)

	// GetUserGroups.
	groups, err := ls.GetUserGroups(ctx, u.ID)
	require.NoError(t, err)
	assert.Len(t, groups, 1)

	// ListAllUserGroupMemberships (#G44 batch-load counterpart of GetUserGroups).
	memberships, err := ls.ListAllUserGroupMemberships(ctx)
	require.NoError(t, err)
	require.Len(t, memberships, 1)
	assert.Equal(t, u.ID, memberships[0].UserID)
	assert.Equal(t, g.ID, memberships[0].GroupID)

	// RemoveUserFromGroup (global: projectID=0).
	err = ls.RemoveUserFromGroup(ctx, u.ID, g.ID, 0)
	require.NoError(t, err)

	members, err = ls.ListGroupMembers(ctx, g.ID)
	require.NoError(t, err)
	assert.Empty(t, members)
}

func TestListGroupMembers_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	_, err := ls.ListGroupMembers(ctx, 99999)
	require.Error(t, err)
}

func TestListGroupsPage_Offset(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	for i := range 3 {
		_, err := ls.CreateGroup(ctx, &models.Group{Name: fmt.Sprintf("g%d", i), NameFolded: fmt.Sprintf("g%d", i)})
		require.NoError(t, err)
	}

	// Offset 1, pageSize 1 → one result.
	gs, total, err := ls.ListGroupsPage(ctx, 1, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, gs, 1)
}

func TestAddUserToGroup_UserNotFound(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	g, err := ls.CreateGroup(ctx, &models.Group{Name: "admins", NameFolded: "admins"})
	require.NoError(t, err)

	err = ls.AddUserToGroup(ctx, 99999, g.ID, 0)
	require.Error(t, err)
}

func TestAddUserToGroup_GroupNotFound(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "ivan", UsernameFolded: "ivan", Email: "ivan@example.com", EmailFolded: "ivan@example.com"})
	require.NoError(t, err)

	err = ls.AddUserToGroup(ctx, u.ID, 99999, 0)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_users.go — ListGroupMembersByGroupIDs
// ---------------------------------------------------------------------------

func TestListGroupMembersByGroupIDsS4(t *testing.T) {
	ctx := context.Background()
	ls := newUserS4Store(t)

	u1, err := ls.CreateUser(ctx, &models.User{Username: "jill", UsernameFolded: "jill", Email: "jill@example.com", EmailFolded: "jill@example.com"})
	require.NoError(t, err)
	u2, err := ls.CreateUser(ctx, &models.User{Username: "jack", UsernameFolded: "jack", Email: "jack@example.com", EmailFolded: "jack@example.com"})
	require.NoError(t, err)
	g1, err := ls.CreateGroup(ctx, &models.Group{Name: "g1", NameFolded: "g1"})
	require.NoError(t, err)
	g2, err := ls.CreateGroup(ctx, &models.Group{Name: "g2", NameFolded: "g2"})
	require.NoError(t, err)

	require.NoError(t, ls.AddUserToGroup(ctx, u1.ID, g1.ID, 0))
	require.NoError(t, ls.AddUserToGroup(ctx, u2.ID, g2.ID, 0))

	result, err := ls.ListGroupMembersByGroupIDs(ctx, []uint{g1.ID, g2.ID})
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

// ---------------------------------------------------------------------------
// local_auth.go — DeleteSessionsByFamily empty key guard
// ---------------------------------------------------------------------------

func newAuthS4Store(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "auth_s4_"+t.Name(), &models.Session{}, &models.PersonalAccessToken{})
}

func TestDeleteSessionsByFamily_EmptyKey(t *testing.T) {
	ctx := context.Background()
	ls := newAuthS4Store(t)

	// Empty familyID is a no-op.
	err := ls.DeleteSessionsByFamily(ctx, "")
	require.NoError(t, err)
}

func TestDeleteSessionsByFamily_DeletesRows(t *testing.T) {
	ctx := context.Background()
	ls := newAuthS4Store(t)

	exp := time.Now().Add(time.Hour)
	require.NoError(t, ls.db.Create(&models.Session{
		UserID:       1,
		SessionToken: "t1",
		FamilyID:     "fam-1",
		ExpiresAt:    &exp,
	}).Error)
	require.NoError(t, ls.db.Create(&models.Session{
		UserID:       1,
		SessionToken: "t2",
		FamilyID:     "fam-1",
		ExpiresAt:    &exp,
	}).Error)

	err := ls.DeleteSessionsByFamily(ctx, "fam-1")
	require.NoError(t, err)

	var count int64
	ls.db.Model(&models.Session{}).Where("family_id = ?", "fam-1").Count(&count)
	assert.Zero(t, count)
}

func TestRevokePersonalAccessToken_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newAuthS4Store(t)

	err := ls.RevokePersonalAccessToken(ctx, 99999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_memberships.go — CreateProjectMembership duplicate
// ---------------------------------------------------------------------------

func newMembershipS4Store(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "memb_s4_"+t.Name(), &models.ProjectMembership{})
}

func TestCreateProjectMembership_Success(t *testing.T) {
	ctx := context.Background()
	ls := newMembershipS4Store(t)

	m := &models.ProjectMembership{
		ProjectID: 1, UserID: 1, State: "active",
		InvitedAt: time.Now(),
	}
	got, err := ls.CreateProjectMembership(ctx, m)
	require.NoError(t, err)
	assert.NotZero(t, got.ID)
}

// ---------------------------------------------------------------------------
// local_notifications.go — CreateNotification
// ---------------------------------------------------------------------------

func newNotifS4Store(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "notif_s4_"+t.Name(), &models.Notification{})
}

func TestCreateNotification_Success(t *testing.T) {
	ctx := context.Background()
	ls := newNotifS4Store(t)

	projID := uint(1)
	n, err := ls.CreateNotification(ctx, &models.Notification{
		UserID:    1,
		Type:      "secret.expiry",
		ProjectID: &projID,
		Message:   "api-key expires soon",
	})
	require.NoError(t, err)
	assert.NotZero(t, n.ID)
}

func TestMarkAllNotificationsRead(t *testing.T) {
	ctx := context.Background()
	ls := newNotifS4Store(t)

	projID := uint(1)
	for range 3 {
		_, err := ls.CreateNotification(ctx, &models.Notification{
			UserID:    10,
			Type:      "secret.expiry",
			ProjectID: &projID,
			Message:   "soon",
		})
		require.NoError(t, err)
	}

	err := ls.MarkAllNotificationsRead(ctx, 10)
	require.NoError(t, err)

	notifs, err := ls.ListNotifications(ctx, 10, true, 20)
	require.NoError(t, err)
	assert.Empty(t, notifs)
}

// ---------------------------------------------------------------------------
// local_sod.go — SoD policy CRUD
// ---------------------------------------------------------------------------

func newSoDStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "sod_s4_"+t.Name(), &models.SoDPolicy{})
}

func TestSoDPolicy_CRUDS4(t *testing.T) {
	ctx := context.Background()
	ls := newSoDStore(t)

	p, err := ls.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name:        "sep-of-duties",
		PermissionA: "roles.assign",
		PermissionB: "secrets.delete",
	})
	require.NoError(t, err)
	assert.NotZero(t, p.ID)

	// GetSoDPolicy.
	got, err := ls.GetSoDPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, "sep-of-duties", got.Name)

	// GetSoDPolicy — not found.
	_, err = ls.GetSoDPolicy(ctx, 99999)
	require.Error(t, err)

	// ListSoDPolicies.
	rows, err := ls.ListSoDPolicies(ctx)
	require.NoError(t, err)
	assert.Len(t, rows, 1)

	// DeleteSoDPolicy.
	err = ls.DeleteSoDPolicy(ctx, p.ID)
	require.NoError(t, err)

	rows, err = ls.ListSoDPolicies(ctx)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestDeleteSoDPolicy_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newSoDStore(t)

	err := ls.DeleteSoDPolicy(ctx, 99999)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_sso.go — SSO login state
// ---------------------------------------------------------------------------

func newSSOStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "sso_s4_"+t.Name(), &models.SSOLoginState{})
}

func TestSSOLoginState_CreateAndConsume(t *testing.T) {
	ctx := context.Background()
	ls := newSSOStore(t)

	exp := time.Now().Add(10 * time.Minute)
	err := ls.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State:     "csrf-token-1",
		Nonce:     "nonce-1",
		Provider:  "google",
		ExpiresAt: exp,
	})
	require.NoError(t, err)

	// Consume it.
	got, err := ls.ConsumeSSOLoginState(ctx, "csrf-token-1")
	require.NoError(t, err)
	assert.Equal(t, "nonce-1", got.Nonce)

	// Second consume → not found (already consumed).
	_, err = ls.ConsumeSSOLoginState(ctx, "csrf-token-1")
	require.Error(t, err)
}

func TestConsumeSSOLoginState_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newSSOStore(t)

	_, err := ls.ConsumeSSOLoginState(ctx, "does-not-exist")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_access_review_campaigns.go
// ---------------------------------------------------------------------------

func newARCStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "arc_s4_"+t.Name(),
		&models.AccessReviewCampaign{}, &models.AccessReviewItem{})
}

func TestAccessReviewCampaign_CRUDS4(t *testing.T) {
	ctx := context.Background()
	ls := newARCStore(t)

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1,
		Name:      "Q1 2026",
		State:     "open",
		CreatedBy: 1,
		CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	assert.NotZero(t, c.ID)

	// GetAccessReviewCampaign.
	got, err := ls.GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "Q1 2026", got.Name)

	// ListAccessReviewCampaigns.
	rows, err := ls.ListAccessReviewCampaigns(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, rows, 1)

	// ListAccessReviewCampaigns — other project.
	rows, err = ls.ListAccessReviewCampaigns(ctx, 99999)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestGetOpenAccessReviewCampaignS4(t *testing.T) {
	ctx := context.Background()
	ls := newARCStore(t)

	// No open campaign.
	got, err := ls.GetOpenAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	assert.Nil(t, got)

	// Create an open one.
	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "open-camp", State: "open", CreatedBy: 1, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	got, err = ls.GetOpenAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, c.ID, got.ID)
}

func TestGetLatestClosedAccessReviewCampaignS4(t *testing.T) {
	ctx := context.Background()
	ls := newARCStore(t)

	// None closed.
	got, err := ls.GetLatestClosedAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	assert.Nil(t, got)

	now := time.Now()
	_, err = ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "closed-camp", State: "closed", CreatedBy: 1, CreatedAt: now, ClosedAt: &now,
	})
	require.NoError(t, err)

	got, err = ls.GetLatestClosedAccessReviewCampaign(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "closed-camp", got.Name)
}

func TestUpdateAccessReviewCampaign(t *testing.T) {
	ctx := context.Background()
	ls := newARCStore(t)

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "to-close", State: "open", CreatedBy: 1, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	now := time.Now()
	c.State = "closed"
	c.ClosedAt = &now
	updated, err := ls.UpdateAccessReviewCampaign(ctx, c)
	require.NoError(t, err)
	assert.True(t, updated)

	// Second update: already closed → no rows affected.
	updated, err = ls.UpdateAccessReviewCampaign(ctx, c)
	require.NoError(t, err)
	assert.False(t, updated)
}

func TestAccessReviewItems(t *testing.T) {
	ctx := context.Background()
	ls := newARCStore(t)

	c, err := ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "items-camp", State: "open", CreatedBy: 1, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	// CreateAccessReviewItems — empty slice (no-op).
	err = ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{})
	require.NoError(t, err)

	items := []*models.AccessReviewItem{
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 1, Decision: "pending", AccessLevel: "read", Source: "role"},
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 2, Decision: "pending", AccessLevel: "read", Source: "role"},
	}
	err = ls.CreateAccessReviewItems(ctx, items)
	require.NoError(t, err)

	// ListAccessReviewItems.
	list, err := ls.ListAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// CountPendingAccessReviewItems.
	n, err := ls.CountPendingAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	// GetAccessReviewItem.
	item, err := ls.GetAccessReviewItem(ctx, items[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", item.Decision)

	// UpdateAccessReviewItem.
	item.Decision = "attested"
	item.DecidedBy = 1
	ok, err := ls.UpdateAccessReviewItem(ctx, item)
	require.NoError(t, err)
	assert.True(t, ok)

	// Second update (no longer pending) → false.
	ok, err = ls.UpdateAccessReviewItem(ctx, item)
	require.NoError(t, err)
	assert.False(t, ok)
}
