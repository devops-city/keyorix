// core_s27_test.go — sprint-27 coverage blitz:
// scim.go (ProvisionSCIMUser validation paths),
// webauthn.go (checkPasswordlessAccountState),
// audit_diff.go (BuildSecretUpdateDiff helper functions),
// jit_access.go (AssignGroupRoleWithExpiry error paths),
// account.go (UpdateOwnProfile, ChangePassword validation),
// access_review_campaign.go (ListAccessReviewCampaigns, GetAccessReviewCampaign),
// versions.go (getSecretValueByVersionForUser branches),
// users.go (DeleteUser validation + suspend path, buildUserForCreate email-exists),
// anomaly_alerting.go (notifyAnomalyAdmins zero-projectID),
// sharing_validation.go (validateShareSecretRequest more branches).
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── scim.go — ProvisionSCIMUser ──────────────────────────────────────────────

func TestProvisionSCIMUser_EmptyUserName(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ProvisionSCIMUser(context.Background(), 0, "", "", "", "", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "userName is required")
}

func TestProvisionSCIMUser_ExistingUserFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// FindSCIMUser checks GetUserByExternalID first.
	ms.On("GetUserByExternalID", mock.Anything, "ext-123").Return(&models.User{ID: 5, ExternalID: "ext-123"}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.ProvisionSCIMUser(context.Background(), 0, "alice", "", "alice@x.com", "ext-123", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestProvisionSCIMUser_FindError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext-bad").Return(nil, errors.New("db down"))
	ms.On("GetUserByEmail", mock.Anything, "alice@x.com").Return(nil, errors.New("db down"))
	c := NewKeyorixCore(ms)
	_, err := c.ProvisionSCIMUser(context.Background(), 0, "alice", "", "alice@x.com", "ext-bad", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check for an existing user")
}

// ── webauthn.go — checkPasswordlessAccountState ──────────────────────────────

func TestCheckPasswordlessAccountState_Inactive(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	user := &models.User{ID: 1, IsActive: false, AccountState: "active"}
	err := c.checkPasswordlessAccountState(context.Background(), user)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

func TestCheckPasswordlessAccountState_AccountBlocked(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// AccountLoginBlocked returns true for deprovisioned state.
	user := &models.User{ID: 1, IsActive: true, AccountState: AccountDeprovisioned}
	err := c.checkPasswordlessAccountState(context.Background(), user)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

func TestCheckPasswordlessAccountState_Locked(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// Enable lockout and set a future locked-until.
	c.loginLockout = LoginLockoutPolicy{Enabled: true, BaseCooldown: time.Hour}
	future := c.now().Add(time.Hour)
	user := &models.User{ID: 1, IsActive: true, AccountState: "active", LoginLockedUntil: &future}
	err := c.checkPasswordlessAccountState(context.Background(), user)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "temporarily locked")
}

// ── audit_diff.go — helpers ──────────────────────────────────────────────────

func TestEqIntPtr_BothNil(t *testing.T) {
	t.Parallel()
	assert.True(t, eqIntPtr(nil, nil))
}

func TestEqIntPtr_OneNil(t *testing.T) {
	t.Parallel()
	v := 5
	assert.False(t, eqIntPtr(nil, &v))
	assert.False(t, eqIntPtr(&v, nil))
}

func TestEqIntPtr_BothNonNilEqual(t *testing.T) {
	t.Parallel()
	a, b := 7, 7
	assert.True(t, eqIntPtr(&a, &b))
}

func TestEqIntPtr_BothNonNilDifferent(t *testing.T) {
	t.Parallel()
	a, b := 7, 8
	assert.False(t, eqIntPtr(&a, &b))
}

func TestIntPtrVal_Nil(t *testing.T) {
	t.Parallel()
	assert.Nil(t, intPtrVal(nil))
}

func TestIntPtrVal_NonNil(t *testing.T) {
	t.Parallel()
	v := 42
	assert.Equal(t, 42, intPtrVal(&v))
}

func TestEqTimePtr_BothNil(t *testing.T) {
	t.Parallel()
	assert.True(t, eqTimePtr(nil, nil))
}

func TestEqTimePtr_OneNil(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	assert.False(t, eqTimePtr(nil, &ts))
	assert.False(t, eqTimePtr(&ts, nil))
}

func TestEqTimePtr_BothNonNilEqual(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	ts2 := ts
	assert.True(t, eqTimePtr(&ts, &ts2))
}

func TestEqTimePtr_BothNonNilDifferent(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	ts2 := ts.Add(time.Second)
	assert.False(t, eqTimePtr(&ts, &ts2))
}

func TestBuildSecretUpdateDiff_NilInputs(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", BuildSecretUpdateDiff(nil, nil, false))
	assert.Equal(t, "", BuildSecretUpdateDiff(&models.SecretNode{}, nil, false))
	assert.Equal(t, "", BuildSecretUpdateDiff(nil, &UpdateSecretRequest{}, false))
}

func TestBuildSecretUpdateDiff_ValueChanged(t *testing.T) {
	t.Parallel()
	old := &models.SecretNode{}
	req := &UpdateSecretRequest{}
	result := BuildSecretUpdateDiff(old, req, true)
	assert.Contains(t, result, `"value"`)
	assert.Contains(t, result, `"changed":true`)
}

func TestBuildSecretUpdateDiff_MaxReadsChanged(t *testing.T) {
	t.Parallel()
	old := &models.SecretNode{}
	newMax := 5
	req := &UpdateSecretRequest{MaxReads: &newMax}
	result := BuildSecretUpdateDiff(old, req, false)
	assert.Contains(t, result, `"max_reads"`)
}

func TestBuildSecretUpdateDiff_ClearExpiration_s27(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	old := &models.SecretNode{Expiration: &ts}
	req := &UpdateSecretRequest{ClearExpiration: true}
	result := BuildSecretUpdateDiff(old, req, false)
	assert.Contains(t, result, `"expiration"`)
}

func TestBuildSecretUpdateDiff_NoChange_s27(t *testing.T) {
	t.Parallel()
	old := &models.SecretNode{}
	req := &UpdateSecretRequest{}
	result := BuildSecretUpdateDiff(old, req, false)
	assert.Equal(t, "", result)
}

// ── account.go — UpdateOwnProfile ────────────────────────────────────────────

func TestUpdateOwnProfile_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.UpdateOwnProfile(context.Background(), 0, "Alice", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestUpdateOwnProfile_NoEmailChange(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", DisplayName: "Alice"}
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.AnythingOfType("*models.User"), false).Return(true, nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil) // AUDIT-TX-3: the update commits with its audit row
	c := NewKeyorixCore(ms)
	// email is empty → no email change branch → no password check → just UpdateUser
	u, err := c.UpdateOwnProfile(context.Background(), 1, "Alice S.", "", "")
	require.NoError(t, err)
	assert.Equal(t, "Alice S.", u.DisplayName)
}

// ── versions.go — getSecretValueByVersionForUser branches ────────────────────

func TestGetSecretValueByVersionForUser_ZeroSecretID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// GetSecretValueByVersion delegates to getSecretValueByVersionForUser
	_, err := c.GetSecretValueByVersion(context.Background(), 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestGetSecretValueByVersionForUser_ZeroVersionNumber(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueByVersion(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version number must be positive")
}

func TestGetSecretValueByVersionForUser_SecretNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueByVersion(context.Background(), 1, 1)
	require.Error(t, err)
}

func TestGetSecretValueByVersionForUser_Expired(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	past := time.Now().Add(-time.Hour)
	secret := &models.SecretNode{ID: 1, Expiration: &past}
	ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueByVersion(context.Background(), 1, 1)
	require.Error(t, err)
	// Error message comes from i18n ErrorSecretExpired
}

func TestGetSecretValueByVersionForUser_Suspended(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 1, Status: SecretStatusSuspended}
	ms.On("GetSecret", mock.Anything, uint(1)).Return(secret, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueByVersion(context.Background(), 1, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}

// ── users.go — DeleteUser validation ─────────────────────────────────────────

func TestDeleteUser_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.DeleteUser(context.Background(), 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestDeleteUser_UserNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before
	// GetUser is ever reached.
	ms.On("GetUserRoleScopes", mock.Anything, uint(99)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.DeleteUser(context.Background(), 0, 99)
	require.Error(t, err)
}

// ── users.go — buildUserForCreate email-already-exists branch ────────────────

func TestBuildUserForCreate_EmailAlreadyExists(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUserByUsername", mock.Anything, "alice").Return(nil, storage.ErrUserNotFound)
	// Email already taken.
	ms.On("GetUserByEmail", mock.Anything, "taken@x.com").Return(&models.User{ID: 9, Email: "taken@x.com"}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Username: "alice",
		Email:    "taken@x.com",
		Password: testPassword,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserAlreadyExists))
}

// ── anomaly_alerting.go — notifyAnomalyAdmins zero-projectID ─────────────────

func TestNotifyAnomalyAdmins_ZeroProjectID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	alert := &models.AnomalyAlert{AlertType: "unusual_access", Severity: "high"}
	// projectID=0 → early return nil
	err := c.notifyAnomalyAdmins(context.Background(), 0, alert)
	require.NoError(t, err)
}

func TestNotifyAnomalyAdmins_WithProjectID_NoMembers(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// ListProjectMembers is a hardcoded stub returning nil, nil.
	c := NewKeyorixCore(ms)
	alert := &models.AnomalyAlert{AlertType: "unusual_access", Severity: "high", SecretName: "my-secret"}
	err := c.notifyAnomalyAdmins(context.Background(), 1, alert)
	require.NoError(t, err)
}

// ── sharing_validation.go — validateShareSecretRequest remaining branches ─────

func TestValidateShareSecretRequest_NilRequest(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateShareSecretRequest(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestValidateShareSecretRequest_ZeroSecretID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateShareSecretRequest(&ShareSecretRequest{
		SecretID:    0,
		RecipientID: 1,
		Permission:  "read",
		SharedBy:    2,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestValidateShareSecretRequest_ZeroRecipient(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateShareSecretRequest(&ShareSecretRequest{
		SecretID:    1,
		RecipientID: 0,
		Permission:  "read",
		SharedBy:    2,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recipient ID is required")
}

func TestValidateShareSecretRequest_InvalidPermission(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateShareSecretRequest(&ShareSecretRequest{
		SecretID:    1,
		RecipientID: 2,
		Permission:  "admin",
		SharedBy:    3,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permission")
}

func TestValidateShareSecretRequest_ZeroSharedBy(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.validateShareSecretRequest(&ShareSecretRequest{
		SecretID:    1,
		RecipientID: 2,
		Permission:  "read",
		SharedBy:    0,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sharedBy is required")
}

// ── access_review_campaign.go — ListAccessReviewCampaigns ─────────────────────

func TestListAccessReviewCampaigns_ZeroProjectID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListAccessReviewCampaigns(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

func TestListAccessReviewCampaigns_StorageError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListAccessReviewCampaigns", mock.Anything, uint(1)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.ListAccessReviewCampaigns(context.Background(), 1)
	require.Error(t, err)
}

func TestListAccessReviewCampaigns_Empty(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListAccessReviewCampaigns", mock.Anything, uint(1)).Return([]*models.AccessReviewCampaign{}, nil)
	c := NewKeyorixCore(ms)
	result, err := c.ListAccessReviewCampaigns(context.Background(), 1)
	require.NoError(t, err)
	assert.Empty(t, result)
}

// ── access_review_campaign.go — GetAccessReviewCampaign ──────────────────────

func TestGetAccessReviewCampaign_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// campaignID=5 is passed as second argument to GetAccessReviewCampaign(ctx, projectID, campaignID)
	ms.On("GetAccessReviewCampaign", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetAccessReviewCampaign(context.Background(), 1, 5)
	require.Error(t, err)
}

// ── jit_access.go — AssignGroupRoleWithExpiry ────────────────────────────────

func TestAssignGroupRoleWithExpiry_RoleNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.AssignGroupRoleWithExpiry(context.Background(), 1, 2, 99, Scope{}, time.Now().Add(time.Hour), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Role not found")
}

// ── versions.go — GetSecretValue zero-ID branch ──────────────────────────────

func TestGetSecretValue_ZeroID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValue(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

// ── audit_checkpoint.go — AuditCheckpointsAvailable ─────────────────────────

func TestAuditCheckpointsAvailable_NoKey(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	assert.False(t, c.AuditCheckpointsAvailable())
}

func TestAuditCheckpointsAvailable_WithKey(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	assert.True(t, c.AuditCheckpointsAvailable())
}

// ── audit_checkpoint.go — VerifyCheckpointAnchor nil/empty ───────────────────

func TestVerifyCheckpointAnchor_NilCP(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, ok, err := c.VerifyCheckpointAnchor(nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyCheckpointAnchor_EmptyToken(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	cp := &models.AuditCheckpoint{ChainedEvents: 1, AnchorToken: nil}
	_, ok, err := c.VerifyCheckpointAnchor(cp)
	require.NoError(t, err)
	assert.False(t, ok)
}

// ── WriteAuditCheckpoint — unavailable (no key) ───────────────────────────────

func TestWriteAuditCheckpoint_NoKey(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// No checkpoint key → AuditCheckpointsAvailable() is false → returns nil, false, nil.
	cp, ok, err := c.WriteAuditCheckpoint(context.Background())
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, cp)
}

// ── sharing query — ListSharesByUser (zero user ID) ───────────────────────────

func TestListSharesByUser_ZeroUserID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.ListSharesByUser(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestListSharesByUser_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	shares := []*models.ShareRecord{{ID: 1, SecretID: 10, RecipientID: 2}}
	ms.On("ListSharesByUser", mock.Anything, uint(2)).Return(shares, nil)
	ms.On("ListSharesByOwner", mock.Anything, uint(2)).Return([]*models.ShareRecord{}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListSharesByUser(context.Background(), 2)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// ── DeprovisionSCIMUser — validation ─────────────────────────────────────────

func TestDeprovisionSCIMUser_UserNotFound_s27(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.DeprovisionSCIMUser(context.Background(), 0, 99)
	require.Error(t, err)
}

// ── NormalizeAccountState ─────────────────────────────────────────────────────

func TestNormalizeAccountState_Empty(t *testing.T) {
	t.Parallel()
	assert.Equal(t, AccountActive, NormalizeAccountState(""))
}

func TestNormalizeAccountState_Known(t *testing.T) {
	t.Parallel()
	assert.Equal(t, AccountSuspended, NormalizeAccountState(AccountSuspended))
}

// ── AccountLoginBlocked ───────────────────────────────────────────────────────

func TestAccountLoginBlocked_Active(t *testing.T) {
	t.Parallel()
	assert.False(t, AccountLoginBlocked(1, "active"))
}

func TestAccountLoginBlocked_Deprovisioned(t *testing.T) {
	t.Parallel()
	assert.True(t, AccountLoginBlocked(1, AccountDeprovisioned))
}

func TestAccountLoginBlocked_Suspended(t *testing.T) {
	t.Parallel()
	assert.True(t, AccountLoginBlocked(1, AccountSuspended))
}

// ── versions.go — getSecretValueForUser branches ─────────────────────────────

func TestGetSecretValueForUser_SecretNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValue(context.Background(), 5)
	require.Error(t, err)
}

func TestGetSecretValueForUser_ExpiredSecret(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	past := time.Now().Add(-time.Hour)
	secret := &models.SecretNode{ID: 5, Expiration: &past}
	ms.On("GetSecret", mock.Anything, uint(5)).Return(secret, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValue(context.Background(), 5)
	require.Error(t, err)
}

func TestGetSecretValueForUser_SuspendedSecret(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 5, Status: SecretStatusSuspended}
	ms.On("GetSecret", mock.Anything, uint(5)).Return(secret, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValue(context.Background(), 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}

// ── OpenAccessReviewCampaign — zero project ID ────────────────────────────────

func TestOpenAccessReviewCampaign_ZeroProjectID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.OpenAccessReviewCampaign(context.Background(), 1, 0, 0, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

// ── scim_groups.go — helpers ──────────────────────────────────────────────────

func TestDeprovisionSCIMGroup_DeleteGroupError_s27(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// guardLastGlobalAdminGroupDelete (#G02) runs first; no admin roles seeded
	// in this fixture, so it's a no-op and the simulated DeleteGroup failure
	// under test is reached.
	ms.On("GetRoleByName", mock.Anything, "super_admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "admin").Return(nil, errors.New("not found"))
	ms.On("GetRoleByName", mock.Anything, "system_admin").Return(nil, errors.New("not found"))
	// SESSION-AT #2352: DeprovisionSCIMGroup now shares DeleteGroup's own
	// deleteGroupGuarded helper (withGroupProjectAdminGuardLocks ->
	// projectAdminScopesHeldByGroup -> GetGroup), so this fixture needs both
	// of those stubbed too, not just the two guard checks.
	ms.On("ListGroupRoleAssignments", mock.Anything, uint(5)).Return([]storage.RoleAssignment{}, nil)
	ms.On("GetGroup", mock.Anything, uint(5)).Return(&models.Group{ID: 5, Name: "g"}, nil)
	// guardLastProjectAdminGroupDelete (core-project-members.json#3) runs next;
	// no group role assignments in this fixture, so it's a no-op too.
	ms.On("DeleteGroup", mock.Anything, uint(5)).Return(errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.DeprovisionSCIMGroup(context.Background(), 0, 5)
	require.Error(t, err)
}

// ── audit_diff.go — metadataVal and eqMetadata ──────────────────────────────

func TestEqMetadata_EmptyBoth(t *testing.T) {
	t.Parallel()
	assert.True(t, eqMetadata(models.JSON{}, map[string]string{}))
}

func TestEqMetadata_NilOld(t *testing.T) {
	t.Parallel()
	assert.True(t, eqMetadata(nil, map[string]string{}))
}

func TestEqMetadata_Different(t *testing.T) {
	t.Parallel()
	old := models.JSON(`{"key":"val1"}`)
	new := map[string]string{"key": "val2"}
	assert.False(t, eqMetadata(old, new))
}

func TestEqMetadata_Same(t *testing.T) {
	t.Parallel()
	old := models.JSON(`{"key":"val"}`)
	new := map[string]string{"key": "val"}
	assert.True(t, eqMetadata(old, new))
}

// ── HealthCheck — with real storage (verifies error is returned) ──────────────

func TestHealthCheck_StorageReturnsError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("HealthCheck", mock.Anything).Return(errors.New("db down"))
	c := NewKeyorixCore(ms)
	err := c.HealthCheck(context.Background())
	require.Error(t, err)
}

func TestHealthCheck_StorageOK_s27(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("HealthCheck", mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.HealthCheck(context.Background())
	require.NoError(t, err)
}
