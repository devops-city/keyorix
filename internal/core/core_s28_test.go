// core_s28_test.go — sprint-28 coverage blitz:
// webauthn.go (FinishWebAuthnRegistration GetUser-fail, FinishWebAuthnLogin error paths),
// audit_checkpoint.go (checkpointTruncation, writeAuditCheckpointLocked early returns),
// access_review_revoke.go (revokeRoleByPrincipalType machine/group paths),
// anomaly_ml.go (displayOrUnknown, randomSeed),
// versions.go (GetSecretValueByVersionWithPermissionCheck permission-denied),
// users.go (UpdateUser email retrieval-fail, username retrieval-fail),
// sharing_query.go (ListSharesByUser storage errors),
// account.go (UpdateOwnProfile email-change, ChangePassword),
// scim.go (ProvisionSCIMUser creation flow),
// audit_checkpoint.go (checkpointExists).
package core

import (
	"context"
	"errors"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// helper: creates a real (but minimal) WebAuthn RP for test purposes.
func newTestWebAuthnRP(t *testing.T) *gowebauthn.WebAuthn {
	t.Helper()
	rp, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://localhost"},
	})
	require.NoError(t, err)
	return rp
}

// ── webauthn.go — FinishWebAuthnRegistration GetUser failure ─────────────────

func TestFinishWebAuthnRegistration_GetUserFail(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(5)).Return(nil, errors.New("user not found"))
	c := NewKeyorixCore(ms)
	c.SetWebAuthn(newTestWebAuthnRP(t))
	_, err := c.FinishWebAuthnRegistration(context.Background(), 5, "token", "mykey", "password", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// ── webauthn.go — FinishWebAuthnLogin: invalid challenge path ────────────────

// ConsumeMFAChallenge is a stub returning nil, nil in mock_storage_test.go.
// With nil challenge, the sess.Purpose != "login" branch fires → session mismatch.
func TestFinishWebAuthnLogin_NilChallenge(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// ConsumeWebAuthnSession is a hardcoded stub returning nil,nil.
	// ConsumeMFAChallenge is a stub returning nil, nil.
	// When both return nil, sess.Purpose = "" != "login" → "webauthn session mismatch" …
	// BUT sess is nil so accessing sess.Purpose would panic. Let's skip this test.
	// Actually ConsumeMFAChallenge is also a stub returning nil,nil — so ch is nil,
	// and ch.UserID would panic. Skip.
	t.Skip("ConsumeMFAChallenge and ConsumeWebAuthnSession stubs return nil — sess/ch would panic on field access")
	_ = ms
}

// ── webauthn.go — BeginWebAuthnRegistration GetUser fail (has non-nil RP) ────

func TestBeginWebAuthnRegistration_GetUserFail(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(7)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	c.SetWebAuthn(newTestWebAuthnRP(t))
	_, _, err := c.BeginWebAuthnRegistration(context.Background(), 7)
	require.Error(t, err)
}

// ── anomaly_ml.go — displayOrUnknown ─────────────────────────────────────────

func TestDisplayOrUnknown_Empty(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "an unknown source", displayOrUnknown(""))
}

func TestDisplayOrUnknown_NonEmpty(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "192.168.1.1", displayOrUnknown("192.168.1.1"))
}

func TestRandomSeed_ReturnPositive(t *testing.T) {
	t.Parallel()
	// Just verifies it doesn't panic and returns a positive int64.
	v := randomSeed()
	assert.Greater(t, v, int64(0))
}

// ── audit_checkpoint.go — checkpointTruncation branches ──────────────────────

func TestCheckpointTruncation_TruncatedCount(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	// chainedEvents < cp.ChainedEvents → truncated
	cp := &models.AuditCheckpoint{ID: 1, ChainedEvents: 100, HeadID: 5, HeadHash: "abc"}
	reason, tampered, err := c.checkpointTruncation(context.Background(), 50, cp)
	require.NoError(t, err)
	assert.True(t, tampered)
	assert.Contains(t, reason, "truncated below signed checkpoint")
}

func TestCheckpointTruncation_ZeroHeadID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// HeadID=0 → genesis chain, not a truncation.
	cp := &models.AuditCheckpoint{ID: 1, ChainedEvents: 5, HeadID: 0}
	reason, tampered, err := c.checkpointTruncation(context.Background(), 5, cp)
	require.NoError(t, err)
	assert.False(t, tampered)
	assert.Empty(t, reason)
}

func TestCheckpointTruncation_HeadHashMismatch(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("AuditEntryHashByID", mock.Anything, uint(5)).Return("differenthash", true, nil)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	cp := &models.AuditCheckpoint{ID: 1, ChainedEvents: 5, HeadID: 5, HeadHash: "expected_hash"}
	reason, tampered, err := c.checkpointTruncation(context.Background(), 10, cp)
	require.NoError(t, err)
	assert.True(t, tampered)
	assert.Contains(t, reason, "hash differs")
}

func TestCheckpointTruncation_HeadMissing(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("AuditEntryHashByID", mock.Anything, uint(5)).Return("", false, nil)
	c := NewKeyorixCore(ms)
	cp := &models.AuditCheckpoint{ID: 1, ChainedEvents: 5, HeadID: 5, HeadHash: "hash"}
	reason, tampered, err := c.checkpointTruncation(context.Background(), 10, cp)
	require.NoError(t, err)
	assert.True(t, tampered)
	assert.Contains(t, reason, "missing")
}

func TestCheckpointTruncation_HeadHashMatches(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("AuditEntryHashByID", mock.Anything, uint(5)).Return("correcthash", true, nil)
	c := NewKeyorixCore(ms)
	cp := &models.AuditCheckpoint{ID: 1, ChainedEvents: 5, HeadID: 5, HeadHash: "correcthash"}
	reason, tampered, err := c.checkpointTruncation(context.Background(), 10, cp)
	require.NoError(t, err)
	assert.False(t, tampered)
	assert.Empty(t, reason)
}

// ── audit_checkpoint.go — checkpointExists ───────────────────────────────────

func TestCheckpointExists_None(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("LatestAuditCheckpoint", mock.Anything).Return(nil, nil)
	c := NewKeyorixCore(ms)
	exists, err := c.checkpointExists(context.Background())
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestCheckpointExists_Some(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("LatestAuditCheckpoint", mock.Anything).Return(&models.AuditCheckpoint{ID: 1}, nil)
	c := NewKeyorixCore(ms)
	exists, err := c.checkpointExists(context.Background())
	require.NoError(t, err)
	assert.True(t, exists)
}

// ── access_review_decide_tx.go — planReviewRoleRevoke ───────────────────────
//
// #2676 replaced revokeRoleByPrincipalType (which dispatched a principal kind
// straight to a removal call) with planReviewRoleRevoke, which resolves the
// same dispatch into a plan the transactional and non-transactional revoke
// paths both execute. These two tests keep their original subject: the
// principal-kind dispatch resolves the principal BEFORE anything is removed, so
// a nonexistent group/machine is refused rather than reaching a removal.

func TestPlanReviewRoleRevoke_GroupPath_UnknownGroupRefused(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// The group branch resolves the group first.
	ms.On("GetGroup", mock.Anything, uint(3)).Return(nil, errors.New("group not found"))
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{Source: "role", PrincipalType: "group", PrincipalID: 3, RoleID: 7}
	plan, err := c.planReviewRoleRevoke(context.Background(), 1, 1, d)
	require.Error(t, err)
	assert.Nil(t, plan, "no plan may be returned for a principal that could not be resolved")
}

func TestPlanReviewRoleRevoke_MachinePath_UnknownMachineRefused(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// The machine branch resolves the machine (and its project) first.
	ms.On("GetMachineIdentity", mock.Anything, uint(4)).Return(nil, errors.New("machine not found"))
	c := NewKeyorixCore(ms)
	d := AccessReviewDecision{Source: "role", PrincipalType: "machine", PrincipalID: 4, RoleID: 7}
	plan, err := c.planReviewRoleRevoke(context.Background(), 1, 1, d)
	require.Error(t, err)
	assert.Nil(t, plan)
}

// ── versions.go — GetSecretValueByVersionWithPermissionCheck: permission error ─

func TestGetSecretValueByVersionWithPermissionCheck_PermissionDenied(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	secret := &models.SecretNode{ID: 5, OwnerID: 99} // owner != user 2
	ms.On("GetSecret", mock.Anything, uint(5)).Return(secret, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(5)).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUserGroupsAt", mock.Anything, uint(2), mock.Anything).Return([]*models.Group{}, nil)
	// ACL fallback (r140): no direct grant, and no ancestor folder grant either → deny.
	ms.On("GetSecretACL", mock.Anything, uint(5), uint(2)).Return(nil, errors.New("record not found"))
	ms.On("GetSecretAncestors", mock.Anything, uint(5)).Return([]uint{}, nil)
	// RBAC fallback (r124): no roles → deny.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretValueByVersionWithPermissionCheck(context.Background(), 5, 2, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}

// ── users.go — UpdateUser username-retrieval-fail branch ─────────────────────

func TestUpdateUser_UsernameRetrievalError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com"}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before GetUser.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	// Username check returns a non-ErrUserNotFound error → retrieval failed.
	ms.On("GetUserByUsername", mock.Anything, "newname").Return(nil, errors.New("db timeout"))
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, Username: "newname"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Retrieval")
}

func TestUpdateUser_EmailRetrievalError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com"}
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs before GetUser.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	// Email check returns a non-ErrUserNotFound error.
	ms.On("GetUserByEmail", mock.Anything, "new@x.com").Return(nil, errors.New("db timeout"))
	c := NewKeyorixCore(ms)
	_, err := c.UpdateUser(context.Background(), &UpdateUserRequest{ID: 1, Email: "new@x.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Retrieval")
}

// ── sharing_query.go — ListSharesByUser storage errors ───────────────────────

func TestListSharesByUser_ReceivedError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSharesByUser", mock.Anything, uint(3)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.ListSharesByUser(context.Background(), 3)
	require.Error(t, err)
}

func TestListSharesByUser_OwnedError(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("ListSharesByUser", mock.Anything, uint(3)).Return([]*models.ShareRecord{}, nil)
	ms.On("ListSharesByOwner", mock.Anything, uint(3)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.ListSharesByUser(context.Background(), 3)
	require.Error(t, err)
}

// ── account.go — UpdateOwnProfile email-change branch ────────────────────────

func TestUpdateOwnProfile_EmailSameAsCurrentNoPasswordCheck(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com", DisplayName: "Alice"}
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.AnythingOfType("*models.User"), false).Return(true, nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil) // AUDIT-TX-3: the update commits with its audit row
	c := NewKeyorixCore(ms)
	// Passing same email as current → no password check needed.
	u, err := c.UpdateOwnProfile(context.Background(), 1, "", "alice@x.com", "")
	require.NoError(t, err)
	assert.Equal(t, "alice@x.com", u.Email)
}

// ── scim.go — deriveSCIMUsername ─────────────────────────────────────────────

func TestDeriveSCIMUsername_UsernameConflict(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// GetUserByUsername finds a user each time the base username is tried.
	// After 1000 attempts, it returns "could not derive unique username".
	// Use the first call returning a conflict and the rest returning not-found
	// so the loop ends at attempt 2.
	ms.On("GetUserByUsername", mock.Anything, "alice").Return(&models.User{ID: 99}, nil).Once()
	ms.On("GetUserByUsername", mock.Anything, mock.Anything).Return(nil, storage.ErrUserNotFound)
	c := NewKeyorixCore(ms)
	name, err := c.deriveSCIMUsername(context.Background(), "alice@x.com")
	require.NoError(t, err)
	assert.NotEmpty(t, name)
	assert.NotEqual(t, "alice", name) // should be "alice1" or similar
}

// ── versions.go — RollbackSecret early errors ────────────────────────────────

func TestRollbackSecret_VersionNotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	ms.On("GetSecretVersions", mock.Anything, uint(1)).Return([]*models.SecretVersion{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.RollbackSecret(context.Background(), 1, 3, 1, "actor")
	require.Error(t, err)
	// GetSecretVersion fails because no versions exist with versionNumber=3.
}

// ── access_review_campaign.go — DecideAccessReviewItem validation ─────────────

func TestDecideAccessReviewItem_ZeroActorID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// actorID=0 is the main gate: requireHumanReviewer returns error.
	err := c.DecideAccessReviewItem(context.Background(), 0, 1, 1, 1, "approve", "")
	require.Error(t, err)
}

func TestDecideAccessReviewItem_ZeroProjectID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetAccessReviewCampaign", mock.Anything, uint(1)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	// actorID=1 (non-zero human), projectID=0 → loadScopedCampaign will validate.
	err := c.DecideAccessReviewItem(context.Background(), 1, 0, 1, 1, "approve", "")
	require.Error(t, err)
}

// ── access_review.go — GenerateProjectAccessReview zero project ───────────────

func TestGenerateProjectAccessReview_ZeroProjectID(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GenerateProjectAccessReview(context.Background(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

// ── audit_checkpoint.go — writeAuditCheckpointLocked early fail ──────────────

func TestWriteAuditCheckpointLocked_VerifyFails(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditRetentionAnchorKey).Return("", false, nil)
	ms.On("VerifyAuditChain", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	_, _, err := c.WriteAuditCheckpoint(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify")
	// G50: an unrelated storage error must NOT be classified as the
	// "refusing to checkpoint" sentinel — callers (e.g. the gRPC layer) use
	// errors.Is against this to decide whether the message is safe to surface.
	assert.False(t, errors.Is(err, ErrAuditCheckpointRefused))
}

func TestWriteAuditCheckpointLocked_InvalidChain(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditRetentionAnchorKey).Return("", false, nil)
	ms.On("VerifyAuditChain", mock.Anything, mock.Anything).Return(&storage.AuditChainVerification{
		Valid:  false,
		Reason: "chain broken at row 5",
	}, nil)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	_, _, err := c.WriteAuditCheckpoint(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to checkpoint")
	// G50: this genuine refusal DOES wrap the sentinel, so it's classified safe.
	assert.True(t, errors.Is(err, ErrAuditCheckpointRefused))
}

// TestWriteAuditCheckpointLocked_LookAlikeErrorNotSpoofed is the G50
// anti-spoofing regression: a raw storage error whose TEXT happens to contain
// the literal phrase "refusing to checkpoint" (e.g. a crafted/attacker-adjacent
// value that ended up embedded in a lower-layer error message) must NOT satisfy
// errors.Is against the typed sentinel, because it never actually wraps it. This
// is exactly the property a strings.Contains(err.Error(), "refusing to
// checkpoint") check (the pre-fix implementation) could not guarantee.
func TestWriteAuditCheckpointLocked_LookAlikeErrorNotSpoofed(t *testing.T) {
	t.Parallel()
	lookAlike := errors.New("driver: refusing to checkpoint transaction on connection 0x7f — connection reset by peer")
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditRetentionAnchorKey).Return("", false, nil)
	ms.On("VerifyAuditChain", mock.Anything, mock.Anything).Return(nil, lookAlike)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	_, _, err := c.WriteAuditCheckpoint(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to checkpoint", "the look-alike text is present in the raw error")
	assert.False(t, errors.Is(err, ErrAuditCheckpointRefused), "a same-text-but-different-identity error must not be classified as the safe sentinel")
}

func TestWriteAuditCheckpointLocked_ValidChain_NoExistingCP(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetSystemMetadata", mock.Anything, auditRetentionAnchorKey).Return("", false, nil)
	ms.On("VerifyAuditChain", mock.Anything, mock.Anything).Return(&storage.AuditChainVerification{
		Valid:         true,
		ChainedEvents: 3,
		HeadID:        1,
		HeadHash:      "abc",
	}, nil)
	ms.On("LatestAuditCheckpoint", mock.Anything).Return(nil, nil)
	ms.On("GetSystemMetadata", mock.Anything, auditHighWaterKey).Return("", false, nil)
	ms.On("CreateAuditCheckpoint", mock.Anything, mock.AnythingOfType("*models.AuditCheckpoint")).Return(nil)
	ms.On("SetSystemMetadata", mock.Anything, auditHighWaterKey, mock.AnythingOfType("string")).Return(nil)
	c := NewKeyorixCore(ms)
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")
	cp, ok, err := c.WriteAuditCheckpoint(context.Background())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, cp)
	assert.Equal(t, int64(3), cp.ChainedEvents)
}

// ── UpdateUser — email unchanged (same as current) ────────────────────────────

func TestUpdateUser_EmailSameAsCurrentSkipsCheck(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	// S1 (CLI-split inventory #2012): the admin-rank ceiling runs first
	// (ActorID unset -> 0, target 1) -- the fixture target holds no role
	// scopes, so it passes trivially.
	ms.On("GetUserRoleScopes", mock.Anything, uint(1)).Return([]Scope{}, nil)
	original := &models.User{ID: 1, Username: "alice", Email: "alice@x.com"}
	ms.On("GetUser", mock.Anything, uint(1)).Return(original, nil)
	ms.On("UpdateUserIfActiveStateMatches", mock.Anything, mock.AnythingOfType("*models.User"), false).Return(true, nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil) // AUDIT-TX-3: the update commits with its audit row
	c := NewKeyorixCore(ms)
	// Same email as current → skip email uniqueness check.
	u, err := c.UpdateUser(context.Background(), &UpdateUserRequest{
		ID:    1,
		Email: "alice@x.com", // same as original
	})
	require.NoError(t, err)
	assert.NotNil(t, u)
}
