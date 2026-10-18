package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uptr(u uint) *uint { return &u }

// GenerateProjectAccessReview reports every project-scoped role grant whose role
// confers a secrets.* permission (users and groups), with the highest action, and
// excludes roles that grant no secret access.
func TestGenerateProjectAccessReview(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	const proj = uint(2)
	// alice: editor (secrets.read+write) at project 2 → write.
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))
	// bob: auditor (audit.read, NO secrets.*) at project 2 → excluded.
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 11, 5, uptr(proj))
	// carol: viewer (secrets.read) at a DIFFERENT project → excluded from project 2.
	h.CreateTestUser(t, "carol", 12)
	h.AssignUserRole(t, 12, 4, uptr(uint(3)))
	// devs group: viewer (secrets.read) at project 2 → read.
	h.CreateTestGroup(t, "devs", "", 100)
	h.AssignGroupRole(t, 100, 4, uptr(proj))

	report, err := h.CoreService.GenerateProjectAccessReview(context.Background(), proj)
	require.NoError(t, err)

	type got struct{ typ, name, level string }
	var rows []got
	for _, e := range report.Entries {
		rows = append(rows, got{e.PrincipalType, e.PrincipalName, e.AccessLevel})
	}
	assert.ElementsMatch(t, []got{
		{"user", "alice", "write"},
		{"group", "devs", "read"},
	}, rows, "alice (editor→write) and the devs group (viewer→read); bob (auditor, no secrets) and carol (other project) excluded")
}

// TestGenerateProjectAccessReview_IncludesMachineIdentities pins #91: a machine
// identity (CI runner, k8s workload) holding a project-scoped role that confers
// secrets access is a project member exactly like a user or group, but was never
// enumerated — a privileged CI/k8s principal passed through a "completed"
// recertification campaign entirely un-attested.
func TestGenerateProjectAccessReview_IncludesMachineIdentities(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	const proj = uint(2)
	require.NoError(t, h.DB.Create(&models.MachineIdentity{
		ID: 50, ProjectID: proj, Name: "ci-runner", IdentityType: "ci", State: "active",
	}).Error)
	// role_id 3 = editor (secrets.read+write), matching the seeded roles used elsewhere
	// in this file.
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{
		MachineIdentityID: 50, RoleID: 3, ProjectID: proj,
	}).Error)

	report, err := h.CoreService.GenerateProjectAccessReview(context.Background(), proj)
	require.NoError(t, err)

	var found *core.AccessReviewEntry
	for _, e := range report.Entries {
		if e.PrincipalType == "machine" {
			found = e
		}
	}
	require.NotNil(t, found, "the machine identity's role grant must appear in the review")
	assert.Equal(t, uint(50), found.PrincipalID)
	assert.Equal(t, "ci-runner", found.PrincipalName)
	assert.Equal(t, "write", found.AccessLevel)
}

// TestRevokeAccessReviewGrant_MachineRole pins the revoke side of #91: a reviewer
// must be able to close the loop on a machine-identity finding, not just view it.
func TestRevokeAccessReviewGrant_MachineRole(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	require.NoError(t, h.DB.Create(&models.MachineIdentity{
		ID: 50, ProjectID: proj, Name: "ci-runner", IdentityType: "ci", State: "active",
	}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{
		MachineIdentityID: 50, RoleID: 3, ProjectID: proj,
	}).Error)

	err := h.CoreService.RevokeAccessReviewGrant(context.Background(), 1, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "machine", PrincipalID: 50, RoleID: 3,
	})
	require.NoError(t, err)

	var count int64
	require.NoError(t, h.DB.Model(&models.MachineIdentityRole{}).
		Where("machine_identity_id = ? AND role_id = ?", 50, 3).Count(&count).Error)
	assert.Zero(t, count, "the machine's role grant must be removed")
}

// The review also reports per-secret grants: ownership and direct/group shares.
func TestGenerateProjectAccessReview_SharesAndOwnership(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10) // owner
	h.CreateTestUser(t, "bob", 11)   // direct-share recipient
	h.CreateTestGroup(t, "devs", "", 100)

	require.NoError(t, h.DB.Create(&models.Environment{ID: 20, ProjectID: proj, Name: "prod"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 500, ProjectID: proj, EnvironmentID: 20, OwnerID: 10, Name: "db-pw", Type: "password", Status: "active", IsSecret: true,
	}).Error)
	require.NoError(t, h.DB.Create(&models.ShareRecord{SecretID: 500, RecipientID: 11, IsGroup: false, Permission: "read"}).Error)
	require.NoError(t, h.DB.Create(&models.ShareRecord{SecretID: 500, RecipientID: 100, IsGroup: true, Permission: "write"}).Error)

	report, err := h.CoreService.GenerateProjectAccessReview(context.Background(), proj)
	require.NoError(t, err)

	type got struct{ source, typ, name, level, secret string }
	var rows []got
	for _, e := range report.Entries {
		rows = append(rows, got{e.Source, e.PrincipalType, e.PrincipalName, e.AccessLevel, e.SecretName})
	}
	assert.Contains(t, rows, got{"owner", "user", "alice", "owner", "db-pw"})
	assert.Contains(t, rows, got{"direct_share", "user", "bob", "read", "db-pw"})
	assert.Contains(t, rows, got{"group_share", "group", "devs", "write", "db-pw"})
}

func TestGenerateProjectAccessReview_RequiresProject(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	_, err := h.CoreService.GenerateProjectAccessReview(context.Background(), 0)
	require.Error(t, err)
}

// Revoking a role grant removes the underlying role assignment, so it no longer
// appears in a subsequent review.
func TestRevokeAccessReviewGrant_Role(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // editor → write

	ctx := context.Background()
	before, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	require.Len(t, before.Entries, 1, "alice's editor grant is present before revoke")

	err = h.CoreService.RevokeAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "user", PrincipalID: 10, RoleID: 3,
	})
	require.NoError(t, err)

	after, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	assert.Empty(t, after.Entries, "alice's role grant is gone after revoke")
}

// TestRevokeAccessReviewGrant_RejectsSelfCertification is #G52: before the
// fix, the standalone RevokeAccessReviewGrant/AttestAccessReviewGrant
// endpoints had NO reviewer-independence check at all — only
// DecideAccessReviewItem (the campaign flow) enforced it, BEFORE calling
// into these same two functions. A caller reaching them directly (the
// project_members.go standalone HTTP handlers) could self-certify their own
// access.
func TestRevokeAccessReviewGrant_RejectsSelfCertification(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj)) // editor → write

	err := h.CoreService.RevokeAccessReviewGrant(context.Background(), 10, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "user", PrincipalID: 10, RoleID: 3,
	})
	require.Error(t, err, "alice must not be able to revoke her own access")
	assert.Contains(t, err.Error(), "your own access")
}

// TestRevokeAccessReviewGrant_RejectsNonHumanReviewer is #G52: actorID 0
// (a machine-identity credential, which authorizes via PrincipalID not
// UserID) must not be able to act as a reviewer via the standalone endpoint.
func TestRevokeAccessReviewGrant_RejectsNonHumanReviewer(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	err := h.CoreService.RevokeAccessReviewGrant(context.Background(), 0, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "user", PrincipalID: 10, RoleID: 3,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attributable human reviewer")
}

// TestAttestAccessReviewGrant_RejectsSelfCertification_Share is #G52's share
// case: a direct-share recipient must not be able to attest their OWN share
// via the standalone endpoint — AccessReviewDecision.PrincipalType is only
// ever populated for "role" sources, so this exercises
// principalTypeForDecision's "direct_share is always a user" inference.
func TestAttestAccessReviewGrant_RejectsSelfCertification_Share(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.AuditEvent{}))

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10) // owner
	h.CreateTestUser(t, "bob", 11)   // direct-share recipient
	require.NoError(t, h.DB.Create(&models.Environment{ID: 20, ProjectID: proj, Name: "prod"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 500, ProjectID: proj, EnvironmentID: 20, OwnerID: 10, Name: "db-pw", Type: "password", Status: "active", IsSecret: true,
	}).Error)
	require.NoError(t, h.DB.Create(&models.ShareRecord{SecretID: 500, RecipientID: 11, IsGroup: false, Permission: "read"}).Error)

	err := h.CoreService.AttestAccessReviewGrant(context.Background(), 11, proj, core.AccessReviewDecision{
		Source: "direct_share", PrincipalID: 11, SecretID: 500,
	})
	require.Error(t, err, "bob must not be able to attest his own share")
	assert.Contains(t, err.Error(), "your own access")
}

// Revoking a group share removes that ShareRecord; revoking ownership is refused.
func TestRevokeAccessReviewGrant_ShareAndOwner(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10) // owner
	h.CreateTestGroup(t, "devs", "", 100)
	require.NoError(t, h.DB.Create(&models.Environment{ID: 20, ProjectID: proj, Name: "prod"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 500, ProjectID: proj, EnvironmentID: 20, OwnerID: 10, Name: "db-pw", Type: "password", Status: "active", IsSecret: true,
	}).Error)
	require.NoError(t, h.DB.Create(&models.ShareRecord{SecretID: 500, RecipientID: 100, IsGroup: true, Permission: "write"}).Error)

	ctx := context.Background()
	// Revoke the group share.
	err := h.CoreService.RevokeAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "group_share", PrincipalID: 100, SecretID: 500,
	})
	require.NoError(t, err)

	report, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	for _, e := range report.Entries {
		assert.NotEqual(t, "group_share", e.Source, "the group share is gone after revoke")
	}

	// Ownership cannot be revoked through the review.
	err = h.CoreService.RevokeAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "owner", PrincipalID: 10, SecretID: 500,
	})
	require.Error(t, err)

	// A share that doesn't exist is a not-found error, not a silent success.
	err = h.CoreService.RevokeAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "direct_share", PrincipalID: 999, SecretID: 500,
	})
	require.Error(t, err)
}

// TestRevokeAccessReviewGrant_CrossProjectShareRevokeRefused pins #99: a reviewer
// authorized on project A must not be able to revoke a share belonging to a
// secret in project B by passing its SecretID — revokeReviewShare previously
// looked up the share purely by SecretID with no check that the secret actually
// belongs to the caller's project (IDOR).
func TestRevokeAccessReviewGrant_CrossProjectShareRevokeRefused(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))

	const projA, projB = uint(2), uint(3)
	h.CreateTestUser(t, "alice", 10) // owner in project B
	h.CreateTestUser(t, "bob", 11)   // direct-share recipient in project B
	require.NoError(t, h.DB.Create(&models.Environment{ID: 30, ProjectID: projB, Name: "prod"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 600, ProjectID: projB, EnvironmentID: 30, OwnerID: 10, Name: "b-secret", Type: "password", Status: "active", IsSecret: true,
	}).Error)
	require.NoError(t, h.DB.Create(&models.ShareRecord{SecretID: 600, RecipientID: 11, IsGroup: false, Permission: "read"}).Error)

	ctx := context.Background()
	// A reviewer scoped to project A passes project B's SecretID.
	err := h.CoreService.RevokeAccessReviewGrant(ctx, 1, projA, core.AccessReviewDecision{
		Source: "direct_share", PrincipalID: 11, SecretID: 600,
	})
	require.Error(t, err, "a secret from a different project must not be revocable")

	// The share still exists — untouched.
	var count int64
	require.NoError(t, h.DB.Model(&models.ShareRecord{}).Where("secret_id = ? AND recipient_id = ?", 600, 11).Count(&count).Error)
	assert.Equal(t, int64(1), count, "the cross-project share must survive the refused revoke attempt")
}

// Attesting a grant changes no access but records an access_review.attested audit
// event as the evidence of recertification.
func TestAttestAccessReviewGrant_AuditsDecision(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	ctx := context.Background()
	err := h.CoreService.AttestAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "user", PrincipalID: 10, RoleID: 3,
	})
	require.NoError(t, err)

	// The grant is untouched — still in the review.
	report, err := h.CoreService.GenerateProjectAccessReview(ctx, proj)
	require.NoError(t, err)
	assert.Len(t, report.Entries, 1, "attest does not change access")

	var count int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccessReviewAttested).Count(&count).Error)
	assert.Equal(t, int64(1), count, "an access_review.attested event was recorded")
}

func TestRevokeAccessReviewGrant_RequiresProject(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	err := h.CoreService.RevokeAccessReviewGrant(context.Background(), 1, 0, core.AccessReviewDecision{Source: "role"})
	require.Error(t, err)
}

// #209: attesting a role grant that has since been revoked (or never existed) must
// be refused, not silently recorded as clean compliance evidence — an attestation
// certifies "I reviewed and confirmed this access is still needed," which would be a
// false statement for a grant that's already gone.
func TestAttestAccessReviewGrant_RefusesRevokedRoleGrant(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	ctx := context.Background()
	// The grant is revoked through a path unrelated to the (now-stale) campaign item...
	require.NoError(t, h.CoreService.RevokeAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "user", PrincipalID: 10, RoleID: 3,
	}))

	// ...so attesting the same decision (as a reviewer acting on stale campaign data
	// would) must be refused, not recorded as clean evidence.
	err := h.CoreService.AttestAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "user", PrincipalID: 10, RoleID: 3,
	})
	require.Error(t, err, "attesting a grant that no longer exists must be refused")

	var count int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccessReviewAttested).Count(&count).Error)
	assert.Equal(t, int64(0), count, "no fabricated attestation evidence must be recorded")
}

// #209: attesting an outright fabricated tuple (a role never assigned to this
// principal) must be refused the same way — the campaign item's cached fields alone
// are not sufficient evidence a grant exists.
func TestAttestAccessReviewGrant_RefusesFabricatedRoleGrant(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10)
	// alice is never actually granted role 3 at project 2.

	err := h.CoreService.AttestAccessReviewGrant(context.Background(), 1, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "user", PrincipalID: 10, RoleID: 3,
	})
	require.Error(t, err, "attesting a grant that was never real must be refused")

	var count int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccessReviewAttested).Count(&count).Error)
	assert.Equal(t, int64(0), count, "no fabricated attestation evidence must be recorded")
}

// A live share attestation still succeeds, and a stale/revoked share attestation is
// refused the same way as a role grant.
func TestAttestAccessReviewGrant_Share(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.AuditEvent{}))

	const proj = uint(2)
	h.CreateTestUser(t, "alice", 10) // owner
	h.CreateTestUser(t, "bob", 11)   // direct-share recipient
	require.NoError(t, h.DB.Create(&models.Environment{ID: 20, ProjectID: proj, Name: "prod"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 500, ProjectID: proj, EnvironmentID: 20, OwnerID: 10, Name: "db-pw", Type: "password", Status: "active", IsSecret: true,
	}).Error)
	require.NoError(t, h.DB.Create(&models.ShareRecord{SecretID: 500, RecipientID: 11, IsGroup: false, Permission: "read"}).Error)

	ctx := context.Background()
	// A live share attests cleanly.
	require.NoError(t, h.CoreService.AttestAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "direct_share", PrincipalID: 11, SecretID: 500,
	}))

	// A share that was never granted (fabricated recipient) is refused.
	err := h.CoreService.AttestAccessReviewGrant(ctx, 1, proj, core.AccessReviewDecision{
		Source: "direct_share", PrincipalID: 999, SecretID: 500,
	})
	require.Error(t, err)

	var count int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccessReviewAttested).Count(&count).Error)
	assert.Equal(t, int64(1), count, "exactly the one live attestation was recorded")
}

// TestAttestAccessReviewGrant_MachineRole is #G51's machine-identity gap: a
// machine identity's role grant lives in a separate table from user/group
// grants, so verifyAccessReviewGrantExists must check it too, mirroring
// TestGenerateProjectAccessReview_IncludesMachineIdentities and
// TestRevokeAccessReviewGrant_MachineRole (#91) — before the fix, this
// attestation spuriously failed "no longer exists" for a grant that was very
// much live.
func TestAttestAccessReviewGrant_MachineRole(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	require.NoError(t, h.DB.Create(&models.MachineIdentity{
		ID: 50, ProjectID: proj, Name: "ci-runner", IdentityType: "ci", State: "active",
	}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{
		MachineIdentityID: 50, RoleID: 3, ProjectID: proj,
	}).Error)

	err := h.CoreService.AttestAccessReviewGrant(context.Background(), 1, proj, core.AccessReviewDecision{
		Source: "role", PrincipalType: "machine", PrincipalID: 50, RoleID: 3,
	})
	require.NoError(t, err, "a live machine-identity role grant must attest cleanly")

	var count int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccessReviewAttested).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// TestAttestAccessReviewGrant_RefusesCrossProjectShare is #G51's cross-tenant
// IDOR: a reviewer authorized on project 2 must not be able to certify (as
// compliance evidence) a share belonging to a secret in a DIFFERENT project,
// by passing that secret's ID alongside a recipient who happens to hold SOME
// share on it. Mirrors revokeReviewShare's identical guard (#99).
func TestAttestAccessReviewGrant_RefusesCrossProjectShare(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.AuditEvent{}))

	const reviewedProject = uint(2)
	const otherProject = uint(3)
	h.CreateTestUser(t, "alice", 10) // owner, other project
	h.CreateTestUser(t, "bob", 11)   // direct-share recipient, other project
	require.NoError(t, h.DB.Create(&models.Environment{ID: 30, ProjectID: otherProject, Name: "prod"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 501, ProjectID: otherProject, EnvironmentID: 30, OwnerID: 10, Name: "other-project-secret", Type: "password", Status: "active", IsSecret: true,
	}).Error)
	require.NoError(t, h.DB.Create(&models.ShareRecord{SecretID: 501, RecipientID: 11, IsGroup: false, Permission: "read"}).Error)

	// A reviewer scoped to reviewedProject attests a share on a secret that
	// actually lives in otherProject — must be refused as "not found", not
	// silently certified.
	err := h.CoreService.AttestAccessReviewGrant(context.Background(), 1, reviewedProject, core.AccessReviewDecision{
		Source: "direct_share", PrincipalID: 11, SecretID: 501,
	})
	require.Error(t, err, "a share on a secret outside the reviewed project must be refused")

	var count int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccessReviewAttested).Count(&count).Error)
	assert.Equal(t, int64(0), count, "no cross-project attestation evidence must be recorded")
}

// TestAttestAccessReviewGrant_RefusesCrossProjectOwnership is the "owner"
// source analogue of the share IDOR above.
func TestAttestAccessReviewGrant_RefusesCrossProjectOwnership(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SecretNode{}, &models.Environment{}, &models.AuditEvent{}))

	const reviewedProject = uint(2)
	const otherProject = uint(3)
	h.CreateTestUser(t, "alice", 10)
	require.NoError(t, h.DB.Create(&models.Environment{ID: 30, ProjectID: otherProject, Name: "prod"}).Error)
	require.NoError(t, h.DB.Create(&models.SecretNode{
		ID: 502, ProjectID: otherProject, EnvironmentID: 30, OwnerID: 10, Name: "other-project-secret", Type: "password", Status: "active", IsSecret: true,
	}).Error)

	err := h.CoreService.AttestAccessReviewGrant(context.Background(), 1, reviewedProject, core.AccessReviewDecision{
		Source: "owner", PrincipalID: 10, SecretID: 502,
	})
	require.Error(t, err, "ownership of a secret outside the reviewed project must be refused")

	var count int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccessReviewAttested).Count(&count).Error)
	assert.Equal(t, int64(0), count, "no cross-project attestation evidence must be recorded")
}
