package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedClassificationGateFixture creates a project, a requester (owner of the
// secret and project viewer, so ValidateSecretAccess passes the owner + live-
// membership check introduced in #1205/RBAC-001), an admin approver, and a
// secret at the given classification with one version.
func seedClassificationGateFixture(t *testing.T, st *store.LocalStorage, classification string) (secretID, requesterID, approverID, projectID uint) {
	t.Helper()
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "classification-gate-" + classification + "-test"})
	require.NoError(t, err)

	requester, err := st.CreateUser(ctx, foldedTestUser(t, "requester-"+classification, "requester-"+classification+"@example.com"))
	require.NoError(t, err)

	// Assign the requester a project-scoped viewer role so IsProjectMember
	// (added as an owner-bypass gate in #1205) returns true. Without this the
	// owner shortcut in CheckSecretPermission falls through to "permission denied".
	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, requester.ID, viewerRole.ID, storage.Scope{ProjectID: proj.ID}))

	approver, err := st.CreateUser(ctx, foldedTestUser(t, "approver-"+classification, "approver-"+classification+"@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, approver.ID, adminRole.ID, storage.Scope{}))

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: requester.ID, Status: "active", Classification: classification,
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t-value"),
	})
	require.NoError(t, err)

	return secret.ID, requester.ID, approver.ID, proj.ID
}

// Requirement (1): the setting defaults to false, so a "restricted" secret reads
// exactly like any other, for both a permission-checked user read and a direct
// (machine-shaped) read with no user ID at all.
func TestClassificationGate_OffByDefault_RestrictedSecretUnaffected(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	// c.classificationRestrictedRequiresApproval is the zero value (false) —
	// never touched in this test, pinning the true out-of-the-box default.
	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.NoError(t, err, "restricted must read like any other secret while the gate is off")
	assert.Equal(t, "s3cr3t-value", string(val))

	// Machine-shaped direct read (no user ID) is likewise unaffected.
	val, err = c.GetSecretValue(ctx, secretID)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-value", string(val))

	// Metadata reads were never gated and stay that way.
	secret, err := c.GetSecret(ctx, secretID)
	require.NoError(t, err)
	assert.Equal(t, ClassificationRestricted, secret.Classification)
}

// Requirement (2): with the setting on, an unapproved read of a restricted
// secret is denied — even for a user who otherwise has full (owner) read rights.
func TestClassificationGate_OnAndUnapproved_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
	assert.Contains(t, err.Error(), "approved access request")
}

// Requirement (2)/machine consideration: a read with no identifiable user (the
// same shape server/http uses for a machine-principal read, or the embedded
// CLI) must be denied too — fail-closed, no silent bypass for automation.
func TestClassificationGate_OnAndNoUser_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, _, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	_, err := c.GetSecretValue(ctx, secretID)
	require.Error(t, err, "a read with no identifiable user must be denied, not silently allowed")
	assert.Contains(t, err.Error(), "restricted")
}

// Requirement (3): with an approved, valid AccessRequest scoped to that secret,
// the read succeeds.
func TestClassificationGate_OnAndApproved_Succeeds(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	// Sanity: unapproved is still denied at this point.
	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.Error(t, err)

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it for an incident")
	require.NoError(t, err)
	assert.Equal(t, AccessRequestPending, req.State)
	require.NotNil(t, req.SecretID)
	assert.Equal(t, secretID, *req.SecretID)

	approved, err := c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)
	assert.Equal(t, AccessRequestApproved, approved.State)
	// No role is granted for a secret-scoped request.
	assert.Empty(t, approved.GrantedRole)

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.NoError(t, err, "an approved, secret-scoped access request must let the read through")
	assert.Equal(t, "s3cr3t-value", string(val))

	// By-version read is gated (and unblocked) the same way.
	val, err = c.GetSecretValueByVersionWithPermissionCheck(ctx, secretID, requesterID, 1)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement (4): a lower-tier classified secret is never gated, regardless of
// the setting.
func TestClassificationGate_LowerTierNeverGated(t *testing.T) {
	t.Parallel()
	for _, level := range []string{ClassificationPublic, ClassificationInternal, ClassificationConfidential, ""} {
		t.Run("classification="+level, func(t *testing.T) {
			c, st := newBootstrappedCore(t)
			secretID, requesterID, _, _ := seedClassificationGateFixture(t, st, level)
			ctx := context.Background()
			c.SetClassificationRestrictedRequiresApproval(true)

			val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
			require.NoError(t, err, "only the highest tier is gated")
			assert.Equal(t, "s3cr3t-value", string(val))
		})
	}
}

// ApproveSecretAccessRequest's own guards: maker != checker, admin-authority
// ceiling, pending-only, and refusing a project/role (SecretID nil) request.
func TestApproveSecretAccessRequest_Guards(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "")
	require.NoError(t, err)

	// Maker != checker.
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, requesterID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot approve their own")

	// A non-admin approver is refused.
	nonAdmin, err := st.CreateUser(ctx, foldedTestUser(t, "nonadmin", "nonadmin@example.com"))
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, nonAdmin.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "administrator")

	// A project/role (SecretID nil) request is refused by this function.
	roleReq, err := c.RequestProjectAccess(ctx, projectID, requesterID, "viewer", "")
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, roleReq.ID, approverID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a secret-scoped")

	// The real approval succeeds and is idempotent-refusing on a second attempt.
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
}

// ── restricted_requires_permission tests ─────────────────────────────────────

// seedRestrictedPermissionFixture extends the base fixture with a second user who
// owns a restricted secret and holds an explicit secrets.read.restricted grant at
// the project scope — used to verify that the explicit-grant path allows reads.
func seedRestrictedPermissionFixture(t *testing.T, st *store.LocalStorage) (secretID, ownerID, grantedUserID, projectID uint) {
	t.Helper()
	ctx := context.Background()

	secretID, ownerID, _, projectID = seedClassificationGateFixture(t, st, ClassificationRestricted)

	// Create a role with secrets.read.restricted and assign it to grantedUser at
	// the project scope. The user also needs to pass ValidateSecretAccess, so we
	// share the secret with them at read level.
	perm, err := st.CreatePermission(ctx, &models.Permission{Name: PermSecretReadRestricted})
	require.NoError(t, err)

	restrictedReaderName, err := identity.NewFoldedName("restricted-reader")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, restrictedReaderName, "")
	require.NoError(t, err)

	require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, perm.ID))

	grantedUser, err := st.CreateUser(ctx, foldedTestUser(t, "granted-user", "granted@example.com"))
	require.NoError(t, err)

	require.NoError(t, st.AssignRole(ctx, grantedUser.ID, role.ID, storage.Scope{ProjectID: projectID}))

	// Share the secret with grantedUser so ValidateSecretAccess passes.
	secret, err := st.GetSecret(ctx, secretID)
	require.NoError(t, err)
	_, err = st.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secretID,
		OwnerID:     secret.OwnerID,
		RecipientID: grantedUser.ID,
		Permission:  "read",
		IsGroup:     false,
	})
	require.NoError(t, err)

	return secretID, ownerID, grantedUser.ID, projectID
}

// Requirement: off by default — owner (no secrets.read.restricted grant) can still read.
func TestClassificationPermissionGate_OffByDefault_OwnerCanRead(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	// gate is off (zero value); owner has no secrets.read.restricted grant
	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.NoError(t, err, "permission gate off: owner must read unrestricted")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: when on, a user without secrets.read.restricted is denied.
func TestClassificationPermissionGate_On_NoPermission_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
	assert.Contains(t, err.Error(), PermSecretReadRestricted)
}

// Requirement: machine/no-user read is always denied when the gate is active.
func TestClassificationPermissionGate_On_NoUser_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, _, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)

	_, err := c.GetSecretValue(ctx, secretID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
}

// Requirement: admin role bypass — an admin who owns the secret passes both
// ValidateSecretAccess (as owner) and the RBAC check (admin bypass in Authorize).
func TestClassificationPermissionGate_On_AdminAllowed(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// Seed a project and an admin who OWNS the restricted secret.
	proj, err := st.CreateProject(ctx, &models.Project{Name: "admin-restricted-gate-test"})
	require.NoError(t, err)

	admin, err := st.CreateUser(ctx, foldedTestUser(t, "admin-owner", "admin-owner@example.com"))
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, admin.ID, adminRole.ID, storage.Scope{}))

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "top-secret", ProjectID: proj.ID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: admin.ID, Status: "active", Classification: ClassificationRestricted,
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("top-secret-value"),
	})
	require.NoError(t, err)

	c.SetClassificationRestrictedRequiresPermission(true)

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secret.ID, admin.ID)
	require.NoError(t, err, "admin bypass must let an admin owner read a restricted secret")
	assert.Equal(t, "top-secret-value", string(val))
}

// Requirement: explicit secrets.read.restricted grant allows the read.
func TestClassificationPermissionGate_On_ExplicitGrantAllowed(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, _, grantedUserID, _ := seedRestrictedPermissionFixture(t, st)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, grantedUserID)
	require.NoError(t, err, "explicit secrets.read.restricted grant must allow the read")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: lower-tier secrets are never gated by the permission check.
func TestClassificationPermissionGate_On_LowerTierUnaffected(t *testing.T) {
	t.Parallel()
	for _, level := range []string{ClassificationPublic, ClassificationInternal, ClassificationConfidential, ""} {
		t.Run("classification="+level, func(t *testing.T) {
			c, st := newBootstrappedCore(t)
			secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, level)
			ctx := context.Background()
			c.SetClassificationRestrictedRequiresPermission(true)

			val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
			require.NoError(t, err, "permission gate must not affect non-restricted secrets")
			assert.Equal(t, "s3cr3t-value", string(val))
		})
	}
}

// Requirement: when both gates are on, BOTH must be satisfied. A user who holds
// the permission but lacks an approved access request is still denied.
func TestClassificationPermissionGate_Combined_BothRequired(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, _, grantedUserID, _ := seedRestrictedPermissionFixture(t, st)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)
	c.SetClassificationRestrictedRequiresApproval(true)

	// grantedUser has the secrets.read.restricted permission but no approved request.
	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, grantedUserID)
	require.Error(t, err, "both gates active: permission alone is insufficient without approval")
	assert.Contains(t, err.Error(), "access request")
}

// ── restricted_requires_mfa_stepup tests ─────────────────────────────────────

// Requirement: off by default — no change even for a user without a step-up token.
func TestClassificationMFAStepUp_OffByDefault_OwnerCanRead(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.NoError(t, err, "MFA step-up gate off: owner must read unrestricted")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: when on, a user without an active step-up token is denied.
func TestClassificationMFAStepUp_On_NoToken_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
	assert.Contains(t, err.Error(), "MFA")
}

// Requirement: machine/no-user read is always denied when the gate is active.
func TestClassificationMFAStepUp_On_NoUser_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, _, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	_, err := c.GetSecretValue(ctx, secretID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
}

// Requirement: a user with an active (non-expired) step-up grant can read.
func TestClassificationMFAStepUp_On_ActiveToken_Allowed(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	// Directly seed the step-up grant (as VerifyMFAStepUp would).
	expiresAt := c.now().Add(15 * time.Minute)
	require.NoError(t, st.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: ownerID, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: expiresAt}))

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.NoError(t, err, "active MFA step-up grant must allow the read")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: an expired step-up grant is treated as absent — denied.
func TestClassificationMFAStepUp_On_ExpiredToken_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	// Seed an already-expired grant.
	expiredAt := c.now().Add(-1 * time.Minute)
	require.NoError(t, st.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: ownerID, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: expiredAt}))

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err, "expired step-up grant must not grant access")
	assert.Contains(t, err.Error(), "MFA")
}

// Requirement: lower-tier secrets are never gated by the MFA step-up check.
func TestClassificationMFAStepUp_On_LowerTierUnaffected(t *testing.T) {
	t.Parallel()
	for _, level := range []string{ClassificationPublic, ClassificationInternal, ClassificationConfidential, ""} {
		t.Run("classification="+level, func(t *testing.T) {
			c, st := newBootstrappedCore(t)
			secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, level)
			ctx := context.Background()
			c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

			val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
			require.NoError(t, err, "MFA step-up gate must not affect non-restricted secrets")
			assert.Equal(t, "s3cr3t-value", string(val))
		})
	}
}

// Requirement: combined with approval gate — both must pass. A user with a valid
// step-up token but no approved access request is still denied.
func TestClassificationMFAStepUp_Combined_BothRequired(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	// Give the owner an active step-up grant.
	require.NoError(t, st.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: ownerID, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: c.now().Add(15 * time.Minute)}))

	// No approved access request yet → denied.
	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err, "approval gate must still deny even with a valid MFA step-up token")
	assert.Contains(t, err.Error(), "access request")
}

// Requirement: when windowMinutes > 0 the custom duration is applied and surfaced in
// the denial message, exercising the positive-windowMinutes branch of
// SetClassificationRestrictedRequiresMFAStepUp.
func TestClassificationMFAStepUp_On_CustomWindow_Denied(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 5) // positive windowMinutes

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "5m0s", "denial must mention the custom 5-minute window")
}

// ── HTTP-route-layer core additions: RequestSecretAccess dedup, GetSecretAccessRequest,
// RejectSecretAccessRequest, ListSecretAccessRequestsForUser ──────────────────

// #G82's sibling gap for the secret-scoped shape: a second pending request for
// the SAME (user, secret) pair must be refused, exactly as RequestProjectAccess
// already refuses a second pending (user, project) role request.
func TestRequestSecretAccess_DuplicatePendingRefused(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	first, err := c.RequestSecretAccess(ctx, secretID, requesterID, "first")
	require.NoError(t, err)

	_, err = c.RequestSecretAccess(ctx, secretID, requesterID, "second")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already have a pending")

	// Once the first is resolved, a fresh request is allowed again.
	_, err = c.ApproveSecretAccessRequest(ctx, first.ID, approverID)
	require.NoError(t, err)
	_, err = c.RequestSecretAccess(ctx, secretID, requesterID, "third")
	require.NoError(t, err, "a new request must be allowed once the prior one is resolved")
}

// A request against a DIFFERENT secret is unaffected by an existing pending
// request on this one (the dedup guard is scoped per-secret, not per-project).
func TestRequestSecretAccess_DuplicateGuardScopedPerSecret(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, _, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	_, err := c.RequestSecretAccess(ctx, secretID, requesterID, "first")
	require.NoError(t, err)

	otherSecret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "other-secret", ProjectID: projectID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: requesterID, Status: "active", Classification: ClassificationRestricted,
	})
	require.NoError(t, err)

	_, err = c.RequestSecretAccess(ctx, otherSecret.ID, requesterID, "different secret")
	require.NoError(t, err, "a pending request on a different secret must not block this one")
}

// GetSecretAccessRequest's visibility rules: the requester sees their own
// request, an admin at the project sees it too, an unrelated non-admin gets
// the SAME "not found" a truly nonexistent ID would produce, and a project/role
// (SecretID nil) request ID is likewise reported not found through this accessor.
func TestGetSecretAccessRequest_Visibility(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it")
	require.NoError(t, err)

	// Requester sees their own.
	got, err := c.GetSecretAccessRequest(ctx, req.ID, requesterID)
	require.NoError(t, err)
	assert.Equal(t, req.ID, got.ID)

	// Admin at the project sees it too.
	got, err = c.GetSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)
	assert.Equal(t, req.ID, got.ID)

	// An unrelated non-admin gets a "not found" identical to a bogus ID.
	stranger, err := st.CreateUser(ctx, &models.User{Username: "stranger", Email: "stranger@example.com", IsActive: true})
	require.NoError(t, err)
	_, errStranger := c.GetSecretAccessRequest(ctx, req.ID, stranger.ID)
	require.Error(t, errStranger)
	_, errBogus := c.GetSecretAccessRequest(ctx, 999999, stranger.ID)
	require.Error(t, errBogus)
	assert.Equal(t, errBogus.Error(), errStranger.Error(), "a real request the caller can't see must read identically to a nonexistent one")

	// A project/role request is out of scope for this accessor.
	roleReq, err := c.RequestProjectAccess(ctx, projectID, requesterID, "viewer", "")
	require.NoError(t, err)
	_, errRole := c.GetSecretAccessRequest(ctx, roleReq.ID, approverID)
	require.Error(t, errRole)
	assert.Equal(t, errBogus.Error(), errRole.Error())
}

// RejectSecretAccessRequest mirrors ApproveSecretAccessRequest's own guards:
// admin-authority ceiling, pending-only, and refusing a project/role request.
func TestRejectSecretAccessRequest_Guards(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "")
	require.NoError(t, err)

	// A non-admin rejecter is refused.
	nonAdmin, err := st.CreateUser(ctx, &models.User{Username: "nonadmin-reject", Email: "nonadmin-reject@example.com", IsActive: true})
	require.NoError(t, err)
	_, err = c.RejectSecretAccessRequest(ctx, req.ID, nonAdmin.ID, 0, "no")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "administrator")

	// A project/role (SecretID nil) request is refused by this function.
	roleReq, err := c.RequestProjectAccess(ctx, projectID, requesterID, "viewer", "")
	require.NoError(t, err)
	_, err = c.RejectSecretAccessRequest(ctx, roleReq.ID, approverID, 0, "no")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a secret-scoped")

	// The real rejection succeeds, and the read stays refused afterward.
	c.SetClassificationRestrictedRequiresApproval(true)
	rejected, err := c.RejectSecretAccessRequest(ctx, req.ID, approverID, 0, "not now")
	require.NoError(t, err)
	assert.Equal(t, AccessRequestRejected, rejected.State)
	_, err = c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.Error(t, err, "a rejected request must not satisfy the classification gate")

	// A second reject attempt refuses (no longer pending).
	_, err = c.RejectSecretAccessRequest(ctx, req.ID, approverID, 0, "again")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
}

// ListSecretAccessRequestsForUser splits visible requests into "mine" and
// "pendingApproval", excluding self-approval and requests the caller has no
// authority over.
func TestListSecretAccessRequestsForUser(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it")
	require.NoError(t, err)

	// Requester's own view: "mine" has it, "pendingApproval" does not (no
	// self-approval listing) even though the request is pending.
	mine, pending, err := c.ListSecretAccessRequestsForUser(ctx, requesterID)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	assert.Equal(t, req.ID, mine[0].ID)
	assert.Empty(t, pending, "a requester must never see their own request in their approval queue")

	// Approver's view: "pendingApproval" has it, "mine" does not.
	mine, pending, err = c.ListSecretAccessRequestsForUser(ctx, approverID)
	require.NoError(t, err)
	assert.Empty(t, mine)
	require.Len(t, pending, 1)
	assert.Equal(t, req.ID, pending[0].ID)

	// An unrelated non-admin sees neither.
	stranger, err := st.CreateUser(ctx, &models.User{Username: "stranger-list", Email: "stranger-list@example.com", IsActive: true})
	require.NoError(t, err)
	mine, pending, err = c.ListSecretAccessRequestsForUser(ctx, stranger.ID)
	require.NoError(t, err)
	assert.Empty(t, mine)
	assert.Empty(t, pending)

	// Once resolved, it drops out of the approver's pending queue but stays
	// in the requester's "mine".
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)
	mine, pending, err = c.ListSecretAccessRequestsForUser(ctx, approverID)
	require.NoError(t, err)
	assert.Empty(t, mine)
	assert.Empty(t, pending, "a resolved request must not remain in the approval queue")
	mine, _, err = c.ListSecretAccessRequestsForUser(ctx, requesterID)
	require.NoError(t, err)
	require.Len(t, mine, 1)
}

// End-to-end classification-gate lifecycle over the new core surface: request
// -> approve unlocks the read for the approved (user, secret) pair -> a
// rejected request on a DIFFERENT secret never unlocks it -> the approval
// never lets a different user, or a read of a different secret, piggyback on
// it (not reusable across secrets or users).
func TestSecretAccessRequestLifecycle_ApproveGrantsRejectRefuses(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	// A second restricted secret, and a second requester, to prove the
	// eventual grant does not leak across either axis.
	otherSecret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "other-secret-2", ProjectID: projectID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: requesterID, Status: "active", Classification: ClassificationRestricted,
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: otherSecret.ID, VersionNumber: 1, EncryptedValue: []byte("other-value"),
	})
	require.NoError(t, err)
	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	otherUser, err := st.CreateUser(ctx, &models.User{Username: "other-requester", Email: "other-requester@example.com", IsActive: true})
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, otherUser.ID, viewerRole.ID, storage.Scope{ProjectID: projectID}))

	// Reject a request on the OTHER secret — must not affect the first secret at all.
	otherReq, err := c.RequestSecretAccess(ctx, otherSecret.ID, requesterID, "")
	require.NoError(t, err)
	_, err = c.RejectSecretAccessRequest(ctx, otherReq.ID, approverID, 0, "no")
	require.NoError(t, err)
	_, err = c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.Error(t, err, "an unrelated rejection must not affect this secret's gate")

	// Approve the real request.
	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it")
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)

	// The approved (user, secret) pair reads — any number of times.
	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-value", string(val))
	val, err = c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-value", string(val))

	// Not reusable across secrets: the same requester still cannot read the
	// OTHER secret (whose own request was rejected, not approved).
	_, err = c.GetSecretValueWithPermissionCheck(ctx, otherSecret.ID, requesterID)
	require.Error(t, err, "an approval for one secret must not unlock a different secret")

	// Not reusable across users: a different user, even with equivalent project
	// membership, gets no benefit from someone else's approved request.
	_, err = c.GetSecretValueWithPermissionCheck(ctx, secretID, otherUser.ID)
	require.Error(t, err, "an approval for one user must not unlock the read for a different user")
}

// Coverage gap found in review of #2032: nothing exercised a secret-scoped
// request's WithdrawAccessRequest path end to end. WithdrawAccessRequest
// itself (invitations.go) is reused unchanged, and its own project/role-scoped
// behavior is covered elsewhere -- this pins that reuse actually holds for
// the classification gate specifically: a withdrawn secret-scoped request
// must (1) leave GetSecretValueWithPermissionCheck denied, exactly like a
// rejected one, and (2) be refused by both ApproveSecretAccessRequest and
// RejectSecretAccessRequest afterward (their own `state != pending` guards),
// not silently accepted a second time.
func TestWithdrawSecretAccessRequest_LeavesGateDeniedAndRefusesLaterResolution(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it")
	require.NoError(t, err)
	require.NoError(t, c.WithdrawAccessRequest(ctx, req.ID, requesterID))

	_, err = c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.Error(t, err, "a withdrawn secret-scoped request must not satisfy the classification gate")

	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.Error(t, err, "a withdrawn request must not be approvable")
	assert.Contains(t, err.Error(), "only a pending")

	_, err = c.RejectSecretAccessRequest(ctx, req.ID, approverID, 0, "too late")
	require.Error(t, err, "a withdrawn request must not be rejectable either")
	assert.Contains(t, err.Error(), "only a pending")
}
