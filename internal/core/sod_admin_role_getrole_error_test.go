// sod_admin_role_getrole_error_test.go — deterministic unit test for
// docs/findings/2026-10-02-FINDING-sod-policy-create-getrole-error-misread-as-not-admin.md:
// isGlobalAdminRoleName's GetRole-error `continue` was indistinguishable from a
// successful lookup resolving to a non-admin role, so CreateSoDPolicy denied (and
// audited as a DENIAL) a genuine admin whenever the one GetRole call it needs
// transiently failed.
package core

import (
	"context"
	"errors"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getRoleErrStub wraps a real storage.Storage and overrides exactly GetRole
// to inject a fixed error, mirroring the secretReadErrStub /
// mfaSecretReadErrStub pattern used elsewhere in this package.
type getRoleErrStub struct {
	corestorage.Storage
	err error
}

func (s *getRoleErrStub) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Storage.GetRole(ctx, id)
}

// TestCreateSoDPolicy_GetRoleErrorIsNotMisreadAsNonAdmin: the bootstrapped
// admin's sole role is an admin-tier role (per isGlobalAdminRoleName's own
// reproduction in the finding). A GetRole failure resolving that one role must
// surface as a retrieval error, not a permission-denied, and must NOT write a
// "DENIED: not admin-tier" audit event for an actor who was never actually
// evaluated as non-admin.
func TestCreateSoDPolicy_GetRoleErrorIsNotMisreadAsNonAdmin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)

	realStorage := c.storage
	faultErr := errors.New("fault-fuzz injected failure")
	c.storage = &getRoleErrStub{Storage: realStorage, err: faultErr}

	_, err = c.CreateSoDPolicy(ctx, admin.ID, "fault-test-policy", "", "secrets.read", "secrets.write")
	require.Error(t, err, "a GetRole storage error must still refuse the create")
	assert.NotContains(t, err.Error(), "admin-tier",
		"a storage error must not be reported as a permission denial")
	assert.ErrorIs(t, err, faultErr, "the real storage error must be visible to the caller, not swallowed")

	// No DENIED audit event, and no policy, from the faulted attempt.
	var deniedCount int64
	require.NoError(t, st.DB().Model(&models.AuditEvent{}).
		Where("description LIKE ?", "%is not an admin-tier principal%").Count(&deniedCount).Error)
	assert.Zero(t, deniedCount,
		"a storage error must not be audited as a confirmed non-admin denial")

	policies, err := c.ListSoDPolicies(ctx)
	require.NoError(t, err)
	assert.Empty(t, policies, "the faulted create must not have persisted a policy")

	// Fault clears: the SAME admin, never actually demoted, can now create the
	// policy — proving admin status was never really lost, just unconfirmable.
	c.storage = realStorage
	policy, err := c.CreateSoDPolicy(ctx, admin.ID, "fault-test-policy", "", "secrets.read", "secrets.write")
	require.NoError(t, err)
	require.NotNil(t, policy)
}

// roleIDOrderStub wraps a real storage.Storage and makes GetUserRoleIDsAt
// return a FIXED, caller-chosen id order (GetUserGroupRoleIDsAt returns
// empty) -- real SQL order is unspecified (no ORDER BY in GetUserRoleIDsAt),
// so a test that needs the dangling id checked BEFORE the real admin id
// cannot rely on insertion/rowid order holding by chance.
type roleIDOrderStub struct {
	corestorage.Storage
	ids []uint
}

func (s *roleIDOrderStub) GetUserRoleIDsAt(ctx context.Context, userID uint, scope corestorage.Scope) ([]uint, error) {
	return s.ids, nil
}

func (s *roleIDOrderStub) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope corestorage.Scope) ([]uint, error) {
	return nil, nil
}

// ResolveUserPermissionAt (PERF-FIX-6) reads through this stub's own role-id
// methods, so an Authorize on it sees the same fixed role set.
func (s *roleIDOrderStub) ResolveUserPermissionAt(ctx context.Context, userID uint, scope corestorage.Scope, permission string) (*corestorage.PrincipalPermission, error) {
	return corestorage.ComposeUserPermissionAt(ctx, s, userID, scope, permission)
}

// TestIsGlobalAdminRoleName_DanglingRoleReferenceIsSkippedNotFailed: a
// user-role row pointing at a since-deleted role (AT4's orphan class, guard
// #2380) must NOT block every subsequent isGlobalAdminRoleName check for
// that user forever -- a role that no longer exists cannot confer
// admin-bypass either way, so GetRole's genuine "not found" is "not this
// role, keep looking," not a resolution error to fail closed on. The
// dangling id is forced to resolve BEFORE the real admin id (roleIDOrderStub)
// so this actually exercises the continue branch, not just "found admin on
// the first iteration regardless."
func TestIsGlobalAdminRoleName_DanglingRoleReferenceIsSkippedNotFailed(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	adminRoleIDs, err := st.GetUserRoleIDsAt(ctx, admin.ID, corestorage.Scope{})
	require.NoError(t, err)
	require.NotEmpty(t, adminRoleIDs, "sanity check: the bootstrapped admin must hold at least one role")

	const danglingRoleID = 999999
	_, err = st.GetRole(ctx, danglingRoleID)
	require.Error(t, err, "sanity check: this role ID must not actually exist")
	require.True(t, corestorage.IsRoleNotFound(err), "sanity check: must be a genuine not-found, not some other error")

	// Dangling id first, then every one of the admin's real role ids -- the
	// dangling one must be checked and skipped before the real admin role(s)
	// are ever reached.
	c.storage = &roleIDOrderStub{Storage: c.storage, ids: append([]uint{danglingRoleID}, adminRoleIDs...)}

	policy, err := c.CreateSoDPolicy(ctx, admin.ID, "dangling-role-test-policy", "", "secrets.read", "secrets.write")
	require.NoError(t, err, "a dangling role checked BEFORE a real admin role must still recognize admin-tier")
	require.NotNil(t, policy)
}

// TestIsGlobalAdminRoleName_SoleRoleDanglingEvaluatesToNotAdmin: when the
// ONLY role a user holds is a dangling reference, isGlobalAdminRoleName
// must still reach a definite verdict ("", nil) -- not an error -- so the
// caller correctly (and accurately) denies as a confirmed non-admin, not a
// resolution failure.
func TestIsGlobalAdminRoleName_SoleRoleDanglingEvaluatesToNotAdmin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	nonAdmin, err := st.CreateUser(ctx, foldedTestUser(t, "eve", "eve@example.com"))
	require.NoError(t, err)

	const danglingRoleID = 999998
	require.NoError(t, st.DB().Create(&models.UserRole{UserID: nonAdmin.ID, RoleID: danglingRoleID}).Error)

	_, err = c.CreateSoDPolicy(ctx, nonAdmin.ID, "dangling-sole-role-test-policy", "", "secrets.read", "secrets.write")
	require.Error(t, err, "a sole dangling role reference must evaluate to a confirmed non-admin, not succeed")
	assert.Contains(t, err.Error(), "admin-tier",
		"must be the genuine permission-denied path, not a retrieval error")

	var deniedCount int64
	require.NoError(t, st.DB().Model(&models.AuditEvent{}).
		Where("description LIKE ?", "%is not an admin-tier principal%").Count(&deniedCount).Error)
	assert.EqualValues(t, 1, deniedCount,
		"a confirmed (not merely unconfirmable) non-admin denial is correctly audited as a real denial")
}
