package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An expired time-bound grant must NOT authorize: the scope-aware role-resolution
// query (which backs Authorize) filters it out the instant it passes, before any
// sweep removes the row. A future grant still resolves.
func TestTimeBoundGrant_ExpiredExcludedFromAuthQueries(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	const proj = uint(2)
	ctx := context.Background()
	scope := storage.Scope{ProjectID: proj}
	h.CreateTestUser(t, "alice", 10)

	// Role 3 (editor) granted but already expired → excluded.
	require.NoError(t, h.Storage.AssignRoleWithExpiry(ctx, 10, 3, scope, time.Now().Add(-time.Minute)))
	// Role 4 (viewer) granted with a future expiry → still active.
	require.NoError(t, h.Storage.AssignRoleWithExpiry(ctx, 10, 4, scope, time.Now().Add(time.Hour)))

	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, scope)
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{4}, ids, "expired editor grant excluded; future viewer grant kept")
}

// An expired grant must also be excluded from the flat role/permission lists that
// build UserContext (and thus gRPC self-scoped permission checks / RequireRole),
// not just the scope-aware queries — otherwise expired access still authorizes
// those paths between sweeps.
func TestTimeBoundGrant_ExpiredExcludedFromFlatRoleAndPermLists(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	// Editor (role 3) grants secrets.read+write; grant it already-expired.
	require.NoError(t, h.Storage.AssignRoleWithExpiry(ctx, 10, 3, storage.Scope{ProjectID: 2}, time.Now().Add(-time.Minute)))

	roles, err := h.Storage.GetUserRoles(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, roles, "expired grant excluded from GetUserRoles (feeds UserContext.Roles)")

	perms, err := h.Storage.GetUserPermissions(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, perms, "expired grant confers no permissions via GetUserPermissions (feeds UserContext.Permissions)")
}

// The sweep removes only expired grants (not permanent or future ones), returns
// the count, and audits each removal as role.expired.
func TestRemoveExpiredRoleGrants_SweepsAndAudits(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	scope := storage.Scope{ProjectID: proj}
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "bob", 11)

	require.NoError(t, h.Storage.AssignRoleWithExpiry(ctx, 10, 3, scope, time.Now().Add(-time.Minute))) // expired
	require.NoError(t, h.Storage.AssignRoleWithExpiry(ctx, 11, 4, scope, time.Now().Add(time.Hour)))    // future
	require.NoError(t, h.Storage.AssignRole(ctx, 11, 3, scope))                                         // permanent

	n, err := h.CoreService.RemoveExpiredRoleGrants(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the expired grant is removed")

	// alice's expired editor grant is gone; bob's two grants remain.
	aliceIDs, err := h.Storage.GetUserRoleIDsAt(ctx, 10, scope)
	require.NoError(t, err)
	assert.Empty(t, aliceIDs)
	bobIDs, err := h.Storage.GetUserRoleIDsAt(ctx, 11, scope)
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{3, 4}, bobIDs)

	var expiredEvents int64
	require.NoError(t, h.DB.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventRoleExpired).Count(&expiredEvents).Error)
	assert.Equal(t, int64(1), expiredEvents, "one role.expired event recorded")
}

// A second sweep with nothing expired removes nothing (idempotent).
func TestRemoveExpiredRoleGrants_NoopWhenNothingExpired(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	require.NoError(t, h.Storage.AssignRole(ctx, 10, 3, storage.Scope{ProjectID: 2}))
	n, err := h.CoreService.RemoveExpiredRoleGrants(ctx, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// Approving an access request with a TTL grants the role time-bound: the grant row
// carries an ExpiresAt roughly TTL in the future and is active until then.
func TestApproveAccessRequestWithExpiry_TimeBound(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	// AuditEvent: the approval's grant commits with its audit rows (AUDIT-TX-2).
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10) // requester
	h.CreateTestUser(t, "admin", 1)  // approver
	// #G15/#93/#107/#141: the approver must themselves hold every permission of
	// the role being granted — grant "admin" globally so the ceiling check's
	// admin bypass applies, mirroring TestApproveAccessRequest_PermanentByDefault.
	h.AssignUserRole(t, 1, 2, nil)

	created, err := h.Storage.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: proj, UserID: 10, SuggestedRole: "editor", State: core.AccessRequestPending,
	})
	require.NoError(t, err)

	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, proj, created.ID, 1, 0, "editor", time.Hour)
	require.NoError(t, err)

	// The grant is active now (within the TTL window).
	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.Contains(t, ids, uint(3), "the time-bound editor grant authorizes within its window")

	// The stored grant carries an expiry ~1h out.
	var ur models.UserRole
	require.NoError(t, h.DB.Where("user_id = ? AND role_id = ? AND project_id = ?", 10, 3, proj).First(&ur).Error)
	require.NotNil(t, ur.ExpiresAt, "the grant is time-bound, not permanent")
	assert.WithinDuration(t, time.Now().Add(time.Hour), *ur.ExpiresAt, 2*time.Minute)
}

// With no TTL, approval grants a permanent role (ExpiresAt nil) — unchanged behavior.
func TestApproveAccessRequest_PermanentByDefault(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	// AuditEvent: the approval's grant commits with its audit rows (AUDIT-TX-2).
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	// #93/#107/#141: the approver must themselves hold every permission of the
	// role being granted — grant "admin" globally so the ceiling check's admin
	// bypass applies.
	h.AssignUserRole(t, 1, 2, nil)

	created, err := h.Storage.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: proj, UserID: 10, SuggestedRole: "editor", State: core.AccessRequestPending,
	})
	require.NoError(t, err)

	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, proj, created.ID, 1, 0, "editor", 0)
	require.NoError(t, err)

	var ur models.UserRole
	require.NoError(t, h.DB.Where("user_id = ? AND role_id = ? AND project_id = ?", 10, 3, proj).First(&ur).Error)
	assert.Nil(t, ur.ExpiresAt, "default approval is permanent")
}
