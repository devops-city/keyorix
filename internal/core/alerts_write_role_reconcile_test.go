package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newAlertsWriteReconcileCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.AuditEvent{},
		&models.UserRole{}, &models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}))
	return &KeyorixCore{storage: store.NewLocalStorage(db)}, db
}

// seedPreF1Catalog simulates an install seeded before alerts.write existed:
// every canonical permission except alerts.write, every defaultRoles entry
// except alert_operator (which didn't exist yet), granted their pre-F1
// baseline. Also creates one CUSTOM (non-builtin) role holding system.write —
// exactly the "every existing role holding system.write" case D-1/F1(b)
// requires the backfill to cover, not just the built-in admin/system_admin.
func seedPreF1Catalog(t *testing.T, c *KeyorixCore, db *gorm.DB) (customRoleID uint) {
	t.Helper()
	ctx := context.Background()
	for _, def := range defaultPermissions {
		if def.Name == permAlertsWrite {
			continue // the "new" permission this install predates
		}
		_, err := c.storage.CreatePermission(ctx, &models.Permission{Name: def.Name, Description: def.Description, Resource: def.Resource, Action: def.Action})
		require.NoError(t, err)
	}
	for _, rdef := range defaultRoles {
		if rdef.Name == "alert_operator" {
			continue // didn't exist pre-F1
		}
		foldedName, err := identity.NewFoldedName(rdef.Name)
		require.NoError(t, err)
		role, err := c.storage.CreateRole(ctx, foldedName, rdef.Description)
		require.NoError(t, err)
		for _, permName := range rdef.Permissions {
			if permName == permAlertsWrite {
				continue
			}
			var p models.Permission
			require.NoError(t, db.Where("name = ?", permName).First(&p).Error)
			require.NoError(t, c.storage.AssignPermissionToRole(ctx, role.ID, p.ID))
		}
	}

	// A custom, operator-created role holding system.write — never present in
	// defaultRoles, so ReconcileRBACPermissions' own top-up (which only visits
	// canonical roles) would never touch it. Only ReconcileAlertsWriteRole's
	// broader "every role holding system.write" sweep reaches this one.
	customFolded, err := identity.NewFoldedName("custom_ops_role")
	require.NoError(t, err)
	custom, err := c.storage.CreateRole(ctx, customFolded, "A pre-existing operator-defined role")
	require.NoError(t, err)
	var systemWritePerm models.Permission
	require.NoError(t, db.Where("name = ?", "system.write").First(&systemWritePerm).Error)
	require.NoError(t, c.storage.AssignPermissionToRole(ctx, custom.ID, systemWritePerm.ID))
	return custom.ID
}

func TestReconcileAlertsWriteRole_SeedsRoleAndBackfillsExistingSystemWriteHolders(t *testing.T) {
	t.Parallel()
	c, db := newAlertsWriteReconcileCore(t)
	customRoleID := seedPreF1Catalog(t, c, db)
	ctx := context.Background()

	// Preconditions: alerts.write does not exist yet; alert_operator role does
	// not exist yet; the custom role holds system.write but not alerts.write.
	_, err := c.storage.GetRoleByName(ctx, "alert_operator")
	require.Error(t, err, "alert_operator must not exist before either reconcile runs")
	assert.False(t, roleHasPerm(t, c, "admin", permAlertsWrite))

	// ReconcileRBACPermissions creates the alerts.write permission and grants it
	// to admin/system_admin (its canonical-role baseline, per adminPermissions)
	// — this must run first in production too (main.go), same ordering.
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	assert.True(t, roleHasPerm(t, c, "admin", permAlertsWrite), "admin's own canonical baseline must include alerts.write")

	require.NoError(t, c.ReconcileAlertsWriteRole(ctx))

	t.Run("alert_operator role seeded with exactly alerts.write", func(t *testing.T) {
		role, err := c.storage.GetRoleByName(ctx, "alert_operator")
		require.NoError(t, err)
		perms, err := c.storage.GetRolePermissions(ctx, role.ID)
		require.NoError(t, err)
		require.Len(t, perms, 1)
		assert.Equal(t, permAlertsWrite, perms[0].Name)
	})

	t.Run("pre-existing custom role holding system.write is backfilled", func(t *testing.T) {
		perms, err := c.storage.GetRolePermissions(ctx, customRoleID)
		require.NoError(t, err)
		var names []string
		for _, p := range perms {
			names = append(names, p.Name)
		}
		assert.Contains(t, names, permAlertsWrite,
			"a role holding system.write before F1 must be granted alerts.write by the one-time backfill (D-1: system.write remains a strict superset)")
	})

	t.Run("a role never holding system.write is untouched", func(t *testing.T) {
		assert.False(t, roleHasPerm(t, c, "viewer", permAlertsWrite),
			"viewer never held system.write — the backfill must not grant alerts.write to it")
	})

	t.Run("marker set: a second run is a true no-op, even after a manual revocation", func(t *testing.T) {
		// Simulate an admin's deliberate post-backfill revocation of alerts.write
		// from the custom role — the same hazard #2195 documents for the
		// baseline-role case. A second reconcile run must NOT silently re-grant it.
		role, err := c.storage.GetRoleByName(ctx, "custom_ops_role")
		require.NoError(t, err)
		var alertsWritePerm models.Permission
		require.NoError(t, db.Where("name = ?", permAlertsWrite).First(&alertsWritePerm).Error)
		require.NoError(t, db.Exec("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?", role.ID, alertsWritePerm.ID).Error)

		require.NoError(t, c.ReconcileAlertsWriteRole(ctx))

		assert.False(t, roleHasPerm(t, c, "custom_ops_role", permAlertsWrite),
			"the one-time marker must prevent a second run from re-granting alerts.write after a deliberate revocation")
	})
}

// TestSeedAlertOperatorRole_AtomicOnPermissionGrantFailure: AssignPermissionToRole
// (the second write) fails — CreateRole must roll back too, via the WithTransaction
// wrapping added alongside this test (internal/core/atomicity_guard_test.go's
// TestAtomicityGuard_UnclassifiedMultiWriteFunction caught this during the F1
// rebase, PR #2244). Before the fix, GetRoleByName's existence check treated
// "alert_operator exists" as "already fully seeded" regardless of whether the
// permission grant ever landed, so a role stuck at zero permissions by a failed
// grant would never be retried or repaired — reusing the same failingStorage
// wrapper mfa_atomicity_test.go's #G08 tests use (same package, same pattern).
//
// Also covers a second, coordinator-found defect in the same function (PR #2244
// review): ReconcileAlertsWriteRole used to write its one-time completion marker
// unconditionally, even when this same injected failure caused the seed AND the
// custom_ops_role backfill grant to fail — permanently locking the install out of
// ever retrying, since the marker check at the top of the function short-circuits
// every subsequent run. This test now asserts the marker is withheld on a failed
// run, and that a second, unimpeded run completes the grant the first run missed.
func TestSeedAlertOperatorRole_AtomicOnPermissionGrantFailure(t *testing.T) {
	t.Parallel()
	c, db := newAlertsWriteReconcileCore(t)
	seedPreF1Catalog(t, c, db)
	ctx := context.Background()

	require.NoError(t, c.ReconcileRBACPermissions(ctx))

	realStorage := c.storage
	c.storage = failingStorage(c.storage, "AssignPermissionToRole")
	err := c.ReconcileAlertsWriteRole(ctx)
	// seedAlertOperatorRole's own error is logged, not propagated by its caller
	// (best-effort, matching ReconcileRBACPermissions' contract) — the backfill
	// loop still runs and the function can still return nil. What this test
	// actually asserts is the DB state, not the return value.
	_ = err

	_, roleErr := c.storage.GetRoleByName(ctx, "alert_operator")
	require.Error(t, roleErr,
		"alert_operator must NOT exist after a failed permission grant — CreateRole must have rolled back inside the same transaction, not left a zero-permission role behind for GetRoleByName's existence check to wrongly treat as fully seeded")

	t.Run("completion marker withheld after a failed run", func(t *testing.T) {
		_, done, err := realStorage.GetSystemMetadata(ctx, alertsWriteRoleBackfillMarkerKey)
		require.NoError(t, err)
		assert.False(t, done,
			"the completion marker must NOT be set after a run with injected failures — setting it "+
				"unconditionally would permanently lock the install out of ever retrying the seed and "+
				"the backfill grant this run failed to complete")
	})

	t.Run("second run, unimpeded, completes the grant the first run missed", func(t *testing.T) {
		c.storage = realStorage
		require.NoError(t, c.ReconcileAlertsWriteRole(ctx))

		role, err := c.storage.GetRoleByName(ctx, "alert_operator")
		require.NoError(t, err, "the second run must seed alert_operator that the first run's injected failure rolled back")
		perms, err := c.storage.GetRolePermissions(ctx, role.ID)
		require.NoError(t, err)
		require.Len(t, perms, 1)
		assert.Equal(t, permAlertsWrite, perms[0].Name)

		assert.True(t, roleHasPerm(t, c, "custom_ops_role", permAlertsWrite),
			"the second run must also complete the system.write backfill grant to custom_ops_role that the first run's injected failure left incomplete")

		_, done, err := realStorage.GetSystemMetadata(ctx, alertsWriteRoleBackfillMarkerKey)
		require.NoError(t, err)
		assert.True(t, done, "the completion marker must be set once a run finishes with zero failures")
	})
}
