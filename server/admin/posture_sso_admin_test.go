package admin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// adminSpec is one global administrator to seed; externalID != "" makes the
// account IdP-managed (SSO JIT-provisioned or SCIM-provisioned).
type adminSpec struct {
	name       string
	externalID string
}


func ssoOnlyAdminReport(t *testing.T, specs ...adminSpec) *postureReport {
	t.Helper()
	cfg := writeSecureBaselineConfig(t)
	report := &postureReport{}
	err := withUsableStorage(cfg, func(store corestorage.Storage) error {
		ctx := context.Background()
		roleName, err := identity.NewFoldedName("admin")
		if err != nil {
			return err
		}
		role, err := store.CreateRole(ctx, roleName, "install administrator")
		if err != nil {
			return err
		}
		// A role is admin-tier only through this flag (ListAdminBypassRoleIDs).
		if err := store.SetRoleBypassesPermissionChecks(ctx, role.ID, true); err != nil {
			return err
		}
		for _, s := range specs {
			u, err := store.CreateUser(ctx, &models.User{
				Username: s.name, UsernameFolded: s.name, Email: s.name + "@x.io", EmailFolded: s.name + "@x.io",
				IsActive: true, AccountState: core.AccountActive, ExternalID: s.externalID,
			})
			if err != nil {
				return err
			}
			if err := store.AssignRole(ctx, u.ID, role.ID, corestorage.Scope{}); err != nil {
				return err
			}
		}
		return collectSSOOnlyAdminPosture(ctx, core.NewKeyorixCore(store), report)
	})
	require.NoError(t, err)
	return report
}

// #2914: an install whose only administrator is SSO-managed has no sign-in
// path that survives an IdP outage or deprovisioning. That is a WARN: shown,
// never a failing deviation.
func TestCollectSSOOnlyAdminPosture(t *testing.T) {
	t.Run("only admin is SSO-managed warns", func(t *testing.T) {
		report := ssoOnlyAdminReport(t, adminSpec{"sso-root", "sso:okta:abc"})
		require.Len(t, report.warnings, 1)
		assert.Contains(t, report.warnings[0], "sso-root")
		assert.Contains(t, report.warnings[0], "break-glass")
		assert.Empty(t, report.deviations, "a WARN must not be a counted deviation")
	})
	t.Run("only admin is SCIM-provisioned warns", func(t *testing.T) {
		report := ssoOnlyAdminReport(t, adminSpec{"scim-root", "scim-ext-1"})
		require.Len(t, report.warnings, 1)
		assert.Empty(t, report.deviations)
	})
	t.Run("several admins, all SSO-managed, warns", func(t *testing.T) {
		report := ssoOnlyAdminReport(t, adminSpec{"a", "sso:okta:a"}, adminSpec{"b", "sso:okta:b"})
		require.Len(t, report.warnings, 1)
	})
	t.Run("one local admin plus an SSO admin does not warn", func(t *testing.T) {
		report := ssoOnlyAdminReport(t, adminSpec{"local-root", ""}, adminSpec{"sso-root", "sso:okta:abc"})
		assert.Empty(t, report.warnings)
		assert.Empty(t, report.deviations)
	})
	t.Run("only a local admin does not warn", func(t *testing.T) {
		report := ssoOnlyAdminReport(t, adminSpec{"local-root", ""})
		assert.Empty(t, report.warnings)
	})
	t.Run("no administrator at all does not warn", func(t *testing.T) {
		report := ssoOnlyAdminReport(t)
		assert.Empty(t, report.warnings)
	})
}
