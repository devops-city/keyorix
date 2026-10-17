// auth_bootstrap_role_seeding_order_test.go — regression test for a
// code-ordering bug (not a race): bootstrapSystemLocked used to create the
// admin user before seeding the default role catalog, so CreateUser's own
// best-effort "system_viewer" auto-assign (ADR-021) always missed on the
// very first user, on every backend, every time. Confirmed live via a fresh
// docker-compose Postgres bootstrap before this fix: `user_roles` held only
// the "admin" grant for user 1, never "system_viewer", and the backend log
// printed "Warning: user 1 (admin) created without its baseline system_viewer
// role: Role not found" on every fresh-volume boot.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// bootstrapAdminHasSystemViewerBaseline asserts the bootstrap admin holds the
// system_viewer role and that no "created without its baseline system_viewer
// role" warning was logged during bootstrap.
func bootstrapAdminHasSystemViewerBaseline(t *testing.T, c *KeyorixCore, st *store.LocalStorage, adminUsername string, logOutput string) {
	t.Helper()
	ctx := context.Background()

	admin, err := st.GetUserByUsername(ctx, adminUsername)
	require.NoError(t, err)

	roles, err := c.storage.GetUserRoles(ctx, admin.ID)
	require.NoError(t, err)

	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "system_viewer",
		"the bootstrap admin must hold the system_viewer baseline role (ADR-021), same as every later user")
	assert.NotContains(t, logOutput, "created without its baseline system_viewer role",
		"bootstrap must not fall back to the non-fatal warning path — the role must exist before the admin user is created")
}

// TestBootstrapSystem_AdminHoldsSystemViewerBaseline is the SQLite regression
// case. Red before the fix: newBootstrappedCore's own BootstrapSystem call
// created the admin before defaultRoles was seeded, so system_viewer never
// existed yet when CreateUser's internal GetRoleByName(ctx, "system_viewer")
// ran — the assignment silently (but observably, via the Warning log) failed
// every time.
func TestBootstrapSystem_AdminHoldsSystemViewerBaseline(t *testing.T) {
	var c *KeyorixCore
	var st *store.LocalStorage
	logOutput := withCapturedLog(t, func() {
		c, st = newBootstrappedCore(t)
	})
	bootstrapAdminHasSystemViewerBaseline(t, c, st, "admin", logOutput)
}

// TestBootstrapSystem_AdminHoldsSystemViewerBaseline_Postgres is the same
// assertion against a real, isolated PostgreSQL schema, migrated exactly as
// production does (kxstorage.MigrateExisting, not a hand-picked AutoMigrate
// list — see docs/findings on hand-picked-AutoMigrate schema divergence).
// Skips (does not fail) when KEYORIX_TEST_PG_DSN is unset.
func TestBootstrapSystem_AdminHoldsSystemViewerBaseline_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgMigratedDatabaseDSN(t, base)
	db := pgOpen(t, dsn)

	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")

	logOutput := withCapturedLog(t, func() {
		_, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
			Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
			Token: "test-bootstrap-token",
		})
		require.NoError(t, err)
	})
	bootstrapAdminHasSystemViewerBaseline(t, c, st, "admin", logOutput)
}
