package core

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newPreFixOrderingCore spins up a fresh in-memory SQLite store (full
// production schema) without running BootstrapSystem, so the caller controls
// the exact bootstrap ordering.
func newPreFixOrderingCore(t *testing.T) *KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, kxstorage.MigrateExisting(db))

	return NewKeyorixCore(store.NewLocalStorage(db))
}

// seedDefaultCatalog seeds the canonical permission/role catalog exactly as
// bootstrapSystemLocked does — independent of whether any user has been
// created yet, so a test can control that ordering itself.
func seedDefaultCatalog(t *testing.T, c *KeyorixCore) {
	t.Helper()
	ctx := context.Background()

	permIDs := make(map[string]uint, len(defaultPermissions))
	for _, def := range defaultPermissions {
		p, err := c.storage.CreatePermission(ctx, &models.Permission{
			Name: def.Name, Description: def.Description, Resource: def.Resource, Action: def.Action,
		})
		require.NoError(t, err)
		permIDs[def.Name] = p.ID
	}
	for _, rdef := range defaultRoles {
		foldedName, ferr := identity.NewFoldedName(rdef.Name)
		require.NoError(t, ferr)
		role, err := c.storage.CreateRole(ctx, foldedName, rdef.Description)
		require.NoError(t, err)
		for _, name := range rdef.Permissions {
			require.NoError(t, c.storage.AssignPermissionToRole(ctx, role.ID, permIDs[name]))
		}
	}
}

// bootstrapWithPreFixOrdering reproduces the exact sequence
// bootstrapSystemLocked used before #2188 fixed it: CreateUser runs BEFORE the
// permission/role catalog is seeded, so CreateUser's own best-effort
// system_viewer auto-assign (ADR-021) deterministically misses — GetRoleByName
// finds nothing yet — leaving the resulting admin without the baseline role.
// This is the exact starting state ReconcileUserBaselineRoles exists to
// repair on every subsequent restart of an install that was bootstrapped this
// way (v0.95.0 and earlier, any backend).
//
// Deliberately reproduces the ordering with independent test code rather than
// depending on bootstrapSystemLocked's OWN current ordering, so this
// regression test stays meaningful regardless of whether #2188 has landed on
// whatever branch it runs against.
func bootstrapWithPreFixOrdering(t *testing.T, c *KeyorixCore) *models.User {
	t.Helper()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
	})
	require.NoError(t, err)

	seedDefaultCatalog(t, c)

	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, c.storage.AssignRole(ctx, user.ID, adminRole.ID, Scope{}))
	return user
}

func userHasRoleName(t *testing.T, c *KeyorixCore, userID uint, roleName string) bool {
	t.Helper()
	roles, err := c.storage.GetUserRoles(context.Background(), userID)
	require.NoError(t, err)
	for _, r := range roles {
		if r.Name == roleName {
			return true
		}
	}
	return false
}

// countBaselineBackfillAuditEvents counts role.assigned RBAC audit entries
// tagged reason=baseline_role_backfill for targetUserID — the marker
// LogRoleAssignedBackfill writes (audit.go), distinguishing a startup repair
// grant from an ordinary role.assigned event.
func countBaselineBackfillAuditEvents(t *testing.T, c *KeyorixCore, targetUserID uint) int {
	t.Helper()
	entries, _, err := c.ListRBACAuditLogs(context.Background(), 1, 100)
	require.NoError(t, err)
	n := 0
	for _, e := range entries {
		if e.Action != EventRoleAssigned || e.TargetUserID == nil || *e.TargetUserID != targetUserID {
			continue
		}
		if strings.Contains(e.Details, "reason="+reasonBaselineRoleBackfill) {
			n++
		}
	}
	return n
}

func TestReconcileUserBaselineRoles_RepairsPreFixOrdering(t *testing.T) {
	t.Parallel()
	c := newPreFixOrderingCore(t)
	admin := bootstrapWithPreFixOrdering(t, c)
	ctx := context.Background()

	// Precondition: the admin created under the old ordering does NOT hold
	// system_viewer — the exact defect #2188's own regression test proved for
	// a fresh bootstrap.
	require.False(t, userHasRoleName(t, c, admin.ID, "system_viewer"))
	require.True(t, userHasRoleName(t, c, admin.ID, "admin"), "sanity: admin role itself was granted")

	// Restart #1: the reconcile repairs the existing install.
	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))
	assert.True(t, userHasRoleName(t, c, admin.ID, "system_viewer"), "admin must now hold the baseline role")
	assert.Equal(t, 1, countBaselineBackfillAuditEvents(t, c, admin.ID),
		"exactly one audit event must record the backfill grant")

	// The admin role itself, and every other grant, must be untouched.
	assert.True(t, userHasRoleName(t, c, admin.ID, "admin"), "reconcile must never remove or change any other role")

	// Restart #2: idempotent — nothing new is granted or logged.
	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))
	assert.True(t, userHasRoleName(t, c, admin.ID, "system_viewer"))
	assert.Equal(t, 1, countBaselineBackfillAuditEvents(t, c, admin.ID),
		"a second restart must grant nothing new — no duplicate audit event")

	roles, err := c.storage.GetUserRoles(ctx, admin.ID)
	require.NoError(t, err)
	systemViewerCount := 0
	for _, r := range roles {
		if r.Name == "system_viewer" {
			systemViewerCount++
		}
	}
	assert.Equal(t, 1, systemViewerCount, "no duplicate role assignment row after a second restart")
}

// TestReconcileUserBaselineRoles_SkipsUsersAlreadyCorrect proves the reconcile
// is additive-only: a user who already holds system_viewer (created normally,
// via the production CreateUser path, once the catalog already exists — the
// #2188-fixed ordering) is left untouched by the reconcile — no duplicate
// grant, no audit event.
func TestReconcileUserBaselineRoles_SkipsUsersAlreadyCorrect(t *testing.T) {
	t.Parallel()
	c := newPreFixOrderingCore(t)
	seedDefaultCatalog(t, c)
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "normal", Email: "normal@example.com", Password: "BootstrapPass123!", DisplayName: "Normal",
	})
	require.NoError(t, err)
	require.True(t, userHasRoleName(t, c, user.ID, "system_viewer"), "sanity: CreateUser's own auto-assign already granted it")

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))

	assert.Equal(t, 0, countBaselineBackfillAuditEvents(t, c, user.ID), "a user who already holds the role must not be touched")
}

func TestReconcileUserBaselineRoles_NoopOnFreshInstall(t *testing.T) {
	t.Parallel()
	c := newPreFixOrderingCore(t)
	// Empty catalog (pre-bootstrap): system_viewer does not exist yet, so
	// reconcile must do nothing — first-boot seeding (as fixed by #2188) owns
	// this case.
	require.NoError(t, c.ReconcileUserBaselineRoles(context.Background()))
}

// TestReconcileUserBaselineRoles_OneTimeMarkerBlocksLaterRestarts proves the
// #2195 rework: the completion marker makes the sweep run exactly once. A
// later restart must skip entirely and grant nothing — even when a user has
// since lost the role by some other means — because the marker exists
// specifically to stop an ordinary restart from re-litigating role state the
// install may have changed on purpose after the one-time repair ran.
func TestReconcileUserBaselineRoles_OneTimeMarkerBlocksLaterRestarts(t *testing.T) {
	t.Parallel()
	c := newPreFixOrderingCore(t)
	admin := bootstrapWithPreFixOrdering(t, c)
	ctx := context.Background()

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))
	require.True(t, userHasRoleName(t, c, admin.ID, "system_viewer"), "sanity: first run repaired the admin")
	require.Equal(t, 1, countBaselineBackfillAuditEvents(t, c, admin.ID))

	role, err := c.storage.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	require.NoError(t, c.storage.RemoveRole(ctx, admin.ID, role.ID, Scope{}))
	require.False(t, userHasRoleName(t, c, admin.ID, "system_viewer"), "sanity: the role really is gone now")

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))
	assert.False(t, userHasRoleName(t, c, admin.ID, "system_viewer"),
		"the one-time marker must block a later restart from re-granting a role the install has since changed")
	assert.Equal(t, 1, countBaselineBackfillAuditEvents(t, c, admin.ID),
		"the marker-blocked restart must write no new backfill audit event")
}

// TestReconcileUserBaselineRoles_SkipsAdminRemovedUser proves the other half
// of the #2195 rework: a user with a role.removed audit event for
// system_viewer — an admin's own deliberate removal, which RemoveUserRole
// permits since nothing protects the baseline role — is never re-granted by
// the sweep, even on the one run that does execute.
func TestReconcileUserBaselineRoles_SkipsAdminRemovedUser(t *testing.T) {
	t.Parallel()
	c := newPreFixOrderingCore(t)
	admin := bootstrapWithPreFixOrdering(t, c)
	ctx := context.Background()

	role, err := c.storage.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)

	// Simulate an admin's deliberate removal of the baseline role, recorded
	// in the RBAC audit trail exactly as RemoveUserRole would have logged it.
	c.LogRoleRemoved(ctx, admin.ID, admin.ID, role.ID, Scope{})

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))

	assert.False(t, userHasRoleName(t, c, admin.ID, "system_viewer"),
		"a user with a role.removed history for system_viewer must never be re-granted by the reconcile")
	assert.Equal(t, 0, countBaselineBackfillAuditEvents(t, c, admin.ID),
		"no backfill audit event must be written for a skipped, deliberately-removed user")
}

// TestReconcileUserBaselineRoles_SkipsSSOJITNonDefaultRoleUser proves the
// third category of #2195's rework: a user JIT-provisioned via SSO whose
// provider config sets a DefaultRole other than system_viewer must never be
// granted system_viewer by the sweep — that user's baseline was chosen
// deliberately by the install's own SSO config, not lost to the pre-#2188
// bug this reconcile repairs.
func TestReconcileUserBaselineRoles_SkipsSSOJITNonDefaultRoleUser(t *testing.T) {
	t.Parallel()
	c := newPreFixOrderingCore(t)
	bootstrapWithPreFixOrdering(t, c)
	ctx := context.Background()

	p := &SSOProvider{Name: "okta", DefaultRole: "admin"}
	jit, err := c.provisionSSOUser(ctx, p, "okta|999", "jit@example.com", true, "JIT User")
	require.NoError(t, err)
	require.True(t, userHasRoleName(t, c, jit.ID, "admin"), "sanity: JIT provisioning granted the configured role")
	require.False(t, userHasRoleName(t, c, jit.ID, "system_viewer"), "sanity: JIT provisioning did not grant system_viewer")

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))

	assert.False(t, userHasRoleName(t, c, jit.ID, "system_viewer"),
		"an SSO JIT user with a configured non-default DefaultRole must never be granted system_viewer by the reconcile")
	assert.Equal(t, 0, countBaselineBackfillAuditEvents(t, c, jit.ID),
		"no backfill audit event must be written for a skipped SSO JIT non-default-role user")
}

// TestReconcileUserBaselineRoles_RepairsPreFixOrdering_Postgres mirrors the
// SQLite case against a real, isolated PostgreSQL schema, migrated exactly as
// production does. Skips (does not fail) when KEYORIX_TEST_PG_DSN is unset.
func TestReconcileUserBaselineRoles_RepairsPreFixOrdering_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgMigratedDatabaseDSN(t, base)
	db := pgOpen(t, dsn)
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	c := NewKeyorixCore(store.NewLocalStorage(db))
	admin := bootstrapWithPreFixOrdering(t, c)
	ctx := context.Background()

	require.False(t, userHasRoleName(t, c, admin.ID, "system_viewer"))

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))
	assert.True(t, userHasRoleName(t, c, admin.ID, "system_viewer"))
	assert.Equal(t, 1, countBaselineBackfillAuditEvents(t, c, admin.ID))

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))
	assert.Equal(t, 1, countBaselineBackfillAuditEvents(t, c, admin.ID), "second restart on Postgres grants nothing new")
}

// legacySSOJITUser creates a user exactly as provisionSSOUser did BEFORE the
// structured ssoJITProvisionDetail Diff existed: the configured role granted
// directly, and an auth.sso_jit_provisioned event carrying the role only in
// its free-text Description. Every install the one-time backfill exists to
// repair holds only events of this shape.
func legacySSOJITUser(t *testing.T, c *KeyorixCore, username, roleName string) *models.User {
	t.Helper()
	ctx := context.Background()
	fu, err := identity.NewFoldedName(username)
	require.NoError(t, err)
	fe, err := identity.NewFoldedName(username + "@example.com")
	require.NoError(t, err)
	u, err := c.storage.CreateUser(ctx, &models.User{
		Username: username, UsernameFolded: fu.Folded(),
		Email: username + "@example.com", EmailFolded: fe.Folded(), DisplayName: username,
		IsActive: true, AccountState: AccountActive, ExternalID: ssoExternalID("okta", username),
	})
	require.NoError(t, err)
	r, err := c.storage.GetRoleByName(ctx, roleName)
	require.NoError(t, err)
	require.NoError(t, c.storage.AssignRole(ctx, u.ID, r.ID, Scope{}))
	c.writeAuditEvent(ctx, EventSSOJITProvision, actorPtr(u.ID), nil,
		fmt.Sprintf("SSO JIT-provisioned user %d via %s (externalId=%q, role=%s)", u.ID, "okta", "okta|"+username, roleName))
	return u
}

// TestReconcileUserBaselineRoles_SkipsLegacySSOJITNonDefaultRoleUser: the
// installs this backfill repairs predate the structured JIT Diff, so the
// non-default-role skip must also read legacy Description-only events.
func TestReconcileUserBaselineRoles_SkipsLegacySSOJITNonDefaultRoleUser(t *testing.T) {
	t.Parallel()
	c := newPreFixOrderingCore(t)
	bootstrapWithPreFixOrdering(t, c)
	ctx := context.Background()

	nonDefault := legacySSOJITUser(t, c, "legacy-jit-admin", "admin")
	require.False(t, userHasRoleName(t, c, nonDefault.ID, "system_viewer"), "sanity")

	require.NoError(t, c.ReconcileUserBaselineRoles(ctx))

	assert.False(t, userHasRoleName(t, c, nonDefault.ID, "system_viewer"),
		"a legacy (Description-only) SSO JIT user with a non-default role must never be granted system_viewer")
	assert.Equal(t, 0, countBaselineBackfillAuditEvents(t, c, nonDefault.ID))
}
