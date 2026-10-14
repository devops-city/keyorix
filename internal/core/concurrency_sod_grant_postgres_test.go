package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sodGrantModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
	&models.SoDPolicy{}, &models.AuditEvent{},
}

// TestConcurrency_AssignUserRole_CrossReplicaPostgres_SoDBypass is #1646's SoD
// residual, already established as a real, live-reproducible privilege escalation
// in the original recon -- this is the fix's own regression test, giving two
// independent replicas their OWN *gorm.DB connection (own LocalStorage, own
// KeyorixCore) into the SAME real Postgres schema, then racing two individually
// SoD-clean grants (each carrying one half of a toxic permission pair) against the
// SAME target principal.
//
// Before #1646's fix, sodGrantMu (a KeyorixCore-level sync.Mutex) only serialized
// callers within ONE process -- both replicas could read the target's pre-grant
// permission set, both pass the preventive check individually, and both commit,
// leaving the target holding the full toxic combination the gate exists to block.
// After the fix, AssignUserRole's check-then-write is serialized via
// storage.WithNamedLock's Postgres advisory lock (keyed per target principal): the
// loser re-checks under the lock, now sees the winner's already-committed grant,
// and is correctly refused.
func TestConcurrency_AssignUserRole_CrossReplicaPostgres_SoDBypass(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(sodGrantModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("sod-race-token")
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "sod-race-token",
	})
	require.NoError(t, err)

	// Two roles, each carrying exactly one half of a toxic permission pair --
	// individually harmless, jointly toxic.
	perms, err := setupCore.ListPermissions(ctx)
	require.NoError(t, err)
	var rolesAssignID, secretsDeleteID uint
	for _, p := range perms {
		switch p.Name {
		case "roles.assign":
			rolesAssignID = p.ID
		case "secrets.delete":
			secretsDeleteID = p.ID
		}
	}
	require.NotZero(t, rolesAssignID, "roles.assign must be seeded")
	require.NotZero(t, secretsDeleteID, "secrets.delete must be seeded")

	roleAName, err := identity.NewFoldedName("sod-race-role-a")
	require.NoError(t, err)
	roleA, err := setupCore.Storage().CreateRole(ctx, roleAName, "grants roles.assign")
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignPermissionToRole(ctx, 0, roleA.ID, rolesAssignID, false))
	roleBName, err := identity.NewFoldedName("sod-race-role-b")
	require.NoError(t, err)
	roleB, err := setupCore.Storage().CreateRole(ctx, roleBName, "grants secrets.delete")
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignPermissionToRole(ctx, 0, roleB.ID, secretsDeleteID, false))

	_, err = setupCore.CreateSoDPolicy(ctx, bootRes.User.ID, "race-policy", "roles.assign + secrets.delete is toxic", "roles.assign", "secrets.delete")
	require.NoError(t, err)

	target, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "sod-target", Email: "sod-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	// Two independent replicas, own connections into the SAME schema.
	dbA := pgOpen(t, dsn)
	coreA := NewKeyorixCore(localstore.NewLocalStorage(dbA))
	dbB := pgOpen(t, dsn)
	coreB := NewKeyorixCore(localstore.NewLocalStorage(dbB))

	res := raceReplicas(t,
		func() error { return coreA.AssignUserRole(ctx, bootRes.User.ID, target.ID, roleA.ID, Scope{}, false) },
		func() error { return coreB.AssignUserRole(ctx, bootRes.User.ID, target.ID, roleB.ID, Scope{}, false) },
	)

	t.Logf("grant A (roles.assign) result: %v", res.ErrA)
	t.Logf("grant B (secrets.delete) result: %v", res.ErrB)

	// Verify from a fresh connection, independent of either racing replica.
	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)
	grants, err := verifier.GetUserRoleIDsAt(ctx, target.ID, storage.Scope{})
	require.NoError(t, err)
	hasA, hasB := false, false
	for _, rid := range grants {
		if rid == roleA.ID {
			hasA = true
		}
		if rid == roleB.ID {
			hasB = true
		}
	}
	t.Logf("target holds roleA=%v roleB=%v", hasA, hasB)

	if hasA && hasB {
		t.Errorf("SoD BYPASS CONFIRMED: target holds BOTH roleA (roles.assign) and roleB (secrets.delete) -- "+
			"the toxic combination the preventive gate exists to block, granted by two racing replicas that each "+
			"passed an individually-clean check (errA=%v errB=%v)", res.ErrA, res.ErrB)
	}
	// Positive assertion: exactly one grant may have landed live.
	assert.False(t, hasA && hasB, "at most one of the two toxic-pair roles may be live on the target")
	assert.True(t, hasA || hasB, "at least one of the two racing grants should have succeeded")
}
