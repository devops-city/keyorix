package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sodMachineGrantModels = append(append([]any{}, sodGrantModels...),
	&models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.MachineIdentityCredential{})

// TestConcurrency_AssignMachineRole_CrossReplicaPostgres_SoDBypass is GUARD-2's
// own regression test for the gap found by its inventory sweep:
// AssignMachineRole's check-then-write (requireMachineGrantNoSoDViolation,
// then storage.AssignMachineRole) had NO serialization at all before this —
// not even an in-process mutex, unlike AssignUserRole's sodGrantMu
// predecessor. Two independent replicas, own *gorm.DB connection each (own
// LocalStorage, own KeyorixCore) into the SAME real Postgres schema, race two
// individually SoD-clean role grants — each carrying one half of a toxic
// permission pair — against the SAME target machine identity, mirroring
// TestConcurrency_AssignUserRole_CrossReplicaPostgres_SoDBypass (#1646)
// exactly, substituting a machine identity for a user principal. Uses the
// GUARD-2 raceReplicas harness (concurrency_race_harness_test.go) instead of
// hand-rolling its own barrier.
func TestConcurrency_AssignMachineRole_CrossReplicaPostgres_SoDBypass(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(sodMachineGrantModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("sod-machine-race-token")
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "sod-machine-race-token",
	})
	require.NoError(t, err)

	proj, err := setupCore.CreateProject(ctx, "sod-machine-race-project", "")
	require.NoError(t, err)

	// Two roles, each carrying exactly one half of a toxic permission pair --
	// individually harmless, jointly toxic (identical pair to #1646's own test).
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

	roleAName, err := identity.NewFoldedName("sod-machine-race-role-a")
	require.NoError(t, err)
	roleA, err := setupCore.Storage().CreateRole(ctx, roleAName, "grants roles.assign")
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignPermissionToRole(ctx, 0, roleA.ID, rolesAssignID, false))
	roleBName, err := identity.NewFoldedName("sod-machine-race-role-b")
	require.NoError(t, err)
	roleB, err := setupCore.Storage().CreateRole(ctx, roleBName, "grants secrets.delete")
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignPermissionToRole(ctx, 0, roleB.ID, secretsDeleteID, false))

	_, err = setupCore.CreateSoDPolicy(ctx, bootRes.User.ID, "machine-race-policy", "roles.assign + secrets.delete is toxic", "roles.assign", "secrets.delete")
	require.NoError(t, err)

	machine, err := setupCore.CreateMachineIdentity(ctx, proj.ID, "sod-race-machine", MachineTypeOther, "", "", bootRes.User.ID, 0)
	require.NoError(t, err)

	// Two independent replicas, own connections into the SAME schema.
	coreA := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	scope := Scope{ProjectID: proj.ID}

	res := raceReplicas(t,
		func() error {
			return coreA.AssignMachineRole(ctx, machine.ID, roleA.ID, scope, bootRes.User.ID, false)
		},
		func() error {
			return coreB.AssignMachineRole(ctx, machine.ID, roleB.ID, scope, bootRes.User.ID, false)
		},
	)

	t.Logf("grant A (roles.assign) result: %v", res.ErrA)
	t.Logf("grant B (secrets.delete) result: %v", res.ErrB)

	// Verify from a fresh connection, independent of either racing replica.
	verifierDB := pgOpen(t, dsn)
	var grantedRoleIDs []uint
	require.NoError(t, verifierDB.WithContext(ctx).Model(&models.MachineIdentityRole{}).
		Where("machine_identity_id = ?", machine.ID).Pluck("role_id", &grantedRoleIDs).Error)
	hasA, hasB := false, false
	for _, rid := range grantedRoleIDs {
		if rid == roleA.ID {
			hasA = true
		}
		if rid == roleB.ID {
			hasB = true
		}
	}
	t.Logf("machine holds roleA=%v roleB=%v", hasA, hasB)

	if hasA && hasB {
		t.Errorf("SoD BYPASS CONFIRMED: machine identity holds BOTH roleA (roles.assign) and roleB (secrets.delete) -- "+
			"the toxic combination the preventive gate exists to block, granted by two racing replicas that each "+
			"passed an individually-clean check (errA=%v errB=%v)", res.ErrA, res.ErrB)
	}
	// Positive assertion: exactly one grant may have landed live.
	assert.False(t, hasA && hasB, "at most one of the two toxic-pair roles may be live on the machine identity")
	assert.True(t, hasA || hasB, "at least one of the two racing grants should have succeeded")
}
