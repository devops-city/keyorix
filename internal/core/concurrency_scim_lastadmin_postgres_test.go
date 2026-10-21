package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var scimLastAdminModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
	&models.SoDPolicy{}, &models.AuditEvent{}, &models.PendingAuditEvent{},
}

// TestConcurrency_UpdateSCIMUser_CrossReplicaPostgres_LastAdminGuard is GUARD-2's
// regression test for the inventory's Item B: UpdateSCIMUser's last-admin guard
// (guardLastAdminDeactivation + the deactivating write) was serialized ONLY by
// accountStateMu, an in-process mutex — cross-replica-unsafe, as scim.go's own
// prior comment already named. Two independent replicas, own *gorm.DB connection
// each (own LocalStorage, own KeyorixCore) into the SAME real Postgres schema,
// race two concurrent SCIM deactivations of the install's only two remaining
// global admins — each individually observes "the other admin survives" (true
// at the instant of its own unlocked read) and, before this fix, both proceed,
// jointly stranding the install with zero admins.
func TestConcurrency_UpdateSCIMUser_CrossReplicaPostgres_LastAdminGuard(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(scimLastAdminModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("scim-lastadmin-race-token")
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "scimlaboot", Email: "scimlaboot@example.com", Password: "Xk7#Qp2$Rn5@Wv9!",
		DisplayName: "Install Owner", Token: "scim-lastadmin-race-token",
	})
	require.NoError(t, err)

	adminRole, err := setupCore.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	admin1, err := setupCore.ProvisionSCIMUser(ctx, 0, "scim-admin-1@example.com", "SCIM Admin 1", "", "ext-scim-admin-1", true)
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignUserRole(ctx, bootRes.User.ID, admin1.ID, adminRole.ID, Scope{}, false))

	admin2, err := setupCore.ProvisionSCIMUser(ctx, 0, "scim-admin-2@example.com", "SCIM Admin 2", "", "ext-scim-admin-2", true)
	require.NoError(t, err)
	require.NoError(t, setupCore.AssignUserRole(ctx, bootRes.User.ID, admin2.ID, adminRole.ID, Scope{}, false))

	// Demote the bootstrap admin itself, now that two other admins exist to receive
	// the install's "at least one admin" invariant — leaves exactly two global
	// admins (admin1, admin2), both SCIM-managed, both targetable by UpdateSCIMUser.
	require.NoError(t, setupCore.RemoveUserRole(ctx, bootRes.User.ID, bootRes.User.ID, adminRole.ID, Scope{}))

	// Two independent replicas, own connections into the SAME schema.
	coreA := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))
	inactive := false

	res := raceReplicas(t,
		func() error {
			_, err := coreA.UpdateSCIMUser(ctx, 0, admin1.ID, nil, nil, &inactive)
			return err
		},
		func() error {
			_, err := coreB.UpdateSCIMUser(ctx, 0, admin2.ID, nil, nil, &inactive)
			return err
		},
	)

	t.Logf("deactivate admin1 result: %v", res.ErrA)
	t.Logf("deactivate admin2 result: %v", res.ErrB)

	// Verify from a fresh connection, independent of either racing replica.
	verifierDB := pgOpen(t, dsn)
	var admin1Active, admin2Active bool
	require.NoError(t, verifierDB.WithContext(ctx).Model(&models.User{}).Where("id = ?", admin1.ID).Pluck("is_active", &admin1Active).Error)
	require.NoError(t, verifierDB.WithContext(ctx).Model(&models.User{}).Where("id = ?", admin2.ID).Pluck("is_active", &admin2Active).Error)
	t.Logf("admin1 active=%v admin2 active=%v", admin1Active, admin2Active)

	if !admin1Active && !admin2Active {
		t.Errorf("LAST-ADMIN BYPASS CONFIRMED: both of the install's only two admins were deactivated by two racing "+
			"SCIM replicas that each observed the other admin survive (errA=%v errB=%v) — the install is now stranded "+
			"with zero administrators", res.ErrA, res.ErrB)
	}
	// Positive assertion: at least one admin must survive the race.
	assert.True(t, admin1Active || admin2Active, "at least one of the install's last two admins must remain active after the race")
}
