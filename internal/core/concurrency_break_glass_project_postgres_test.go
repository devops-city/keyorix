package core

// concurrency_break_glass_project_postgres_test.go — the cross-replica
// counterpart to TestConcurrency_RevokeBreakGlassActivationAtomic_TOCTOU_Deterministic
// (concurrency_break_glass_toctou_test.go), same relationship as
// concurrency_remove_user_role_project_postgres_test.go has to the RemoveUserRole
// local test: two independent Postgres connections/replicas, own LocalStorage,
// own KeyorixCore, proving storage.WithNamedLock's pg_advisory_lock itself spans
// RevokeBreakGlassActivationAtomic's guard-then-transaction sequence, not just
// an in-process mutex.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_RevokeBreakGlassActivationAtomic_CrossReplicaPostgres proves
// the last-project-admin guard and the role removal + activation-state
// transaction stay serialized across two genuinely independent Postgres
// connections, using the same delayed-write technique as the local
// deterministic test.
func TestConcurrency_RevokeBreakGlassActivationAtomic_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(append(removeUserRoleProjectModels, &models.BreakGlassActivation{})...))
	require.NoError(t, setupDB.Create(&models.Permission{Name: "roles.assign"}).Error)
	require.NoError(t, setupDB.Create(&models.Project{Name: "proj"}).Error)

	var proj models.Project
	require.NoError(t, setupDB.Where("name = ?", "proj").First(&proj).Error)
	var perm models.Permission
	require.NoError(t, setupDB.Where("name = ?", "roles.assign").First(&perm).Error)

	role := models.Role{Name: "proj_admin"}
	require.NoError(t, setupDB.Create(&role).Error)
	require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	nameA, err := identity.NewFoldedName("bg-admin-a")
	require.NoError(t, err)
	nameB, err := identity.NewFoldedName("bg-admin-b")
	require.NoError(t, err)
	userA := models.User{Username: nameA.String()}
	userB := models.User{Username: nameB.String()}
	require.NoError(t, setupDB.Create(&userA).Error)
	require.NoError(t, setupDB.Create(&userB).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: userA.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: userB.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)

	expiresAt := time.Now().Add(2 * time.Hour)
	setupStorage := localstore.NewLocalStorage(setupDB)
	ctx := context.Background()
	activationA, err := setupStorage.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: proj.ID, UserID: userA.ID, RoleID: role.ID, RoleName: role.Name,
		Justification: "pg cross-replica toctou test A", State: BreakGlassActive, ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)
	activationB, err := setupStorage.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: proj.ID, UserID: userB.ID, RoleID: role.ID, RoleName: role.Name,
		Justification: "pg cross-replica toctou test B", State: BreakGlassActive, ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)

	// Replica A: own connection, wrapped to pause its RemoveRole write for userA.
	wrapped := &pgDelayedRemoveRoleStorage{
		inner:        localstore.NewLocalStorage(pgOpen(t, dsn)),
		targetUserID: userA.ID, targetRoleID: role.ID,
		blocked: make(chan struct{}), release: make(chan struct{}),
	}
	coreA := NewKeyorixCore(wrapped.store())
	// Replica B: its own, independent connection.
	coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))

	scope := Scope{ProjectID: proj.ID}

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		errA = coreA.RevokeBreakGlassActivationAtomic(ctx, 0, 0, activationA, time.Now())
	}()

	<-wrapped.blocked // revoking activationA passed the guard and is paused right before its write lands

	go func() {
		defer close(doneB)
		errB = coreB.RevokeBreakGlassActivationAtomic(ctx, 0, 0, activationB, time.Now())
	}()

	// Give replica B's revoke a generous bounded window to run to COMPLETION
	// before releasing replica A's delayed write -- see
	// concurrency_remove_user_role_toctou_test.go's file doc comment for why
	// waiting for completion (not merely "started reading") is required.
	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
	}
	close(wrapped.release)
	<-doneA
	<-doneB

	t.Logf("revoke A result: %v", errA)
	t.Logf("revoke B result: %v", errB)

	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)
	remainingA, err := verifier.GetUserRoleIDsExact(ctx, userA.ID, scope)
	require.NoError(t, err)
	remainingB, err := verifier.GetUserRoleIDsExact(ctx, userB.ID, scope)
	require.NoError(t, err)
	aSurvives, bSurvives := len(remainingA) > 0, len(remainingB) > 0

	t.Logf("A survives=%v B survives=%v", aSurvives, bSurvives)

	if !aSurvives && !bSurvives {
		t.Errorf("LAST-PROJECT-ADMIN GUARD BYPASSED ACROSS REPLICAS (break-glass): two independent Postgres "+
			"connections, each racing a break-glass revoke through the guard before either write committed, "+
			"removed BOTH project admins' role grants -- the project is left with zero roles.assign holders "+
			"(errA=%v errB=%v)", errA, errB)
	}
	assert.False(t, !aSurvives && !bSurvives, "at least one of the two racing revokes must be refused")
	assert.True(t, aSurvives || bSurvives, "exactly one admin's grant should survive")
}
