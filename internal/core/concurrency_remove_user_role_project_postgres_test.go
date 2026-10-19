package core

// concurrency_remove_user_role_project_postgres_test.go — the cross-replica
// counterpart to TestConcurrency_RemoveUserRole_ProjectScope_TOCTOU_Deterministic
// (concurrency_remove_user_role_toctou_test.go): same deterministic
// delayed-write technique, but each "replica" gets its OWN *gorm.DB connection
// into the SAME real Postgres schema (own LocalStorage, own KeyorixCore), so
// storage.WithNamedLock's pg_advisory_lock -- not an in-process sync.Mutex -- is
// the only thing that can still serialize them. A plain timing race here (no
// artificial delay) could not land the bug reliably either, for the same
// structural reason documented in concurrency_last_admin_race_test.go: 20+
// trials across 2-way and 8-way races, real Postgres, always left exactly one
// admin standing even against the unfixed code.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pgDelayedRemoveRoleStorage is this file's own copy of
// concurrency_remove_user_role_toctou_test.go's delayedRemoveRoleStorage --
// that one lives in package core_test (external, black-box), this file lives
// in package core (needed for the unexported pgTestDSN/pgOpen/pgIsolatedSchemaDSN
// helpers in postgres_contention_helpers_test.go), so the two can't share the
// type directly. See that file's doc comment for the full mechanism rationale.
type pgDelayedRemoveRoleStorage struct {
	inner                      storage.Storage
	targetUserID, targetRoleID uint
	blocked, release           chan struct{}
}

// WithTransaction wraps the transaction-scoped storage.Storage fn receives
// with an identical decorator sharing this one's channels -- see
// concurrency_remove_user_role_toctou_test.go's delayedRemoveRoleStorage.WithTransaction
// for the full rationale (RevokeBreakGlassActivationAtomic's tx.RemoveRole
// call needs this to be paused at all).
func (d *pgDelayedRemoveRoleStorage) RemoveRole(next storage.Storage, ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	if userID == d.targetUserID && roleID == d.targetRoleID {
		close(d.blocked)
		<-d.release
	}
	return next.RemoveRole(ctx, userID, roleID, scope)
}

// wrap returns inner decorated with pgDelayedRemoveRoleStorage's overrides.
func (d *pgDelayedRemoveRoleStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx:     true,
		RemoveRole: d.RemoveRole,
	})
}

// store returns d.inner decorated with pgDelayedRemoveRoleStorage's overrides.
func (d *pgDelayedRemoveRoleStorage) store() storage.Storage { return d.wrap(d.inner) }

var removeUserRoleProjectModels = []any{
	&models.User{}, &models.Session{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SystemMetadata{},
}

// TestConcurrency_RemoveUserRole_ProjectScope_CrossReplicaPostgres proves
// storage.WithNamedLock's pg_advisory_lock -- not just the in-process mutex the
// local SQLite test exercises -- actually spans RemoveUserRole's write, using
// two independent Postgres connections/replicas (own LocalStorage, own
// KeyorixCore) into the same schema. Same delayed-write technique as the local
// deterministic test: replica A's write is paused right after it passes the
// guard, replica B's call is confirmed to have either already read the
// pre-write state (pre-fix) or be genuinely blocked acquiring the advisory
// lock (post-fix) before A's write is released.
func TestConcurrency_RemoveUserRole_ProjectScope_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(removeUserRoleProjectModels...))
	require.NoError(t, setupDB.Create(&models.Permission{Name: "roles.assign"}).Error)
	require.NoError(t, setupDB.Create(&models.Project{Name: "proj"}).Error)

	var proj models.Project
	require.NoError(t, setupDB.Where("name = ?", "proj").First(&proj).Error)
	var perm models.Permission
	require.NoError(t, setupDB.Where("name = ?", "roles.assign").First(&perm).Error)

	role := models.Role{Name: "proj_admin"}
	require.NoError(t, setupDB.Create(&role).Error)
	require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	nameA, err := identity.NewFoldedName("proj-admin-a")
	require.NoError(t, err)
	nameB, err := identity.NewFoldedName("proj-admin-b")
	require.NoError(t, err)
	userA := models.User{Username: nameA.String()}
	userB := models.User{Username: nameB.String()}
	require.NoError(t, setupDB.Create(&userA).Error)
	require.NoError(t, setupDB.Create(&userB).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: userA.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: userB.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)

	// Replica A: own connection, wrapped to pause its RemoveRole write for userA.
	wrapped := &pgDelayedRemoveRoleStorage{
		inner:        localstore.NewLocalStorage(pgOpen(t, dsn)),
		targetUserID: userA.ID, targetRoleID: role.ID,
		blocked: make(chan struct{}), release: make(chan struct{}),
	}
	coreA := NewKeyorixCore(wrapped.store())
	// Replica B: its own, independent connection.
	coreB := NewKeyorixCore(localstore.NewLocalStorage(pgOpen(t, dsn)))

	ctx := context.Background()
	scope := Scope{ProjectID: proj.ID}

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		errA = coreA.RemoveUserRole(ctx, 0, userA.ID, role.ID, scope)
	}()

	<-wrapped.blocked // replica A's removal passed the guard and is paused right before its write lands

	go func() {
		defer close(doneB)
		errB = coreB.RemoveUserRole(ctx, 0, userB.ID, role.ID, scope)
	}()

	// Give replica B's call a generous bounded window to run to COMPLETION
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

	t.Logf("remove A result: %v", errA)
	t.Logf("remove B result: %v", errB)

	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)
	remainingA, err := verifier.GetUserRoleIDsExact(ctx, userA.ID, scope)
	require.NoError(t, err)
	remainingB, err := verifier.GetUserRoleIDsExact(ctx, userB.ID, scope)
	require.NoError(t, err)
	aSurvives, bSurvives := len(remainingA) > 0, len(remainingB) > 0

	t.Logf("A survives=%v B survives=%v", aSurvives, bSurvives)

	if !aSurvives && !bSurvives {
		t.Errorf("LAST-PROJECT-ADMIN GUARD BYPASSED ACROSS REPLICAS: two independent Postgres connections, "+
			"each racing through the guard before either write committed, removed BOTH project admins' role "+
			"grants -- the project is left with zero roles.assign holders (errA=%v errB=%v)", errA, errB)
	}
	assert.False(t, !aSurvives && !bSurvives, "at least one of the two racing removals must be refused")
	assert.True(t, aSurvives || bSurvives, "exactly one admin's grant should survive")
}
