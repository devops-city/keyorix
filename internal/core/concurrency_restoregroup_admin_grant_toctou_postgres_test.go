package core

// concurrency_restoregroup_admin_grant_toctou_postgres_test.go — the
// CROSS-REPLICA Postgres counterpart to
// concurrency_restoregroup_admin_grant_toctou_test.go (package core_test),
// which is #2455's existing deterministic regression.
//
// Why this file exists, stated plainly: the SQLite test hands goroutine A and
// goroutine B the SAME storage.Storage instance. On a non-Postgres dialect
// WithNamedLock serializes through that one LocalStorage's own in-process
// namedLockRegistry mutex (local_named_lock.go), so that test cannot
// distinguish "RestoreGroup's read+check+write section is serialized against a
// concurrent grant" from "both callers happened to share one process-local
// mutex." It is a correct regression for the single-process shape and proves
// nothing about the HA shape ADR-039 ships: two replicas, two processes, two
// connection pools, where pg_advisory_lock is the only thing that can still
// serialize them. A fix that silently lost its Postgres branch would leave
// that test green.
//
// This test closes that gap. Each simulated replica gets its OWN *gorm.DB into
// the SAME isolated schema (own LocalStorage, own namedLockRegistry, own
// KeyorixCore), so the in-process mutex is structurally incapable of
// serializing them — only the advisory lock can.
//
// The interleaving is forced, not statistical:
//
//  1. Replica A calls RestoreGroup for a non-global-admin actor. Its real,
//     unmodified GetGroupRoles read runs (role set empty) and
//     requireGlobalAdminToReinstateAdminRoles passes trivially. A then blocks,
//     via a thin storage decorator, immediately before its own storage-level
//     RestoreGroup write — still inside WithNamedLock, still holding
//     sodGrantLockKey("group", id).
//  2. Once A is confirmed blocked there, replica B — a genuinely separate
//     connection — calls the real AssignGroupRoleWithExpiry to grant the group
//     an admin-tier role. That is exactly the call whose storage-level write
//     (assignGroupRole, local_rbac.go) never checks the target group's
//     existence or soft-delete state, so it lands on a soft-deleted group
//     happily.
//  3. B is given a generous bounded window to finish BEFORE A is released.
//     Without a cross-connection lock, nothing blocks B and that window is
//     always enough. With it, B is parked on pg_advisory_lock inside Postgres
//     and the window always elapses.
//
// Skipped (not failed) without KEYORIX_TEST_PG_DSN: pg-gated, per
// docs/security-closures.tsv's verification column convention.
//
// package core (not core_test) for the unexported pgTestDSN /
// pgIsolatedSchemaDSN / pgOpen helpers in postgres_contention_helpers_test.go,
// the same reason concurrency_2352_lastadmin_guard_sweep_postgres_test.go is.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// pgDelayedRestoreGroupStorage wraps a real storage.Storage, pausing exactly
// one targeted RestoreGroup(id) call until released, and signaling blocked
// once it starts waiting. Deliberately a separate type from the core_test
// package's delayedRestoreGroupStorage rather than shared: that one lives in
// an external test package this file cannot import.
type pgDelayedRestoreGroupStorage struct {
	inner            storage.Storage
	targetGroupID    uint
	blocked, release chan struct{}
}

func (d *pgDelayedRestoreGroupStorage) RestoreGroup(next storage.Storage, ctx context.Context, id uint) error {
	if id == d.targetGroupID {
		close(d.blocked)
		<-d.release
	}
	return next.RestoreGroup(ctx, id)
}

// wrap returns inner decorated with pgDelayedRestoreGroupStorage's overrides.
func (d *pgDelayedRestoreGroupStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx:       true,
		RestoreGroup: d.RestoreGroup,
	})
}

// store returns d.inner decorated with pgDelayedRestoreGroupStorage's overrides.
func (d *pgDelayedRestoreGroupStorage) store() storage.Storage { return d.wrap(d.inner) }

// WithTransaction rewraps the tx handle, so the delay still fires now that
// core.RestoreGroup performs its restore write through that handle (#2428)
// rather than the outer storage.
var restoreGroupTOCTOUPGModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SoDPolicy{},
}

func TestConcurrency_RestoreGroup_AdminGrantRace_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(restoreGroupTOCTOUPGModels...))
	require.NoError(t, setupDB.Create(&models.Permission{Name: "roles.assign"}).Error)
	// The admin-tier role's one real signal is the structural bypass flag
	// (ADR-084, roleSetContainsAdmin) -- not its name, not its bundled
	// permissions. Named innocuously on purpose.
	adminRole := models.Role{Name: "sneaky_admin", BypassesPermissionChecks: true}
	require.NoError(t, setupDB.Create(&adminRole).Error)
	nonAdmin := models.User{Username: "rg-nonadmin", UsernameFolded: "rg-nonadmin", IsActive: true, AccountState: AccountActive}
	require.NoError(t, setupDB.Create(&nonAdmin).Error)
	softDeleted := models.Group{Name: "rg-target", NameFolded: "rg-target", DeletedAt: gorm.DeletedAt{Time: time.Now(), Valid: true}}
	require.NoError(t, setupDB.Create(&softDeleted).Error)
	closePG(setupDB) // free the setup connection before the replicas open theirs

	// Two independent pools into the same schema: replica A and replica B each
	// get their own LocalStorage, hence their own in-process namedLockRegistry.
	dbA, dbB := pgOpen(t, dsn), pgOpen(t, dsn)
	defer closePG(dbA)
	defer closePG(dbB)

	wrappedA := &pgDelayedRestoreGroupStorage{
		inner:         localstore.NewLocalStorage(dbA),
		targetGroupID: softDeleted.ID,
		blocked:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	coreA := NewKeyorixCore(wrappedA.store())
	coreB := NewKeyorixCore(localstore.NewLocalStorage(dbB))
	ctx := context.Background()

	var errA, errB error
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(doneA)
		_, errA = coreA.RestoreGroup(ctx, nonAdmin.ID, softDeleted.ID)
	}()

	select {
	case <-wrappedA.blocked: // A's read+check have run and passed; A holds the lock
	case <-time.After(30 * time.Second):
		t.Fatal("replica A never reached its RestoreGroup write — fixture problem, not a finding")
	}

	// actorID 0 is the trusted system pseudo-actor
	// (requireGranterHoldsRolePermissions short-circuits it): it stands in for
	// any sufficiently-privileged granter. The property under test is
	// RestoreGroup's own cross-replica serialization, not this call's gate.
	go func() {
		defer close(doneB)
		errB = coreB.AssignGroupRoleWithExpiry(ctx, 0, softDeleted.ID, adminRole.ID, Scope{}, time.Now().Add(time.Hour), false)
	}()

	var bCompletedBeforeARelease bool
	select {
	case <-doneB:
		bCompletedBeforeARelease = true
	case <-time.After(5 * time.Second):
		bCompletedBeforeARelease = false
	}
	close(wrappedA.release)
	<-doneA
	<-doneB

	t.Logf("replica A restore (actor=non-global-admin) result: %v", errA)
	t.Logf("replica B admin-tier grant result: %v", errB)

	// A connection-level failure must surface as the infra problem it is: its
	// observable effect (B did not complete) is indistinguishable from the lock
	// working, which would turn a broken environment into a false pass.
	if isConnectionError(errA) {
		t.Fatalf("replica A failed with a connection-level error, not an application result: %v", errA)
	}
	if isConnectionError(errB) {
		t.Fatalf("replica B failed with a connection-level error, not an application result: %v", errB)
	}

	assert.False(t, bCompletedBeforeARelease,
		"ADMIN-GRANT TOCTOU ACROSS REPLICAS (#2455): replica B's admin-tier role grant to group %d "+
			"completed on a SEPARATE connection while replica A's RestoreGroup read+check+write section "+
			"was still in flight for that same group. A's ceiling check could not have seen this grant, "+
			"so a non-global-admin actor's restore was approved against a role set already stale by the "+
			"time it committed. sodGrantLockKey(\"group\", id) is not holding across connections — "+
			"WithNamedLock's pg_advisory_lock branch is the only thing that can close this window in HA "+
			"(ADR-039); the in-process mutex the SQLite regression exercises cannot",
		softDeleted.ID)

	require.NoError(t, errB, "the admin-tier grant must still succeed once it is unblocked, not be lost")
	require.NoError(t, errA, "the restore itself is legitimate (checked against an honestly-empty role set) and must succeed")

	verifier := pgOpen(t, dsn)
	defer closePG(verifier)
	var grants int64
	require.NoError(t, verifier.Model(&models.GroupRole{}).
		Where("group_id = ? AND role_id = ?", softDeleted.ID, adminRole.ID).Count(&grants).Error)
	assert.EqualValues(t, 1, grants,
		"the admin-tier grant must land exactly once, and only AFTER the restore's atomic section released")
}
