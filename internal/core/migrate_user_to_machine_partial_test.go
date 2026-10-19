// migrate_user_to_machine_partial_test.go — #2867: MigrateUserToMachine's
// identity insert and its source-user suspension commit together, and every
// check that can refuse the operation runs BEFORE either write.
//
// Why this exists. The function used to create the machine identity in its own
// transaction and then suspend the user in a second one, reporting the partial
// state in its error when the suspension failed. That left a brand-new machine
// identity beside a still-ACTIVE human account with live sessions and PATs —
// and crucially, the two refusals that reach that path are reachable on
// ORDINARY input, not just under injected faults:
//   - an actor who does not outrank the target (setAccountState's admin-rank
//     ceiling), and
//   - a target who is the install's last global admin (guardLastAdminDeactivation).
//
// Both are now hoisted ahead of any write, and the two writes share one
// transaction, so each of the tests below asserts the same invariant from a
// different angle: NOTHING is committed unless EVERYTHING is.
//
// All of them run against a REAL SQLite store rather than MockStorage, for two
// reasons. A mock's WithTransaction runs its closure inline and commits nothing,
// so it cannot demonstrate a rollback at all — asserting rollback against one
// would be a test whose fixture structurally cannot exercise what its name
// claims. And both refusal paths fan out across roles, permissions, groups and
// group-role grants; stubbing each lookup is brittle and proves less than
// seeding two real admin grants.
//
// Each refusal test asserts its FIXTURE PRECONDITION first — that the guard
// under test really does refuse this target, and that the OTHER guard really
// does pass. Without that, "the migration was refused" says nothing about WHICH
// check refused it, and both tests would have passed for the wrong reason: while
// writing them, the preconditions caught a seeded role that was not actually an
// admin role (admin-ness is Role.BypassesPermissionChecks, ADR-084, not the
// name) and an AutoMigrate list short enough that the guards were failing closed
// on a missing table instead of refusing.
//
// A happy-path test sits alongside them on the same fixture: without it, three
// "nothing was committed" assertions would be satisfied by a function that never
// works.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestMigrateUserToMachine_UnderRankedActorCreatesNoIdentity: the admin-rank
// ceiling must be checked before the insert, not inside the suspension that
// follows it.
// Real store, same reasoning as the last-admin test below: the ceiling check
// fans out over role scopes and role-ID sets, and seeding two real admin grants
// is both simpler and a truer exercise than stubbing each lookup.
//
// A SECOND global admin (user 8) is seeded deliberately so the last-admin guard
// — which now runs first — passes, and the refusal under test is unambiguously
// the rank ceiling rather than the lockout guard.
func TestMigrateUserToMachine_UnderRankedActorCreatesNoIdentity(t *testing.T) {
	t.Parallel()
	c, db := newMigrateRealDBCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "system_admin", NameFolded: "system_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{
		ID: 8, Username: "other-admin", UsernameFolded: "other-admin",
		Email: "oa@example.com", EmailFolded: "oa@example.com",
		AccountState: AccountActive, IsActive: true,
	}).Error)
	require.NoError(t, db.Create(&models.User{
		ID: 9, Username: "weak-actor", UsernameFolded: "weak-actor",
		Email: "wa@example.com", EmailFolded: "wa@example.com",
		AccountState: AccountActive, IsActive: true,
	}).Error)
	// Target (7) and a second admin (8) both hold system_admin; the actor (9)
	// holds nothing, so it does not outrank the target.
	require.NoError(t, db.Create(&models.UserRole{UserID: 7, RoleID: 1, ProjectID: 0}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 8, RoleID: 1, ProjectID: 0}).Error)

	// Fixture preconditions, so a refusal below cannot be the wrong refusal.
	require.NoError(t, c.guardLastAdminDeactivation(ctx, 7),
		"fixture precondition: with a second admin seeded, the last-admin guard must PASS")
	require.Error(t, c.requireAdminRankCeilingForTarget(ctx, 9, 7, "change the account state of"),
		"fixture precondition: the actor must fail the rank ceiling against this target")

	m, err := c.MigrateUserToMachine(ctx, "ci-bot", 3, "", "", 9, 0, true)

	require.Error(t, err, "an actor who does not outrank the target must be refused")
	assert.Nil(t, m)

	// THE INVARIANT: no identity was inserted at all.
	var identities int64
	require.NoError(t, db.Model(&models.MachineIdentity{}).Count(&identities).Error)
	assert.Zero(t, identities, "a refused migration must create no machine identity")

	var user models.User
	require.NoError(t, db.First(&user, uint(7)).Error)
	assert.Equal(t, AccountActive, user.AccountState, "the refused target must stay active")
}

// TestMigrateUserToMachine_LastAdminTargetCreatesNoIdentity: the last-admin
// guard must likewise refuse before the insert. Under the old ordering this
// returned "machine identity N created but failed to suspend source user M" —
// an identity the operator never asked to exist on its own.
// Uses the REAL store rather than mock choreography: guardLastAdminDeactivation
// fans out across targetHasGlobalAdminRole, installAdminRoleIDSet,
// ListProjectRoleAssignments and resolveGlobalAdminHolders, and stubbing each of
// those is both brittle and a worse test — seeding one real system_admin grant
// makes the guard fire for the real reason.
func TestMigrateUserToMachine_LastAdminTargetCreatesNoIdentity(t *testing.T) {
	t.Parallel()
	c, db := newMigrateRealDBCore(t)
	ctx := context.Background()

	// The target is the install's ONLY global administrator.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "system_admin", NameFolded: "system_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 7, RoleID: 1, ProjectID: 0}).Error)

	// Sanity: the guard really does refuse this target on its own, so a refusal
	// below cannot be coming from somewhere else.
	require.Error(t, c.guardLastAdminDeactivation(ctx, 7),
		"fixture precondition: the seeded user must be the last global admin")

	m, err := c.MigrateUserToMachine(ctx, "ci-bot", 3, "", "", 9, 0, true)

	require.Error(t, err, "migrating the install's last global admin must be refused")
	assert.Nil(t, m)

	// THE INVARIANT: refused before any write. Under the old ordering this
	// returned "machine identity N created but failed to suspend source user M".
	var identities int64
	require.NoError(t, db.Model(&models.MachineIdentity{}).Count(&identities).Error)
	assert.Zero(t, identities, "a refused migration must create no machine identity")

	var user models.User
	require.NoError(t, db.First(&user, uint(7)).Error)
	assert.Equal(t, AccountActive, user.AccountState, "the refused target must stay active")
}

// newMigrateRealDBCore builds a core over a REAL SQLite store, so
// WithTransaction is a real transaction whose rollback can be observed. The
// mock's WithTransaction runs its closure inline and commits nothing, so it
// cannot be used for this.
func newMigrateRealDBCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// models.AllTestModels(), not a hand-picked list. guardLastAdminDeactivation
	// and requireAdminRankCeilingForTarget fan out across roles, permissions,
	// groups and group-role grants, and both FAIL CLOSED on a lookup error — so a
	// missing table silently turns "the guard passed" into "the guard errored",
	// and the fixture would be asserting the wrong refusal. Found exactly that
	// way: a 7-model list made the happy path and the ceiling precondition both
	// fail with a lookup error, not with the refusal under test. (CLAUDE.md:
	// hand-picked AutoMigrate lists hide schema divergence.)
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	require.NoError(t, db.Create(&models.User{
		ID: 7, Username: "ci-bot", UsernameFolded: "ci-bot",
		Email: "ci-bot@example.com", EmailFolded: "ci-bot@example.com",
		AccountState: AccountActive, IsActive: true,
	}).Error)
	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }}, db
}

// failSetAccountStateStorage fails SetAccountState — the suspension's own state
// write, which runs AFTER the identity insert inside the shared transaction.
//
// WithTransaction is overridden to re-wrap the tx handle: without that the
// decorator is inert for the faulted call, because the embedded storage hands
// the closure its OWN tx with no override on it (the same tx-handle blind spot
// CLAUDE.md records for raw_storage_bypass_guard_test.go).
func failSetAccountStateStorage(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		SetAccountState: func(_ storage.Storage, ctx context.Context, userID uint, state string, at time.Time) error {
			return errors.New("injected fault: SetAccountState")
		},
	})
}

// TestMigrateUserToMachine_FaultedSuspendRollsBackTheIdentity is the atomicity
// half, against a real transaction: the identity insert succeeds, the
// suspension's state write then fails, and the rollback must take the identity
// with it.
//
// This is the case the function used to report as a partial state and leave for
// an operator to clean up by hand.
func TestMigrateUserToMachine_FaultedSuspendRollsBackTheIdentity(t *testing.T) {
	t.Parallel()
	c, db := newMigrateRealDBCore(t)
	ctx := context.Background()

	// Sanity: the fixture can actually express the thing being asserted. Without
	// this, a migration that never inserted anything would "pass" the
	// zero-identities assertion below for the wrong reason.
	var before int64
	require.NoError(t, db.Model(&models.MachineIdentity{}).Count(&before).Error)
	require.Zero(t, before)

	c.storage = failSetAccountStateStorage(c.storage)

	m, err := c.MigrateUserToMachine(ctx, "ci-bot", 3, "", "", 9, 0, true)
	require.Error(t, err, "a failed suspension must be reported")
	assert.Nil(t, m, "no identity may be returned when nothing committed")

	// THE INVARIANT: the identity insert rolled back with the suspension.
	var identities int64
	require.NoError(t, db.Model(&models.MachineIdentity{}).Count(&identities).Error)
	assert.Zero(t, identities,
		"ATOMICITY VIOLATED: the machine identity survived a failed suspension — the insert and the "+
			"suspension must commit or roll back together, or a migration leaves a new machine identity "+
			"beside a still-active human account with live sessions and PATs (#2867)")

	// And the source user is untouched: still active, not half-suspended.
	var user models.User
	require.NoError(t, db.First(&user, uint(7)).Error)
	assert.Equal(t, AccountActive, user.AccountState,
		"the source user must be left exactly as it was when nothing committed")

	// No audit event may claim either half happened.
	var events []models.AuditEvent
	require.NoError(t, db.Find(&events).Error)
	for _, e := range events {
		assert.NotEqual(t, "machine_identity.created", e.EventType,
			"no create event may be written for an identity that rolled back")
		assert.NotEqual(t, "account.suspended", e.EventType,
			"no suspend event may be written for a suspension that rolled back")
		assert.NotEqual(t, "machine_identity.migrated_from_user", e.EventType,
			"no migration event may be written when nothing committed")
	}
}

// TestMigrateUserToMachine_MachineActorAttributionSurvivesTheAtomicRewrite pins
// the one thing this PR's restructuring could plausibly have dropped on the
// floor: #2495/#2784 made this path record CreatedByMachineIdentityID so a
// migration performed BY a machine identity is attributed to it rather than to
// nobody (the route is actor-aware, so a machine identity holding the required
// permissions can drive it).
//
// Inlining CreateMachineIdentity's insert into the shared transaction meant
// re-plumbing actorMachineID through newMachineIdentityForCreate by hand, and
// passing 0 there would have compiled, passed every other test in this file, and
// silently re-opened that attribution gap behind an atomicity fix. Nothing else
// here looks at the field.
//
// Both branches are covered, because they assemble the row by different routes:
// suspendSource=true goes through newMachineIdentityForCreate + tx insert,
// suspendSource=false still goes through CreateMachineIdentity.
func TestMigrateUserToMachine_MachineActorAttributionSurvivesTheAtomicRewrite(t *testing.T) {
	t.Parallel()
	const actingMachineID uint = 44

	for _, tc := range []struct {
		name          string
		suspendSource bool
	}{
		{"suspending branch (shared transaction)", true},
		{"keep-user branch (CreateMachineIdentity)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, db := newMigrateRealDBCore(t)
			ctx := context.Background()

			// actorID 0 + a non-zero actorMachineID is the machine-actor shape:
			// there is no human admin behind this call.
			m, err := c.MigrateUserToMachine(ctx, "ci-bot", 3, "", "", 0, actingMachineID, tc.suspendSource)
			require.NoError(t, err)
			require.NotNil(t, m)

			// Read the row back rather than trusting the returned struct — the
			// attribution has to be PERSISTED, which is the half a dropped
			// parameter would break.
			var stored models.MachineIdentity
			require.NoError(t, db.First(&stored, m.ID).Error)
			assert.Equal(t, actingMachineID, stored.CreatedByMachineIdentityID,
				"ATTRIBUTION LOST: a migration performed by a machine identity must record it in "+
					"CreatedByMachineIdentityID (#2495/#2784) — passing 0 through "+
					"newMachineIdentityForCreate compiles and breaks nothing else")
		})
	}
}

// TestMigrateUserToMachine_HappyPathCommitsBothAndAudits is the green half of
// the same fixture: the real-DB path really does commit both writes and emit
// all three audit events. Without it, the three failure tests above would be
// satisfied by a function that simply never works.
func TestMigrateUserToMachine_HappyPathCommitsBothAndAudits(t *testing.T) {
	t.Parallel()
	c, db := newMigrateRealDBCore(t)
	ctx := context.Background()

	m, err := c.MigrateUserToMachine(ctx, "ci-bot", 3, "", "", 9, 0, true)
	require.NoError(t, err)
	require.NotNil(t, m)

	var identities int64
	require.NoError(t, db.Model(&models.MachineIdentity{}).Count(&identities).Error)
	assert.Equal(t, int64(1), identities, "the identity must be committed on the happy path")

	var user models.User
	require.NoError(t, db.First(&user, uint(7)).Error)
	assert.Equal(t, AccountSuspended, user.AccountState, "the source user must end up suspended")

	var events []models.AuditEvent
	require.NoError(t, db.Find(&events).Error)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.EventType] = true
	}
	assert.True(t, seen["machine_identity.created"], "create event (written after commit)")
	assert.True(t, seen["account.suspended"], "suspend event (written after commit)")
	assert.True(t, seen["machine_identity.migrated_from_user"], "migration event")
}
