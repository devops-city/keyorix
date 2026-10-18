// cross_replica_invariants_fuzz_test.go — FuzzCrossReplicaInvariants (GUARD-4):
// a strict-PAIR two-replica Postgres fuzzer purpose-built for the CTA-parent
// class of cross-replica check-then-act gaps (#2646-#2660): a destructive op
// (delete/suspend/revoke/disable) on one replica racing a constructive op
// (create/restore/grant/enable) on the other, with GLOBAL invariants
// re-checked after EVERY PAIR — not once at the end of a whole fuzzed
// program the way FuzzCrossReplicaOps (this package's existing two-replica
// fuzzer, cross_replica_ops_fuzz_test.go) checks its own, disjoint oracle set
// (token/session/lease revocation linearizability + single-winner name
// races). That fuzzer and this one share the two-independent-*gorm.DB-pools
// shape (crPgTestDSN/crPgIsolatedSchemaDSN/crPgOpen, defined there, reused
// here) and raceReplicas' barrier (concurrency_race_harness_test.go), but
// check entirely different properties, so this is a new target rather than
// an extension of that one.
//
// Op catalog and invariants are deliberately the CTA-parent shapes
// concurrency_check_then_act_exempt_review_postgres_test.go
// (C-GUARD2-EXEMPT-REVIEW) demonstrates one FORCED interleaving at a time
// for; this fuzzer explores the much larger space of WHICH two ops race and
// in which order, re-derived fresh from random fuzz input every iteration
// rather than hand-picked per test, catching races nobody has written a
// named test for yet.
//
// Postgres only; skipped cleanly when KEYORIX_TEST_PG_DSN is unset (same
// gate every concurrency_*_postgres_test.go and FuzzCrossReplicaOps in this
// package use).
//
// World (built once per testing.F, reset at the top of every top-level fuzz
// iteration — NOT between pairs within one iteration, so state legitimately
// evolves pair-to-pair the way a running system would):
//
//   - one project/environment pair carrying the delete/restore races,
//   - one "share secret" (owner + recipient + a group) for
//     share/ACL grant/update/revoke races,
//   - three secrets wired with one pre-existing dependency edge, for the
//     AddSecretDependency cross-replica cycle race (#2660 class),
//   - two global-admin holders, so a concurrent double-removal race has
//     somewhere to land other than "refused because it's the only one",
//   - one project member (membership lifecycle: invite/activate/revoke),
//   - one SEPARATE user for the direct project-scope role assign/remove
//     family, deliberately NOT the project member above: a direct
//     /user-roles grant is independent of the membership lifecycle by design
//     (ADR-021), and pointing both families at one user made invariant 6
//     unable to tell a membership-derived grant from an admin-issued one —
//     see g4OrphanedMembershipGrants,
//   - one group with a project-scoped role grant and one machine identity,
//     for the user/group/machine role assign-remove families,
//   - one mutable "victim" user for suspend/reactivate/profile-update/
//     change-password races (deliberately the SAME row for all of them —
//     that's the actual #2653/#2654 shape: unrelated write paths stomping
//     the same full-row Save),
//   - one MFA-enrolling user,
//   - one dynamic-secret config + lease,
//   - one access-review campaign item for a dedicated target principal,
//     decided by the (independent) admin reviewer.
//
// Invariants checked after every pair (g4CheckInvariants):
//
//  1. at least one of the two seeded admins is still a live global admin;
//  2. no live share on a soft-deleted secret (#2646/#2647 class);
//  3. no live ACL grant on a soft-deleted secret (#2649 class);
//  4. no active dynamic-secret lease under a soft-deleted project (#2652 class);
//  5. no live environment under a soft-deleted project (#2656 class);
//  6. INV-CORE-44: no (user, project) pair that has a `revoked` membership row
//     and no `active` one still carries a live project-scope role grant
//     (#2657/#2659 class) — see g4OrphanedMembershipGrants for why this is NOT
//     a plain project_memberships-to-user_roles join, and why the second
//     condition is `active` rather than merely "non-revoked";
//  7. the victim user's account_state is `suspended` whenever the last
//     successful suspend/reactivate op on it was a suspend, regardless of
//     what UpdateUser/UpdateOwnProfile/ChangePassword did meanwhile
//     (#2653/#2654 class);
//  8. the three dependency secrets' edges never form a cycle (INV-CORE-31,
//     #2660 class);
//  9. the access-review item is `pending` or its decision's effect is
//     actually applied (a `revoked` decision leaves no live grant);
//  10. the share secret stays deleted unless an explicit restore ran since
//     (#2650 class);
//  11. no enabled dynamic-secret config under a soft-deleted project (#2651
//     class);
//  12. the audit hash chain still verifies end to end (ADR-029).
//
// Seeding: f.Add only carries inputs for the three issues already fixed on
// main (#2648/#2666, the #2658-class admin-ceiling race/#2665, #2660/#2670)
// — a seed for a still-open issue would fail this test on main today, which
// "the test must pass on main" rules out. Seeds for the other issues in
// #2646-#2660 live in testdata/fuzz-pending/<issue>/ and are promoted to the
// live corpus by whoever lands that issue's fix PR; see
// fuzz_cross_replica_invariants_pending_seeds_test.go.
package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- world ------------------------------------------------------------------

type g4World struct {
	setupDB *gorm.DB
	c0, c1  *KeyorixCore
	// db0/db1 are c0's and c1's OWN connection pools. GUARD-5's forced
	// interleaving needs them to register a per-replica sync point (GORM
	// callbacks attach to a *gorm.DB, which is exactly what keeps replica A's
	// pause from perturbing replica B) — see interleave_sync_points_test.go.
	db0, db1 *gorm.DB
	adminID  uint
	admin2ID uint

	projID uint
	envID  uint

	shareSecretID    uint
	shareOwnerID     uint
	shareRecipientID uint
	shareGroupID     uint

	depSecret1, depSecret2, depSecret3 uint

	groupID         uint
	groupMemberID   uint
	groupProjRoleID uint

	memberUserID uint
	// directRoleUserID carries ops 15/16 (AssignUserRole/RemoveUserRole at
	// project scope). It is deliberately a DIFFERENT user from memberUserID so
	// that memberUserID's only source of a project-scope grant is membership
	// activation — the precondition invariant 6 rests on.
	directRoleUserID uint
	viewerRoleID     uint

	machineID       uint
	machineProjRole uint

	victimID uint

	mfaUserID       uint
	mfaUserPassword string

	dynConfigID uint

	arTargetID uint
	arRoleID   uint

	globalAdminRoleID uint

	// mu guards the handful of fields the dispatcher mutates while ops run
	// concurrently (op A and op B can both race to read/write these).
	mu sync.Mutex
	// suspendExpected tracks which outcome of the victim's suspend/reactivate
	// race is the one this iteration's invariant check must hold: true once a
	// suspend op has reported success and no later reactivate op has.
	suspendExpected bool
	// shareSecretDeletedExpected is the same register for the share secret's
	// delete/restore pair: true once a DeleteSecret has reported success and
	// no later RestoreSecret has (#2650 class: a write path other than
	// RestoreSecret silently undeleting it).
	shareSecretDeletedExpected bool
	// campaignID is the current iteration's open access-review campaign.
	campaignID uint

	// passwordSupersededHash is the victim's password hash as it stood
	// immediately before a ChangePassword op that then reported success. Once
	// set, the stored hash must never equal it again: a successful password
	// change that a concurrent write silently reverts is #2654, and NO
	// pre-existing invariant observed it — invariant 7 watches account_state
	// only, which is #2653's half of that pair. Empty when no ChangePassword
	// has succeeded this iteration.
	passwordSupersededHash string
	// mfaValidatedSecret is the TOTP secret an ActivateMFA op validated a code
	// against, recorded BEFORE the activation write (that ordering is the
	// whole point: #2655 is a secret swapped in between validation and
	// activation). mfaActivated says an activation then reported success, so
	// the claim "the active secret is the validated one" is live.
	mfaValidatedSecret string
	mfaActivated       bool
}

const g4VictimPassword = "VictimPass123!xyz-long-enough"
const g4MFAPassword = "MfaUserPass123!xyz-long-enough"

func buildG4World(f testing.TB) *g4World {
	f.Helper()
	require.NoError(f, i18n.InitializeForTesting())

	base := crPgTestDSN(f)
	dsn := crPgIsolatedSchemaDSN(f, base)

	setupDB := crPgOpen(f, dsn)
	require.NoError(f, setupDB.AutoMigrate(kxstorage.AllModels()...))

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, f.TempDir())
	require.NoError(f, enc.Initialize("guard4-fuzz-passphrase"))

	newCore := func(db *gorm.DB) *KeyorixCore {
		c := NewKeyorixCore(localstore.NewLocalStorage(db))
		c.SetAuthEncryptor(enc)
		return c
	}

	setup := newCore(setupDB)
	setup.SetBootstrapToken("guard4-fuzz-token")
	ctx := context.Background()
	boot, err := setup.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "g4admin", Email: "g4admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "guard4-fuzz-token",
	})
	require.NoError(f, err)
	setup.SetBootstrapToken("")

	db0, db1 := crPgOpen(f, dsn), crPgOpen(f, dsn)
	w := &g4World{setupDB: setupDB, c0: newCore(db0), c1: newCore(db1), db0: db0, db1: db1, adminID: boot.User.ID}
	// Open validation mode: InviteMember commits the membership as `active`
	// straight away (see InviteMemberOpenMode's doc in
	// concurrency_check_then_act_exempt_review_postgres_test.go) — the shape
	// #2659 names, reachable on both replicas.
	w.c0.SetMembershipValidationMode(ValidationModeOpen)
	w.c1.SetMembershipValidationMode(ValidationModeOpen)

	globalAdminRole, err := setup.Storage().GetRoleByName(ctx, "admin")
	require.NoError(f, err)
	w.globalAdminRoleID = globalAdminRole.ID

	proj, err := setup.CreateProject(ctx, "g4-project", "")
	require.NoError(f, err)
	w.projID = proj.ID
	env, err := setup.CreateEnvironment(ctx, proj.ID, "g4-env")
	require.NoError(f, err)
	w.envID = env.ID

	mkUser := func(uname, password string) uint {
		u, err := setup.CreateUser(ctx, &CreateUserRequest{Username: uname, Email: uname + "@example.com", Password: password})
		require.NoError(f, err)
		return u.ID
	}
	w.admin2ID = mkUser("g4admin2", "BootstrapPass123!")
	require.NoError(f, setup.Storage().AssignRole(ctx, w.admin2ID, w.globalAdminRoleID, Scope{}))

	w.shareOwnerID = mkUser("g4-share-owner", "SharePass123!xyz-long-enough")
	w.shareRecipientID = mkUser("g4-share-recipient", "SharePass123!xyz-long-enough")
	// GUARD-5: both of these need a project-scoped grant, which makes them
	// project MEMBERS (IsProjectMember resolves a project-scoped role grant).
	// Without it the whole share/ACL op family was DEAD: ShareSecret refuses
	// unless SharedBy is a live owner AND the recipient is a project member
	// (sharing.go), and GrantSecretACL refuses a non-member grantee
	// (secret_acl.go). Op kinds 6/7/8/9/10/11 could therefore never create a
	// row, which made invariants 2 and 3 — the ONLY oracles for the
	// #2646/#2647/#2649 classes — vacuously true in every iteration the
	// fuzzer has ever run. Found by replaying those three pending seeds
	// through the forced driver and watching the share INSERT never happen;
	// see cross_replica_forced_interleaving_test.go.
	w.memberUserID = mkUser("g4-member", "MemberPass123!xyz-long-enough")
	w.directRoleUserID = mkUser("g4-direct-role", "DirectPass123!xyz-long-enough")
	w.groupMemberID = mkUser("g4-group-member", "GroupPass123!xyz-long-enough")
	w.victimID = mkUser("g4-victim", g4VictimPassword)
	w.mfaUserID = mkUser("g4-mfa-user", g4MFAPassword)
	w.mfaUserPassword = g4MFAPassword
	w.arTargetID = mkUser("g4-ar-target", "ArTargetPass123!xyz-long-enough")

	viewerRole, err := setup.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(f, err)
	w.viewerRoleID = viewerRole.ID
	w.arRoleID = viewerRole.ID
	w.groupProjRoleID = viewerRole.ID
	w.machineProjRole = viewerRole.ID

	// GUARD-5: the share/ACL family's project-membership prerequisite (see the
	// comment above w.memberUserID). project_admin for the owner because
	// requireLiveOwnerAuthority wants a live project member who owns the
	// secret; project_viewer is enough for the recipient and the ACL grantee.
	projAdminRole, err := setup.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(f, err)
	require.NoError(f, setup.Storage().AssignRole(ctx, w.shareOwnerID, projAdminRole.ID, Scope{ProjectID: w.projID}))
	require.NoError(f, setup.Storage().AssignRole(ctx, w.shareRecipientID, w.viewerRoleID, Scope{ProjectID: w.projID}))

	mkSecret := func(name string, ownerID uint) uint {
		s := &models.SecretNode{Name: name, ProjectID: w.projID, EnvironmentID: w.envID, IsSecret: true, OwnerID: ownerID}
		require.NoError(f, setupDB.Create(s).Error)
		return s.ID
	}
	w.shareSecretID = mkSecret("g4-share-secret", w.shareOwnerID)
	w.depSecret1 = mkSecret("g4-dep-1", w.adminID)
	w.depSecret2 = mkSecret("g4-dep-2", w.adminID)
	w.depSecret3 = mkSecret("g4-dep-3", w.adminID)
	// One pre-existing edge so there is a row for the cycle-race's FOR UPDATE
	// to lock (mirrors TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres).
	_, err = setup.AddSecretDependency(ctx, ActorTypeUser, w.adminID, w.depSecret3, w.depSecret1, "", 0)
	require.NoError(f, err)

	group := &models.Group{Name: "g4-group", NameFolded: "g4-group"}
	require.NoError(f, setupDB.Create(group).Error)
	w.shareGroupID = group.ID
	w.groupID = group.ID
	require.NoError(f, setup.Storage().AssignRoleToGroup(ctx, group.ID, w.groupProjRoleID, Scope{ProjectID: w.projID}))
	require.NoError(f, setupDB.Create(&models.UserGroup{UserID: w.groupMemberID, GroupID: group.ID}).Error)

	m, err := setup.CreateMachineIdentity(ctx, proj.ID, "g4-machine", MachineTypeOther, "", "", w.adminID, 0)
	require.NoError(f, err)
	w.machineID = m.ID

	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	engineFactory := func(string) (dynamic.CredentialEngine, error) { return fake, nil }
	w.c0.SetDynamicEngineFactory(engineFactory)
	w.c1.SetDynamicEngineFactory(engineFactory)
	setup.SetDynamicEngineFactory(engineFactory)

	cfg, err := setup.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
		Name: "g4-dyn-cfg", ProjectID: w.projID, EnvironmentID: w.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "g4admin", ActorID: w.adminID,
	})
	require.NoError(f, err)
	w.dynConfigID = cfg.ID

	// Seed the access-review target's direct grant BEFORE opening the
	// campaign, so GenerateProjectAccessReview's snapshot has an item to
	// decide against. require.NoError(f, ...): a global admin granting a
	// project role at scope{ProjectID} needs no further setup here.
	require.NoError(f, setup.Storage().AssignRole(ctx, w.arTargetID, w.arRoleID, Scope{ProjectID: w.projID}))

	return w
}

// g4ResetIteration restores every mutable piece of world state to its
// baseline, synchronously, before any goroutine starts for this top-level
// fuzz input. Pairs WITHIN one iteration are deliberately NOT reset against
// each other — state evolves pair-to-pair the way a running system would;
// only a fresh top-level fuzz input gets a clean baseline.
func g4ResetIteration(t testing.TB, w *g4World) uint {
	t.Helper()
	ctx := context.Background()

	// secret/project/environment: live again.
	_ = w.c0.RestoreSecret(ctx, w.adminID, w.shareSecretID)
	if err := w.c0.RestoreProject(ctx, w.adminID, w.projID); err != nil {
		t.Logf("reset: restore project (probably already live): %v", err)
	}
	if err := w.c0.RestoreEnvironment(ctx, w.adminID, w.projID, w.envID); err != nil {
		t.Logf("reset: restore environment (probably already live): %v", err)
	}
	// Both seeded admins: re-grant the global admin role if a previous
	// iteration's op 36/37 (remove each admin's global role) actually
	// removed it — every reset op below acts as w.adminID, so that actor
	// losing admin privileges must not leak into the next iteration.
	for _, id := range []uint{w.adminID, w.admin2ID} {
		if isAdmin, _ := w.c0.IsGlobalAdmin(ctx, id); !isAdmin {
			if err := w.c0.Storage().AssignRole(ctx, id, w.globalAdminRoleID, Scope{}); err != nil {
				t.Fatalf("reset: re-grant global admin role to user %d: %v", id, err)
			}
		}
	}

	// DeleteProject(force=true) cascades to every secret in the project, not
	// just shareSecretID — the dependency-graph secrets live in the same
	// project, so they need restoring too before the dependency edge below
	// can be re-seeded.
	for _, id := range []uint{w.depSecret1, w.depSecret2, w.depSecret3} {
		if err := w.c0.RestoreSecret(ctx, w.adminID, id); err != nil {
			t.Logf("reset: restore dep secret %d (probably already live): %v", id, err)
		}
	}

	// victim: back to active, model register reset.
	_ = w.c0.ReactivateUser(ctx, w.adminID, w.victimID)
	w.mu.Lock()
	w.suspendExpected = false
	w.shareSecretDeletedExpected = false
	w.passwordSupersededHash = ""
	w.mfaValidatedSecret = ""
	w.mfaActivated = false
	w.mu.Unlock()

	// GUARD-5: project memberships and the member's project grants, back to
	// "no membership at all". Without this, op 12 (InviteMember) was dead
	// after its FIRST success in the whole fuzzer run — inviteMemberWithMode
	// refuses with "user already has a <state> membership in this project"
	// (membership_lifecycle.go's one-active-onboarding-per-(project,user)
	// rule), and nothing ever removed the row. So invariant 6, the only oracle
	// for the #2657/#2659 classes, was reachable in at most one iteration per
	// world. The user_roles cleanup goes with it: a membership deleted while
	// its grant survives would make invariant 6 fire on fixture residue
	// rather than on anything the fuzzed pair did.
	if err := w.setupDB.Exec("DELETE FROM project_memberships WHERE project_id = ? AND user_id = ?",
		w.projID, w.memberUserID).Error; err != nil {
		t.Fatalf("reset: clear project memberships: %v", err)
	}
	if err := w.setupDB.Exec("DELETE FROM user_roles WHERE project_id = ? AND user_id = ?",
		w.projID, w.memberUserID).Error; err != nil {
		t.Fatalf("reset: clear member project grants: %v", err)
	}

	// GUARD-5: MFA back to not-enrolled, so a later ActivateMFA op can
	// actually run (it refuses when MFA is already active) and so no stale
	// active secret from a previous iteration can satisfy or break invariant
	// 13 by itself.
	if err := w.setupDB.Exec("DELETE FROM mfa_secrets WHERE user_id = ?", w.mfaUserID).Error; err != nil {
		t.Fatalf("reset: clear MFA secrets: %v", err)
	}
	if err := w.setupDB.Exec("UPDATE users SET mfa_enabled = false WHERE id = ?", w.mfaUserID).Error; err != nil {
		t.Fatalf("reset: clear MFA enabled flag: %v", err)
	}

	// dynamic-secret config: enabled again.
	_, _ = w.c0.SetDynamicSecretConfigEnabled(ctx, w.adminID, w.dynConfigID, true)

	// dependency edges among the three dep secrets: back to the one baseline
	// edge (dep3 -> dep1), clearing anything a previous iteration's cycle
	// race left behind.
	if err := w.setupDB.Exec(
		"DELETE FROM secret_dependencies WHERE dependent_secret_id IN (?, ?, ?) OR depends_on_secret_id IN (?, ?, ?)",
		w.depSecret1, w.depSecret2, w.depSecret3, w.depSecret1, w.depSecret2, w.depSecret3).Error; err != nil {
		t.Fatalf("reset: clear dependency edges: %v", err)
	}
	if _, err := w.c0.AddSecretDependency(ctx, ActorTypeUser, w.adminID, w.depSecret3, w.depSecret1, "", 0); err != nil {
		t.Fatalf("reset: re-seed baseline dependency edge: %v", err)
	}

	// access-review: fresh campaign (previous one, if any, stays closed/open
	// as it was — a new campaign's snapshot is what matters).
	cwp, err := w.c0.OpenAccessReviewCampaign(ctx, w.adminID, 0, w.projID, "g4-fuzz-campaign")
	if err != nil {
		t.Fatalf("reset: open access-review campaign: %v", err)
	}
	w.mu.Lock()
	w.campaignID = cwp.Campaign.ID
	w.mu.Unlock()
	return cwp.Campaign.ID
}

// --- op dispatcher -----------------------------------------------------------

// g4Op is one decoded fuzz op: kind selects the operation family, misc varies
// its parameters (which secret/role/action) within that family.
type g4Op struct {
	kind byte
	misc byte
}

const g4NumOpKinds = 40

// g4Replica returns the core for replica index i (0 or 1).
//
// GUARD-5 replaced the original `pick byte` form, which chose the replica from
// the OP KIND (`pick%2`). That made the replica assignment a pure function of
// the op kind, so the two ops of a pair landed on the SAME replica whenever
// their kinds had the same parity — and always would, for every seed, in every
// iteration, forever. Six of the twelve pending seeds were affected
// (#2646 kinds 0+6, #2649 0+10, #2650 0+38, #2652 2+30, #2653 21+23,
// #2659 14+12): both ops ran through one *KeyorixCore on one connection pool,
// so they were not cross-replica races at all and no amount of blind racing
// could ever have reproduced them. That is a large part of why GUARD-4 found
// six seeds unreproducible after ~400 repetitions each.
//
// The fix is to drop the choice: pair element 0 always runs on c0 and element
// 1 always on c1. Nothing is lost — the op catalog is explored in both orders
// by the fuzzer anyway (a (X,Y) pair and a (Y,X) pair are both reachable
// inputs), so "which replica gets which op" was never adding coverage that
// pair ordering did not already provide. TestG4PairAlwaysSpansBothReplicas
// in cross_replica_forced_interleaving_test.go is the machine check.
func g4Replica(w *g4World, i int) *KeyorixCore {
	if i == 0 {
		return w.c0
	}
	return w.c1
}

// g4RunOp executes one op on the given replica. All errors are tolerated —
// this is fuzzing a mix of ops that frequently legitimately refuse each
// other (that's the point); only g4CheckInvariants' assertions can fail the
// test.
func g4RunOp(t testing.TB, w *g4World, c *KeyorixCore, op g4Op) {
	t.Helper()
	ctx := context.Background()

	switch op.kind % g4NumOpKinds {
	case 0: // delete secret
		if err := c.DeleteSecret(ctx, w.shareSecretID); err == nil {
			w.mu.Lock()
			w.shareSecretDeletedExpected = true
			w.mu.Unlock()
		}

	case 1: // restore secret
		if err := c.RestoreSecret(ctx, w.adminID, w.shareSecretID); err == nil {
			w.mu.Lock()
			w.shareSecretDeletedExpected = false
			w.mu.Unlock()
		}

	case 2: // delete project
		_ = c.DeleteProject(ctx, 0, w.projID, true)

	case 3: // restore project
		_ = c.RestoreProject(ctx, w.adminID, w.projID)

	case 4: // delete environment
		_ = c.DeleteEnvironment(ctx, w.envID)

	case 5: // restore environment
		_ = c.RestoreEnvironment(ctx, w.adminID, w.projID, w.envID)

	case 6: // share secret (user)
		_, _ = c.ShareSecret(ctx, &ShareSecretRequest{
			SecretID: w.shareSecretID, RecipientID: w.shareRecipientID, Permission: "read", SharedBy: w.shareOwnerID,
		})

	case 7: // share secret (group)
		_, _ = c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{
			SecretID: w.shareSecretID, GroupID: w.shareGroupID, Permission: "read", SharedBy: w.shareOwnerID,
		})

	case 8: // update share permission
		if id := g4LookupLiveShare(w, w.shareRecipientID); id != 0 {
			_, _ = c.UpdateSharePermission(ctx, &UpdateShareRequest{ShareID: id, Permission: "write", UpdatedBy: w.shareOwnerID})
		}

	case 9: // revoke share
		if id := g4LookupLiveShare(w, w.shareRecipientID); id != 0 {
			_ = c.RevokeShare(ctx, id, w.shareOwnerID)
		}

	case 10: // grant secret ACL
		_ = c.GrantSecretACL(ctx, w.adminID, w.shareSecretID, w.shareRecipientID, []string{"secrets.read"})

	case 11: // revoke secret ACL
		if id := g4LookupSecretACL(w); id != 0 {
			_ = c.RevokeSecretACL(ctx, w.adminID, w.shareSecretID, id)
		}

	case 12: // invite member (open mode)
		_, _ = c.InviteMember(ctx, w.projID, w.memberUserID, "project_viewer", w.adminID, 0, false)

	case 13: // transition membership: activate
		if id, state := g4LookupMembership(w); id != 0 && state == MembershipProvisioned {
			_, _ = c.TransitionMembership(ctx, w.projID, id, MembershipActive, w.adminID, false)
		}

	case 14: // transition membership: revoke
		if id, state := g4LookupMembership(w); id != 0 && (state == MembershipProvisioned || state == MembershipActive) {
			_, _ = c.TransitionMembership(ctx, w.projID, id, MembershipRevoked, w.adminID, false)
		}

	// Ops 15/16 act on directRoleUserID, NOT memberUserID: a direct
	// /user-roles grant is independent of the membership lifecycle (ADR-021),
	// so pointing it at the membership user would leave invariant 6 unable to
	// distinguish an orphaned membership grant from a legitimate admin-issued
	// one. They still race each other (assign vs remove on one principal),
	// which is the grant/removal race these two ops exist for.
	case 15: // assign user role (project scope)
		_ = c.AssignUserRole(ctx, w.adminID, w.directRoleUserID, w.viewerRoleID, Scope{ProjectID: w.projID}, false)

	case 16: // remove user role (project scope)
		_ = c.RemoveUserRole(ctx, w.adminID, w.directRoleUserID, w.viewerRoleID, Scope{ProjectID: w.projID})

	case 17: // assign role to group (project scope)
		_ = c.AssignRoleToGroup(ctx, w.adminID, w.groupID, w.groupProjRoleID, Scope{ProjectID: w.projID}, false)

	case 18: // remove role from group (project scope)
		_ = c.RemoveRoleFromGroup(ctx, w.adminID, w.groupID, w.groupProjRoleID, Scope{ProjectID: w.projID})

	case 19: // assign machine role (project scope)
		_ = c.AssignMachineRole(ctx, w.machineID, w.machineProjRole, Scope{ProjectID: w.projID}, w.adminID, false)

	case 20: // remove machine role (project scope)
		_ = c.RemoveMachineRole(ctx, w.machineID, w.machineProjRole, Scope{ProjectID: w.projID}, w.adminID)

	case 21: // suspend victim
		if err := c.SuspendUser(ctx, w.adminID, w.victimID); err == nil {
			w.mu.Lock()
			w.suspendExpected = true
			w.mu.Unlock()
		}

	case 22: // reactivate victim
		if err := c.ReactivateUser(ctx, w.adminID, w.victimID); err == nil {
			w.mu.Lock()
			w.suspendExpected = false
			w.mu.Unlock()
		}

	case 23: // update user (admin-driven profile edit)
		_, _ = c.UpdateUser(ctx, &UpdateUserRequest{ID: w.victimID, ActorID: w.adminID, DisplayName: fmt.Sprintf("g4-renamed-%d", op.misc)})

	case 24: // update own profile (self-service, no re-auth)
		_, _ = c.UpdateOwnProfile(ctx, w.victimID, fmt.Sprintf("g4-self-renamed-%d", op.misc), "", "")

	case 25: // change password
		// Read the hash the change is about to supersede BEFORE calling, so a
		// concurrent full-row write that puts it back is detectable. Asserting
		// on ChangePassword's return value instead would prove nothing: it
		// reports success in both the buggy and the fixed case (CLAUDE.md,
		// "to test a fails-open path, assert the effect, not the return
		// value").
		var before string
		_ = w.setupDB.Raw("SELECT password_hash FROM users WHERE id = ?", w.victimID).Scan(&before)
		if err := c.ChangePassword(ctx, w.victimID, g4VictimPassword, "NewVictimPass456!abc-long-enough", ""); err == nil && before != "" {
			w.mu.Lock()
			w.passwordSupersededHash = before
			w.mu.Unlock()
		}

	case 26: // begin MFA enrollment (re-enroll, discard secret)
		_, _, _ = c.BeginMFAEnrollment(ctx, w.mfaUserID)

	case 27: // begin + validate + activate MFA (the real enroll flow, self-contained)
		_, secret, err := c.BeginMFAEnrollment(ctx, w.mfaUserID)
		if err != nil {
			return
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			return
		}
		// Record the validated secret BEFORE the activation write. #2655 is
		// precisely a secret swapped in between validation and activation, so
		// a register written after the call would record the swapped-in one
		// and the oracle would certify the bug as correct.
		w.mu.Lock()
		w.mfaValidatedSecret = secret
		w.mu.Unlock()
		if _, aerr := c.ActivateMFA(ctx, w.mfaUserID, code, w.mfaUserPassword, ""); aerr == nil {
			w.mu.Lock()
			w.mfaActivated = true
			w.mu.Unlock()
		}

	case 28: // add secret dependency dep1 -> dep2
		_, _ = c.AddSecretDependency(ctx, ActorTypeUser, w.adminID, w.depSecret1, w.depSecret2, "", 0)

	case 29: // add secret dependency dep2 -> dep1 (the cycle attempt)
		_, _ = c.AddSecretDependency(ctx, ActorTypeUser, w.adminID, w.depSecret2, w.depSecret1, "", 0)

	case 30: // issue lease
		_, _ = c.IssueLease(ctx, w.dynConfigID, 0, w.adminID)

	case 31: // revoke lease
		if id := g4LookupActiveLease(w); id != "" {
			_ = c.RevokeLease(ctx, id, w.adminID, "g4-fuzz")
		}

	case 32: // disable dynamic-secret config
		_, _ = c.SetDynamicSecretConfigEnabled(ctx, w.adminID, w.dynConfigID, false)

	case 33: // re-enable dynamic-secret config
		_, _ = c.SetDynamicSecretConfigEnabled(ctx, w.adminID, w.dynConfigID, true)

	case 34: // access-review decide: attest
		w.mu.Lock()
		campaignID := w.campaignID
		w.mu.Unlock()
		if id := g4LookupPendingARItem(w, campaignID); id != 0 {
			_ = c.DecideAccessReviewItem(ctx, w.adminID, w.projID, campaignID, id, "attest", "g4-fuzz")
		}

	case 35: // access-review decide: revoke
		w.mu.Lock()
		campaignID := w.campaignID
		w.mu.Unlock()
		if id := g4LookupPendingARItem(w, campaignID); id != 0 {
			_ = c.DecideAccessReviewItem(ctx, w.adminID, w.projID, campaignID, id, "revoke", "g4-fuzz")
		}

	case 36: // remove the FIRST admin's global role
		_ = c.RemoveUserRole(ctx, w.adminID, w.adminID, w.globalAdminRoleID, Scope{})

	case 37: // remove the SECOND admin's global role
		_ = c.RemoveUserRole(ctx, w.adminID, w.admin2ID, w.globalAdminRoleID, Scope{})

	case 38: // enable auto-rotate on the share secret (full-row Save, #2650 class)
		_ = c.SetSecretAutoRotate(ctx, w.shareSecretID, AutoRotateSpec{Enabled: true, Length: 32}, w.adminID)

	default: // 39: create a fresh dynamic-secret config in the fixture project/env (#2651 class)
		_, _ = c.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
			Name: fmt.Sprintf("g4-dyn-%d", crRotateSeq.Add(1)), ProjectID: w.projID, EnvironmentID: w.envID, BackendType: "postgres",
			AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
			CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
			DefaultTTLSeconds: 3600, CreatedBy: "g4admin", ActorID: w.adminID,
		})
	}
}

func g4LookupLiveShare(w *g4World, recipientID uint) uint {
	var id uint
	_ = w.setupDB.Raw("SELECT id FROM share_records WHERE secret_id = ? AND recipient_id = ? AND deleted_at IS NULL LIMIT 1",
		w.shareSecretID, recipientID).Scan(&id)
	return id
}

func g4LookupSecretACL(w *g4World) uint {
	var id uint
	_ = w.setupDB.Raw("SELECT id FROM secret_acls WHERE secret_id = ? AND user_id = ? LIMIT 1", w.shareSecretID, w.shareRecipientID).Scan(&id)
	return id
}

func g4LookupMembership(w *g4World) (id uint, state string) {
	var row struct {
		ID    uint
		State string
	}
	_ = w.setupDB.Raw("SELECT id, state FROM project_memberships WHERE project_id = ? AND user_id = ? ORDER BY id DESC LIMIT 1",
		w.projID, w.memberUserID).Scan(&row)
	return row.ID, row.State
}

func g4LookupActiveLease(w *g4World) string {
	var id string
	_ = w.setupDB.Raw("SELECT lease_id FROM dynamic_secret_leases WHERE config_id = ? AND status = 'active' LIMIT 1", w.dynConfigID).Scan(&id)
	return id
}

func g4LookupPendingARItem(w *g4World, campaignID uint) uint {
	if campaignID == 0 {
		return 0
	}
	var id uint
	_ = w.setupDB.Raw("SELECT id FROM access_review_items WHERE campaign_id = ? AND principal_type = 'user' AND principal_id = ? AND decision = ? LIMIT 1",
		campaignID, w.arTargetID, ReviewItemPending).Scan(&id)
	return id
}

// --- invariant checker ---------------------------------------------------

// g4HasCycle reports whether the dependent->depends_on edges contain a
// cycle, via a standard white/gray/black DFS.
func g4HasCycle(edges map[uint][]uint) bool {
	const white, gray, black = 0, 1, 2
	color := map[uint]int{}
	var dfs func(uint) bool
	dfs = func(n uint) bool {
		color[n] = gray
		for _, m := range edges[n] {
			switch color[m] {
			case gray:
				return true
			case white:
				if dfs(m) {
					return true
				}
			}
		}
		color[n] = black
		return false
	}
	for n := range edges {
		if color[n] == white {
			if dfs(n) {
				return true
			}
		}
	}
	return false
}

// g4OrphanedGrant is one (user, project) pair holding a live project-scope
// role grant while every ProjectMembership row for that pair is `revoked`.
type g4OrphanedGrant struct {
	UserID    uint
	ProjectID uint
}

// g4OrphanedMembershipGrants implements invariant 6, i.e. INV-CORE-44: "a
// project membership never ends `revoked` while its user still holds the role
// grant that membership conferred".
//
// What it checks: a (user, project) pair for which a `revoked` membership row
// exists and NO membership row is in a grant-conferring state, yet user_roles
// still carries a grant at that project's scope. With no membership left that
// could legitimately own a membership-derived grant, a surviving one is
// orphaned — the #2657/#2659 end state.
//
// "grant-conferring state" is `active` and only `active`: both AddProjectMember
// call sites in the membership lifecycle are gated on it
// (membership_lifecycle.go:234, under `created.State == MembershipActive`, and
// :377, under `case MembershipActive`), and `revoked` is the only state that
// removes a grant (:388). That premise is not taken on trust — it is the thing
// TestOnlyActiveMembershipStateConfersProjectGrant derives behaviourally, for
// every validation mode and every state in membershipTransitions, so adding a
// state that grants (or making `provisioned` grant) fails that test rather than
// silently blinding this oracle.
//
// Checking `active` rather than merely "non-revoked" matters: a pair can hold a
// `revoked` row beside a PENDING row (`invited`/`identity_verified`/
// `provisioned`) from a non-open-mode re-invite, and a pending row confers no
// grant, so it must not shield a grant that outlived the revoke. Guarded by
// TestInvariant6_FiresOnOrphanedGrantUnderPendingReinvite.
//
// Why NOT the obvious `project_memberships JOIN user_roles ON user+project
// WHERE m.state = 'revoked'`: that join is not INV-CORE-44 but a strictly
// stronger claim, and the stronger claim is FALSE under legal serial
// execution. A (project, user) pair accumulates membership rows over time —
// at most one non-revoked (uniq_project_memberships_active), any number of
// revoked ones — so `invite(open) → revoke → re-invite` ends with a revoked
// row beside a fresh `active` row whose own grant is live and correct. The
// join pairs the revoked row with the ACTIVE row's grant and fires, with no
// concurrency involved at all. That is what made #2659's seed fail after its
// fix had already landed; TestInvariant6_SoundOnSerialReinvite pins it with
// zero goroutines.
//
// The two conditions are not interchangeable and both are load-bearing: the
// EXISTS(revoked) clause is what makes this a membership-lifecycle claim at
// all (a pair that never had a membership is not this invariant's business),
// and the NOT EXISTS(active) clause is what keeps it true of serial
// executions.
//
// What it does NOT check: a project-scope grant reached by any path other
// than membership activation — a direct /user-roles grant, a group grant, an
// access-review leftover. Those are independent of the membership lifecycle
// by design (ADR-021) and the schema records no provenance that would let
// this query tell them apart after the fact, so the fuzz world keeps them on
// their own principals instead (g4World.directRoleUserID). A future op that
// grants memberUserID a project role directly would make this oracle fire on
// a legitimate state again; put it on another principal.
//
// Sensitivity is not assumed: TestInvariant6_FiresOnOpenModeInviteVsRevoke_WithoutMembershipLock
// and its activate-path sibling remove membershipLockKey and confirm this
// predicate still reports the real #2659/#2657 violation.
func g4OrphanedMembershipGrants(db *gorm.DB) ([]g4OrphanedGrant, error) {
	// The two states are bound from the package's own constants, not spelled
	// as SQL literals, so renaming either one is a compile-time break here
	// rather than a silently-never-matching query.
	var out []g4OrphanedGrant
	err := db.Raw(`
SELECT DISTINCT ur.user_id, ur.project_id
FROM user_roles ur
WHERE EXISTS (
        SELECT 1 FROM project_memberships m
        WHERE m.user_id = ur.user_id AND m.project_id = ur.project_id
          AND m.state = ?)
  AND NOT EXISTS (
        SELECT 1 FROM project_memberships m2
        WHERE m2.user_id = ur.user_id AND m2.project_id = ur.project_id
          AND m2.state = ?)
ORDER BY ur.user_id, ur.project_id`, MembershipRevoked, MembershipActive).Scan(&out).Error
	return out, err
}

// g4CheckInvariants fails the test on the first violated global invariant.
// This is what the fuzz target calls: a violation there IS the finding, so
// aborting immediately is right.
func g4CheckInvariants(t testing.TB, w *g4World) {
	t.Helper()
	if v := g4FindViolation(t, w); v != "" {
		t.Fatal(v)
	}
}

// g4FindViolation returns the first violated global invariant's message, or ""
// when all twelve hold.
//
// Split out of g4CheckInvariants (GUARD-5) because the forced-interleaving
// regression tests in cross_replica_forced_interleaving_test.go need to ASSERT
// on the outcome in both directions — "this ordering must break invariant N
// while #NNNN is open" and "this ordering must keep every invariant once the
// fix lands" — and a t.Fatalf inside the checker can only express one of
// those. A t.Fatalf-only checker would have forced those tests to assert on a
// proxy (did the op return an error?) instead of on the effect, which is the
// specific mistake CLAUDE.md's "to test a fails-open path, assert the effect,
// not the return value" warns about: every one of these ops reports success
// in both the buggy and the fixed case.
//
// require.NoError on the DB reads below is deliberately NOT converted: a
// failed invariant QUERY is a broken test, not a violated invariant, and
// returning it as a violation string would let a typo'd column name read as a
// real finding.
func g4FindViolation(t testing.TB, w *g4World) string {
	if v := g4FindStateViolation(t, w); v != "" {
		return v
	}
	return g4FindAuditChainViolation(t, w)
}

// g4FindStateViolation is g4FindViolation minus the audit-chain check — the
// bounded, per-run half. See g4FindAuditChainViolation for why the split
// exists.
func g4FindStateViolation(t testing.TB, w *g4World) string {
	t.Helper()
	ctx := context.Background()

	// 1. at least one live global admin.
	admin1, _ := w.c0.IsGlobalAdmin(ctx, w.adminID)
	admin2, _ := w.c0.IsGlobalAdmin(ctx, w.admin2ID)
	if !admin1 && !admin2 {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED: no live global admin remains (checked adminID=%d admin2ID=%d)", w.adminID, w.admin2ID)
	}

	// 2. no live share on a soft-deleted secret (#2646/#2647 class).
	var liveShareOnDeletedSecret int64
	require.NoError(t, w.setupDB.Raw(
		"SELECT count(*) FROM share_records sr JOIN secret_nodes s ON sr.secret_id = s.id WHERE sr.deleted_at IS NULL AND s.deleted_at IS NOT NULL",
	).Scan(&liveShareOnDeletedSecret).Error)
	if liveShareOnDeletedSecret > 0 {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2646/#2647 class): %d live share(s) exist on a soft-deleted secret", liveShareOnDeletedSecret)
	}

	// 3. no live ACL grant on a soft-deleted secret (#2649 class).
	var liveACLOnDeletedSecret int64
	require.NoError(t, w.setupDB.Raw(
		"SELECT count(*) FROM secret_acls a JOIN secret_nodes s ON a.secret_id = s.id WHERE s.deleted_at IS NOT NULL",
	).Scan(&liveACLOnDeletedSecret).Error)
	if liveACLOnDeletedSecret > 0 {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2649 class): %d ACL grant(s) exist on a soft-deleted secret", liveACLOnDeletedSecret)
	}

	// 4. no active dynamic-secret lease under a soft-deleted project (#2652 class).
	var liveLeaseUnderDeletedProject int64
	require.NoError(t, w.setupDB.Raw(
		"SELECT count(*) FROM dynamic_secret_leases l JOIN projects p ON l.project_id = p.id WHERE l.status = 'active' AND p.deleted_at IS NOT NULL",
	).Scan(&liveLeaseUnderDeletedProject).Error)
	if liveLeaseUnderDeletedProject > 0 {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2652 class): %d active lease(s) exist under a soft-deleted project", liveLeaseUnderDeletedProject)
	}

	// 5. no live environment under a soft-deleted project (#2656 class).
	var liveEnvUnderDeletedProject int64
	require.NoError(t, w.setupDB.Raw(
		"SELECT count(*) FROM environments e JOIN projects p ON e.project_id = p.id WHERE e.deleted_at IS NULL AND p.deleted_at IS NOT NULL",
	).Scan(&liveEnvUnderDeletedProject).Error)
	if liveEnvUnderDeletedProject > 0 {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2656 class): %d live environment(s) exist under a soft-deleted project", liveEnvUnderDeletedProject)
	}

	// 6. INV-CORE-44: no (user, project) pair whose memberships are all
	// `revoked` still carries a live project-scope grant (#2657/#2659 class).
	orphaned, err := g4OrphanedMembershipGrants(w.setupDB)
	require.NoError(t, err)
	if len(orphaned) > 0 {
		t.Fatalf("GLOBAL INVARIANT VIOLATED (INV-CORE-44, #2657/#2659 class): %d (user, project) pair(s) hold a live project-scope role grant while every membership row for the pair is `revoked`: %+v",
			len(orphaned), orphaned)
	}

	// 7. victim stays suspended unless an explicit reactivate op ran since.
	w.mu.Lock()
	suspendExpected := w.suspendExpected
	w.mu.Unlock()
	if suspendExpected {
		var state string
		require.NoError(t, w.setupDB.Raw("SELECT account_state FROM users WHERE id = ?", w.victimID).Scan(&state).Error)
		if state != AccountSuspended {
			return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2653/#2654 class): victim user %d's last successful suspend/reactivate op was a suspend, but account_state=%q", w.victimID, state)
		}
	}

	// 8. no dependency cycle among the three dep secrets (INV-CORE-31, #2660 class).
	type edgeRow struct {
		FromID uint
		ToID   uint
	}
	var edgeRows []edgeRow
	require.NoError(t, w.setupDB.Raw(
		"SELECT dependent_secret_id AS from_id, depends_on_secret_id AS to_id FROM secret_dependencies WHERE dependent_secret_id IN (?, ?, ?) AND depends_on_secret_id IN (?, ?, ?)",
		w.depSecret1, w.depSecret2, w.depSecret3, w.depSecret1, w.depSecret2, w.depSecret3,
	).Scan(&edgeRows).Error)
	edges := map[uint][]uint{}
	for _, e := range edgeRows {
		edges[e.FromID] = append(edges[e.FromID], e.ToID)
	}
	if g4HasCycle(edges) {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (INV-CORE-31, #2660 class): the secret-dependency graph has a cycle among {%d,%d,%d}: %v",
			w.depSecret1, w.depSecret2, w.depSecret3, edges)
	}

	// 9. the access-review target's item is pending, or its decision's effect
	// is actually applied: a `revoked` decision leaves no live role grant.
	w.mu.Lock()
	campaignID := w.campaignID
	w.mu.Unlock()
	if campaignID != 0 {
		var decision string
		err := w.setupDB.Raw(
			"SELECT decision FROM access_review_items WHERE campaign_id = ? AND principal_type = 'user' AND principal_id = ? LIMIT 1",
			campaignID, w.arTargetID).Scan(&decision).Error
		require.NoError(t, err)
		if decision == ReviewItemRevoked {
			var liveGrant int64
			require.NoError(t, w.setupDB.Model(&models.UserRole{}).
				Where("user_id = ? AND role_id = ? AND project_id = ?", w.arTargetID, w.arRoleID, w.projID).
				Count(&liveGrant).Error)
			if liveGrant > 0 {
				return fmt.Sprintf("GLOBAL INVARIANT VIOLATED: access-review item for user %d is decided `revoked` but the role grant it targeted is still live", w.arTargetID)
			}
		}
	}

	// 11. the share secret stays deleted unless an explicit RestoreSecret ran
	// since (#2650 class: SetSecretAutoRotate's stale full-row Save undeletes
	// it with no RestoreSecret call).
	w.mu.Lock()
	shareSecretDeletedExpected := w.shareSecretDeletedExpected
	w.mu.Unlock()
	if shareSecretDeletedExpected {
		var isDeleted bool
		require.NoError(t, w.setupDB.Raw("SELECT deleted_at IS NOT NULL FROM secret_nodes WHERE id = ?", w.shareSecretID).Scan(&isDeleted).Error)
		if !isDeleted {
			return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2650 class): secret %d's last successful delete/restore op was a delete, but it is live again with no RestoreSecret call", w.shareSecretID)
		}
	}

	// 12. no enabled dynamic-secret config under a soft-deleted project (#2651 class).
	var enabledConfigUnderDeletedProject int64
	require.NoError(t, w.setupDB.Raw(
		"SELECT count(*) FROM dynamic_secret_configs c JOIN projects p ON c.project_id = p.id WHERE c.disabled = false AND p.deleted_at IS NOT NULL",
	).Scan(&enabledConfigUnderDeletedProject).Error)
	if enabledConfigUnderDeletedProject > 0 {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2651 class): %d enabled dynamic-secret config(s) exist under a soft-deleted project", enabledConfigUnderDeletedProject)
	}

	// 14. a password hash a successful ChangePassword superseded is never the
	// stored hash again (#2654 class). GUARD-5 addition: invariant 7 above
	// watches account_state, which is #2653's half of that pair and says
	// nothing about the password. Without this, the #2654 pending seed could
	// not reproduce even under a perfectly forced interleaving — there was no
	// oracle for its effect at all.
	w.mu.Lock()
	superseded := w.passwordSupersededHash
	w.mu.Unlock()
	if superseded != "" {
		var nowHash string
		require.NoError(t, w.setupDB.Raw("SELECT password_hash FROM users WHERE id = ?", w.victimID).Scan(&nowHash).Error)
		if nowHash == superseded {
			return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2654 class): victim user %d's password hash was superseded by a successful ChangePassword, but the OLD hash is stored again", w.victimID)
		}
	}

	// 15. MFA is only ever active with a TOTP secret the account holder
	// validated a code against (#2655 class). GUARD-5 addition, same reason
	// as 14: no pre-existing invariant observed MFA at all, so the #2655 seed
	// had no oracle.
	w.mu.Lock()
	mfaActivated, mfaValidated := w.mfaActivated, w.mfaValidatedSecret
	w.mu.Unlock()
	if mfaActivated && mfaValidated != "" {
		active, aerr := w.c0.loadTOTPSecret(ctx, w.mfaUserID)
		require.NoError(t, aerr)
		if active != mfaValidated {
			return fmt.Sprintf("GLOBAL INVARIANT VIOLATED (#2655 class): MFA for user %d is active with a TOTP secret the account holder never validated a code against", w.mfaUserID)
		}
	}

	return ""
}

// g4FindAuditChainViolation checks invariant 13 (the audit hash chain verifies
// end to end, ADR-029) on its own.
//
// Split out of g4FindViolation (GUARD-5 item 3) because it is the one
// invariant whose cost grows with the audit log, and the audit log grows
// monotonically for the life of a world. Every other invariant is a bounded
// indexed query; this one re-hashes every row. Checking it after each of the
// ordering sweep's 174 runs made the sweep quadratic and it blew the 60-minute
// test timeout without finishing. The sweep calls g4FindStateViolation
// per-run and this one ONCE at the end instead — so a broken chain is still
// caught, just not re-verified 174 times.
//
// The per-issue regression tests and the fuzz target keep checking it every
// time, which is where per-operation granularity actually matters: there, a
// chain break needs to be attributable to one pair.
func g4FindAuditChainViolation(t testing.TB, w *g4World) string {
	t.Helper()
	v, err := w.c0.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	if !v.Valid {
		return fmt.Sprintf("GLOBAL INVARIANT VIOLATED: audit hash chain broken: %s (first broken id=%v)", v.Reason, v.FirstBrokenID)
	}
	return ""
}

// --- fuzz target ---------------------------------------------------------

const g4MaxPairs = 8

// decodeG4Pairs reads 4 bytes per pair (kindA, miscA, kindB, miscB), capped
// at g4MaxPairs pairs so one iteration stays a bounded, fast burst.
func decodeG4Pairs(data []byte) [][2]g4Op {
	var pairs [][2]g4Op
	for i := 0; i+3 < len(data) && len(pairs) < g4MaxPairs; i += 4 {
		pairs = append(pairs, [2]g4Op{
			{kind: data[i], misc: data[i+1]},
			{kind: data[i+2], misc: data[i+3]},
		})
	}
	return pairs
}

func FuzzCrossReplicaInvariants(f *testing.F) {
	w := buildG4World(f)

	// Seeds: only the issues already fixed on main (see header comment) — a
	// seed for a still-open issue would fail this test on main today. They live
	// one per file (cross_replica_seed_entry_<issue>_test.go, registered into
	// g4FuzzSeedPrograms; see registry_entries_test.go), never in a list here.
	for _, s := range g4FuzzSeedPrograms {
		f.Add(s.program)
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, program []byte) {
		campaignID := g4ResetIteration(t, w)
		w.mu.Lock()
		w.campaignID = campaignID
		w.mu.Unlock()

		pairs := decodeG4Pairs(program)
		for _, pair := range pairs {
			replicaA := g4Replica(w, 0)
			replicaB := g4Replica(w, 1)
			raceReplicas(t,
				func() error { g4RunOp(t, w, replicaA, pair[0]); return nil },
				func() error { g4RunOp(t, w, replicaB, pair[1]); return nil },
			)
			g4CheckInvariants(t, w)
		}
	})
}
