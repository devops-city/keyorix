// concurrency_break_glass_activate_vs_revoke_postgres_test.go — #2722.
//
// ActivateBreakGlass performs two separate storage operations with no shared
// transaction: it inserts the activation record (state=active), then grants the
// emergency role. RevokeBreakGlassActivationAtomic removes the role and
// transitions the record in one transaction, and deliberately TOLERATES
// ErrRoleNotAssigned ("already gone — proceed to reconcile the record"). So a
// revoke landing between the activation's two writes removed nothing, set the
// record to `revoked`, audited success — and then the activation granted the
// emergency role anyway.
//
// End state: a self-granted, SoD-bypassing role live for its whole TTL, while
// the record every reviewer and the UI reads says revoked. Because the admin's
// revoke reported success, nobody revisits it; ReconcileExpired only touches
// `active` rows so it never cleans it up; and the freed unique-index slot lets
// the user activate a second time.
//
// WHY THE TESTS HERE ARE SHAPED THIS WAY, which is the part worth reading:
//
// Every other fix in this class is proved with the ctaReview beforeA hook — a
// one-shot GORM callback that runs replica B's whole operation immediately
// before replica A's own write. That technique CANNOT be used here, and the
// reason is structural rather than incidental: the fix serializes A and B on a
// named lock, and beforeA runs B SYNCHRONOUSLY INSIDE A's callback, on A's
// goroutine, while A already holds that lock. B would block on the lock
// forever, inside A's own call stack, and the test would hang rather than fail.
// The hook is only usable when A and B contend on database row locks (which the
// DB resolves) and not on an advisory lock held across both.
//
// So the serialization is proved directly instead:
//
//   - TestCTAReview_BreakGlassActivate_WaitsForTheRevokeLock_Postgres holds
//     projectAdminGuardLockKey on replica B — the exact key
//     RevokeBreakGlassActivationAtomic takes — and asserts A's activation does
//     not complete until it is released. That is mutual exclusion with the
//     revoke path, established without needing the revoke itself to be mid-flight.
//   - TestCTAReview_BreakGlassActivate_vs_Revoke_CrossReplicaPostgres races the
//     two operations concurrently, many times, and asserts the INVARIANT on the
//     end state: if the revoke reported success, no live emergency grant may
//     remain. This one is probabilistic by construction, and it is only here
//     because it is red without the lock (see the PR for the measured rate) —
//     it is corroboration, not the primary guard.
//
// The primary guard is neither of those: it is the structural
// TestActivateBreakGlass_InsertAndGrantShareTheRevokeLock in
// break_glass_lock_guard_test.go, which runs in the DSN-less CI leg.
package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	breakGlassTestRole = "project_developer"
	// The activating user must already be a project MEMBER: ActivateBreakGlass
	// refuses a non-member outright ("break-glass is available only to members of
	// the project"), long before it reaches the insert or the grant. Granting a
	// DIFFERENT role than the emergency one, so a pre-existing user_roles row can
	// never be miscounted as the emergency grant under test.
	//
	// This was not a guess: the first version of these tests used a user with no
	// project role, and TestCTAReview_..._WaitsForTheRevokeLock caught it —
	// ActivateBreakGlass returned the membership refusal immediately instead of
	// waiting on the lock. The concurrent test alongside it had been PASSING
	// vacuously for the same reason: every activation failed the membership check,
	// so there was never a grant to race against a revoke.
	breakGlassMemberRole = "project_viewer"
)

// enableBreakGlass configures the policy on every replica of the fixture and
// returns the emergency role. It fails the test if the role is missing or is one
// ActivateBreakGlass would refuse, so a fixture drift shows up as a fixture
// error rather than as every subtest silently taking the refusal path.
func (f *ctaReview) enableBreakGlass() *models.Role {
	f.t.Helper()
	p := BreakGlassPolicy{Enabled: true, EmergencyRole: breakGlassTestRole, DefaultTTL: time.Hour, MaxTTL: time.Hour}
	for _, c := range []*KeyorixCore{f.setup, f.coreA, f.coreB} {
		c.SetBreakGlassPolicy(p)
	}
	role, err := f.setup.Storage().GetRoleByName(f.ctx, breakGlassTestRole)
	require.NoError(f.t, err, "fixture: the emergency role %q must exist after bootstrap", breakGlassTestRole)
	hasAssign, err := f.setup.Storage().RoleSetHasPermission(f.ctx, []uint{role.ID}, "roles.assign")
	require.NoError(f.t, err)
	require.False(f.t, hasAssign,
		"fixture: %q now carries roles.assign, so ActivateBreakGlass refuses it outright and these tests would "+
			"pass without ever reaching the race", breakGlassTestRole)
	return role
}

// liveEmergencyGrants counts live user_roles rows for the emergency role at the
// fixture project — the effect that must not survive a successful revoke.
func (f *ctaReview) liveEmergencyGrants(userID, roleID uint) int64 {
	f.t.Helper()
	return f.countLive(&models.UserRole{}, "user_id = ? AND role_id = ? AND project_id = ?", userID, roleID, f.projectID)
}

func TestCTAReview_BreakGlassActivate_WaitsForTheRevokeLock_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	f.enableBreakGlass()
	u := f.user("bg2722wait", breakGlassMemberRole)

	held := make(chan struct{}) // closed once B holds the lock
	release := make(chan struct{})
	lockDone := make(chan struct{})

	// The release is registered as a CLEANUP, not left to the happy path. A
	// t.Fatalf below would otherwise abort this test with the goroutine still
	// parked inside WithNamedLock, holding the lock forever — and on Postgres an
	// advisory lock is scoped to the DATABASE, not to pgIsolatedSchemaDSN's
	// schema, so every other pg-gated test in the same database that touches
	// projectAdminGuardLockKey blocks on it indefinitely. Found the hard way:
	// the first red-proof run of this file failed exactly as intended here and
	// then HUNG the parallel test alongside it for the full 600s timeout. A test
	// that hangs the suite on failure instead of failing is worse than no test.
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		<-lockDone
	})

	go func() {
		defer close(lockDone)
		// B holds the SAME key RevokeBreakGlassActivationAtomic takes.
		_ = f.coreB.Storage().WithNamedLock(f.ctx, projectAdminGuardLockKey(f.projectID), func(context.Context) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	activated := make(chan error, 1)
	go func() {
		_, err := f.coreA.ActivateBreakGlass(f.ctx, f.projectID, u.ID, "prod incident 2722", "")
		activated <- err
	}()

	// A must still be waiting. A generous window: this asserts "did not complete",
	// so a slow machine makes it MORE likely to hold, never less — the failure
	// direction is a fix that does not take the lock at all, which completes
	// immediately.
	select {
	case err := <-activated:
		t.Fatalf("ActivateBreakGlass completed while the revoke's own lock was held by another replica — "+
			"the insert and the grant are not serialized against RevokeBreakGlassActivationAtomic (#2722); err=%v", err)
	case <-time.After(750 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	<-lockDone
	require.NoError(t, <-activated, "once the lock is released the activation must proceed normally")
}

func TestCTAReview_BreakGlassActivate_vs_Revoke_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	role := f.enableBreakGlass()

	// Each iteration is a fresh user, so the partial unique index on
	// (project_id, user_id) WHERE state='active' never rejects a later iteration
	// for a reason unrelated to the race.
	const iterations = 12
	asserted := 0
	for i := range iterations {
		u := f.user(breakGlassIterUser(i), breakGlassMemberRole)

		var wg sync.WaitGroup
		var revokeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = f.coreA.ActivateBreakGlass(f.ctx, f.projectID, u.ID, "prod incident 2722", "")
		}()
		go func() {
			defer wg.Done()
			// B revokes whatever active activation this user has, the moment it can
			// see one. Polling rather than a fixed sleep: a sleep long enough to be
			// reliable is long enough that A has usually finished, which would make
			// the race never happen and the assertion vacuous.
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				acts, err := f.coreB.ListBreakGlassActivations(f.ctx, f.projectID)
				if err == nil {
					for _, a := range acts {
						if a.UserID == u.ID && a.State == BreakGlassActive {
							revokeErr = f.coreB.RevokeBreakGlass(f.ctx, f.adminID, 0, f.projectID, a.ID)
							return
						}
					}
				}
			}
		}()
		wg.Wait()

		// The invariant, asserted on the EFFECT: a revoke that reported success
		// must leave no live emergency grant. If B never saw an activation to
		// revoke (revokeErr stays nil with nothing revoked) the grant may
		// legitimately be live, so the assertion is conditioned on a revoke having
		// actually happened and succeeded.
		var revoked int64
		require.NoError(t, f.setupDB.Model(&models.BreakGlassActivation{}).
			Where("project_id = ? AND user_id = ? AND state = ?", f.projectID, u.ID, BreakGlassRevoked).
			Count(&revoked).Error)
		if revoked == 0 || revokeErr != nil {
			continue // no successful revoke this iteration: nothing to assert
		}
		asserted++
		assert.Zero(t, f.liveEmergencyGrants(u.ID, role.ID),
			"iteration %d: the activation record says revoked and the revoke reported success, but the "+
				"emergency role is still granted — a self-granted SoD-bypassing role surviving an explicit "+
				"revoke, live for its full TTL, that nobody will revisit (#2722)", i)
	}

	// Without this floor the test is vacuous whenever B never manages a
	// successful revoke: every iteration takes the `continue` above and nothing
	// is ever asserted. That is not hypothetical — the first version of this file
	// passed exactly that way, because the activating user was not a project
	// member so no activation existed for B to revoke (see breakGlassMemberRole).
	// A probabilistic test MUST report when the scenario it needs did not occur.
	require.GreaterOrEqual(t, asserted, iterations/2,
		"only %d of %d iterations produced a successfully-revoked activation to assert on — the race this "+
			"test exists to cover mostly did not happen, so a green result proves nothing; investigate the "+
			"fixture rather than trusting it", asserted, iterations)
}

func breakGlassIterUser(i int) string {
	return "bg2722-" + string(rune('a'+i%26)) + "-" + itoaSmall(i)
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
