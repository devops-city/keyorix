// interleave_driver_selftest_postgres_test.go — the driver's own calibration
// against ALREADY-FIXED cross-replica pairs.
//
// "A guard nobody has watched fail is not a guard", and its twin: a driver
// nobody has watched succeed on a known answer proves nothing when it later
// reports success on an unknown one. Every per-issue regression test in this
// campaign rests on one claim about this driver — that it really does pause a
// replica between its check and its write, and really does release the two
// writes in the order asked for. These tests pin that claim to pairs whose
// answer is already known from main:
//
//   - #2648 (UpdateSharePermission vs RevokeShare, fixed by #2666): under
//     EVERY one of the six orderings, a revoke that reported success must
//     stay revoked. The pre-#2666 code failed exactly the A-check,B-check,
//     B-act,A-act ordering; the fix made all six hold. So all six passing
//     here is the positive control. Since SHARE-CAS-1 the update holds the
//     share row lock from its in-transaction read, so the two orderings that
//     need B's act while A is parked (A-check,B-check,B-act,A-act and
//     B-check,A-check,B-act,A-act) are serialized and must be REPORTED as
//     blocked, invariant intact; the other four must still be forced. The
//     driver's own red direction is
//     covered by interleave_production_purity_test.go's planted-violation
//     test plus the per-issue tests that DO go red.
//   - #2660 (AddSecretDependency cross-replica cycle, fixed by #2670): the
//     fix is an advisory lock, so the second replica cannot reach its sync
//     point at all — it blocks on the lock the first replica holds. That is
//     the driver's "Degraded: blocked" path, and this test asserts the driver
//     reports it as such AND still drives both operations to completion with
//     the invariant intact. Without this case a future change that silently
//     turned every blocked run into a pass would go unnoticed.
//
// Postgres only; skipped cleanly when KEYORIX_TEST_PG_DSN is unset.
package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestInterleaveDriver_AllSixOrderings_OnAFixedPair_Postgres drives the
// already-fixed #2648 pair through every ordering and asserts both that the
// driver forced each one and that the invariant holds in all six.
func TestInterleaveDriver_AllSixOrderings_OnAFixedPair_Postgres(t *testing.T) {
	t.Parallel()
	for _, order := range allInterleavings {
		t.Run(string(order), func(t *testing.T) {
			t.Parallel()
			f := newCTAReview(t)
			owner := f.user("ilv-owner", "project_admin")
			recipient := f.user("ilv-recipient", "project_viewer")
			s := f.secret("ilv-secret", owner.ID)
			share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
				SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
			})
			require.NoError(t, err)

			spA := newSyncPoint(t, f.dbA, "UpdateSharePermission", "update", "share_records")
			// RevokeShare SOFT-deletes the share: the SQL is an UPDATE of
			// deleted_at, but GORM routes it through the Delete callback
			// family, not Update. Getting this wrong is silent — the sync
			// point simply never fires and the ordering degrades — which is
			// exactly why runInterleaving reports Forced/Degraded explicitly
			// and why requireForced exists. The first draft of this test used
			// "update" here and all four interleaved orderings reported
			// DEGRADED rather than passing vacuously.
			spB := newSyncPoint(t, f.dbB, "RevokeShare", "delete", "share_records")

			opA := func() error {
				_, err := f.coreA.UpdateSharePermission(f.ctx, &UpdateShareRequest{
					ShareID: share.ID, Permission: "write", UpdatedBy: owner.ID,
				})
				return err
			}
			opB := func() error { return f.coreB.RevokeShare(f.ctx, share.ID, owner.ID) }
			if order == orderABBaAa || order == orderBABcBa {
				// SHARE-CAS-1: A holds the share row lock from its
				// in-transaction read (LockShareRecordForUpdate), so B's act
				// cannot land while A is parked at its UPDATE: these two
				// orderings are serialized by design, and the driver must say
				// so (the blocked-path control, as in the test below) while
				// still running both to completion. 3 s as there.
				res := runInterleavingTimeout(t, order, spA, spB, opA, opB, 3*time.Second)
				t.Log(res.String())
				assert.False(t, res.Forced, "B's revoke landed while A held the share row lock: the row lock is gone")
				assert.Contains(t, res.Degraded, "serialized", "the driver must report WHY the ordering degraded")
				require.NoError(t, res.ErrB, "the revoke itself must report success under %s", order)
			} else {
				res := runInterleaving(t, order, spA, spB, opA, opB)
				// Both ops write share_records, so both sync points must be
				// reachable in these orderings. A degraded run here would mean
				// the driver cannot pin this pair at all, which would
				// invalidate every per-issue test built on the same mechanism.
				requireForced(t, res)
				require.NoError(t, res.ErrB, "the revoke itself must report success under %s", order)
			}

			assert.Zero(t, f.countLive(&models.ShareRecord{}, "id = ? AND deleted_at IS NULL", share.ID),
				"#2648 regression under %s: a share whose revocation reported success is live again", order)
		})
	}
}

// TestInterleaveDriver_ReportsBlockedWhenTheFixSerializes_Postgres pins the
// driver's blocked-on-lock path against #2660's landed advisory-lock fix.
//
// This is the case most likely to rot silently: if a future refactor made
// waitArrive return true spuriously, or made a timeout look like a forced
// run, every "fixed" verdict in this campaign would become unfalsifiable. So
// the assertion is on the driver's own report (Forced must be FALSE, with a
// blocked reason), not only on the invariant.
func TestInterleaveDriver_ReportsBlockedWhenTheFixSerializes_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s1 := f.secret("ilv-dep-1", f.adminID)
	s2 := f.secret("ilv-dep-2", f.adminID)
	s3 := f.secret("ilv-dep-3", f.adminID)
	// One pre-existing edge so the project has a row at all (see
	// TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres).
	_, err := f.setup.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s3.ID, s1.ID, "", 0)
	require.NoError(t, err)

	spA := newSyncPoint(t, f.dbA, "AddSecretDependency", "create", "secret_dependencies")
	spB := newSyncPoint(t, f.dbB, "AddSecretDependency", "create", "secret_dependencies")

	// 3 s, not the default 15 s: blocking is the EXPECTED outcome here (the
	// whole point of the test), so the default hang-detector budget would be
	// pure wall-clock and would push this one test past the brief's
	// 10 s-per-test ceiling. 3 s is still ~100x the window A's own INSERT
	// needs, so a genuine arrival cannot be mistaken for a block.
	res := runInterleavingTimeout(t, orderABBaAa, spA, spB,
		func() error {
			_, err := f.coreA.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s1.ID, s2.ID, "", 0)
			return err
		},
		func() error {
			_, err := f.coreB.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s2.ID, s1.ID, "", 0)
			return err
		},
		3*time.Second,
	)
	t.Log(res.String())

	require.True(t, spA.fired(), "replica A must have paused before its edge INSERT")
	assert.False(t, res.Forced,
		"#2670's advisory lock must prevent B from reaching its own INSERT while A holds the graph lock — a forced run here means the serialization is gone")
	assert.False(t, spB.fired(),
		"B reached its edge INSERT while A held the graph lock, so the two cycle checks are not serialized")
	assert.Contains(t, res.Degraded, "never reached",
		"the driver must report WHY the ordering degraded, not just that it did")

	both := f.countLive(&models.SecretDependency{},
		"(dependent_secret_id = ? AND depends_on_secret_id = ?) OR (dependent_secret_id = ? AND depends_on_secret_id = ?)",
		s1.ID, s2.ID, s2.ID, s1.ID)
	assert.Less(t, both, int64(2), "INV-CORE-31: both edges committed — a persisted dependency cycle")
	assert.ErrorContains(t, res.ErrB, "cycle", "B's cycle check runs after A commits and must refuse")
}
