package store

// state_transition_full_row_test.go — INV-STORE-14 (#2510), the zero-value half.
// A conditional state transition persists every column it OWNS in the same
// UPDATE as the state change, including columns the caller set to their zero
// value: a plain struct Updates skips zero values, so without an explicit
// Select the write would silently keep a stale column while still reporting
// matched=true.
//
// TransitionMachineIdentityState still uses Select("*") for this.
// TransitionSecretStatus does NOT any more — #2695 narrowed it to
// Select("Status", "UpdatedAt"), because a full-row write reverted every column
// a narrower concurrent writer had changed since the caller's read. See
// TestTransitionSecretStatus_WritesOnlyStatusAndUpdatedAt below for the full
// reasoning and for how the zero-value property is preserved. The fromState predicate and real-Postgres concurrency halves of
// INV-STORE-14/15 are covered by local_state_transition_cas_test.go and the
// concurrency_*_postgres_test.go files.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestTransitionMachineIdentityState_PersistsFullRowIncludingZeroValues(t *testing.T) {
	ctx := context.Background()
	ls := newMachineStore(t)
	created := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)
	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ID: 1, ProjectID: 1, Name: "ci-runner", State: "active", Description: "old description",
		Classification: "restricted", CreatedAt: created, UpdatedAt: created,
	}).Error)

	m, err := ls.GetMachineIdentity(ctx, 1)
	require.NoError(t, err)
	revokedAt := created.Add(time.Hour)
	m.State = "revoked"
	m.UpdatedAt = revokedAt
	m.RevokedAt = &revokedAt
	m.Description = ""
	m.Classification = ""

	matched, err := ls.TransitionMachineIdentityState(ctx, m, "active")
	require.NoError(t, err)
	require.True(t, matched)

	got, err := ls.GetMachineIdentity(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "revoked", got.State)
	require.NotNil(t, got.RevokedAt, "revoked_at must be persisted in the same statement as the state change")
	assert.True(t, got.RevokedAt.Equal(revokedAt))
	assert.Empty(t, got.Description, "a field the caller cleared must be persisted as cleared (Select(\"*\")), not left stale")
	assert.Empty(t, got.Classification, "a field the caller cleared must be persisted as cleared (Select(\"*\")), not left stale")
}

// TestTransitionSecretStatus_WritesOnlyStatusAndUpdatedAt replaces what used to
// be TestTransitionSecretStatus_PersistsFullRowIncludingZeroValues, and it is the
// ONE place #2695 inverts an existing assertion rather than adding one — so the
// reasoning belongs here, in full.
//
// The old test asserted that clearing Description and Classification on the
// in-memory struct persisted those clears, i.e. it pinned Select("*"). #2695
// identifies that exact behaviour as the defect: this method's only callers
// (SuspendSecret, ResumeSecret) set Status and UpdatedAt and nothing else, so
// every other column it wrote came from a read that is already stale by the time
// the CAS runs — reverting a concurrent read-count increment (a spent MaxReads
// budget), an ownership clear, a classification change or a rotation-config
// change. The CAS stopped it resurrecting a deleted row; it did not stop it
// losing those updates.
//
// What about the zero-value property the old test was built around (GORM's
// struct-based Updates skips zero values, so a column the method owns could
// silently keep a stale value while still reporting matched=true)? It does not
// apply to this method any more, and this test does not pretend to cover it. The
// two remaining in-scope columns are Status — which no caller ever sets to ""
// (both set a non-empty constant) — and UpdatedAt, which GORM stamps itself on
// an Updates against a model carrying that field. I wrote a subtest for it first
// and then confirmed by mutation that it passed with the Select removed
// entirely, i.e. it asserted nothing; it is deleted rather than kept as decoration.
// The whitelist's job here is purely EXCLUSION — keeping the other columns out —
// which is what the one remaining subtest asserts, and what goes red when the
// Select is widened back to "*".
//
// TransitionMachineIdentityState still needs the inclusion half (it writes
// RevokedAt and clears Description/Classification), so its sibling test above is
// unchanged.
func TestTransitionSecretStatus_WritesOnlyStatusAndUpdatedAt(t *testing.T) {
	ctx := context.Background()

	t.Run("an out-of-scope column a concurrent writer changed is left alone", func(t *testing.T) {
		ls := newTransitionSecretStatusStore(t)
		require.NoError(t, ls.db.Create(&models.SecretNode{
			ID: 1, Name: "db-password", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
			Description: "old description", Classification: "restricted", ReadCount: 0, OwnerID: 7,
		}).Error)

		var secret models.SecretNode
		require.NoError(t, ls.db.First(&secret, 1).Error)

		// Simulate the concurrent narrower writers whose updates the full-row
		// version reverted: a read-count increment (a MaxReads budget being
		// spent) and an ownership clear (offboarding).
		require.NoError(t, ls.db.Model(&models.SecretNode{}).Where("id = ?", 1).
			Updates(map[string]any{"read_count": 3, "owner_id": 0}).Error)

		// Now the stale struct's suspend lands. It also "clears" two columns it
		// does not own, which the old Select("*") honoured.
		secret.Status = "suspended"
		secret.Description = ""
		secret.Classification = ""

		matched, err := ls.TransitionSecretStatus(ctx, &secret, "active")
		require.NoError(t, err)
		require.True(t, matched)

		var got models.SecretNode
		require.NoError(t, ls.db.First(&got, 1).Error)
		assert.Equal(t, "suspended", got.Status, "the transition itself must still land")
		assert.Equal(t, 3, got.ReadCount,
			"#2695: a suspend must not revert a concurrent read-count increment — that re-opens a spent MaxReads budget")
		assert.Zero(t, got.OwnerID,
			"#2695: a suspend must not revert a concurrent ownership clear — that hands the owner short-circuit back to a departed user")
		assert.Equal(t, "old description", got.Description,
			"#2695: description is not this transition's to write; the caller's stale copy of it must not reach the UPDATE")
		assert.Equal(t, "restricted", got.Classification,
			"#2695: classification is not this transition's to write either")
	})
}
