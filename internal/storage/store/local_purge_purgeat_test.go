package store

// RETENTION-1: the purge job never removes a secret before the purge date that was shown
// for it. The rule under test is secretPurgeCandidate.eligible (see its doc comment); the
// integration tests drive it through the real DeleteSecret / PurgeDeletedSecretsBefore.

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func day(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// Table test on the boundary itself: strictly after purge_at, never at or before it, and
// `before` (derived from the CURRENT config) is irrelevant for a row with a frozen date.
func TestSecretPurgeCandidate_Eligible_Boundary(t *testing.T) {
	deleted := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	purgeAt := deleted.AddDate(0, 0, 30)
	del := gorm.DeletedAt{Time: deleted, Valid: true}

	cases := []struct {
		name   string
		cand   secretPurgeCandidate
		now    time.Time
		before time.Time
		want   bool
	}{
		{"frozen: 1ns before purge_at", secretPurgeCandidate{DeletedAt: del, PurgeAt: &purgeAt}, purgeAt.Add(-time.Nanosecond), purgeAt, false},
		{"frozen: exactly purge_at", secretPurgeCandidate{DeletedAt: del, PurgeAt: &purgeAt}, purgeAt, purgeAt, false},
		{"frozen: 1ns after purge_at", secretPurgeCandidate{DeletedAt: del, PurgeAt: &purgeAt}, purgeAt.Add(time.Nanosecond), purgeAt, true},
		{"frozen: window SHORTENED after deletion (before is far in the future) must not pull it earlier",
			secretPurgeCandidate{DeletedAt: del, PurgeAt: &purgeAt}, deleted.Add(day(10)), deleted.Add(day(10)).AddDate(0, 0, -7), false},
		{"frozen: window LENGTHENED after deletion does not defer the shown date",
			secretPurgeCandidate{DeletedAt: del, PurgeAt: &purgeAt}, purgeAt.Add(time.Hour), purgeAt.Add(time.Hour).AddDate(0, 0, -90), true},
		{"frozen: purge_at in another zone is compared as the same instant",
			secretPurgeCandidate{DeletedAt: del, PurgeAt: ptrTime(purgeAt.In(time.FixedZone("x", 5*3600)))}, purgeAt.Add(-time.Second), purgeAt, false},
		{"frozen: override is already folded into purge_at, not re-applied",
			secretPurgeCandidate{DeletedAt: del, PurgeAt: &purgeAt, RetentionOverrideDays: 7}, deleted.Add(day(10)), time.Time{}, false},
		{"legacy: before the cutoff", secretPurgeCandidate{DeletedAt: del}, purgeAt.Add(time.Hour), purgeAt, true},
		{"legacy: not past the cutoff", secretPurgeCandidate{DeletedAt: del}, purgeAt, deleted.Add(-time.Hour), false},
		{"legacy: override longer than global holds it", secretPurgeCandidate{DeletedAt: del, RetentionOverrideDays: 90}, purgeAt.Add(day(5)), purgeAt.Add(day(5)).AddDate(0, 0, -30), false},
		{"legacy: override shorter than global releases it", secretPurgeCandidate{DeletedAt: del, RetentionOverrideDays: 7}, deleted.Add(day(8)), deleted.Add(day(8)).AddDate(0, 0, -30), true},
		{"not deleted", secretPurgeCandidate{}, purgeAt.Add(day(400)), purgeAt, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.cand.eligible(tc.now, tc.before))
		})
	}
}

// Property: for any deletion window D1 (optionally overridden), any later config D2 and
// any clock reading, a stamped secret is eligible only strictly after the date it was
// shown with (deleted_at + effective window at deletion). Includes readings within a
// second of the boundary.
func TestSecretPurgeCandidate_NeverEligibleBeforeShownDate_Property(t *testing.T) {
	rng := rand.New(rand.NewSource(20261010))
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 20000; i++ {
		d1 := 1 + rng.Intn(400)
		override := 0
		if rng.Intn(3) == 0 {
			override = 7 + rng.Intn(400)
		}
		d2 := 1 + rng.Intn(400) // config at purge time; unrelated to d1
		deleted := base.Add(time.Duration(rng.Int63n(int64(day(365)))))
		node := models.SecretNode{
			DeletedAt:             gorm.DeletedAt{Time: deleted, Valid: true},
			RetentionOverrideDays: override,
		}
		stamp := models.PurgeAtFor(deleted, d1)
		if override > 0 {
			stamp = models.PurgeAtFor(deleted, override)
		}
		node.PurgeAt = &stamp
		shown, ok := node.EffectivePurgeAt(d1)
		require.True(t, ok)
		require.True(t, shown.Equal(stamp), "the shown date IS the frozen date")

		var now time.Time
		switch rng.Intn(3) {
		case 0:
			now = shown.Add(time.Duration(rng.Int63n(int64(2*time.Second))) - time.Second)
		default:
			now = deleted.Add(time.Duration(rng.Int63n(int64(day(900)))))
		}
		cand := secretPurgeCandidate{ID: 1, DeletedAt: node.DeletedAt, RetentionOverrideDays: override, PurgeAt: &stamp}
		before := now.AddDate(0, 0, -d2)
		if cand.eligible(now, before) {
			require.True(t, now.After(shown), "purged at %s, before shown date %s (d1=%d override=%d d2=%d)", now, shown, d1, override, d2)
		} else {
			// and it is released as soon as the shown date has passed: the date is truthful, not
			// merely a lower bound that never arrives.
			require.False(t, now.After(shown), "still held at %s although shown date %s has passed", now, shown)
		}
	}
}

func newPurgeAtStore(t *testing.T, days int) *LocalStorage {
	t.Helper()
	ls := newSoftDeleteTestStore(t)
	ls.SetSoftDeleteRetentionDays(days)
	// deleteProjectCascade also disables the project's dynamic-secret configs.
	require.NoError(t, ls.db.AutoMigrate(&models.DynamicSecretConfig{}))
	require.NoError(t, ls.db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, ls.db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "dev"}).Error)
	return ls
}

func makeSecret(t *testing.T, ls *LocalStorage, name string, override int) uint {
	t.Helper()
	s, err := ls.CreateSecret(context.Background(), &models.SecretNode{
		ProjectID: 1, EnvironmentID: 10, Name: name, IsSecret: true, Type: "api_key", Status: "active",
		RetentionOverrideDays: override,
	})
	require.NoError(t, err)
	return s.ID
}

// ageDeletion moves a soft-deleted secret's deletion (deleted_at AND its frozen purge_at)
// k days into the past, i.e. "the secret was deleted k days ago", without a fake clock.
func ageDeletion(t *testing.T, ls *LocalStorage, id uint, k int) {
	t.Helper()
	var n models.SecretNode
	require.NoError(t, ls.db.Unscoped().First(&n, id).Error)
	updates := map[string]interface{}{"deleted_at": n.DeletedAt.Time.AddDate(0, 0, -k)}
	if n.PurgeAt != nil {
		updates["purge_at"] = n.PurgeAt.AddDate(0, 0, -k)
	}
	require.NoError(t, ls.db.Unscoped().Model(&models.SecretNode{}).Where("id = ?", id).UpdateColumns(updates).Error)
}

func exists(t *testing.T, ls *LocalStorage, id uint) bool {
	t.Helper()
	var c int64
	require.NoError(t, ls.db.Unscoped().Model(&models.SecretNode{}).Where("id = ?", id).Count(&c).Error)
	return c == 1
}

func TestDeleteSecret_FreezesPurgeAtInUTC(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	id := makeSecret(t, ls, "a", 0)
	require.NoError(t, ls.DeleteSecret(context.Background(), id))

	got, err := ls.GetSecretIncludingDeleted(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, got.PurgeAt, "purge_at stamped by the delete itself")
	assert.Equal(t, time.UTC, got.PurgeAt.Location())
	assert.True(t, got.PurgeAt.Equal(got.DeletedAt.Time.UTC().AddDate(0, 0, 30)), "deleted_at + 30d, got %s", got.PurgeAt)
}

func TestDeleteSecret_PerSecretOverrideIsFrozenIntoPurgeAt(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	id := makeSecret(t, ls, "hv", 90)
	require.NoError(t, ls.DeleteSecret(context.Background(), id))
	got, err := ls.GetSecretIncludingDeleted(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, got.PurgeAt)
	assert.True(t, got.PurgeAt.Equal(got.DeletedAt.Time.UTC().AddDate(0, 0, 90)))
}

// The reported scenario: the operator SHORTENS retention after a secret was deleted. The
// shown date (deleted + 30d) must hold; under the old rule the secret was purged at day 8.
func TestPurge_RetentionShortenedAfterDeletion_DoesNotPurgeEarlierThanShown(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	ctx := context.Background()
	id := makeSecret(t, ls, "a", 0)
	require.NoError(t, ls.DeleteSecret(ctx, id))
	shownBefore, err := ls.GetSecretIncludingDeleted(ctx, id)
	require.NoError(t, err)
	shown := *shownBefore.PurgeAt

	ls.SetSoftDeleteRetentionDays(7) // config change after the delete
	ageDeletion(t, ls, id, 10)       // 10 days later: past the NEW 7-day window, inside the shown 30
	n, err := ls.PurgeDeletedSecretsBefore(ctx, time.Now().UTC().AddDate(0, 0, -7))
	require.NoError(t, err)
	assert.Zero(t, n, "purged at day 10 although the shown date was day 30")
	assert.True(t, exists(t, ls, id))

	after, err := ls.GetSecretIncludingDeleted(ctx, id)
	require.NoError(t, err)
	assert.True(t, after.PurgeAt.Equal(shown.AddDate(0, 0, -10)), "the date follows the (aged) deletion, never the new config")

	ageDeletion(t, ls, id, 21) // now 31 days after deletion
	n, err = ls.PurgeDeletedSecretsBefore(ctx, time.Now().UTC().AddDate(0, 0, -7))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "released once the shown date has passed")
	assert.False(t, exists(t, ls, id))
}

// Chosen rule, other direction: lengthening retention after deletion does not defer the
// date already shown either - the shown date is exactly when the purge happens.
func TestPurge_RetentionLengthenedAfterDeletion_KeepsShownDate(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	ctx := context.Background()
	id := makeSecret(t, ls, "a", 0)
	require.NoError(t, ls.DeleteSecret(ctx, id))

	ls.SetSoftDeleteRetentionDays(90)
	ageDeletion(t, ls, id, 31)
	n, err := ls.PurgeDeletedSecretsBefore(ctx, time.Now().UTC().AddDate(0, 0, -90))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestPurge_OverrideLongerThanGlobal_HoldsUntilItsOwnDate(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	ctx := context.Background()
	id := makeSecret(t, ls, "hv", 90)
	require.NoError(t, ls.DeleteSecret(ctx, id))
	ageDeletion(t, ls, id, 60)
	n, err := ls.PurgeDeletedSecretsBefore(ctx, time.Now().UTC().AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.True(t, exists(t, ls, id))
}

func TestRestoreClearsPurgeAt_AndRedeleteRestamps(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	ctx := context.Background()
	id := makeSecret(t, ls, "a", 0)
	require.NoError(t, ls.DeleteSecret(ctx, id))
	require.NoError(t, ls.RestoreSecret(ctx, id))
	live, err := ls.GetSecret(ctx, id)
	require.NoError(t, err)
	assert.Nil(t, live.PurgeAt, "a live secret carries no purge date")

	ls.SetSoftDeleteRetentionDays(45)
	require.NoError(t, ls.DeleteSecret(ctx, id))
	again, err := ls.GetSecretIncludingDeleted(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, again.PurgeAt)
	assert.True(t, again.PurgeAt.Equal(again.DeletedAt.Time.UTC().AddDate(0, 0, 45)), "re-delete gets a fresh window")
}

func TestDeleteProjectCascade_StampsEachSecretsPurgeAt(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	ctx := context.Background()
	plain := makeSecret(t, ls, "plain", 0)
	hv := makeSecret(t, ls, "hv", 60)
	require.NoError(t, ls.DeleteProject(ctx, 1))

	for id, days := range map[uint]int{plain: 30, hv: 60} {
		got, err := ls.GetSecretIncludingDeleted(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, got.PurgeAt, "secret %d swept by the project cascade has a purge date", id)
		assert.True(t, got.PurgeAt.Equal(got.DeletedAt.Time.UTC().AddDate(0, 0, days)))
	}
}

// A store never told the window (NewLocalStorage only) stamps nothing and the purge keeps
// its legacy cutoff behaviour, so rows from before this change are not stranded.
func TestPurge_UnstampedRowsKeepLegacyCutoffRule(t *testing.T) {
	ls := newSoftDeleteTestStore(t) // no SetSoftDeleteRetentionDays
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, ls.db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "dev"}).Error)
	id := makeSecret(t, ls, "legacy", 0)
	require.NoError(t, ls.DeleteSecret(ctx, id))
	got, err := ls.GetSecretIncludingDeleted(ctx, id)
	require.NoError(t, err)
	assert.Nil(t, got.PurgeAt)

	ageDeletion(t, ls, id, 31)
	n, err := ls.PurgeDeletedSecretsBefore(ctx, time.Now().UTC().AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestWithTransactionClone_SharesRetentionSoItStamps(t *testing.T) {
	ls := newPurgeAtStore(t, 30)
	ctx := context.Background()
	id := makeSecret(t, ls, "a", 0)
	require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error { return tx.DeleteSecret(ctx, id) }))
	got, err := ls.GetSecretIncludingDeleted(ctx, id)
	require.NoError(t, err)
	assert.NotNil(t, got.PurgeAt, "a delete inside WithTransaction is stamped like any other")
}
