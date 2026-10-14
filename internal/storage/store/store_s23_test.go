// store_s23_test.go — white-box coverage sweep for s23 gaps.
//
// Targets (all previously untested local paths):
//
//	local_notifications.go
//	  CreateNotification      — duplicate reminder sentinel (ErrDuplicateReminderNotification)
//	  ListNotifications       — limit > 200 clamped to defaultNotificationLimit (50)
//
//	local_dynamic.go
//	  CountActiveLeases       — revoke_failed leases are included in the count
//
//	local_memberships.go
//	  isUniqueViolation       — helper returns false on nil and true on SQLite msg
//
//	local_machine_identities.go
//	  CountStaleMachineIdentitiesByProject — recently-created machine with no
//	                                         last_seen_at is NOT stale
package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newS23Store opens a unique in-memory SQLite DB, migrates the supplied models
// and returns the LocalStorage. Mirrors the s21/s22 helper pattern, using a
// "_s23" suffix so test-name-based DSNs cannot collide with other sweeps.
func newS23Store(t *testing.T, mods ...any) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores23_", sqlite.Open, &gorm.Config{})
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return NewLocalStorage(db)
}

// newS23NotifStore creates a store with the Notification table AND the partial
// unique index that production installs via ensureReminderNotificationDedupIndex
// (internal/storage/factory.go). The index is required to exercise the
// ErrDuplicateReminderNotification path in CreateNotification.
func newS23NotifStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "stores23_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.Notification{}))
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_notifications_unread_reminder "+
			"ON notifications (user_id, type, project_id) "+
			"WHERE is_read = false AND type IN ('rotation.reminder', 'secret.expiry_reminder')",
	).Error)
	return NewLocalStorage(db)
}

// ---------------------------------------------------------------------------
// local_notifications.go — CreateNotification duplicate reminder sentinel
// ---------------------------------------------------------------------------

// TestCreateNotification_S23_DuplicateReminderSentinel verifies that a second
// concurrent unread reminder of the same (user, type, project) fails with
// ErrDuplicateReminderNotification, not a generic storage error (#488). This
// requires the partial unique index installed by the production migration.
func TestCreateNotification_S23_DuplicateReminderSentinel(t *testing.T) {
	ls := newS23NotifStore(t)
	ctx := context.Background()

	pid := uint(5)

	// First unread rotation.reminder — must succeed.
	_, err := ls.CreateNotification(ctx, &models.Notification{
		UserID:    10,
		ProjectID: &pid,
		Type:      "rotation.reminder",
		Title:     "Rotate now",
		Message:   "first reminder",
	})
	require.NoError(t, err)

	// Second unread rotation.reminder for the same (user, type, project) must
	// fail with the sentinel — not a generic storage error.
	_, err = ls.CreateNotification(ctx, &models.Notification{
		UserID:    10,
		ProjectID: &pid,
		Type:      "rotation.reminder",
		Title:     "Rotate now (again)",
		Message:   "duplicate reminder",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, corestorage.ErrDuplicateReminderNotification),
		"a duplicate unread reminder must surface as ErrDuplicateReminderNotification, got: %v", err)

	// Only one row must exist in the table.
	var count int64
	require.NoError(t, ls.db.Model(&models.Notification{}).
		Where("user_id = ? AND type = ? AND project_id = ?", 10, "rotation.reminder", pid).
		Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// TestCreateNotification_S23_DuplicateReminderDifferentUser verifies that the
// dedup index is scoped per-user: two users can each have their own unread
// rotation.reminder for the same project without conflicting.
func TestCreateNotification_S23_DuplicateReminderDifferentUser(t *testing.T) {
	ls := newS23NotifStore(t)
	ctx := context.Background()

	pid := uint(7)

	_, err := ls.CreateNotification(ctx, &models.Notification{
		UserID: 20, ProjectID: &pid, Type: "rotation.reminder", Title: "T", Message: "m",
	})
	require.NoError(t, err)

	_, err = ls.CreateNotification(ctx, &models.Notification{
		UserID: 21, ProjectID: &pid, Type: "rotation.reminder", Title: "T", Message: "m",
	})
	require.NoError(t, err, "a different user must be allowed their own unread reminder")
}

// TestCreateNotification_S23_ReadReminderDoesNotBlock verifies that a reminder
// that has already been read (is_read=true) does not occupy the partial unique
// index slot, so a fresh unread reminder for the same (user, type, project) can
// be created after the old one is marked read.
func TestCreateNotification_S23_ReadReminderDoesNotBlock(t *testing.T) {
	ls := newS23NotifStore(t)
	ctx := context.Background()

	pid := uint(9)

	// Create the first reminder and immediately mark it read.
	first, err := ls.CreateNotification(ctx, &models.Notification{
		UserID:    30,
		ProjectID: &pid,
		Type:      "secret.expiry_reminder",
		Title:     "Expires soon",
		Message:   "first",
	})
	require.NoError(t, err)
	require.NoError(t, ls.MarkNotificationRead(ctx, first.ID, 30))

	// A new unread expiry reminder for the same (user, type, project) must
	// succeed because the index only covers is_read=false rows.
	_, err = ls.CreateNotification(ctx, &models.Notification{
		UserID:    30,
		ProjectID: &pid,
		Type:      "secret.expiry_reminder",
		Title:     "Expires soon (new)",
		Message:   "second",
	})
	require.NoError(t, err, "a fresh unread reminder after the prior one is read must succeed")
}

// ---------------------------------------------------------------------------
// local_notifications.go — ListNotifications limit clamping
// ---------------------------------------------------------------------------

// TestListNotifications_S23_LimitAbove200Clamped verifies that a limit argument
// above 200 is clamped to defaultNotificationLimit (50), not applied as-is.
// The clamping branch (limit <= 0 || limit > 200) was never exercised in any
// prior sweep.
func TestListNotifications_S23_LimitAbove200Clamped(t *testing.T) {
	ls := newS23Store(t, &models.Notification{})
	ctx := context.Background()

	// Insert 60 notifications for user 42.
	for range 60 {
		_, err := ls.CreateNotification(ctx, &models.Notification{
			UserID: 42, Type: "info", Title: "N", Message: "msg",
		})
		require.NoError(t, err)
	}

	// A limit of 201 is out-of-range and must be clamped to 50.
	rows, err := ls.ListNotifications(ctx, 42, false, 201)
	require.NoError(t, err)
	assert.Len(t, rows, defaultNotificationLimit,
		"limit > 200 must be clamped to defaultNotificationLimit (%d)", defaultNotificationLimit)
}

// TestListNotifications_S23_NegativeLimitClamped verifies the negative-limit
// branch of the same guard (limit <= 0).
func TestListNotifications_S23_NegativeLimitClamped(t *testing.T) {
	ls := newS23Store(t, &models.Notification{})
	ctx := context.Background()

	for range 60 {
		_, err := ls.CreateNotification(ctx, &models.Notification{
			UserID: 43, Type: "info", Title: "N", Message: "msg",
		})
		require.NoError(t, err)
	}

	rows, err := ls.ListNotifications(ctx, 43, false, -5)
	require.NoError(t, err)
	assert.Len(t, rows, defaultNotificationLimit,
		"limit < 0 must be clamped to defaultNotificationLimit (%d)", defaultNotificationLimit)
}

// ---------------------------------------------------------------------------
// local_dynamic.go — CountActiveLeases includes revoke_failed
// ---------------------------------------------------------------------------

// TestCountActiveLeases_S23_RevokeFailed verifies that leases with
// status="revoke_failed" are included in CountActiveLeases, because their
// upstream credential is still live (#411). Only counting "active" would allow
// an attacker to exceed MaxActiveLeases by keeping leases in revoke_failed state.
func TestCountActiveLeases_S23_RevokeFailed(t *testing.T) {
	ls := newS23Store(t, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{})
	seedDynamicConfigProjects(t, ls.db)
	ctx := context.Background()

	now := time.Now()

	cfg, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "pg-db", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
	})
	require.NoError(t, err)

	// Insert one active lease and one revoke_failed lease.
	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "active-one",
		ConfigID:  cfg.ID,
		Status:    "active",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "failed-one",
		ConfigID:  cfg.ID,
		Status:    "revoke_failed",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	// Insert a fully revoked lease — must NOT be counted.
	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		LeaseID:   "revoked-one",
		ConfigID:  cfg.ID,
		Status:    "revoked",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	n, err := ls.CountActiveLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n,
		"CountActiveLeases must count both 'active' and 'revoke_failed' leases")
}

// ---------------------------------------------------------------------------
// local_memberships.go — isUniqueViolation helper
// ---------------------------------------------------------------------------

// TestIsUniqueViolation_S23_Nil verifies the nil guard in isUniqueViolation.
func TestIsUniqueViolation_S23_Nil(t *testing.T) {
	assert.False(t, isUniqueViolation(nil), "nil error must not be a unique violation")
}

// TestIsUniqueViolation_S23_SQLiteMsg verifies that the SQLite unique-constraint
// message is recognized.
func TestIsUniqueViolation_S23_SQLiteMsg(t *testing.T) {
	err := errors.New("UNIQUE constraint failed: project_memberships.project_id, project_memberships.user_id")
	assert.True(t, isUniqueViolation(err), "SQLite UNIQUE constraint message must be recognized")
}

// TestIsUniqueViolation_S23_UnrelatedError verifies that a non-constraint error
// is not misidentified as a unique violation.
func TestIsUniqueViolation_S23_UnrelatedError(t *testing.T) {
	err := errors.New("connection refused")
	assert.False(t, isUniqueViolation(err), "an unrelated error must not be a unique violation")
}

// ---------------------------------------------------------------------------
// local_machine_identities.go — CountStaleMachineIdentitiesByProject
//   recently-created identity with last_seen_at=NULL is NOT stale
// ---------------------------------------------------------------------------

// TestCountStaleMachineIdentitiesByProject_S23_RecentCreationNotStale verifies
// the second predicate branch of CountStaleMachineIdentitiesByProject: an active
// machine identity with last_seen_at IS NULL but created_at AFTER the cutoff is
// not counted as stale. The existing test only exercises the "last_seen_at IS NULL
// AND created_at < cutoff" stale path, not the complementary non-stale path.
func TestCountStaleMachineIdentitiesByProject_S23_RecentCreationNotStale(t *testing.T) {
	ls := newS23Store(t, &models.MachineIdentity{})
	ctx := context.Background()

	now := time.Now()
	cutoff := now.Add(-7 * 24 * time.Hour)
	recentCreatedAt := now.Add(-time.Hour) // created within the last hour → NOT stale

	// Active, never seen, but recently created — must NOT be counted as stale.
	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ProjectID: 1, Name: "new-ci-runner", State: "active",
		CreatedAt: recentCreatedAt, // after cutoff, so not stale
		// LastSeenAt is nil (zero-value pointer)
	}).Error)

	counts, err := ls.CountStaleMachineIdentitiesByProject(ctx, []uint{1}, cutoff)
	require.NoError(t, err)
	assert.Equal(t, 0, counts[1],
		"an active machine created after the cutoff with no last_seen_at must not be stale")
}

// TestCountStaleMachineIdentitiesByProject_S23_LastSeenStale verifies that an
// active machine last seen BEFORE the cutoff is counted as stale regardless of
// its creation time.
func TestCountStaleMachineIdentitiesByProject_S23_LastSeenStale(t *testing.T) {
	ls := newS23Store(t, &models.MachineIdentity{})
	ctx := context.Background()

	now := time.Now()
	cutoff := now.Add(-7 * 24 * time.Hour)
	oldSeen := now.Add(-30 * 24 * time.Hour)

	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ProjectID:  2,
		Name:       "old-runner",
		State:      "active",
		CreatedAt:  oldSeen,
		LastSeenAt: &oldSeen, // set but older than cutoff
	}).Error)

	counts, err := ls.CountStaleMachineIdentitiesByProject(ctx, []uint{2}, cutoff)
	require.NoError(t, err)
	assert.Equal(t, 1, counts[2],
		"an active machine last seen before the cutoff must be counted as stale")
}

// TestCountStaleMachineIdentitiesByProject_S23_EmptyProjectIDs confirms the
// early-return path returns an empty map without a DB round-trip.
func TestCountStaleMachineIdentitiesByProject_S23_EmptyProjectIDs(t *testing.T) {
	ls := newS23Store(t, &models.MachineIdentity{})
	ctx := context.Background()

	counts, err := ls.CountStaleMachineIdentitiesByProject(ctx, []uint{}, time.Now())
	require.NoError(t, err)
	assert.NotNil(t, counts)
	assert.Empty(t, counts, "empty project IDs slice must return an empty map, not nil")
}
