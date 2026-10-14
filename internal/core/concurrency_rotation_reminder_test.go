package core_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_SendRotationReminders_NoDuplicateReminder is the (#488) TOCTOU
// regression: SendRotationReminders (and its sibling SendExpiryReminders) dedupe an
// admin's standing reminder with a check-then-act read (GetUnreadNotification)
// followed by a separate CreateNotification call — two calls with no atomicity
// between them. The SCHEDULED path is safe (run under WithSchedulerLock,
// single-replica-gated, ADR-039), but server/http/handlers.AdminJobsHandler's
// on-demand RunRotationReminders/RunExpiryReminders triggers call the core function
// directly with NO lock at all, so an operator hitting
// POST /api/v1/admin/jobs/rotation-reminders twice in quick succession (or racing the
// scheduler's own tick) against a project with no existing reminder can have both
// calls pass the "does a reminder already exist" check before either commits,
// producing duplicate reminder rows.
//
// This drives many concurrent SendRotationReminders runs against the same project —
// through a real file-backed SQLite, migrated the same way factory.go's
// ensureReminderNotificationDedupIndex does, so the DB-level guard production
// installs get is actually in place — and asserts exactly one unread
// rotation.reminder notification row survives for the admin.
func TestConcurrency_SendRotationReminders_NoDuplicateReminder(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "rotation-reminders.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{}, &models.Notification{},
	))
	// Mirror factory.go's ensureReminderNotificationDedupIndex exactly, so this test
	// exercises the same DB-level guard production installs get (rather than only the
	// in-process check-then-act, which this test demonstrates is not enough on its own).
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_notifications_unread_reminder "+
		"ON notifications (user_id, type, project_id) "+
		"WHERE is_read = false AND type IN ('rotation.reminder', 'secret.expiry_reminder')").Error)

	now := time.Now()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "payments"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "ada", Email: "ada@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1, ProjectID: 1}).Error) // admin
	// A secret created 100 days ago, never rotated → overdue under a 30-day policy, so
	// every concurrent run finds something to remind the admin about.
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 10, Name: "db-password", ProjectID: 1, EnvironmentID: 2, Type: "password",
		CreatedAt: now.AddDate(0, 0, -100),
	}).Error)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "30-day", Scope: "project", ProjectID: &pid,
		IntervalDays: 30, AlertDaysBefore: 7, IsActive: true, CreatedBy: "ada",
	}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))

	// Fire many concurrent on-demand runs at once, exactly as two overlapping admin
	// requests to POST /api/v1/admin/jobs/rotation-reminders (or one racing the
	// scheduler's own tick) would.
	const attackers = 30
	start := make(chan struct{})
	errs := make([]error, attackers)
	var wg sync.WaitGroup
	for i := range attackers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := c.SendRotationReminders(context.Background())
			errs[i] = err
		}(i)
	}
	close(start) // release every run at once
	wg.Wait()

	for _, err := range errs {
		assert.NoError(t, err, "SendRotationReminders must never surface the benign duplicate-skip as a caller-visible error")
	}

	// Exactly one unread rotation.reminder row must exist for the admin — no
	// duplicate from the TOCTOU window between the dedup read and the create.
	var count int64
	require.NoError(t, db.Model(&models.Notification{}).
		Where("user_id = ? AND type = ? AND project_id = ? AND is_read = ?", 5, "rotation.reminder", 1, false).
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "exactly one standing rotation reminder must exist despite the concurrent runs")
}
