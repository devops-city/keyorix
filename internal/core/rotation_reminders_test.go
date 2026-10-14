package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newRotationReminderCore sets up a real-SQLite core with one project, a
// project_admin member (user 5), and a secret overdue under an active rotation
// policy, for exercising SendRotationReminders end to end.
func newRotationReminderCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{}, &models.Notification{},
		&models.AuditEvent{},
	))

	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "payments"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "ada", Email: "ada@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 6, Username: "viewer", Email: "v@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "project_viewer"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1, ProjectID: 1}).Error) // admin
	require.NoError(t, db.Create(&models.UserRole{UserID: 6, RoleID: 2, ProjectID: 1}).Error) // viewer (no reminder)
	// A secret created 100 days ago, never rotated → overdue under a 30-day policy.
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 10, Name: "db-password", ProjectID: 1, EnvironmentID: 2, Type: "password",
		CreatedAt: now.AddDate(0, 0, -100),
	}).Error)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "30-day", Scope: "project", ProjectID: &pid,
		IntervalDays: 30, AlertDaysBefore: 7, IsActive: true, CreatedBy: "ada",
	}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db, now
}

func TestSendRotationReminders(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, _ := newRotationReminderCore(t)

	// First run: the project_admin (user 5) is notified; the viewer (user 6) is not.
	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "only the project admin is notified")

	var notes []models.Notification
	require.NoError(t, db.Where("type = ?", NotificationRotationDue).Find(&notes).Error)
	require.Len(t, notes, 1)
	assert.Equal(t, uint(5), notes[0].UserID)
	require.NotNil(t, notes[0].ProjectID)
	assert.Equal(t, uint(1), *notes[0].ProjectID)
	assert.Contains(t, notes[0].Message, "overdue")
	assert.Contains(t, notes[0].Message, "payments")

	// Second run while the reminder is still UNREAD: deduped — no new notification.
	sent, err = c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "a standing unread reminder is not duplicated")
	var n int64
	require.NoError(t, db.Model(&models.Notification{}).Where("type = ?", NotificationRotationDue).Count(&n).Error)
	assert.Equal(t, int64(1), n)

	// Once read, a still-overdue secret nudges the admin again on the next run.
	require.NoError(t, db.Model(&models.Notification{}).Where("id = ?", notes[0].ID).Update("is_read", true).Error)
	sent, err = c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "after reading, a still-overdue secret re-notifies")
}

// TestHasUnreadRotationReminder_NotBuriedByNotificationVolume is a regression test
// for #399: the dedup check must find a genuine standing rotation reminder even
// when it's buried under more than 100 newer, unrelated unread notifications — it
// must not depend on the reminder happening to fall inside a "newest N of any
// type" window.
func TestHasUnreadRotationReminder_NotBuriedByNotificationVolume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, now := newRotationReminderCore(t)

	// Seed the genuine rotation reminder first (oldest), already at the severity
	// the fixture's secret warrants (overdue → Critical) so this run is a pure
	// anti-burying check, not an escalation. Then bury it under 150 newer,
	// unrelated unread notifications for the same user.
	pid := uint(1)
	require.NoError(t, db.Create(&models.Notification{
		UserID: 5, ProjectID: &pid, Type: NotificationRotationDue,
		Title: "Secrets due for rotation", Message: "old standing reminder",
		Severity: models.NotificationSeverityCritical,
		IsRead:   false, CreatedAt: now.Add(-24 * time.Hour),
	}).Error)
	for i := range 150 {
		require.NoError(t, db.Create(&models.Notification{
			UserID: 5, ProjectID: &pid, Type: NotificationAccessRequested,
			Title: "Unrelated", Message: "noise",
			IsRead: false, CreatedAt: now.Add(time.Duration(i) * time.Minute),
		}).Error)
	}

	assert.NotNil(t, c.unreadRotationReminder(ctx, 5, 1),
		"the standing reminder must be found even though 150 newer unread notifications of another type exist")

	// The straightforward case (no volume issue, no reminder) still works.
	assert.Nil(t, c.unreadRotationReminder(ctx, 6, 1),
		"a user with no rotation reminder at all must not be reported as having one")

	// SendRotationReminders itself must not duplicate the reminder despite the noise.
	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "the buried-but-genuine reminder still dedupes the run")
	var n int64
	require.NoError(t, db.Model(&models.Notification{}).
		Where("type = ? AND user_id = ?", NotificationRotationDue, 5).Count(&n).Error)
	assert.Equal(t, int64(1), n, "no duplicate rotation reminder was created")
}

func TestSendRotationReminders_NothingDue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, now := newRotationReminderCore(t)
	// Rotate the secret now → no longer overdue/approaching.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 10).Update("last_rotated_at", now).Error)

	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, sent)
}

// TestSendRotationReminders_EscalatesOnMoreSevereState is a regression test for
// #250: an unread standing reminder must not freeze at a stale severity. First
// run notes the secret is merely *approaching* its rotation deadline (Warning);
// once it becomes genuinely *overdue* (Critical) while that reminder is still
// unread, the next run must escalate the SAME notification row in place rather
// than silently suppressing the far more consequential state.
func TestSendRotationReminders_EscalatesOnMoreSevereState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, now := newRotationReminderCore(t)

	// 25 days into a 30-day policy with a 7-day alert window: approaching, not
	// yet overdue (30-25=5 <= 7).
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 10).
		Update("created_at", now.AddDate(0, 0, -25)).Error)

	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "the project admin is notified of the approaching deadline")

	var note models.Notification
	require.NoError(t, db.Where("type = ?", NotificationRotationDue).First(&note).Error)
	assert.Equal(t, models.NotificationSeverityWarning, note.Severity)
	assert.Contains(t, note.Message, "approaching")
	assert.False(t, note.IsRead)
	firstID := note.ID

	// Now the secret is 35 days old → overdue (Critical) — a strictly more
	// severe state — while the Warning reminder is STILL UNREAD.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 10).
		Update("created_at", now.AddDate(0, 0, -35)).Error)

	sent, err = c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "the escalation to overdue must reach the admin")

	var notes []models.Notification
	require.NoError(t, db.Where("type = ?", NotificationRotationDue).Find(&notes).Error)
	require.Len(t, notes, 1, "the standing reminder was updated in place, not duplicated")
	assert.Equal(t, firstID, notes[0].ID, "same notification row, upgraded")
	assert.Equal(t, models.NotificationSeverityCritical, notes[0].Severity)
	assert.Contains(t, notes[0].Message, "overdue")
	assert.False(t, notes[0].IsRead)
}

// TestSendRotationReminders_EscalationRedispatchesDelivery is a regression test for
// #482: escalating a standing rotation reminder in place (#250) must also re-fire the
// out-of-band delivery channel (email/webhook via recipientNotificationSink), not just
// update the notification row's Severity/Title/Message in the DB. Before the fix,
// upgradeReminder never called dispatchNotification, so an admin whose "approaching"
// reminder silently escalated to "overdue" while still unread would never actually
// receive a second alert — undermining the entire point of escalation-aware reminders.
func TestSendRotationReminders_EscalationRedispatchesDelivery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, now := newRotationReminderCore(t)
	sink := &fakeSink{}
	c.SetRecipientNotificationSink(sink)

	// 25 days into a 30-day policy with a 7-day alert window: approaching, not overdue.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 10).
		Update("created_at", now.AddDate(0, 0, -25)).Error)

	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, sent)
	require.Len(t, sink.events, 1, "the initial reminder must be delivered")
	assert.Contains(t, sink.events[0].Message, "approaching")

	// Now overdue (Critical) while the Warning reminder is still unread: an escalation.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 10).
		Update("created_at", now.AddDate(0, 0, -35)).Error)

	sent, err = c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "the escalation counts as sent")

	require.Len(t, sink.events, 2,
		"the escalation must re-fire delivery — a Warning reminder silently becoming Critical must not go out unless the channel actually re-sends")
	assert.Contains(t, sink.events[1].Message, "overdue",
		"the redispatched event carries the escalated message, not the stale one")
	assert.Equal(t, NotificationRotationDue, sink.events[1].Type)
}

// TestSendRotationReminders_NoEscalation_SameOrLowerSeverity_NoNoise is the
// inverse of the escalation test: once a Critical (overdue) reminder is
// standing, a recheck that finds the state no worse must not touch it or
// create noise — only a genuine escalation updates the notification.
func TestSendRotationReminders_NoEscalation_SameOrLowerSeverity_NoNoise(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, _ := newRotationReminderCore(t)

	// Default fixture: the secret is already overdue → first run creates a
	// Critical standing reminder.
	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, sent)

	var before models.Notification
	require.NoError(t, db.Where("type = ?", NotificationRotationDue).First(&before).Error)
	require.Equal(t, models.NotificationSeverityCritical, before.Severity)

	// Still overdue (same severity) and still unread: no escalation, no noise.
	sent, err = c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "an at-or-below-severity recheck must not notify again")

	var after models.Notification
	require.NoError(t, db.Where("type = ?", NotificationRotationDue).First(&after).Error)
	assert.Equal(t, before.Message, after.Message, "the standing reminder is untouched")
	assert.Equal(t, before.Severity, after.Severity)
}

func TestRotationReminderMessage(t *testing.T) {
	t.Parallel()
	assert.Contains(t, rotationReminderMessage("p", 3, 2), "3 secret(s) in p are overdue")
	assert.Contains(t, rotationReminderMessage("p", 3, 2), "2 more are approaching")
	assert.Equal(t, "1 secret(s) in p are overdue for rotation.", rotationReminderMessage("p", 1, 0))
	assert.Contains(t, rotationReminderMessage("p", 0, 4), "approaching their rotation deadline")
}
