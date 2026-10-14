package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newNotificationStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.Notification{}))
	return NewLocalStorage(db)
}

func TestNotifications_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationStore(t)

	// User 2: two unread + one already read. User 3: one unread.
	for _, n := range []*models.Notification{
		{UserID: 2, Type: "a", Title: "A", Message: "m1"},
		{UserID: 2, Type: "b", Title: "B", Message: "m2"},
		{UserID: 2, Type: "c", Title: "C", Message: "m3", IsRead: true},
		{UserID: 3, Type: "d", Title: "D", Message: "m4"},
	} {
		_, err := ls.CreateNotification(ctx, n)
		require.NoError(t, err)
	}

	all, err := ls.ListNotifications(ctx, 2, false, 0)
	require.NoError(t, err)
	assert.Len(t, all, 3, "all of user 2's notifications")

	unread, err := ls.ListNotifications(ctx, 2, true, 0)
	require.NoError(t, err)
	assert.Len(t, unread, 2, "only unread")

	count, err := ls.CountUnreadNotifications(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Mark one (known-unread) read; the unread count drops.
	require.NoError(t, ls.MarkNotificationRead(ctx, unread[0].ID, 2))
	count, err = ls.CountUnreadNotifications(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Ownership: user 3 can't mark user 2's notification.
	require.Error(t, ls.MarkNotificationRead(ctx, unread[1].ID, 3))

	// Mark all read for user 2 → zero unread; user 3 untouched.
	require.NoError(t, ls.MarkAllNotificationsRead(ctx, 2))
	count, err = ls.CountUnreadNotifications(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
	other, err := ls.CountUnreadNotifications(ctx, 3)
	require.NoError(t, err)
	assert.Equal(t, int64(1), other)
}

// TestHasUnreadNotification_NotBuriedByVolume is a regression test for #399:
// unlike ListNotifications (newest-N of any type, dedup callers used to filter
// client-side), HasUnreadNotification filters user_id/type/project_id/is_read at
// the DB level, so a genuine match can't be pushed out of a "top N" window by a
// pile of newer, unrelated unread notifications.
func TestHasUnreadNotification_NotBuriedByVolume(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationStore(t)
	pid := uint(7)

	// The target notification is the OLDEST row for this user.
	_, err := ls.CreateNotification(ctx, &models.Notification{
		UserID: 9, ProjectID: &pid, Type: "rotation.reminder", Title: "T", Message: "target",
	})
	require.NoError(t, err)

	// Bury it under 150 newer, unrelated unread notifications for the same user.
	for range 150 {
		_, err := ls.CreateNotification(ctx, &models.Notification{
			UserID: 9, ProjectID: &pid, Type: "access_request.created", Title: "N", Message: "noise",
		})
		require.NoError(t, err)
	}

	has, err := ls.HasUnreadNotification(ctx, 9, "rotation.reminder", 7)
	require.NoError(t, err)
	assert.True(t, has, "the target notification must be found despite 150 newer unread rows of another type")

	// Straightforward negative cases: wrong type, wrong project, wrong user.
	has, err = ls.HasUnreadNotification(ctx, 9, "no.such.type", 7)
	require.NoError(t, err)
	assert.False(t, has)

	has, err = ls.HasUnreadNotification(ctx, 9, "rotation.reminder", 99)
	require.NoError(t, err)
	assert.False(t, has)

	has, err = ls.HasUnreadNotification(ctx, 42, "rotation.reminder", 7)
	require.NoError(t, err)
	assert.False(t, has)

	// A read notification of the right type/project doesn't count as "unread".
	_, err = ls.CreateNotification(ctx, &models.Notification{
		UserID: 9, ProjectID: &pid, Type: "rotation.reminder", Title: "T2", Message: "read",
		IsRead: true,
	})
	require.NoError(t, err)
	has, err = ls.HasUnreadNotification(ctx, 9, "rotation.reminder", 7)
	require.NoError(t, err)
	assert.True(t, has, "still true because of the earlier unread target row")
}
