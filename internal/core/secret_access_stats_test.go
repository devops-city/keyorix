package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestGetSecretAccessStats(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "mallory", Email: "m@t.com"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Two versions carry max_reads accounting counters (3 + 5 = 8). They are NOT the
	// secret's read count (AUDIT-UX-3): total_reads comes from the access log (#2972).
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: secret.ID, VersionNumber: 1, ReadCount: 3}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: secret.ID, VersionNumber: 2, ReadCount: 5}).Error)

	now := time.Now()
	mk := func(by, action string, when time.Time) {
		require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
			SecretNodeID: secret.ID, AccessedBy: by, Action: action, AccessTime: when,
		}))
	}
	mk("owner", "read", now.Add(-1*time.Hour))     // in window
	mk("alice", "read", now.Add(-2*time.Hour))     // in window, different reader
	mk("owner", "update", now.Add(-1*time.Hour))   // not a read → excluded
	mk("owner", "read", now.Add(-40*24*time.Hour)) // outside the 30-day window

	t.Run("aggregates lifetime + recent-window read stats", func(t *testing.T) {
		stats, err := c.GetSecretAccessStats(ctx, secret.ID, 1, 0) // 0 → default 30-day window
		require.NoError(t, err)
		assert.Equal(t, 3, stats.TotalReads, "lifetime access-log reads (core.SecretTotalReads), including the 40-day-old one; NOT the 3+5 max_reads counters")
		assert.Equal(t, 2, stats.Versions)
		assert.Equal(t, 30, stats.WindowDays)
		assert.Equal(t, 2, stats.ReadsInWindow, "two reads in window; the update and the 40-day-old read are excluded")
		assert.Equal(t, 2, stats.UniqueReaders, "owner + alice")
		require.NotNil(t, stats.LastReadAt)
		assert.WithinDuration(t, now.Add(-1*time.Hour), *stats.LastReadAt, time.Minute)
	})

	t.Run("window is clamped (cap 365)", func(t *testing.T) {
		stats, err := c.GetSecretAccessStats(ctx, secret.ID, 1, 1000)
		require.NoError(t, err)
		assert.Equal(t, 365, stats.WindowDays)
		assert.Equal(t, 3, stats.ReadsInWindow, "365-day window now includes the 40-day-old read")
	})

	t.Run("a non-reader is denied", func(t *testing.T) {
		_, err := c.GetSecretAccessStats(ctx, secret.ID, 2, 0)
		require.Error(t, err)
	})

	t.Run("a zero secret ID is rejected", func(t *testing.T) {
		_, err := c.GetSecretAccessStats(ctx, 0, 1, 0)
		require.Error(t, err)
	})
}
