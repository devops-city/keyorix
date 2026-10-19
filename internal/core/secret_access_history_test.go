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

func TestListSecretAccessHistory(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}))
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

	now := time.Now()
	// Two recent reads + one outside the window.
	require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: secret.ID, AccessedBy: "owner", Action: "read", IPAddress: "10.0.0.1", AccessTime: now.Add(-1 * time.Hour),
	}))
	require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: secret.ID, AccessedBy: "owner", Action: "read", IPAddress: "10.0.0.2", AccessTime: now.Add(-2 * time.Hour),
	}))
	require.NoError(t, c.storage.CreateSecretAccessLog(ctx, &models.SecretAccessLog{
		SecretNodeID: secret.ID, AccessedBy: "owner", Action: "read", IPAddress: "10.0.0.3", AccessTime: now.Add(-40 * 24 * time.Hour),
	}))

	t.Run("owner sees recent reads within the window", func(t *testing.T) {
		logs, err := c.ListSecretAccessHistory(ctx, secret.ID, 1, now.Add(-7*24*time.Hour))
		require.NoError(t, err)
		assert.Len(t, logs, 2, "the 40-day-old entry is outside the 7-day window")
		for _, l := range logs {
			assert.Equal(t, "read", l.Action)
		}
	})

	t.Run("a non-reader is denied", func(t *testing.T) {
		_, err := c.ListSecretAccessHistory(ctx, secret.ID, 2, now.Add(-7*24*time.Hour))
		require.Error(t, err)
	})
}
