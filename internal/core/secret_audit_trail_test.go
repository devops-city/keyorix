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

func TestListSecretAuditEvents(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.AuditEvent{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}))
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

	other, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "api", ProjectID: 1, EnvironmentID: 1, Type: "token", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	now := time.Now()
	uid := uint(1)
	// Three lifecycle events on the target secret, plus one on a different secret.
	require.NoError(t, c.storage.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.created", UserID: &uid, SecretNodeID: &secret.ID, EventTime: now.Add(-3 * time.Hour),
	}))
	require.NoError(t, c.storage.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.rotated", UserID: &uid, SecretNodeID: &secret.ID, EventTime: now.Add(-2 * time.Hour),
	}))
	require.NoError(t, c.storage.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.suspended", UserID: &uid, SecretNodeID: &secret.ID, EventTime: now.Add(-1 * time.Hour),
	}))
	require.NoError(t, c.storage.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.created", UserID: &uid, SecretNodeID: &other.ID, EventTime: now.Add(-1 * time.Hour),
	}))

	t.Run("owner sees only this secret's events, newest first", func(t *testing.T) {
		events, err := c.ListSecretAuditEvents(ctx, secret.ID, 1, 0)
		require.NoError(t, err)
		require.Len(t, events, 3, "the other secret's event must not leak in")
		assert.Equal(t, "secret.suspended", events[0].EventType, "newest first")
		assert.Equal(t, "secret.created", events[2].EventType)
		for _, e := range events {
			require.NotNil(t, e.SecretNodeID)
			assert.Equal(t, secret.ID, *e.SecretNodeID)
		}
	})

	t.Run("limit is honored", func(t *testing.T) {
		events, err := c.ListSecretAuditEvents(ctx, secret.ID, 1, 1)
		require.NoError(t, err)
		require.Len(t, events, 1)
		assert.Equal(t, "secret.suspended", events[0].EventType)
	})

	t.Run("a non-reader is denied", func(t *testing.T) {
		_, err := c.ListSecretAuditEvents(ctx, secret.ID, 2, 0)
		require.Error(t, err)
	})
}
