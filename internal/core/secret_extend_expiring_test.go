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

func TestExtendExpiringSecrets(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p.ID}).Error)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	mk := func(name string, exp *time.Time) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1, IsSecret: true,
			Expiration: exp, CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
		return s.ID
	}

	expired := now.Add(-2 * 24 * time.Hour)
	soon := now.Add(10 * 24 * time.Hour)
	far := now.Add(300 * 24 * time.Hour)

	expiredID := mk("expired", &expired)
	soonID := mk("soon", &soon)
	farID := mk("far", &far)    // outside the 30d window — untouched
	neverID := mk("never", nil) // no expiry — untouched

	t.Run("renews expiring/expired secrets to now+window, leaves others", func(t *testing.T) {
		n, truncated, err := c.ExtendExpiringSecrets(ctx, p.ID, 30, 90, "admin", 1)
		require.NoError(t, err)
		assert.Equal(t, 2, n, "expired + soon renewed; far + never untouched")
		assert.False(t, truncated)

		want := now.Add(90 * 24 * time.Hour)
		get := func(id uint) *models.SecretNode {
			s, err := c.storage.GetSecret(ctx, id)
			require.NoError(t, err)
			return s
		}
		require.NotNil(t, get(expiredID).Expiration)
		assert.WithinDuration(t, want, *get(expiredID).Expiration, time.Minute)
		assert.WithinDuration(t, want, *get(soonID).Expiration, time.Minute)
		// far (300d out) is already past the 90d window → left as-is; never stays nil.
		assert.WithinDuration(t, far, *get(farID).Expiration, time.Minute)
		assert.Nil(t, get(neverID).Expiration)
	})

	t.Run("a project ID or actor ID of zero is rejected", func(t *testing.T) {
		_, _, err := c.ExtendExpiringSecrets(ctx, 0, 30, 90, "admin", 1)
		require.Error(t, err)
		_, _, err = c.ExtendExpiringSecrets(ctx, p.ID, 30, 90, "admin", 0)
		require.Error(t, err)
	})
}
