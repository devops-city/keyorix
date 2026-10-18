package core

import (
	"context"
	"strings"
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

func TestSetSecretDescription(t *testing.T) {
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

	t.Run("owner sets a description (trimmed)", func(t *testing.T) {
		got, err := c.SetSecretDescription(ctx, 1, secret.ID, "  prod DB password — contact dba@  ")
		require.NoError(t, err)
		assert.Equal(t, "prod DB password — contact dba@", got.Description)
		read, _ := c.storage.GetSecret(ctx, secret.ID)
		assert.Equal(t, "prod DB password — contact dba@", read.Description)
	})

	t.Run("clearing to empty works", func(t *testing.T) {
		got, err := c.SetSecretDescription(ctx, 1, secret.ID, "")
		require.NoError(t, err)
		assert.Equal(t, "", got.Description)
	})

	t.Run("a non-writer is denied", func(t *testing.T) {
		_, err := c.SetSecretDescription(ctx, 2, secret.ID, "nope")
		require.Error(t, err)
	})

	t.Run("an over-long description is rejected", func(t *testing.T) {
		_, err := c.SetSecretDescription(ctx, 1, secret.ID, strings.Repeat("a", maxSecretDescriptionLen+1))
		require.Error(t, err)
	})
}

func TestCreateSecret_Description(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	e, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	t.Run("description is persisted at creation", func(t *testing.T) {
		s, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: "db", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", CreatedBy: "owner", OwnerID: 1, Description: "  the prod DB  ",
		})
		require.NoError(t, err)
		assert.Equal(t, "the prod DB", s.Description)
	})

	t.Run("an over-long description is rejected at creation", func(t *testing.T) {
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: "db2", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", CreatedBy: "owner", OwnerID: 1, Description: strings.Repeat("a", maxSecretDescriptionLen+1),
		})
		require.Error(t, err)
	})
}
