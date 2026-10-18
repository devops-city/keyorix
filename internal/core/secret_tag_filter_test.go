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

func TestListSecretsInScope_TagFilter(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}, &models.Tag{}, &models.SecretTag{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p.ID}).Error)

	mk := func(name string, tags ...string) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1, IsSecret: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		if len(tags) > 0 {
			_, err := c.SetSecretTags(ctx, s.ID, 1, tags)
			require.NoError(t, err)
		}
		return s.ID
	}

	mk("db", "prod", "tier1")
	mk("cache", "prod")
	mk("scratch") // untagged

	scope := func(tags ...string) []*models.SecretWithSharingInfo {
		resp, err := c.ListSecretsInScope(ctx, &models.SecretListFilter{ProjectID: &p.ID, Tags: tags})
		require.NoError(t, err)
		return resp.Secrets
	}

	t.Run("no tag filter returns all", func(t *testing.T) {
		assert.Len(t, scope(), 3)
	})

	t.Run("single tag returns matching secrets", func(t *testing.T) {
		got := scope("prod")
		names := map[string]bool{}
		for _, s := range got {
			names[s.Name] = true
		}
		assert.Len(t, got, 2)
		assert.True(t, names["db"] && names["cache"])
		assert.False(t, names["scratch"])
	})

	t.Run("multiple tags are AND (narrowing)", func(t *testing.T) {
		got := scope("prod", "tier1")
		require.Len(t, got, 1)
		assert.Equal(t, "db", got[0].Name)
	})

	t.Run("tag match is case-insensitive", func(t *testing.T) {
		assert.Len(t, scope("PROD"), 2)
	})

	t.Run("an unknown tag matches nothing", func(t *testing.T) {
		assert.Empty(t, scope("nope"))
	})
}
