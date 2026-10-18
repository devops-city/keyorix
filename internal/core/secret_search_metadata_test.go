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

func TestSecretSearch_NameDescriptionTags(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.Tag{}, &models.SecretTag{}, &models.AuditEvent{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	e, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p.ID}).Error)

	mk := func(name, desc string, tags ...string) {
		s, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: name, Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", CreatedBy: "owner", OwnerID: 1, Description: desc,
		})
		require.NoError(t, err)
		if len(tags) > 0 {
			_, err := c.SetSecretTags(ctx, s.ID, 1, tags)
			require.NoError(t, err)
		}
	}
	mk("alpha", "")
	mk("beta", "the billing database")
	mk("gamma", "", "payments")

	search := func(q string) []string {
		resp, err := c.ListSecretsInScope(ctx, &models.SecretListFilter{ProjectID: &p.ID, Search: &q})
		require.NoError(t, err)
		names := make([]string, 0, len(resp.Secrets))
		for _, s := range resp.Secrets {
			names = append(names, s.Name)
		}
		return names
	}

	t.Run("matches by name", func(t *testing.T) {
		assert.Equal(t, []string{"alpha"}, search("alph"))
	})
	t.Run("matches by description", func(t *testing.T) {
		assert.Equal(t, []string{"beta"}, search("billing"))
	})
	t.Run("matches by tag", func(t *testing.T) {
		assert.Equal(t, []string{"gamma"}, search("payment"))
	})
	t.Run("no match returns nothing", func(t *testing.T) {
		assert.Empty(t, search("zzz-nope"))
	})
}
