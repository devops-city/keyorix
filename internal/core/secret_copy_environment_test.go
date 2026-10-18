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

func TestCopyEnvironmentSecrets(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.SecretAccessSchedule{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	staging, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	prod, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	p2, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	otherEnv, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p.ID}).Error)

	mk := func(envID uint, name string) {
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: name, Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: envID,
			Type: "password", CreatedBy: "owner", OwnerID: 1,
		})
		require.NoError(t, err)
	}
	mk(staging.ID, "db")
	mk(staging.ID, "api")
	mk(prod.ID, "db") // pre-existing in target → name clash, should be skipped

	t.Run("copies new secrets, skips name clashes", func(t *testing.T) {
		copied, skipped, err := c.CopyEnvironmentSecrets(ctx, p.ID, staging.ID, prod.ID, "owner", 1, "203.0.113.5", "test-agent/1.0")
		require.NoError(t, err)
		assert.Equal(t, 1, copied, "only 'api' is new in prod")
		assert.Equal(t, 1, skipped, "'db' already exists in prod")

		// prod now has db (original) + api (copied).
		resp, err := c.ListSecretsInScope(ctx, &models.SecretListFilter{ProjectID: &p.ID, EnvironmentID: &prod.ID})
		require.NoError(t, err)
		names := map[string]bool{}
		for _, s := range resp.Secrets {
			names[s.Name] = true
		}
		assert.True(t, names["db"] && names["api"])

		// #290: each per-secret copy attempt left a read audit event for the source (the
		// value is read before the name-clash is discovered at create time), and the one
		// successful copy ('api') also left a create event for the destination.
		var readCount, createCount int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "secret.read").Count(&readCount).Error)
		assert.Equal(t, int64(2), readCount, "both 'db' and 'api' sources were read, even though 'db' was then skipped as a name clash")
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "secret.created").Count(&createCount).Error)
		assert.Equal(t, int64(1), createCount, "exactly one destination create ('api')")
	})

	t.Run("a cross-project target is rejected", func(t *testing.T) {
		_, _, err := c.CopyEnvironmentSecrets(ctx, p.ID, staging.ID, otherEnv.ID, "owner", 1, "", "")
		require.Error(t, err)
	})

	t.Run("source == target is rejected", func(t *testing.T) {
		_, _, err := c.CopyEnvironmentSecrets(ctx, p.ID, staging.ID, staging.ID, "owner", 1, "", "")
		require.Error(t, err)
	})

	t.Run("required IDs are validated", func(t *testing.T) {
		_, _, err := c.CopyEnvironmentSecrets(ctx, 0, staging.ID, prod.ID, "owner", 1, "", "")
		require.Error(t, err)
	})
}
