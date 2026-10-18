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

func TestListDeletedSecrets(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	// #370: DeleteSecret revokes ShareRecord rows in the same transaction as the
	// secret's own soft-delete.
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	// Two projects, each with an environment (the list query joins environments).
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)

	mk := func(name string, projectID, envID uint) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID, Type: "password", OwnerID: 1, IsSecret: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}

	live := mk("alive", p1.ID, e1.ID)
	delOld := mk("old", p1.ID, e1.ID)
	delNew := mk("new", p1.ID, e1.ID)
	otherProj := mk("other", p2.ID, e2.ID)

	// Soft-delete two in p1 (old first, then new) and one in p2. The brief gap
	// keeps the deleted_at timestamps distinct so the newest-first order is stable.
	require.NoError(t, c.storage.DeleteSecret(ctx, delOld))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, c.storage.DeleteSecret(ctx, delNew))
	require.NoError(t, c.storage.DeleteSecret(ctx, otherProj))

	t.Run("returns only this project's soft-deleted secrets", func(t *testing.T) {
		got, err := c.ListDeletedSecrets(ctx, p1.ID, 0)
		require.NoError(t, err)
		require.Len(t, got, 2, "the live secret and the other project's deleted one must not appear")
		ids := map[uint]bool{got[0].ID: true, got[1].ID: true}
		assert.True(t, ids[delOld] && ids[delNew])
		assert.False(t, ids[live])
		assert.False(t, ids[otherProj])
		for _, s := range got {
			assert.True(t, s.DeletedAt.Valid, "every entry is soft-deleted")
		}
	})

	t.Run("newest-deleted first", func(t *testing.T) {
		got, err := c.ListDeletedSecrets(ctx, p1.ID, 0)
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, delNew, got[0].ID, "the most-recently-deleted secret leads")
		assert.Equal(t, delOld, got[1].ID)
	})

	t.Run("limit is honored", func(t *testing.T) {
		got, err := c.ListDeletedSecrets(ctx, p1.ID, 1)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, delNew, got[0].ID)
	})

	t.Run("a project ID of zero is rejected", func(t *testing.T) {
		_, err := c.ListDeletedSecrets(ctx, 0, 0)
		require.Error(t, err)
	})

	t.Run("an empty bin returns no entries", func(t *testing.T) {
		empty, err := c.storage.CreateProject(ctx, &models.Project{Name: "empty"})
		require.NoError(t, err)
		_, err = c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: empty.ID})
		require.NoError(t, err)
		got, err := c.ListDeletedSecrets(ctx, empty.ID, 0)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}
