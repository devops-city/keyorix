package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// DASH-SIGNALS-1 item 2: the environment list carries per-environment secret
// counts computed by the server in one grouped query (no per-environment round
// trip). The count tracks create, soft-delete and restore, and never includes
// folders or another environment's secrets.
func TestCountSecretsByEnvironment_CreateDeleteRestore(t *testing.T) {
	t.Parallel()
	c, db := newStatsTestCore(t)
	// Soft-deleting a secret also sweeps its share records and ACLs.
	require.NoError(t, db.AutoMigrate(&models.ShareRecord{}, &models.SecretACL{}))
	ctx := context.Background()
	now := time.Now()

	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "env-counts"})
	require.NoError(t, err)
	prod, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)
	dev, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "development", ProjectID: proj.ID})
	require.NoError(t, err)
	empty, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: proj.ID})
	require.NoError(t, err)
	ids := []uint{prod.ID, dev.ID, empty.ID}

	mk := func(name string, envID uint, isSecret bool) *models.SecretNode {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: proj.ID, EnvironmentID: envID,
			Type: "password", IsSecret: isSecret, CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
		return s
	}
	counts := func() map[uint]int64 {
		m, err := c.CountSecretsByEnvironment(ctx, ids)
		require.NoError(t, err)
		return m
	}

	// Before any secret: every environment reads zero (absent or 0).
	m := counts()
	assert.Zero(t, m[prod.ID])
	assert.Zero(t, m[dev.ID])

	// Create: two in production, one in development, plus a folder that must not count.
	a := mk("a", prod.ID, true)
	mk("b", prod.ID, true)
	mk("c", dev.ID, true)
	mk("folder", prod.ID, false)
	m = counts()
	assert.Equal(t, int64(2), m[prod.ID], "production: two secrets, folder excluded")
	assert.Equal(t, int64(1), m[dev.ID])
	assert.Zero(t, m[empty.ID])

	// Soft-delete one production secret.
	require.NoError(t, c.DeleteSecret(ctx, a.ID))
	m = counts()
	assert.Equal(t, int64(1), m[prod.ID], "soft-deleted secret leaves the count")
	assert.Equal(t, int64(1), m[dev.ID], "other environment untouched")

	// Restore it.
	require.NoError(t, c.RestoreSecret(ctx, 0, a.ID))
	m = counts()
	assert.Equal(t, int64(2), m[prod.ID], "restored secret counts again")
}

func TestCountSecretsByEnvironment_NoIDs(t *testing.T) {
	t.Parallel()
	c, _ := newStatsTestCore(t)
	m, err := c.CountSecretsByEnvironment(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, m)
}
