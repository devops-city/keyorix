package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// These tests pin the project/environment scope filter in ListSecrets — the
// tenant-isolation boundary for secret *visibility*. The load-bearing invariant
// (documented in ListSecrets) is that a project filter JOINs environments and
// requires environments.project_id to equal the requested project, so a secret
// whose environment belongs to a DIFFERENT project cannot leak into a project's
// listing even if its own project_id column says otherwise.

func newSecretScopeTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}))
	return NewLocalStorage(db)
}

func uptr(u uint) *uint { return &u }

func secretNames(secrets []*models.SecretNode) []string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, s.Name)
	}
	return out
}

func TestListSecrets_ScopeFilter_CrossProjectIsolation(t *testing.T) {
	ls := newSecretScopeTestStore(t)
	ctx := context.Background()

	// env 1,2 belong to project 5; env 9 belongs to project 6.
	for _, e := range []models.Environment{
		{ID: 1, ProjectID: 5, Name: "p5-dev"},
		{ID: 2, ProjectID: 5, Name: "p5-prod"},
		{ID: 9, ProjectID: 6, Name: "p6-dev"},
	} {
		require.NoError(t, ls.db.Create(&e).Error)
	}
	// s4 is the integrity-violation case: project_id says 5 but it lives in env 9,
	// which belongs to project 6. The JOIN must keep it out of BOTH listings.
	for _, s := range []models.SecretNode{
		{ProjectID: 5, EnvironmentID: 1, Name: "p5e1", IsSecret: true, Type: "api_key", Status: "active"},
		{ProjectID: 5, EnvironmentID: 2, Name: "p5e2", IsSecret: true, Type: "api_key", Status: "active"},
		{ProjectID: 6, EnvironmentID: 9, Name: "p6e9", IsSecret: true, Type: "api_key", Status: "active"},
		{ProjectID: 5, EnvironmentID: 9, Name: "mismatch", IsSecret: true, Type: "api_key", Status: "active"},
	} {
		require.NoError(t, ls.db.Create(&s).Error)
	}

	page := func(f *storage.SecretFilter) *storage.SecretFilter { f.Page = 1; f.PageSize = 100; return f }

	t.Run("project 5 returns only project-5 secrets, not the cross-project mismatch", func(t *testing.T) {
		got, total, err := ls.ListSecrets(ctx, page(&storage.SecretFilter{ProjectID: uptr(5)}))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"p5e1", "p5e2"}, secretNames(got))
		assert.Equal(t, int64(2), total)
	})

	t.Run("project 6 returns only its own secret", func(t *testing.T) {
		got, _, err := ls.ListSecrets(ctx, page(&storage.SecretFilter{ProjectID: uptr(6)}))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"p6e9"}, secretNames(got))
	})

	t.Run("project + environment narrows to that environment", func(t *testing.T) {
		got, _, err := ls.ListSecrets(ctx, page(&storage.SecretFilter{ProjectID: uptr(5), EnvironmentID: uptr(1)}))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"p5e1"}, secretNames(got))
	})

	t.Run("the mismatched secret is in NEITHER project's listing", func(t *testing.T) {
		p5, _, err := ls.ListSecrets(ctx, page(&storage.SecretFilter{ProjectID: uptr(5)}))
		require.NoError(t, err)
		p6, _, err := ls.ListSecrets(ctx, page(&storage.SecretFilter{ProjectID: uptr(6)}))
		require.NoError(t, err)
		assert.NotContains(t, secretNames(p5), "mismatch")
		assert.NotContains(t, secretNames(p6), "mismatch")
	})

	t.Run("no project filter lists everything (caller-level authz decides)", func(t *testing.T) {
		got, total, err := ls.ListSecrets(ctx, page(&storage.SecretFilter{}))
		require.NoError(t, err)
		assert.Equal(t, int64(4), total)
		assert.Len(t, got, 4)
	})
}

func TestListSecrets_Pagination(t *testing.T) {
	ls := newSecretScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 5, Name: "dev"}).Error)
	for i := range 5 {
		require.NoError(t, ls.db.Create(&models.SecretNode{
			ProjectID: 5, EnvironmentID: 1, Name: "s" + string(rune('a'+i)), IsSecret: true, Type: "api_key", Status: "active",
		}).Error)
	}

	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{ProjectID: uptr(5), Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, int64(5), total, "total reflects the full filtered set, not the page")
	assert.Len(t, got, 2, "page size caps the returned rows")

	got2, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{ProjectID: uptr(5), Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, got2, 1, "last page returns the remainder")
}

// The OwnerID filter selects by owner_id (the canonical ownership), not the
// created_by username — so it includes a secret whose created_by differs from the
// owner's username (e.g. a CLI-created "cli-user" secret) that a created_by filter
// would miss, and excludes another user's secrets.
func TestListSecrets_OwnerFilter(t *testing.T) {
	ls := newSecretScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Environment{ID: 1, ProjectID: 5, Name: "dev"}).Error)
	for _, s := range []models.SecretNode{
		{ProjectID: 5, EnvironmentID: 1, OwnerID: 7, CreatedBy: "alice", Name: "alice-secret", IsSecret: true, Type: "api_key", Status: "active"},
		{ProjectID: 5, EnvironmentID: 1, OwnerID: 7, CreatedBy: "cli-user", Name: "cli-secret", IsSecret: true, Type: "api_key", Status: "active"},
		{ProjectID: 5, EnvironmentID: 1, OwnerID: 8, CreatedBy: "bob", Name: "bob-secret", IsSecret: true, Type: "api_key", Status: "active"},
	} {
		require.NoError(t, ls.db.Create(&s).Error)
	}

	got, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{OwnerID: uptr(7), Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.ElementsMatch(t, []string{"alice-secret", "cli-secret"}, secretNames(got),
		"owner 7 owns both, including the CLI secret whose created_by != the owner's username")

	got, _, err = ls.ListSecrets(ctx, &storage.SecretFilter{OwnerID: uptr(8), Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"bob-secret"}, secretNames(got), "owner 8 sees only its own")
}
