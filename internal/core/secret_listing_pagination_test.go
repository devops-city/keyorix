// secret_listing_pagination_test.go — regression coverage for #251: a post-fetch
// filter (tag AND-match / search) must not be applied to an already
// DB-paginated page. Before the fix, ListSecretsInScope and
// ListSecretsWithSharingInfo passed the caller's Page/PageSize straight through
// to the storage layer (which paginates with LIMIT/OFFSET), then filtered the
// resulting single page in Go, then re-paginated that already-filtered/short
// page using the SAME Page/PageSize — so page >= 2 could come back empty even
// though more matching secrets existed, and Total/TotalPages reflected the
// pre-filter page count rather than the true post-filter match count.
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

// TestListSecretsInScope_PaginationSurvivesPostFetchTagFilter creates six
// secrets, only every other one tagged "keep" (a post-fetch filter — it can't
// be pushed into the SQL query the way Type/Classification are, since it
// requires an AND-match across a joined tag table per secret). Requesting
// page 2 of the filtered set must return the real second page of matches, not
// an empty page, and Total/TotalPages must reflect the 3 true matches — not
// the 6 raw rows or whatever happened to land on the DB's page 1.
func TestListSecretsInScope_PaginationSurvivesPostFetchTagFilter(t *testing.T) {
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

	mk := func(name string, keep bool) {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1, IsSecret: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		if keep {
			_, err := c.SetSecretTags(ctx, s.ID, 1, []string{"keep"})
			require.NoError(t, err)
		}
	}

	// Alternate matching/non-matching secrets so a naive "paginate first" pass
	// would land non-matching rows on the raw DB page and matching rows split
	// across pages — exactly the shape that used to break.
	mk("s1", true)
	mk("s2", false)
	mk("s3", true)
	mk("s4", false)
	mk("s5", true)
	mk("s6", false)

	filterFor := func(page int) *models.SecretListFilter {
		return &models.SecretListFilter{
			ProjectID: &p.ID,
			Tags:      []string{"keep"},
			SortBy:    "name",
			SortOrder: "asc",
			Page:      page,
			PageSize:  2,
		}
	}

	page1, err := c.ListSecretsInScope(ctx, filterFor(1))
	require.NoError(t, err)
	page2, err := c.ListSecretsInScope(ctx, filterFor(2))
	require.NoError(t, err)

	// Total/TotalPages must reflect the 3 true (post-filter) matches, not the
	// 6 raw rows and not just whatever landed on a single DB page.
	assert.Equal(t, int64(3), page1.Total, "page1 Total should reflect the true post-filter match count")
	assert.Equal(t, 2, page1.TotalPages)
	assert.Equal(t, int64(3), page2.Total, "page2 Total must match page1 Total")
	assert.Equal(t, 2, page2.TotalPages)

	require.Len(t, page1.Secrets, 2)
	assert.Equal(t, "s1", page1.Secrets[0].Name)
	assert.Equal(t, "s3", page1.Secrets[1].Name)

	// This is the crux of #251: page 2 must NOT come back empty.
	require.Len(t, page2.Secrets, 1, "page 2 must return the remaining true match, not be silently empty")
	assert.Equal(t, "s5", page2.Secrets[0].Name)
}

// TestListSecretsWithSharingInfo_PaginationSurvivesPostFetchSearchFilter covers
// the owned-secrets path (getOwnedSecretsWithSharingInfo -> merge -> paginate),
// which additionally used to double-paginate: the owned-secrets storage fetch
// itself was offset by the caller's page/pageSize, and then the merged,
// filtered result was re-sliced with the same page/pageSize again.
func TestListSecretsWithSharingInfo_PaginationSurvivesPostFetchSearchFilter(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{}, &models.Tag{}, &models.SecretTag{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	mk := func(name, description string) {
		_, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, Description: description, ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", OwnerID: 1, IsSecret: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
	}

	mk("s1", "match")
	mk("s2", "")
	mk("s3", "match")
	mk("s4", "")
	mk("s5", "match")
	mk("s6", "")

	search := "match"
	filterFor := func(page int) *models.SecretListFilter {
		return &models.SecretListFilter{
			Search:        &search,
			ShowOwnedOnly: true, // isolate the owned-only path (no shared merge)
			SortBy:        "name",
			SortOrder:     "asc",
			Page:          page,
			PageSize:      2,
		}
	}

	page1, err := c.ListSecretsWithSharingInfo(ctx, 1, filterFor(1))
	require.NoError(t, err)
	page2, err := c.ListSecretsWithSharingInfo(ctx, 1, filterFor(2))
	require.NoError(t, err)

	assert.Equal(t, int64(3), page1.Total)
	assert.Equal(t, 2, page1.TotalPages)
	assert.Equal(t, int64(3), page2.Total)
	assert.Equal(t, 2, page2.TotalPages)

	require.Len(t, page1.Secrets, 2)
	assert.Equal(t, "s1", page1.Secrets[0].Name)
	assert.Equal(t, "s3", page1.Secrets[1].Name)

	require.Len(t, page2.Secrets, 1, "page 2 must return the remaining true match, not be silently empty")
	assert.Equal(t, "s5", page2.Secrets[0].Name)
}
