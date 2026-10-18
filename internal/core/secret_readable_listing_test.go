// secret_readable_listing_test.go — ListReadableSecrets' own contract, including the
// two defects the extraction out of the ListSecrets handler fixed (#2780).
//
// Those two are worth their own tests because they are behaviour CHANGES, not just
// a move: the old handler fetched each scope at the caller's page size before
// merging (so a multi-scope reader's reported Total undercounted, and the later
// pages did not exist), and it never re-sorted the merged set despite a comment
// saying it did.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// readableListingFixture builds a core over SQLite with the schema the listing
// path touches, plus a reader role carrying secrets.read.
func readableListingFixture(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.SecretACL{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "reader", Email: "reader@example.com"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "readable-listing-reader"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seedReadableProject creates a project + environment with n secrets named
// "<prefix>-NN", and grants user 1 secrets.read at that project's scope.
func seedReadableProject(t *testing.T, db *gorm.DB, projectID uint, name, prefix string, n int) {
	t.Helper()
	require.NoError(t, db.Create(&models.Project{ID: projectID, Name: name}).Error)
	envID := projectID * 100
	require.NoError(t, db.Create(&models.Environment{ID: envID, ProjectID: projectID, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: projectID}).Error)
	for i := range n {
		require.NoError(t, db.Create(&models.SecretNode{
			Name: fmt.Sprintf("%s-%02d", prefix, i), ProjectID: projectID, EnvironmentID: envID,
			IsSecret: true, CreatedBy: "someone-else", OwnerID: 999,
		}).Error)
	}
}

// TestListReadableSecrets_TotalIsNotTruncatedByPageSize covers defect 1. The old
// handler fetched each scope at the caller's page size and then merged, so a reader
// of three 25-secret projects asking for page_size=10 was told Total=30 instead of
// 75, and pages 4..8 came back empty.
//
// Red against the old code (which reported 3 * pageSize); green now.
func TestListReadableSecrets_TotalIsNotTruncatedByPageSize(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 25)
	seedReadableProject(t, db, 2, "beta", "b", 25)
	seedReadableProject(t, db, 3, "gamma", "g", 25)

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)

	assert.Equal(t, int64(75), resp.Total,
		"Total must count every readable secret across every scope, not pageSize-per-scope — "+
			"a truncated total is a silently wrong number, and the pages beyond it do not exist")
	assert.Equal(t, 8, resp.TotalPages, "ceil(75/10)")
	assert.Len(t, resp.Secrets, 10, "the requested page width")

	// The pages the old behaviour could not reach.
	last, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 8, PageSize: 10})
	require.NoError(t, err)
	assert.Len(t, last.Secrets, 5, "page 8 holds the remaining five")
	assert.Equal(t, int64(75), last.Total)
}

// TestListReadableSecrets_MergedResultIsSorted covers defect 2. Each scope arrived
// individually sorted and the concatenation was returned as-is, so ?sort_by=name
// came out interleaved by scope (a-00, a-01, …, b-00, …) rather than sorted across
// the union. With names chosen so per-scope order and global order differ, an
// unsorted merge is detectable.
func TestListReadableSecrets_MergedResultIsSorted(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	// Interleaving names: project 1 holds m-* and project 2 holds n-*, but the
	// per-scope blocks would put every m before every n, while a correct global
	// sort by name descending must start with the n's.
	seedReadableProject(t, db, 1, "alpha", "m", 3)
	seedReadableProject(t, db, 2, "beta", "n", 3)

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{
		Page: 1, PageSize: 10, SortBy: "name", SortOrder: "desc",
	})
	require.NoError(t, err)
	require.Len(t, resp.Secrets, 6)

	names := make([]string, 0, len(resp.Secrets))
	for _, s := range resp.Secrets {
		names = append(names, s.Name)
	}
	assert.Equal(t, []string{"n-02", "n-01", "n-00", "m-02", "m-01", "m-00"}, names,
		"the MERGED set must be sorted, not each scope separately then concatenated")
}

// TestListReadableSecrets_GlobalReaderSeesEveryScopeWithoutDoubleCounting replaces
// TestListReadableSecrets_GlobalReaderUnchanged.
//
// That test asserted `Total <= 4` with the comment "global readers take tier 1, which
// is unchanged" — and its premise was the bug. Tier 1 delegated to
// ListSecretsWithSharingInfo (owned ∪ shared ∪ ACL-granted), so a global reader who
// owned nothing saw ZERO, and `<= 4` passed on a 0 just as happily as on a 4. The
// assertion could not distinguish "sees everything it may read" from "sees nothing".
// See secret_readable_listing_global_test.go for the dedicated regression.
//
// What is asserted here instead is the property that test's fixture was actually
// positioned to check and did not: a caller holding BOTH a global grant and a
// project-scoped grant on the same project — realistic, since an admin can also be a
// project member — gets each secret exactly once.
func TestListReadableSecrets_GlobalReaderSeesEveryScopeWithoutDoubleCounting(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 4) // also grants project-scoped read
	seedReadableProject(t, db, 2, "beta", "b", 3)
	// The global grant on top of the per-project ones seeded above.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(7), resp.Total,
		"every secret across both projects, exactly once — a global grant stacked on project grants "+
			"must not double-count, and must not fall back to the owned-only set either")
	require.Len(t, resp.Secrets, 7)

	seen := map[string]int{}
	for _, s := range resp.Secrets {
		seen[s.Name]++
	}
	for name, n := range seen {
		assert.Equal(t, 1, n, "secret %q appears exactly once", name)
	}
}

// TestListReadableSecrets_NoGrantsIsEmptyNotAnError pins tier 3's fail-open-to-empty
// shape: a caller with no scope and nothing owned gets an empty list, never an
// error and never a denial. This is the property the endpoint's whole no-403 design
// rests on.
func TestListReadableSecrets_NoGrantsIsEmptyNotAnError(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	// A project exists with secrets in it, but user 2 holds nothing — so an empty
	// result is meaningful rather than vacuous.
	seedReadableProject(t, db, 1, "alpha", "a", 3)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "outsider", Email: "outsider@example.com"}).Error)

	resp, err := c.ListReadableSecrets(ctx, 2, 2, &models.SecretListFilter{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(0), resp.Total)
	assert.Empty(t, resp.Secrets)
}

// TestCountReadableSecrets_MatchesTheListing is the invariant the dashboard depends
// on, asserted at the core layer as well as over HTTP: the count and the list must
// agree, because they are the same function.
func TestCountReadableSecrets_MatchesTheListing(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 7)
	seedReadableProject(t, db, 2, "beta", "b", 5)

	listed, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 1})
	require.NoError(t, err)
	counted, exact, err := c.CountReadableSecrets(ctx, 1, 1)
	require.NoError(t, err)
	require.True(t, exact, "the fixture is well under the union bound, so the count must be exact")

	assert.Equal(t, int64(12), counted, "every readable secret across both scopes")
	assert.Equal(t, listed.Total, counted,
		"the count IS the listing's total — a count derived some other way is a second definition waiting to diverge")
}
