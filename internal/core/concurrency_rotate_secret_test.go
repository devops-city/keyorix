package core_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_RotateSecret_NoDuplicateVersionNumbers is the (#121) TOCTOU
// regression: RotateSecret's GetLatestSecretVersion → +1 → storeSecretVersion is not
// atomic, so many concurrent rotations of the same secret can all read the same
// "latest" version and all attempt to write the same next version_number. This
// drives many concurrent RotateSecret calls for one secret against a real
// file-backed SQLite (through the same migration path production uses, so the
// uniq_secret_versions_node_version unique index — storage.ensureSecretVersionIndex
// — is actually in place), with a real connection pool (SetMaxOpenConns > 1) so the
// goroutines genuinely interleave rather than being serialized by a single shared
// connection. Every concurrent rotation must succeed (storeNextSecretVersion retries
// a lost race rather than failing it), and the DB must end up with exactly one row
// per version number, 1..N+1, with no gaps or duplicates.
func TestConcurrency_RotateSecret_NoDuplicateVersionNumbers(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "rotate.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(20)

	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_secret_versions_node_version ON secret_versions (secret_node_id, version_number)").Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "rotated-secret", Value: []byte("v0"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: 1, CreatedBy: "owner",
	})
	require.NoError(t, err)

	const rotators = 15 // matches the empirically-reproduced #121 finding
	start := make(chan struct{})
	errs := make([]error, rotators)
	var wg sync.WaitGroup
	for i := range rotators {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, rerr := c.RotateSecret(ctx, sec.ID, []byte(fmt.Sprintf("rotated-value-%d", i)), 0, "rotator")
			errs[i] = rerr
		}(i)
	}
	close(start) // release every rotation at once
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "concurrent rotation %d must succeed, not fail on ordinary contention", i)
	}

	// The DB must hold exactly one row per version number 1..rotators+1 — no
	// duplicate version_number for the secret (the #121 corruption), and no gap left
	// behind by a rotation that silently failed instead of retrying.
	var versions []models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", sec.ID).Order("version_number ASC").Find(&versions).Error)
	require.Len(t, versions, rotators+1, "one row for the initial CreateSecret version plus one per successful rotation")

	seen := make(map[int]int, len(versions))
	for _, v := range versions {
		seen[v.VersionNumber]++
	}
	var dupes []int
	for vn, count := range seen {
		if count > 1 {
			dupes = append(dupes, vn)
		}
	}
	sort.Ints(dupes)
	assert.Empty(t, dupes, "no version_number may be shared by more than one row")

	got := make([]int, 0, len(versions))
	for _, v := range versions {
		got = append(got, v.VersionNumber)
	}
	want := make([]int, 0, rotators+1)
	for n := 1; n <= rotators+1; n++ {
		want = append(want, n)
	}
	assert.Equal(t, want, got, "version numbers must be exactly the sequential run 1..N+1, no gaps")

	// The rotation timestamp must also have landed (RotateSecret's other write).
	updated, err := c.GetSecret(ctx, sec.ID)
	require.NoError(t, err)
	assert.NotNil(t, updated.LastRotatedAt, "LastRotatedAt must be set after a successful rotation")
}
