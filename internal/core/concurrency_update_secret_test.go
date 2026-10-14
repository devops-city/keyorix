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

// TestConcurrency_UpdateSecret_NoDuplicateVersionNumbers is a (#121) follow-up to
// TestConcurrency_RotateSecret_NoDuplicateVersionNumbers: UpdateSecret raced the exact
// same GetLatestSecretVersion -> +1 -> storeSecretVersion pattern RotateSecret used to,
// but only RotateSecret was switched to the retrying storeNextSecretVersion — a losing
// concurrent UpdateSecret still hit the uniq_secret_versions_node_version unique index
// (storage.ensureSecretVersionIndex) and surfaced a hard error to a caller doing nothing
// wrong, instead of transparently retrying like a concurrent rotation does. This drives
// many concurrent UpdateSecret calls (with a value change, so each writes a version) for
// one secret and asserts every call succeeds and the DB ends up with exactly one row per
// version number, 1..N+1, with no gaps or duplicates.
func TestConcurrency_UpdateSecret_NoDuplicateVersionNumbers(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "update.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
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
		Name: "updated-secret", Value: []byte("v0"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", OwnerID: 1, CreatedBy: "owner",
	})
	require.NoError(t, err)

	const updaters = 15 // matches the empirically-reproduced #121 rotation finding
	start := make(chan struct{})
	errs := make([]error, updaters)
	var wg sync.WaitGroup
	for i := range updaters {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, uerr := c.UpdateSecret(ctx, &core.UpdateSecretRequest{
				ID: sec.ID, Value: []byte(fmt.Sprintf("updated-value-%d", i)), UpdatedBy: "updater",
			})
			errs[i] = uerr
		}(i)
	}
	close(start) // release every update at once
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "concurrent update %d must succeed, not fail on ordinary contention", i)
	}

	// The DB must hold exactly one row per version number 1..updaters+1 — no duplicate
	// version_number for the secret (the #121 corruption), and no gap left behind by an
	// update that silently failed instead of retrying.
	var versions []models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", sec.ID).Order("version_number ASC").Find(&versions).Error)
	require.Len(t, versions, updaters+1, "one row for the initial CreateSecret version plus one per successful update")

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
	want := make([]int, 0, updaters+1)
	for n := 1; n <= updaters+1; n++ {
		want = append(want, n)
	}
	assert.Equal(t, want, got, "version numbers must be exactly the sequential run 1..N+1, no gaps")
}
