package core_test

import (
	"context"
	"path/filepath"
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

// #2951 item 5: pins the DEFINITION of read_count (docs/API_REFERENCE.md,
// "read_count"): it counts the reads charged against max_reads, on the secret
// (lifetime) and, as a display copy, on the version that was read. A secret with
// no max_reads is never charged, so its read_count stays 0 however often it is
// read; the reads themselves are in the audit log (secret.read) and
// `secret access-log`, not in read_count.
func TestReadCount_IsChargedOnlyAgainstMaxReads(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "rc.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	create := func(name string, maxReads *int) *models.SecretNode {
		sec, cerr := c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("v"), ProjectID: 1, EnvironmentID: 1,
			Type: "password", Classification: "internal", MaxReads: maxReads, OwnerID: 1, CreatedBy: "owner",
		})
		require.NoError(t, cerr)
		return sec
	}
	counts := func(id uint) (node, version int) {
		var n models.SecretNode
		require.NoError(t, db.First(&n, id).Error)
		var v models.SecretVersion
		require.NoError(t, db.Where("secret_node_id = ?", id).First(&v).Error)
		return n.ReadCount, v.ReadCount
	}

	plain := create("plain", nil)
	capped := create("capped", func() *int { n := 5; return &n }())
	for range 3 {
		_, err = c.GetSecretValue(ctx, plain.ID)
		require.NoError(t, err)
	}
	for range 2 {
		_, err = c.GetSecretValue(ctx, capped.ID)
		require.NoError(t, err)
	}

	n, v := counts(plain.ID)
	assert.Equal(t, 0, n, "no max_reads: reads are not charged, secret read_count stays 0")
	assert.Equal(t, 0, v, "no max_reads: version read_count stays 0")
	n, v = counts(capped.ID)
	assert.Equal(t, 2, n, "max_reads: every read is charged to the secret")
	assert.Equal(t, 2, v, "max_reads: and mirrored on the version that was read")
}
