package core

import (
	"context"
	"sync"
	"sync/atomic"
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

func newMaxReadsCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // sqlite: serialize connections (statements stay atomic)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.SecretAccessSchedule{}))
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}, db
}

// seedMaxReadsSecret creates a secret with the given max_reads and one version.
func seedMaxReadsSecret(t *testing.T, c *KeyorixCore, max int) uint {
	t.Helper()
	ctx := context.Background()
	maxReads := max
	s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "one-shot", ProjectID: 1, EnvironmentID: 1, Type: "password",
		IsSecret: true, MaxReads: &maxReads, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("v"),
	})
	require.NoError(t, err)
	return s.ID
}

func TestMaxReads_SequentialStopsAtCap(t *testing.T) {
	t.Parallel()
	c, _ := newMaxReadsCore(t)
	id := seedMaxReadsSecret(t, c, 3)
	ctx := context.Background()

	for i := range 3 {
		_, err := c.GetSecretValue(ctx, id)
		require.NoError(t, err, "read %d should be within the cap", i+1)
	}
	_, err := c.GetSecretValue(ctx, id)
	require.Error(t, err, "the 4th read must be denied")
	assert.Contains(t, err.Error(), i18n.T("ErrorMaxReadsExceeded", nil))
}

// The race fix: N concurrent reads of a max-reads=K secret must yield exactly K
// successes, never more. Before the atomic check-and-increment, concurrent readers
// could all pass the in-memory check and exceed the cap.
func TestMaxReads_ConcurrentNeverExceedsCap(t *testing.T) {
	t.Parallel()
	c, db := newMaxReadsCore(t)
	const cap = 5
	const readers = 50
	id := seedMaxReadsSecret(t, c, cap)

	var success int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range readers {
		wg.Go(func() {
			<-start
			if _, err := c.GetSecretValue(context.Background(), id); err == nil {
				atomic.AddInt64(&success, 1)
			}
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int64(cap), success, "exactly cap reads may succeed under concurrency")

	// The persisted read_count must never overshoot the cap either.
	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", id).First(&v).Error)
	assert.LessOrEqual(t, v.ReadCount, cap, "read_count must not exceed the cap")
}

// A by-version read enforces the same max-reads cap as the latest-version read —
// the by-version path must not be a bypass for the read ceiling.
func TestMaxReads_ByVersionStopsAtCap(t *testing.T) {
	t.Parallel()
	c, _ := newMaxReadsCore(t)
	id := seedMaxReadsSecret(t, c, 2)
	ctx := context.Background()

	for i := range 2 {
		_, err := c.GetSecretValueByVersion(ctx, id, 1)
		require.NoError(t, err, "by-version read %d should be within the cap", i+1)
	}
	_, err := c.GetSecretValueByVersion(ctx, id, 1)
	require.Error(t, err, "the 3rd by-version read must be denied")
	assert.Contains(t, err.Error(), i18n.T("ErrorMaxReadsExceeded", nil))
}

// TestMaxReads_SurvivesRotateAndRollback pins #133: the max-reads counter used
// to be keyed on the VERSION, which starts at zero for every new version — so a
// burn-after-N-read secret became re-readable simply by rotating (or rolling
// back, which also creates a new version) it, resetting the budget. The cap
// must be enforced against the secret's lifetime read count, surviving both.
func TestMaxReads_SurvivesRotateAndRollback(t *testing.T) {
	t.Parallel()
	c, _ := newMaxReadsCore(t)
	id := seedMaxReadsSecret(t, c, 1)
	ctx := context.Background()

	// Burn the one allowed read.
	_, err := c.GetSecretValue(ctx, id)
	require.NoError(t, err)
	_, err = c.GetSecretValue(ctx, id)
	require.Error(t, err, "the budget is exhausted")

	// Rotating creates a brand-new version (read_count reset to 0 on THAT row) —
	// the secret-level counter must still refuse the next read.
	_, err = c.RotateSecret(ctx, id, []byte("v2"), 0, "actor")
	require.NoError(t, err)
	_, err = c.GetSecretValue(ctx, id)
	require.Error(t, err, "rotating must not grant a fresh read budget")
	assert.Contains(t, err.Error(), i18n.T("ErrorMaxReadsExceeded", nil))

	// Rolling back to version 1 also creates a new version — same requirement.
	_, err = c.RollbackSecret(ctx, id, 1, 1, "actor")
	require.NoError(t, err)
	_, err = c.GetSecretValue(ctx, id)
	require.Error(t, err, "rolling back must not grant a fresh read budget either")
	assert.Contains(t, err.Error(), i18n.T("ErrorMaxReadsExceeded", nil))
}
