package core_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
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

// TestConcurrency_MaxReads_FullReadPathEnforcesCap drives the real burn-after-read
// path — GetSecretValue → readVersionValue → TryIncrementSecretReadCount — from many
// concurrent readers against a max_reads-capped secret, and asserts the value is handed
// out EXACTLY max_reads times. This is the user-facing invariant an attacker races: a
// secret meant to be read N times must never be read N+1 times, even under contention.
// Uses a file-backed SQLite (real multi-connection concurrency), run under -race.
func TestConcurrency_MaxReads_FullReadPathEnforcesCap(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := "file:" + filepath.Join(t.TempDir(), "c.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	maxReads := 3
	sec, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "burn-after-read", Value: []byte("topsecret"), ProjectID: 1, EnvironmentID: 1,
		Type: "password", Classification: "internal", MaxReads: &maxReads, OwnerID: 1, CreatedBy: "owner",
	})
	require.NoError(t, err)

	const readers = 40
	var succeeded atomic.Int64
	unexpected := make(chan error, readers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range readers {
		wg.Go(func() {
			<-start
			val, gerr := c.GetSecretValue(ctx, sec.ID)
			if gerr != nil {
				// The only expected failure is the cap being hit (max-reads exceeded).
				return
			}
			if string(val) != "topsecret" {
				unexpected <- fmt.Errorf("read returned the wrong value: %q", val)
				return
			}
			succeeded.Add(1)
		})
	}
	close(start) // release all readers simultaneously
	wg.Wait()
	close(unexpected)
	for e := range unexpected {
		require.NoError(t, e)
	}

	assert.Equal(t, int64(maxReads), succeeded.Load(), "the value must be served exactly max_reads times, never more")

	var got models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", sec.ID).First(&got).Error)
	assert.Equal(t, maxReads, got.ReadCount, "the persisted read_count must settle exactly at the cap")
}
