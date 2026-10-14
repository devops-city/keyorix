package store

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// concurrentDB opens a temp FILE-backed SQLite (not :memory:) with a busy timeout and
// WAL, so multiple connections genuinely contend — the only way to test that an atomic
// check-and-increment holds under real concurrency. A single shared in-memory
// connection would serialize every statement and mask a check-then-act race.
func concurrentDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "c.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	return db
}

// TestConcurrency_MaxReads_NeverExceedsCap is the burn-after-read invariant: a secret
// version with read_count capped at maxReads must let through EXACTLY maxReads reads,
// no matter how many readers race. TryIncrementSecretReadCount is a single conditional
// UPDATE (read_count < maxReads), so concurrent callers can't collectively over-read;
// this drives many readers at once and asserts exactly maxReads succeed.
func TestConcurrency_MaxReads_NeverExceedsCap(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.SecretVersion{}))
	ls := NewLocalStorage(db)

	v := &models.SecretVersion{SecretNodeID: 1, VersionNumber: 1, ReadCount: 0}
	require.NoError(t, db.Create(v).Error)

	const maxReads = 5
	const readers = 64

	var succeeded atomic.Int64
	errs := make(chan error, readers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range readers {
		wg.Go(func() {
			<-start
			ok, err := ls.TryIncrementSecretReadCount(context.Background(), v.ID, maxReads)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				succeeded.Add(1)
			}
		})
	}
	close(start) // release all readers at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(maxReads), succeeded.Load(), "exactly maxReads reads may succeed, never more")

	var got models.SecretVersion
	require.NoError(t, db.First(&got, v.ID).Error)
	assert.Equal(t, maxReads, got.ReadCount, "the stored read_count must settle exactly at the cap")
}

// TestConcurrency_MaxReadsSecretLevel_NeverExceedsCap mirrors the version-level
// test above for TryIncrementSecretNodeReadCount (#133): the secret-level
// counter that survives rotate/rollback must have the SAME race-free guarantee
// as the version-level one it supersedes for enforcement.
func TestConcurrency_MaxReadsSecretLevel_NeverExceedsCap(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	ls := NewLocalStorage(db)

	s := &models.SecretNode{Name: "n", ProjectID: 1, EnvironmentID: 1, ReadCount: 0}
	require.NoError(t, db.Create(s).Error)

	const maxReads = 5
	const readers = 64

	var succeeded atomic.Int64
	errs := make(chan error, readers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range readers {
		wg.Go(func() {
			<-start
			ok, err := ls.TryIncrementSecretNodeReadCount(context.Background(), s.ID, maxReads)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				succeeded.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(maxReads), succeeded.Load(), "exactly maxReads reads may succeed, never more")

	var got models.SecretNode
	require.NoError(t, db.First(&got, s.ID).Error)
	assert.Equal(t, maxReads, got.ReadCount, "the stored read_count must settle exactly at the cap")
}
