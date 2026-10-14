package store_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_LoginAttempts_NoLostRecords is the rate-limiter count-integrity
// invariant (ADR-040). The per-IP login limiter is a windowed COUNT over independent
// attempt rows; each failed login is its own INSERT (not an increment of a shared
// counter), so the count cannot be deflated by a lost-update race. This drives many
// concurrent RecordLoginAttempt calls for one IP and asserts every single one is durably
// counted — if a future change turned the record path into a non-atomic upsert/increment,
// concurrent attempts would lose writes, the window count would under-report, and the
// brute-force budget would be silently inflated. That regression is what this guards.
//
// The database is opened the way the server opens it (storage.OpenGormDB: the
// production DSN, pool cap and in-process FIFO write gate, #2630), not a bare
// SQLite handle. Against a bare handle 100 writers queue inside SQLite's busy
// handler, which has no queue position, so on a slow disk an unlucky writer is
// overtaken for the whole busy_timeout and returns SQLITE_BUSY (#3087). The server
// never runs that shape for RecordLoginAttempt: GORM's Create goes through a
// gated BeginTx, so concurrent writers are served in arrival order. A residual
// error there (gate wait exhausted, second process holding the lock) is not a
// lost attempt either: core's budgetRecord counts it in memory (auth_budget.go).
// The assertion is unchanged: no writer may error and all 100 rows must be counted.
func TestConcurrency_LoginAttempts_NoLostRecords(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "c.db")
	db, err := kxstorage.OpenGormDB(cfg)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}))
	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	now := time.Now().UTC()

	const attempts = 100
	const ip = "203.0.113.7"

	errs := make(chan error, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			// Spread timestamps within the window so each row is distinct, but all newer
			// than `since` below.
			if err := ls.RecordLoginAttempt(ctx, ip, now.Add(time.Duration(n)*time.Millisecond)); err != nil {
				errs <- err
			}
		}(i)
	}
	close(start) // release all writers at once
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// Every concurrent attempt must be counted — no lost inserts under contention.
	n, err := ls.CountRecentLoginAttempts(ctx, ip, now.Add(-time.Minute))
	require.NoError(t, err)
	assert.Equal(t, int64(attempts), n, "every concurrent login attempt must be durably counted")

	// A different IP shares none of those attempts (the WHERE ip = ? scoping holds).
	other, err := ls.CountRecentLoginAttempts(ctx, "198.51.100.1", now.Add(-time.Minute))
	require.NoError(t, err)
	assert.Equal(t, int64(0), other, "attempts must not leak across IPs")
}
