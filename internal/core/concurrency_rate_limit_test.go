package core_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_LoginRateLimit_TripsAndStaysTripped drives the real per-IP brute-force
// path — RecordFailedLogin → IsLoginRateLimited (ADR-040) — from many concurrent attempts
// and asserts the end-to-end invariant: once the failed-attempt budget is reached, the IP
// is rate-limited and stays that way, with every attempt counted. The limiter is a
// fail-open backstop (the check is intentionally separate from the record, so it does NOT
// promise "at most N attempts ever pass" under a race) — the guarantee it MUST keep is
// that concurrent attempts can't deflate the count and slip the IP back under budget.
func TestConcurrency_LoginRateLimit_TripsAndStaysTripped(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "rl.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const ip = "203.0.113.42"
	// Fire well past the budget concurrently.
	const attempts = 100
	require.Greater(t, attempts, core.LoginMaxAttempts)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			<-start
			c.RecordFailedLogin(ctx, ip)
		})
	}
	close(start) // release all attempts at once
	wg.Wait()

	// Every concurrent attempt was recorded, so the IP is over budget and stays limited
	// across repeated checks (the count is monotonic within the window).
	assert.True(t, c.IsLoginRateLimited(ctx, ip), "IP must be rate-limited once the budget is exceeded")
	assert.True(t, c.IsLoginRateLimited(ctx, ip), "rate-limit verdict must be stable, not flap")

	// A fresh IP with no attempts is not limited — the budget is per-IP, not global.
	assert.False(t, c.IsLoginRateLimited(ctx, "198.51.100.9"), "an unrelated IP must not be limited")

	// An empty IP fails open (never limited) by design.
	assert.False(t, c.IsLoginRateLimited(ctx, ""), "empty IP must fail open")
}
