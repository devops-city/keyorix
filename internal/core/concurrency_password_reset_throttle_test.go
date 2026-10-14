package core_test

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// countingDeliverer is a thread-safe delivery.CredentialDelivery fake that counts
// how many setup-link "emails" it was asked to send — the direct proxy for the
// mail-bombing/inbox-flooding harm #249 describes.
type countingDeliverer struct {
	sent atomic.Int32
}

func (d *countingDeliverer) DeliverSetupLink(_ context.Context, _ delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	d.sent.Add(1)
	return delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}, nil
}

func (d *countingDeliverer) Name() string { return "counting-fake" }

// TestConcurrency_RequestPasswordReset_BurstIsThrottled is the regression for the
// check-then-act half of #249: POST /auth/password-reset's abuse control
// (checkResendThrottle, ADR-028's 60s min-interval + 10/day cap) must not be
// defeated by a burst of concurrent requests for the same victim email each
// reading the same pre-burst count and all passing. provisionSetupLinkThrottled
// already serializes the count-then-issue window per process via setupResendMu
// (held across the throttle check AND the token write); this drives a real burst
// — far larger than the daily cap — against genuine SQLite-backed storage and
// asserts that only ONE reset email is ever actually sent, not one per
// concurrent request.
func TestConcurrency_RequestPasswordReset_BurstIsThrottled(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "pwreset.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.SetupToken{}, &models.AuditEvent{}))

	const email = "victim@acme.io"
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "victim", UsernameFolded: "victim", Email: email, EmailFolded: email, AccountState: core.AccountActive,
	}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	fake := &countingDeliverer{}
	c.SetCredentialDelivery(fake, "https://keyorix.example.internal")

	const burst = 50 // far more than the daily cap (10) and the 60s min interval allows
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range burst {
		wg.Go(func() {
			<-start
			// RequestPasswordReset always returns nil (enumeration-safe) regardless of
			// throttling — the observable effect under test is how many emails went out.
			_ = c.RequestPasswordReset(context.Background(), email)
		})
	}
	close(start)
	wg.Wait()

	// RequestPasswordReset returns as soon as the throttle-check-and-deliver work is
	// handed off to a detached background goroutine (#117: the caller must not block
	// on delivery, or its latency becomes an account-enumeration side-channel). So
	// wg.Wait() above only proves all 50 calls RETURNED, not that their background
	// deliveries have run yet — poll instead of asserting immediately, or this test
	// flakes under CPU pressure (the background goroutines simply haven't been
	// scheduled yet when the assertion below would otherwise fire).
	require.Eventually(t, func() bool { return fake.sent.Load() >= 1 }, 5*time.Second, 10*time.Millisecond,
		"expected one reset email to be delivered once the throttle-serialized burst finishes")

	// The 60s min-interval means at most one reset email can go out per burst that
	// completes well inside that window — a burst of 50 concurrent requests must
	// not fan out into 50 emails to the victim's inbox. Give the other 49
	// (throttled, mutex-serialized) background goroutines a generous window to
	// finish before asserting the count is stable, rather than racing them.
	assert.Never(t, func() bool { return fake.sent.Load() > 1 }, 500*time.Millisecond, 10*time.Millisecond,
		"a concurrent burst against one email must be throttled to a single delivery, not one per request")
	assert.Equal(t, int32(1), fake.sent.Load())

	// Defense in depth: exactly one active setup token exists for this subject —
	// the DB state agrees with what was actually delivered.
	var tokenCount int64
	require.NoError(t, db.Model(&models.SetupToken{}).
		Where("purpose = ? AND subject_email = ?", core.SetupPurposePasswordResetLink, email).
		Count(&tokenCount).Error)
	assert.Equal(t, int64(1), tokenCount, "exactly one setup token should have been issued for the burst")
}
