package core_test

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

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_SetupLinkResendThrottle drives the real setup-link resend path
// (ResendAccountSetupLink → checkResendThrottle → IssueSetupToken) from many
// concurrent goroutines for the SAME subject and asserts the abuse-control invariant:
// the count-then-issue window is serialized, so a simultaneous burst cannot all clear
// the throttle before any token row exists.
//
// With a real clock every resend lands inside the 60s min-interval window, so once the
// first resend mints a token the rest must observe it and back off — exactly one token
// may be created. Before setupResendMu, concurrent callers counted zero in parallel and
// all minted, exceeding the cap; this test fails (many tokens) without the lock.
func TestConcurrency_SetupLinkResendThrottle(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "resend.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.SetupToken{}, &models.AuditEvent{}, &models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))

	st := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(st)
	c.SetCredentialDelivery(nil, "https://keyorix.test") // nil channel → out-of-band, no SMTP
	ctx := context.Background()

	const uid = uint(1)
	require.NoError(t, db.Create(&models.User{
		ID:           uid,
		Username:     "dana",
		Email:        "dana@acme.io",
		DisplayName:  "Dana",
		AccountState: core.AccountPendingFirstLogin,
	}).Error)

	const callers = 32
	var ok atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			if _, err := c.ResendAccountSetupLink(ctx, uid, 7); err == nil {
				ok.Add(1)
			}
		})
	}
	close(start) // release the whole burst at once
	wg.Wait()

	var tokens int64
	require.NoError(t, db.Model(&models.SetupToken{}).Count(&tokens).Error)

	// The min-interval admits exactly one issue from a same-window burst; the race
	// would let several through. Token rows are the ground truth (each successful
	// resend mints one), and successes must match.
	assert.Equal(t, int64(1), tokens, "a concurrent burst must mint exactly one setup token, not race past the throttle")
	assert.Equal(t, int64(1), ok.Load(), "exactly one resend may succeed; the rest are throttled")
}
