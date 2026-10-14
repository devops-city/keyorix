package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newRateLimitCore(t *testing.T) (*KeyorixCore, func(time.Time)) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}))
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	setNow := func(t time.Time) { c.now = func() time.Time { return t } }
	return c, setNow
}

func TestRateLimit_BlocksAtBudgetAndExpiresWithWindow(t *testing.T) {
	t.Parallel()
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()

	// Below the budget: allowed.
	for range LoginMaxAttempts - 1 {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "under budget is allowed")

	// Reaching the budget: blocked.
	c.RecordFailedLogin(ctx, "1.2.3.4")
	assert.True(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "at the budget the IP is blocked")

	// A different IP is unaffected.
	assert.False(t, c.IsLoginRateLimited(ctx, "9.9.9.9"))

	// After the window elapses, the old attempts no longer count.
	setNow(base.Add(LoginWindow + time.Minute))
	assert.False(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "attempts age out of the window")
}

func TestRateLimit_EmptyIPNeverLimited(t *testing.T) {
	t.Parallel()
	c, _ := newRateLimitCore(t)
	ctx := context.Background()
	for range LoginMaxAttempts + 5 {
		c.RecordFailedLogin(ctx, "")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, ""), "an empty IP is never rate-limited")
}

// TestCanonicalIP is #G20's detection_idea: assert multiple textual
// representations of the same source normalize to one canonical form.
func TestCanonicalIP(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, want string }{
		{"bare IPv4", "203.0.113.9", "203.0.113.9"},
		{"IPv4 with port", "203.0.113.9:5555", "203.0.113.9"},
		{"bracketed IPv6 with port", "[2001:db8::1]:5555", "2001:db8::1"},
		{"bare unbracketed IPv6, no port", "2001:db8::1", "2001:db8::1"},
		{"expanded IPv6 form compresses to the same canonical address", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"non-IP host is returned unchanged", "not-an-ip", "not-an-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CanonicalIP(tc.in))
		})
	}
}

// TestRateLimit_CanonicalizesIPBeforeKeying is #G20: IsLoginRateLimited/
// RecordFailedLogin previously used the caller-supplied IP string as-is, so
// trivially different textual representations of the SAME source (a
// caller-supplied host:port vs. a bare IP, or two equivalent IPv6 forms) each
// got their own independent budget instead of sharing one — defeating the
// budget for any caller that varies its representation (or simply forgets to
// strip the port, as several HTTP handlers previously did independently and
// inconsistently).
func TestRateLimit_CanonicalizesIPBeforeKeying(t *testing.T) {
	t.Parallel()
	c, _ := newRateLimitCore(t)
	ctx := context.Background()

	// Reach the budget using the host:port form...
	for range LoginMaxAttempts {
		c.RecordFailedLogin(ctx, "203.0.113.9:5555")
	}
	// ...a bare-IP request from the SAME source (identical once canonicalized)
	// must already be blocked, not get a fresh budget under a different key.
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.9"),
		"a bare IP must share the same bucket as a host:port form of the identical address")

	// Two equivalent IPv6 textual forms must also share one bucket.
	c2, _ := newRateLimitCore(t)
	for range LoginMaxAttempts {
		c2.RecordFailedLogin(ctx, "2001:0db8:0000:0000:0000:0000:0000:0001")
	}
	assert.True(t, c2.IsLoginRateLimited(ctx, "2001:db8::1"),
		"an alternate IPv6 textual form of the same address must share the same bucket")
}

// TestRateLimit_SSOBegin_BlocksAtBudgetAndExpiresWithWindow is #G82: BeginSSO/
// BeginSAML previously had no rate limit at all, letting an unauthenticated
// flood grow the SSOLoginState table without bound.
func TestRateLimit_SSOBegin_BlocksAtBudgetAndExpiresWithWindow(t *testing.T) {
	t.Parallel()
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()

	for range SSOBeginMaxAttempts - 1 {
		c.RecordSSOBeginAttempt(ctx, "1.2.3.4")
	}
	assert.False(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "under budget is allowed")

	c.RecordSSOBeginAttempt(ctx, "1.2.3.4")
	assert.True(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "at the budget the IP is blocked")

	assert.False(t, c.IsSSOBeginRateLimited(ctx, "9.9.9.9"), "a different IP is unaffected")

	setNow(base.Add(SSOBeginWindow + time.Minute))
	assert.False(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "attempts age out of the window")
}

func TestRateLimit_SSOBegin_EmptyIPNeverLimited(t *testing.T) {
	t.Parallel()
	c, _ := newRateLimitCore(t)
	ctx := context.Background()
	for range SSOBeginMaxAttempts + 5 {
		c.RecordSSOBeginAttempt(ctx, "")
	}
	assert.False(t, c.IsSSOBeginRateLimited(ctx, ""), "an empty IP is never rate-limited")
}

// TestRateLimit_SSOBegin_SharesLoginAttemptTableButOwnBudget confirms the
// ssoRateLimitPrefix namespacing: an IP flooding the login endpoint doesn't
// also consume its SSO-begin budget, and vice versa — they're independent
// counters sharing one table (matching the existing password-reset prefix
// convention).
func TestRateLimit_SSOBegin_SharesLoginAttemptTableButOwnBudget(t *testing.T) {
	t.Parallel()
	c, _ := newRateLimitCore(t)
	ctx := context.Background()

	for range LoginMaxAttempts {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	require.True(t, c.IsLoginRateLimited(ctx, "1.2.3.4"))
	assert.False(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "login attempts must not consume the SSO-begin budget")
}

func TestRateLimit_PruneRemovesAgedRows(t *testing.T) {
	t.Parallel()
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()
	for range 5 {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	// Move past the window and prune — aged rows are removed.
	setNow(base.Add(LoginWindow + time.Minute))
	removed, err := c.PruneLoginAttempts(ctx, time.Time{}, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(5), removed)

	n, err := c.storage.CountRecentLoginAttempts(ctx, "1.2.3.4", time.Time{})
	require.NoError(t, err)
	assert.Zero(t, n, "table is empty after pruning aged rows")
}

// TestPruneLoginAttempts_ClampsFutureBeforeToWindow is the CORE-RATE-003
// regression test at the core layer: a caller-supplied `before` LATER than
// now-LoginWindow (an attacker-controlled request body's far-future
// timestamp, e.g. "2099-01-01T00:00:00Z") must never widen the deletion
// window — the storage call underneath must always receive the clamped
// cutoff, not the caller's value.
func TestPruneLoginAttempts_ClampsFutureBeforeToWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	maxCutoff := now.Add(-LoginWindow)
	attackerBefore := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	mockStore := new(MockStorage)
	// Expectation is set on the CLAMPED cutoff, not the attacker's `before` —
	// if the fix regresses to passing `before` straight through, this
	// expectation is never satisfied and testify panics on the unexpected call.
	mockStore.On("PruneLoginAttempts", mock.Anything, maxCutoff).Return(int64(3), nil)
	mockStore.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneLoginAttempts(context.Background(), attackerBefore, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed)
	mockStore.AssertExpectations(t)
}

// TestPruneLoginAttempts_NarrowerBeforeIsHonored confirms a caller CAN still
// narrow the deletion window below the default now-LoginWindow cutoff (a
// stricter, not wider, request) — only widening past the window is blocked.
func TestPruneLoginAttempts_NarrowerBeforeIsHonored(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	narrowerBefore := now.Add(-2 * LoginWindow)

	mockStore := new(MockStorage)
	mockStore.On("PruneLoginAttempts", mock.Anything, narrowerBefore).Return(int64(1), nil)
	mockStore.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneLoginAttempts(context.Background(), narrowerBefore, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), removed)
	mockStore.AssertExpectations(t)
}

// TestPruneLoginAttempts_AuditsActorRowCountAndCutoff proves the previously
// entirely-missing audit trail (CORE-RATE-003): a successful prune that
// actually removes rows emits a data.login_attempts_pruned event recording
// the acting principal, the row count, and the effective cutoff — mirroring
// PurgeExpiredSoftDeletes/PurgeExpiredComplianceRecords.
func TestPruneLoginAttempts_AuditsActorRowCountAndCutoff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	maxCutoff := now.Add(-LoginWindow)

	mockStore := new(MockStorage)
	mockStore.On("PruneLoginAttempts", mock.Anything, maxCutoff).Return(int64(7), nil)

	var audited *models.AuditEvent
	mockStore.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		if e.EventType == "data.login_attempts_pruned" {
			audited = e
			return true
		}
		return false
	})).Return(nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	actorID := uint(42)
	removed, err := c.PruneLoginAttempts(context.Background(), time.Time{}, actorID)
	require.NoError(t, err)
	assert.Equal(t, int64(7), removed)

	require.NotNil(t, audited, "a data.login_attempts_pruned audit event must be written when rows are removed")
	require.NotNil(t, audited.UserID, "the acting principal is recorded")
	assert.Equal(t, actorID, *audited.UserID)
	assert.Contains(t, audited.Description, "7", "row count is recorded")
	assert.Contains(t, audited.Description, maxCutoff.UTC().Format(time.RFC3339), "effective cutoff is recorded")
}

// TestPruneLoginAttempts_NoAuditWhenNothingRemoved mirrors
// PurgeExpiredSoftDeletes/PurgeExpiredComplianceRecords: a prune that removes
// zero rows writes no audit event at all (avoids flooding the audit trail
// every maintenance-sweep tick when there's nothing to report).
func TestPruneLoginAttempts_NoAuditWhenNothingRemoved(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	mockStore := new(MockStorage)
	mockStore.On("PruneLoginAttempts", mock.Anything, mock.Anything).Return(int64(0), nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneLoginAttempts(context.Background(), time.Time{}, 5)
	require.NoError(t, err)
	assert.Zero(t, removed)
	mockStore.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}
