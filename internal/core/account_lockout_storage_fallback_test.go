// account_lockout_storage_fallback_test.go — the per-account lockout is an
// auth budget too (Andrei, 2026-10-10 18:52: "no auth budget ever fails open
// on storage errors"). It is the only bound on step-up and recovery-code
// guessing, and the second bound on password and TOTP guessing. Its stored
// state is the four lockout columns on the user row, written by
// recordFailedLogin. That write used to be best-effort with nothing behind it,
// so while it failed no failure was counted at all and the account never
// locked. These tests drive real failures with that write down and require
// the account to lock anyway, from the shared in-memory fallback.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var errLockoutStoreDown = errors.New("pq: connection reset by peer")

// lockoutStateDownStorage fails every write of the lockout columns, inside or
// outside a transaction. Everything else works.
type lockoutStateDownStorage struct{ storage.Storage }

func (s *lockoutStateDownStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&lockoutStateDownStorage{Storage: tx})
	})
}

func (*lockoutStateDownStorage) UpdateLoginLockoutState(context.Context, uint, int, *time.Time, *time.Time, int) error {
	return errLockoutStoreDown
}

var fallbackLockoutPolicy = LoginLockoutPolicy{
	Enabled: true, MaxAttempts: 3, Window: time.Hour,
	BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
}

func TestAccountLockout_StateStorageDown_StepUpStillLocks(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = fallbackLockoutPolicy
	secret, _ := activateMFAForTest(t, c, fixed)
	c.storage = &lockoutStateDownStorage{Storage: c.storage}
	ctx := context.Background()

	for i := 0; i < fallbackLockoutPolicy.MaxAttempts; i++ {
		require.Error(t, c.VerifyMFAStepUp(ctx, 1, "000000"), "wrong code %d", i+1)
	}
	step := fixed.Add(30 * time.Second)
	c.SetClockForTesting(func() time.Time { return step })
	good, err := totp.GenerateCode(secret, step)
	require.NoError(t, err)
	err = c.VerifyMFAStepUp(ctx, 1, good)
	require.Error(t, err, "after MaxAttempts wrong codes the account must be locked even though the lockout write failed every time")
	assert.Contains(t, err.Error(), "temporarily locked")

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Nil(t, u.LoginLockedUntil, "precondition: the stored lock really was never written")
}

func TestAccountLockout_StateStorageDown_PasswordLoginStillLocks(t *testing.T) {
	t.Parallel()
	c, _, _ := newMFATestCore(t)
	c.loginLockout = fallbackLockoutPolicy
	c.storage = &lockoutStateDownStorage{Storage: c.storage}
	ctx := context.Background()

	for i := 0; i < fallbackLockoutPolicy.MaxAttempts; i++ {
		_, _, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: "wrong-password", IPAddress: "198.51.100.7"})
		require.Error(t, err, "wrong password %d", i+1)
	}
	_, _, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: mfaTestPassword, IPAddress: "198.51.100.7"})
	require.Error(t, err, "after MaxAttempts wrong passwords the account must be locked even though the lockout write failed")
	assert.Contains(t, err.Error(), "temporarily locked")
}

// TestAccountLockout_StateStorageDown_BelowTheLimitStillLogsIn is the
// calibration: the fallback must not lock early or lock everyone.
func TestAccountLockout_StateStorageDown_BelowTheLimitStillLogsIn(t *testing.T) {
	t.Parallel()
	c, _, _ := newMFATestCore(t)
	c.loginLockout = fallbackLockoutPolicy
	c.storage = &lockoutStateDownStorage{Storage: c.storage}
	ctx := context.Background()

	for i := 0; i < fallbackLockoutPolicy.MaxAttempts-1; i++ {
		_, _, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: "wrong-password", IPAddress: "198.51.100.8"})
		require.Error(t, err)
	}
	_, _, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: mfaTestPassword, IPAddress: "198.51.100.8"})
	require.NoError(t, err, "one attempt is still left, so the correct password must log in")
}

// TestAccountLockout_HealthyStorage_FallbackStaysEmpty: with storage healthy
// nothing is kept in memory, so the stored lockout alone decides.
func TestAccountLockout_HealthyStorage_FallbackStaysEmpty(t *testing.T) {
	t.Parallel()
	c, db, _ := newMFATestCore(t)
	c.loginLockout = fallbackLockoutPolicy
	ctx := context.Background()

	for i := 0; i < fallbackLockoutPolicy.MaxAttempts; i++ {
		_, _, _ = c.Login(ctx, &LoginRequest{Username: "alice", Password: "wrong-password", IPAddress: "198.51.100.9"})
	}
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	require.NotNil(t, u.LoginLockedUntil, "the stored lockout trips as before")
	assert.Zero(t, c.authBudgetFallback(accountLockoutBudget).size(), "a healthy store must not populate the fallback")
}

// TestAuthBudgetFallback_AuditedAndCountedPerBudget: a fallback on any budget
// writes the error event and moves that budget's metric series.
func TestAuthBudgetFallback_AuditedAndCountedPerBudget(t *testing.T) {
	c, stub, db, _ := newFallbackCore(t)
	ctx := context.Background()
	stub.down = true
	for _, tc := range []struct {
		budget string
		hit    func()
	}{
		{"password_reset", func() { c.RecordPasswordResetAttempt(ctx, "203.0.113.30") }},
		{"sso_begin", func() { _ = c.IsSSOBeginRateLimited(ctx, "203.0.113.31") }},
	} {
		before := testutil.ToFloat64(authRateLimitFallbackTotal.WithLabelValues(tc.budget))
		events := auditEventsOfType(t, db, EventAuthRateLimitError)
		tc.hit()
		assert.Equal(t, before+1, testutil.ToFloat64(authRateLimitFallbackTotal.WithLabelValues(tc.budget)), "%s: one metric increment per fallback", tc.budget)
		assert.Equal(t, events+1, auditEventsOfType(t, db, EventAuthRateLimitError), "%s: one error event per fallback", tc.budget)
	}

	// account_lockout: its stored write is the user row, not login_attempts.
	ac, adb, _ := newMFATestCore(t)
	ac.loginLockout = fallbackLockoutPolicy
	ac.storage = &lockoutStateDownStorage{Storage: ac.storage}
	before := testutil.ToFloat64(authRateLimitFallbackTotal.WithLabelValues("account_lockout"))
	_, _, _ = ac.Login(ctx, &LoginRequest{Username: "alice", Password: "wrong-password", IPAddress: "198.51.100.10"})
	assert.Equal(t, before+1, testutil.ToFloat64(authRateLimitFallbackTotal.WithLabelValues("account_lockout")))
	var ev models.AuditEvent
	require.NoError(t, adb.Where("event_type = ?", EventAuthRateLimitError).First(&ev).Error)
	require.NotNil(t, ev.UserID, "an account fallback is attributed to the account")
	assert.EqualValues(t, 1, *ev.UserID)
	require.NotNil(t, ev.Success)
	assert.False(t, *ev.Success, "an error event, not a success")
}

// TestAuthBudgetFallback_BudgetsDoNotEvictEachOther: each budget has its own
// bounded fallback, so flooding one with distinct keys cannot push an
// account's in-memory lock out of another.
func TestAuthBudgetFallback_BudgetsDoNotEvictEachOther(t *testing.T) {
	t.Parallel()
	c, _, _ := newMFATestCore(t)
	c.loginLockout = fallbackLockoutPolicy
	now := c.now()
	acct := c.accountBudget()
	for i := 0; i < fallbackLockoutPolicy.MaxAttempts; i++ {
		c.authBudgetFallback(acct).reserve(accountBudgetKey(1), now, acct.window, 4*acct.limit)
	}
	require.True(t, c.budgetFallbackLimitedWithStored(acct, accountBudgetKey(1), 0))
	for i := range authFallbackMaxKeys + 10 {
		ip := "10." + itoa(i>>16&255) + "." + itoa(i>>8&255) + "." + itoa(i&255)
		c.authBudgetFallback(loginBudget).reserve(ip, now, LoginWindow, 4*LoginMaxAttempts)
	}
	assert.LessOrEqual(t, c.authBudgetFallback(loginBudget).size(), authFallbackMaxKeys)
	assert.True(t, c.budgetFallbackLimitedWithStored(acct, accountBudgetKey(1), 0), "an IP flood on the login budget must not unlock an account")
}

// TestAccountLockoutFallback_LockSurvivesUpToTheKeyBound pins the bound the
// auth_budget.go header documents for account_lockout's own LRU (#3029 review
// point 3): an account locked in memory stays locked while failures land on up
// to authFallbackMaxKeys-1 other accounts, and the limiter never grows past
// authFallbackMaxKeys. Dropping the lock needs authFallbackMaxKeys distinct
// real accounts failing inside one outage, each also spending the per-IP
// login budget.
func TestAccountLockoutFallback_LockSurvivesUpToTheKeyBound(t *testing.T) {
	t.Parallel()
	c, _, _ := newMFATestCore(t)
	c.loginLockout = fallbackLockoutPolicy
	now := c.now()
	acct := c.accountBudget()
	f := c.authBudgetFallback(acct)
	for i := 0; i < fallbackLockoutPolicy.MaxAttempts; i++ {
		f.reserve(accountBudgetKey(1), now, acct.window, 4*acct.limit)
	}
	require.True(t, c.budgetFallbackLimitedWithStored(acct, accountBudgetKey(1), 0))
	for uid := uint(2); uid <= authFallbackMaxKeys; uid++ { // authFallbackMaxKeys-1 other accounts
		f.reserve(accountBudgetKey(uid), now, acct.window, 4*acct.limit)
	}
	assert.Equal(t, authFallbackMaxKeys, f.size(), "the limiter is full but not over its bound")
	assert.True(t, c.budgetFallbackLimitedWithStored(acct, accountBudgetKey(1), 0),
		"failures on fewer than authFallbackMaxKeys other accounts must not unlock an account")
}
