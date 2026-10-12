// account_lockout_stored_plus_fallback_test.go — the account lockout's check
// adds the in-memory failures to the stored ones (ADR-040 amendment: "The check
// adds the in-memory count to the stored one", every budget). #3029 review at
// 81a070aa: loginLocked and the pre-mint re-check compared each count with
// MaxAttempts on its own, so with the lockout write failing intermittently up
// to 2*(MaxAttempts-1) failures fit before a lock.
package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// lockoutStateFlakyStorage fails the lockout-column write while down is set.
type lockoutStateFlakyStorage struct {
	storage.Storage
	down *atomic.Bool
}

func (s *lockoutStateFlakyStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&lockoutStateFlakyStorage{Storage: tx, down: s.down})
	})
}

func (s *lockoutStateFlakyStorage) UpdateLoginLockoutState(ctx context.Context, id uint, n int, last, until *time.Time, count int) error {
	if s.down.Load() {
		return errLockoutStoreDown
	}
	return s.Storage.UpdateLoginLockoutState(ctx, id, n, last, until, count)
}

// failLogins sends one wrong password per entry of writeDown, with the
// lockout write failing for the entries that are true.
func failLogins(t *testing.T, c *KeyorixCore, down *atomic.Bool, ip string, writeDown ...bool) {
	t.Helper()
	for i, d := range writeDown {
		down.Store(d)
		_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: "wrong-password", IPAddress: ip})
		require.Error(t, err, "wrong password %d", i+1)
		assert.NotContains(t, err.Error(), "temporarily locked", "wrong password %d: locked before MaxAttempts failures", i+1)
	}
	down.Store(false)
}

func newFlakyLockoutCore(t *testing.T) (*KeyorixCore, *atomic.Bool) {
	t.Helper()
	c, _, _ := newMFATestCore(t)
	c.loginLockout = fallbackLockoutPolicy // MaxAttempts 3
	down := &atomic.Bool{}
	c.storage = &lockoutStateFlakyStorage{Storage: c.storage, down: down}
	return c, down
}

// TestAccountLockout_StoredAndFallbackFailuresAreSummed: MaxAttempts failures,
// split between the stored columns and the in-memory fallback in either order,
// lock the account; the correct password is then refused.
func TestAccountLockout_StoredAndFallbackFailuresAreSummed(t *testing.T) {
	t.Parallel()
	for name, writeDown := range map[string][]bool{
		"stored then fallback": {false, true, true},
		"fallback then stored": {true, true, false},
		"interleaved":          {true, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, down := newFlakyLockoutCore(t)
			require.Len(t, writeDown, fallbackLockoutPolicy.MaxAttempts)
			failLogins(t, c, down, "198.51.100.20", writeDown...)

			_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: mfaTestPassword, IPAddress: "198.51.100.20"})
			require.Error(t, err, "MaxAttempts failures, part stored and part in memory, must lock the account")
			assert.Contains(t, err.Error(), "temporarily locked")
		})
	}
}

// TestAccountLockout_StoredAndFallbackBelowTheLimitStillLogsIn is the
// calibration: one attempt short of MaxAttempts across both counts logs in.
func TestAccountLockout_StoredAndFallbackBelowTheLimitStillLogsIn(t *testing.T) {
	t.Parallel()
	c, down := newFlakyLockoutCore(t)
	failLogins(t, c, down, "198.51.100.21", false, true)

	_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: mfaTestPassword, IPAddress: "198.51.100.21"})
	require.NoError(t, err, "one attempt is still left, so the correct password must log in")
}

// TestAccountLockout_StoredFailuresOutsideTheWindowAreNotSummed: a stored
// count whose last failure is older than Window is stale (recordFailedLogin
// restarts it), so it does not add to the in-memory failures.
func TestAccountLockout_StoredFailuresOutsideTheWindowAreNotSummed(t *testing.T) {
	t.Parallel()
	c, down := newFlakyLockoutCore(t)
	base := c.now()
	var now atomic.Pointer[time.Time]
	now.Store(&base)
	c.now = func() time.Time { return *now.Load() }

	failLogins(t, c, down, "198.51.100.22", false, false)
	later := base.Add(fallbackLockoutPolicy.Window + time.Minute)
	now.Store(&later)
	failLogins(t, c, down, "198.51.100.23", true)

	_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: mfaTestPassword, IPAddress: "198.51.100.23"})
	require.NoError(t, err, "two stale stored failures plus one in memory are one failure inside the window")
}

// TestAccountLockout_RecheckSumsTheFreshStoredCount: the pre-mint re-check
// reads the stored count under the row lock, so a caller whose snapshot
// predates the stored failures is still refused once stored + in-memory
// reaches MaxAttempts.
func TestAccountLockout_RecheckSumsTheFreshStoredCount(t *testing.T) {
	t.Parallel()
	c, down := newFlakyLockoutCore(t)
	ctx := context.Background()
	stale, err := c.storage.GetUserByUsername(ctx, "alice")
	require.NoError(t, err)
	require.NoError(t, c.recheckLoginLockFailClosed(ctx, stale), "calibration: nothing counted yet")

	failLogins(t, c, down, "198.51.100.24", false, false, true)
	require.Zero(t, stale.FailedLoginAttempts, "calibration: the snapshot predates the failures")
	err = c.recheckLoginLockFailClosed(ctx, stale)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "temporarily locked")
}
