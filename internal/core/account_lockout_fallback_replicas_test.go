// account_lockout_fallback_replicas_test.go — the account lockout's in-memory
// count is held to the fallback limit (MaxAttempts divided by the configured
// replicas) on its own, while the stored count added to it keeps the normal
// limit (budgetFallbackLimitedWithStored; #3029/#3032 review).
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountLockout_FallbackAloneBindsAtTheReplicaShare(t *testing.T) {
	t.Parallel()
	c, down := newFlakyLockoutCore(t) // MaxAttempts 3
	c.SetAuthRateLimitFallbackReplicas(3)
	require.Equal(t, 1, c.fallbackLimit(c.accountBudget()), "calibration: 3 attempts over 3 replicas")
	failLogins(t, c, down, "198.51.100.30", true)

	_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: mfaTestPassword, IPAddress: "198.51.100.30"})
	require.Error(t, err, "one in-memory failure is this replica's whole share of the lockout budget")
	assert.Contains(t, err.Error(), "temporarily locked")
}

// TestAccountLockout_ReplicaShareDoesNotTouchTheStoredCount is the
// calibration: the divisor applies to the in-memory count only.
func TestAccountLockout_ReplicaShareDoesNotTouchTheStoredCount(t *testing.T) {
	t.Parallel()
	c, down := newFlakyLockoutCore(t)
	c.SetAuthRateLimitFallbackReplicas(3)
	failLogins(t, c, down, "198.51.100.31", false, false)

	_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: mfaTestPassword, IPAddress: "198.51.100.31"})
	require.NoError(t, err, "two stored failures of three are cluster-wide already; the divisor does not apply")
}
