// auth_budget_degraded_test.go — AUTH-AUDIT-1 item 5, points 2-4 (Andrei,
// 2026-10-10 18:52): while an auth budget runs on its in-memory fallback,
//
//   - the password-reset budget is tighter: half the normal per-IP limit, plus
//     a per-account cap (the email-bombing guard);
//   - every fallback limit can be divided by the expected replica count, since
//     each replica keeps its own copy (default 1);
//   - the limiter reports itself degraded, for the health endpoint, until no
//     budget has fallen back within its window.
package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- point 2: password reset during fallback ---------------------------------

func TestPasswordResetBudget_DuringFallbackHalvesThePerIPLimit(t *testing.T) {
	c, stub, _, _ := newFallbackCore(t)
	ctx := context.Background()
	stub.down = true
	half := PasswordResetMaxAttempts / 2
	for i := 0; i < half; i++ {
		require.False(t, c.IsPasswordResetRateLimited(ctx, "203.0.113.40"), "attempt %d is still inside half the limit", i+1)
		c.RecordPasswordResetAttempt(ctx, "203.0.113.40")
	}
	assert.True(t, c.IsPasswordResetRateLimited(ctx, "203.0.113.40"),
		"with its storage failing, the password-reset budget allows half the normal %d per IP", PasswordResetMaxAttempts)
}

func TestPasswordResetBudget_HealthyKeepsTheFullLimit(t *testing.T) {
	c, _, _, _ := newFallbackCore(t)
	ctx := context.Background()
	for i := 0; i < PasswordResetMaxAttempts-1; i++ {
		c.RecordPasswordResetAttempt(ctx, "203.0.113.41")
	}
	assert.False(t, c.IsPasswordResetRateLimited(ctx, "203.0.113.41"), "healthy storage: the normal limit is unchanged")
}

// countingDeliverer counts deliveries and signals each one.
type countingDeliverer struct {
	n    atomic.Int64
	each chan struct{}
}

func (d *countingDeliverer) DeliverSetupLink(context.Context, delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	d.n.Add(1)
	d.each <- struct{}{}
	return delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}, nil
}

func (*countingDeliverer) Name() string { return "counting" }

// loginAttemptsErrMock is MockStorage with its login-attempt methods failing.
// (MockStorage hard-codes them to succeed and ignores .On setups for them.)
type loginAttemptsErrMock struct{ *MockStorage }

func (loginAttemptsErrMock) CountRecentLoginAttempts(context.Context, string, time.Time) (int64, error) {
	return 0, errLoginAttemptsDown
}
func (loginAttemptsErrMock) RecordLoginAttempt(context.Context, string, time.Time) error {
	return errLoginAttemptsDown
}

func TestPasswordReset_DuringFallbackCapsResetsPerAccount(t *testing.T) {
	ctx := context.Background()
	// The fake clock is read by RequestPasswordReset's background provisioning
	// goroutine while this test advances it, so it must be synchronised.
	var nowNanos atomic.Int64
	nowNanos.Store(time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC).UnixNano())
	ms := new(MockStorage)
	c := NewKeyorixCore(loginAttemptsErrMock{ms})
	c.now = func() time.Time { return time.Unix(0, nowNanos.Load()).UTC() }
	d := &countingDeliverer{each: make(chan struct{}, 16)}
	c.SetCredentialDelivery(d, testBaseURL)
	anyAudit(ms)
	user := &models.User{ID: 9, Email: "victim@acme.io", DisplayName: "V", AccountState: AccountActive}
	ms.On("GetUserByEmail", mock.Anything, user.Email).Return(user, nil)
	ms.On("CountSetupTokensSince", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(0), nil)
	ms.On("SupersedeActiveSetupTokens", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ms.On("CreateSetupToken", mock.Anything, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

	// Each request comes from a different address, past the per-email resend
	// interval, so only the new per-account cap can stop it.
	const requests = 4
	for i := 0; i < requests; i++ {
		ip := "198.51.100." + itoa(50+i)
		require.False(t, c.IsPasswordResetRateLimited(ctx, ip))
		c.RecordPasswordResetAttempt(ctx, ip)
		require.NoError(t, c.RequestPasswordReset(ctx, user.Email), "the response never changes")
		nowNanos.Add(int64(resendMinInterval + time.Second))
	}
	capped := PasswordResetMaxAttempts / 2
	for i := 0; i < capped; i++ {
		select {
		case <-d.each:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for delivery %d", i+1)
		}
	}
	select {
	case <-d.each:
		t.Fatalf("a reset beyond the per-account cap was delivered (%d so far) while the password-reset budget was on its fallback", d.n.Load())
	case <-time.After(300 * time.Millisecond):
	}
	assert.EqualValues(t, capped, d.n.Load())
}

// --- point 3: the replica divisor --------------------------------------------

func TestAuthBudgetFallback_ReplicaDivisorScalesTheLimit(t *testing.T) {
	c, stub, _, _ := newFallbackCore(t)
	ctx := context.Background()
	c.SetAuthRateLimitFallbackReplicas(2)
	stub.down = true
	perReplica := LoginMaxAttempts / 2
	for i := 0; i < perReplica; i++ {
		require.False(t, c.IsLoginRateLimited(ctx, "203.0.113.42"), "failure %d is inside this replica's share", i+1)
		c.RecordFailedLogin(ctx, "203.0.113.42")
	}
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.42"),
		"with 2 replicas each one enforces half the limit while on the fallback, so the cluster still allows about %d", LoginMaxAttempts)
}

func TestAuthBudgetFallback_ReplicaDivisorNeverReachesZero(t *testing.T) {
	c, stub, _, _ := newFallbackCore(t)
	ctx := context.Background()
	c.SetAuthRateLimitFallbackReplicas(1000)
	stub.down = true
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.43"), "a fallback limit rounds down to at least one attempt, never zero")
	c.RecordFailedLogin(ctx, "203.0.113.43")
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.43"))
}

func TestAuthBudgetFallback_ReplicaDivisorDoesNotTouchTheStoredLimit(t *testing.T) {
	c, _, _, _ := newFallbackCore(t)
	ctx := context.Background()
	c.SetAuthRateLimitFallbackReplicas(4)
	for i := 0; i < LoginMaxAttempts-1; i++ {
		c.RecordFailedLogin(ctx, "203.0.113.44")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.44"), "healthy storage is cluster-wide already; the divisor applies only to the fallback")
}

// --- point 4: degraded state --------------------------------------------------

func TestAuthRateLimitDegraded_OnlyWhileARecentFallbackExists(t *testing.T) {
	c, stub, _, setNow := newFallbackCore(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	setNow(base)
	assert.False(t, c.AuthRateLimitDegraded(), "no fallback yet")

	stub.down = true
	_ = c.IsLoginRateLimited(ctx, "203.0.113.45")
	stub.down = false
	assert.True(t, c.AuthRateLimitDegraded(), "a fallback just happened")

	setNow(base.Add(LoginWindow - time.Second))
	assert.True(t, c.AuthRateLimitDegraded(), "still inside the window its in-memory attempts live for")
	setNow(base.Add(LoginWindow + time.Second))
	assert.False(t, c.AuthRateLimitDegraded(), "the window passed with storage healthy")
}
