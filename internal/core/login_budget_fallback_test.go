// login_budget_fallback_test.go — Andrei's decision (2026-10-10, AUTH-AUDIT-1):
// the per-IP login budget must neither fail open nor fail closed on a
// LoginAttempt storage error. It falls back to an in-memory per-IP limiter with
// the same limit and window, per process, bounded in size; each fallback is
// audited as an error event and counted in a metric; the client response is
// unchanged; and once storage recovers the stored budget is used again.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var errLoginAttemptsDown = errors.New("pq: connection reset by peer")

// loginAttemptsDownStub fails every login-attempt method while down is set;
// everything else (the audit table) keeps working, so the fallback's own
// audit write is observable.
type loginAttemptsDownStub struct {
	corestorage.Storage
	down bool
}

func (s *loginAttemptsDownStub) CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error) {
	if s.down {
		return 0, errLoginAttemptsDown
	}
	return s.Storage.CountRecentLoginAttempts(ctx, ip, since)
}

func (s *loginAttemptsDownStub) RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error {
	if s.down {
		return errLoginAttemptsDown
	}
	return s.Storage.RecordLoginAttempt(ctx, ip, at)
}

func (s *loginAttemptsDownStub) ReserveLoginAttempt(ctx context.Context, ip string, at time.Time) (uint, error) {
	if s.down {
		return 0, errLoginAttemptsDown
	}
	return s.Storage.ReserveLoginAttempt(ctx, ip, at)
}

func (s *loginAttemptsDownStub) ReleaseLoginAttempt(ctx context.Context, id uint) error {
	if s.down {
		return errLoginAttemptsDown
	}
	return s.Storage.ReleaseLoginAttempt(ctx, id)
}

func newFallbackCore(t *testing.T) (*KeyorixCore, *loginAttemptsDownStub, *gorm.DB, func(time.Time)) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}, &models.AuditEvent{}))
	stub := &loginAttemptsDownStub{Storage: store.NewLocalStorage(db)}
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: stub, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	return c, stub, db, func(t time.Time) { c.now = func() time.Time { return t } }
}

// TestLoginBudgetFallback_StorageDownStillEnforcesTheLimit is the headline:
// with every LoginAttempt call failing, LoginMaxAttempts reserved failures
// from one IP must still refuse that IP (it used to be let through forever),
// a different IP stays allowed, and the window still expires.
func TestLoginBudgetFallback_StorageDownStillEnforcesTheLimit(t *testing.T) {
	t.Parallel()
	c, stub, _, setNow := newFallbackCore(t)
	ctx := context.Background()
	stub.down = true
	base := c.now()

	for i := 0; i < LoginMaxAttempts-1; i++ {
		c.ReserveLoginAttempt(ctx, "203.0.113.9")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.9"), "under the budget is allowed")
	c.RecordFailedLogin(ctx, "203.0.113.9")
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.9"),
		"storage down must not mean no limit: the in-memory fallback enforces the same budget")
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.9:4444"), "same canonical IP, different port")
	assert.False(t, c.IsLoginRateLimited(ctx, "198.51.100.1"), "another IP is unaffected")

	setNow(base.Add(LoginWindow + time.Minute))
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.9"), "fallback attempts age out with the same window")
}

// TestLoginBudgetFallback_ADeliveredLoginReturnsItsMemorySlot keeps #2936's
// "count failures only" during an outage: a reservation the fallback took is
// released by the same ReleaseLoginAttempt call a delivered login makes.
func TestLoginBudgetFallback_ADeliveredLoginReturnsItsMemorySlot(t *testing.T) {
	t.Parallel()
	c, stub, _, _ := newFallbackCore(t)
	ctx := context.Background()
	stub.down = true

	for i := 0; i < 3*LoginMaxAttempts; i++ {
		id, ok := c.ReserveLoginAttempt(ctx, "203.0.113.10")
		require.True(t, ok, "a fallback reservation is a real, releasable reservation")
		c.ReleaseLoginAttempt(ctx, id)
	}
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.10"), "released (delivered) attempts do not count")
}

// TestLoginBudgetFallback_RecoveredStorageIsAuthoritativeAgain: once storage is
// back, the stored budget decides again (memory is not merged into it, and a
// stored reservation is released through storage).
func TestLoginBudgetFallback_RecoveredStorageIsAuthoritativeAgain(t *testing.T) {
	t.Parallel()
	c, stub, db, _ := newFallbackCore(t)
	ctx := context.Background()

	stub.down = true
	c.RecordFailedLogin(ctx, "203.0.113.11")
	stub.down = false

	id, ok := c.ReserveLoginAttempt(ctx, "203.0.113.11")
	require.True(t, ok)
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&n).Error)
	assert.EqualValues(t, 1, n, "with storage back, the reservation is a stored row again")
	c.ReleaseLoginAttempt(ctx, id)
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&n).Error)
	assert.Zero(t, n)
	for i := 0; i < LoginMaxAttempts; i++ {
		c.RecordFailedLogin(ctx, "203.0.113.12")
	}
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.12"), "the stored budget is enforced as before")
}

// TestLoginBudgetFallback_NoFaultNoChange: with storage healthy nothing goes to
// memory, nothing is audited and the metric does not move.
func TestLoginBudgetFallback_NoFaultNoChange(t *testing.T) {
	c, _, db, _ := newFallbackCore(t)
	ctx := context.Background()
	before := testutil.ToFloat64(loginBudgetFallbackTotal)
	for i := 0; i < LoginMaxAttempts; i++ {
		c.RecordFailedLogin(ctx, "203.0.113.13")
	}
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.13"))
	assert.Zero(t, c.loginBudgetFallback().size(), "a healthy store must not populate the fallback")
	assert.Zero(t, auditEventsOfType(t, db, EventLoginBudgetFallback))
	assert.Equal(t, before, testutil.ToFloat64(loginBudgetFallbackTotal))
}

// TestLoginBudgetFallback_IsAuditedAndCounted: every fallback writes the error
// event and increments the metric.
func TestLoginBudgetFallback_IsAuditedAndCounted(t *testing.T) {
	c, stub, db, _ := newFallbackCore(t)
	ctx := context.Background()
	stub.down = true
	before := testutil.ToFloat64(loginBudgetFallbackTotal)

	c.RecordFailedLogin(ctx, "203.0.113.14")
	_, _ = c.ReserveLoginAttempt(ctx, "203.0.113.14")
	_ = c.IsLoginRateLimited(ctx, "203.0.113.14")

	assert.Equal(t, before+3, testutil.ToFloat64(loginBudgetFallbackTotal), "one per fallback")
	assert.EqualValues(t, 3, auditEventsOfType(t, db, EventLoginBudgetFallback), "one error event per fallback")
	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventLoginBudgetFallback).First(&ev).Error)
	require.NotNil(t, ev.Success)
	assert.False(t, *ev.Success, "an error event, not a success")
}

// TestLoginBudgetFallback_BoundedUnderManyDistinctIPs: spoofed or rotating
// source addresses cannot grow the fallback without bound.
func TestLoginBudgetFallback_BoundedUnderManyDistinctIPs(t *testing.T) {
	t.Parallel()
	f := newLoginFallbackLimiter(64)
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10_000; i++ {
		ip := "10." + itoa(i>>16&255) + "." + itoa(i>>8&255) + "." + itoa(i&255)
		f.reserve(ip, now)
	}
	assert.LessOrEqual(t, f.size(), 64, "the fallback holds at most its capacity of IPs")
	// The most recent IPs are the ones kept, and they still count.
	for i := 0; i < LoginMaxAttempts; i++ {
		f.reserve("192.0.2.200", now)
	}
	assert.GreaterOrEqual(t, f.count("192.0.2.200", now.Add(-LoginWindow), true), LoginMaxAttempts)
}

func auditEventsOfType(t *testing.T, db *gorm.DB, typ string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", typ).Count(&n).Error)
	return n
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}
