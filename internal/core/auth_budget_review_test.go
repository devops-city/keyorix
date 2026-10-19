// auth_budget_review_test.go — the two review findings raised on #3023 (at
// 670e1163), #3029 (at bf0ff420) and #3032 (MERGE-MASTER, CHANGES REQUESTED):
//
//  1. budgetLimited failed OPEN when only the COUNT query failed: memory held
//     only attempts whose stored WRITE failed, so with the count down and the
//     insert up nothing ever reached memory and the budget never bound
//     (login, password_reset, sso_begin). loginAttemptsDownStub fails every
//     method together, so it could not show this; countOnlyDownStub fails the
//     count alone.
//  2. a fallback reservation id (a per-process counter with authFallbackIDBit
//     set) was persisted into the shared mfa_challenges / web_authn_sessions
//     login_attempt_id columns: the row could not be read back (SQLite stores
//     it negative), and a release on another replica (or after a restart)
//     refunded an unrelated in-memory reservation there.
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// countOnlyDownStub fails CountRecentLoginAttempts while down is set; every
// write keeps working. The finding's exact shape.
type countOnlyDownStub struct {
	inner corestorage.Storage
	down  bool
}

func (s *countOnlyDownStub) CountRecentLoginAttempts(next corestorage.Storage, ctx context.Context, ip string, since time.Time) (int64, error) {
	if s.down {
		return 0, errLoginAttemptsDown
	}
	return next.CountRecentLoginAttempts(ctx, ip, since)
}

// wrap returns inner decorated with countOnlyDownStub's overrides.
func (s *countOnlyDownStub) wrap(inner corestorage.Storage) corestorage.Storage {
	return hooked(inner, &storeHooks{
		CountRecentLoginAttempts: s.CountRecentLoginAttempts,
	})
}

// store returns s.inner decorated with countOnlyDownStub's overrides.
func (s *countOnlyDownStub) store() corestorage.Storage { return s.wrap(s.inner) }

func newCountOnlyDownCore(t *testing.T) (*KeyorixCore, *countOnlyDownStub, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}, &models.AuditEvent{}))
	stub := &countOnlyDownStub{inner: store.NewLocalStorage(db)}
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: stub.store(), now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	return c, stub, db
}

// TestAuthBudget_CountOnlyFailureStillBinds: with the COUNT failing and every
// write succeeding, each per-IP budget must still refuse once the fallback
// limit's worth of attempts has been made, exactly as it does when the writes
// fail too. Before the fix: 0 of 100 attempts limited.
func TestAuthBudget_CountOnlyFailureStillBinds(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		budget  authBudget
		limited func(*KeyorixCore, string) bool
		attempt func(*KeyorixCore, string)
	}{
		{"login/reserve", loginBudget,
			func(c *KeyorixCore, ip string) bool { return c.IsLoginRateLimited(ctx, ip) },
			func(c *KeyorixCore, ip string) { _, _ = c.ReserveLoginAttempt(ctx, ip) }},
		{"login/record", loginBudget,
			func(c *KeyorixCore, ip string) bool { return c.IsLoginRateLimited(ctx, ip) },
			func(c *KeyorixCore, ip string) { c.RecordFailedLogin(ctx, ip) }},
		{"password_reset", passwordResetBudget,
			func(c *KeyorixCore, ip string) bool { return c.IsPasswordResetRateLimited(ctx, ip) },
			func(c *KeyorixCore, ip string) { c.RecordPasswordResetAttempt(ctx, ip) }},
		{"sso_begin", ssoBeginBudget,
			func(c *KeyorixCore, ip string) bool { return c.IsSSOBeginRateLimited(ctx, ip) },
			func(c *KeyorixCore, ip string) { c.RecordSSOBeginAttempt(ctx, ip) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, stub, db := newCountOnlyDownCore(t)
			stub.down = true
			const ip = "198.51.100.7"
			allowed, refused := 0, 0
			for range 100 {
				if tc.limited(c, ip) {
					refused++
					continue
				}
				allowed++
				tc.attempt(c, ip)
			}
			var stored int64
			require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&stored).Error)
			require.EqualValues(t, allowed, stored, "calibration: every allowed attempt's write succeeded (only the count is down)")
			assert.Equal(t, c.fallbackLimit(tc.budget), allowed,
				"with only the COUNT failing the budget must still bind at its fallback limit (allowed %d, refused %d)", allowed, refused)
			assert.Positive(t, refused, "the budget failed open: no attempt was ever refused")
		})
	}
}

// TestAuthBudget_CountOnlyFailure_RecoveryDoesNotDoubleCount: the attempts
// mirrored into memory while the count was down were ALSO stored, so once the
// count works again they must not be counted twice (memory + stored) against
// the normal limit.
func TestAuthBudget_CountOnlyFailure_RecoveryDoesNotDoubleCount(t *testing.T) {
	ctx := context.Background()
	c, stub, _ := newCountOnlyDownCore(t)
	const ip = "198.51.100.8"
	stub.down = true
	for range 3 {
		require.False(t, c.IsLoginRateLimited(ctx, ip))
		_, _ = c.ReserveLoginAttempt(ctx, ip)
	}
	stub.down = false
	// 3 stored attempts; the normal limit is LoginMaxAttempts. Counted once,
	// the IP has LoginMaxAttempts-3 attempts left.
	left := 0
	for range LoginMaxAttempts {
		if c.IsLoginRateLimited(ctx, ip) {
			break
		}
		left++
		_, _ = c.ReserveLoginAttempt(ctx, ip)
	}
	assert.Equal(t, LoginMaxAttempts-3, left, "attempts stored while the count was down must count exactly once after recovery")
}

func newSlotPersistenceCore(t *testing.T) (*KeyorixCore, *loginAttemptsDownStub, *gorm.DB) {
	t.Helper()
	c, stub, db, _ := newFallbackCore(t)
	require.NoError(t, db.AutoMigrate(&models.MFAChallenge{}, &models.WebAuthnSession{}))
	return c, stub, db
}

// TestFallbackLoginSlot_IsNeverPersistedToSharedRows: a reservation taken by
// the in-memory fallback is meaningful only inside this process. The ceremony
// rows that hold a slot are shared by every replica and outlive the process,
// so a fallback id must never be written there (and, since it exceeds
// MaxInt64, could not be stored in a Postgres bigint anyway). A stored id is
// still persisted (positive control).
func TestFallbackLoginSlot_IsNeverPersistedToSharedRows(t *testing.T) {
	ctx := context.Background()
	for _, storageDown := range []bool{true, false} {
		t.Run(fmt.Sprintf("reserve_storage_down=%v", storageDown), func(t *testing.T) {
			c, stub, db := newSlotPersistenceCore(t)
			stub.down = storageDown
			id, ok := c.ReserveLoginAttempt(ctx, "203.0.113.9")
			require.True(t, ok)
			require.Equal(t, storageDown, id&authFallbackIDBit != 0, "calibration: the id comes from the fallback exactly when storage is down")
			stub.down = false

			_, err := c.CreateMFAChallengeHoldingLoginSlot(ctx, 1, &id)
			require.NoError(t, err)
			_, err = c.storeWebAuthnSessionHoldingLoginSlot(ctx, 1, "login", nil, &id)
			require.NoError(t, err)

			var ch models.MFAChallenge
			require.NoError(t, db.First(&ch).Error)
			var ws models.WebAuthnSession
			require.NoError(t, db.First(&ws).Error)
			if storageDown {
				assert.Nil(t, ch.LoginAttemptID, "mfa_challenges.login_attempt_id must not hold a per-process fallback id")
				assert.Nil(t, ws.LoginAttemptID, "web_authn_sessions.login_attempt_id must not hold a per-process fallback id")
				return
			}
			require.NotNil(t, ch.LoginAttemptID, "a stored reservation is still bound to the challenge")
			assert.Equal(t, id, *ch.LoginAttemptID)
			require.NotNil(t, ws.LoginAttemptID, "a stored reservation is still bound to the ceremony row")
			assert.Equal(t, id, *ws.LoginAttemptID)
		})
	}
}

// TestFallbackLoginSlot_ReleaseOnAnotherReplicaRefundsNothingThere is the
// harm the finding names: replica A's fallback id, read back from the shared
// challenge row by replica B (which consumes the challenge and releases the
// slot it finds there), must not refund B's own, unrelated, fallback
// reservation that happens to carry the same per-process counter value.
func TestFallbackLoginSlot_ReleaseOnAnotherReplicaRefundsNothingThere(t *testing.T) {
	ctx := context.Background()
	a, stubA, db := newSlotPersistenceCore(t)
	b := &KeyorixCore{storage: stubA.store(), now: a.now, passwordPolicy: DefaultPasswordPolicy()}

	stubA.down = true
	idA, _ := a.ReserveLoginAttempt(ctx, "203.0.113.10") // A's first fallback reservation
	idB, _ := b.ReserveLoginAttempt(ctx, "192.0.2.77")   // B's first, for an unrelated IP
	require.Equal(t, idA, idB, "calibration: two processes' first fallback ids collide")
	stubA.down = false

	_, err := a.CreateMFAChallengeHoldingLoginSlot(ctx, 1, &idA)
	require.NoError(t, err)
	var ch models.MFAChallenge
	require.NoError(t, db.First(&ch).Error)

	since := b.now().Add(-LoginWindow)
	before := b.authBudgetFallback(loginBudget).count("192.0.2.77", since, true)
	require.Equal(t, 1, before, "calibration: B's own fallback reservation is counted before the release")
	if ch.LoginAttemptID != nil {
		b.ReleaseLoginAttempt(ctx, *ch.LoginAttemptID) // what B's completed second factor does
	}
	after := b.authBudgetFallback(loginBudget).count("192.0.2.77", since, true)
	assert.Equal(t, 1, after, "replica B refunded an unrelated IP's reservation using replica A's fallback id")
}

// TestAuthBudget_CountOnlyFailure_MirrorAgesOutWithTheWindow: the mirrored
// attempts are bound by the same window, so an IP refused on them is allowed
// again once they age out, as with every other fallback attempt.
func TestAuthBudget_CountOnlyFailure_MirrorAgesOutWithTheWindow(t *testing.T) {
	ctx := context.Background()
	c, stub, _ := newCountOnlyDownCore(t)
	stub.down = true
	const ip = "198.51.100.9"
	base := c.now()
	for range LoginMaxAttempts {
		require.False(t, c.IsLoginRateLimited(ctx, ip))
		c.RecordFailedLogin(ctx, ip)
	}
	require.True(t, c.IsLoginRateLimited(ctx, ip))
	later := base.Add(LoginWindow + time.Minute)
	c.now = func() time.Time { return later }
	assert.False(t, c.IsLoginRateLimited(ctx, ip), "mirrored attempts age out with the window")
}

// TestAuthBudget_CountOnlyFailure_DeliveredLoginReleasesItsMirror keeps
// #2936's "count failures only" while the count is down: a delivered login's
// release refunds the stored row AND its mirror, so successful logins do not
// fill the in-memory budget.
func TestAuthBudget_CountOnlyFailure_DeliveredLoginReleasesItsMirror(t *testing.T) {
	ctx := context.Background()
	c, stub, db := newCountOnlyDownCore(t)
	const ip = "198.51.100.10"
	stub.down = true
	for i := range 2 * LoginMaxAttempts {
		require.False(t, c.IsLoginRateLimited(ctx, ip), "delivered login %d must not be refused", i+1)
		id, ok := c.ReserveLoginAttempt(ctx, ip)
		require.True(t, ok)
		require.Zero(t, id&authFallbackIDBit, "calibration: the write works, so the id is a stored one")
		c.ReleaseLoginAttempt(ctx, id)
	}
	var stored int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&stored).Error)
	assert.Zero(t, stored)
	assert.Zero(t, c.authBudgetFallback(loginBudget).count(ip, c.now().Add(-LoginWindow), true), "every mirror went with its stored row")
}
