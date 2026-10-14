package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// OTP-EXPIRY-1: a one-time password carries an expiry; once it has passed, login is
// refused exactly like a wrong password, audited, and counted toward the lockout.

// setOTPExpiry marks alice's current password as a one-time password expiring at t.
func setOTPExpiry(t *testing.T, db *gorm.DB, at time.Time) {
	t.Helper()
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).
		Updates(map[string]any{"one_time_password_expires_at": at, "account_state": AccountPasswordResetRequired}).Error)
}

func countAudit(t *testing.T, db *gorm.DB, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

func TestOneTimePassword_ValidBeforeExpiry(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)
	setOTPExpiry(t, db, clock.Add(time.Hour))

	require.NoError(t, login(c, lockoutTestPassword), "an unexpired one-time password logs in (into the restricted state)")
	assert.Zero(t, countAudit(t, db, EventOneTimePasswordExpired))
}

func TestOneTimePassword_ExpiredIsRefusedLikeAWrongPassword(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)
	setOTPExpiry(t, db, clock.Add(time.Hour))
	*clock = clock.Add(time.Hour + time.Second)

	expiredErr := login(c, lockoutTestPassword)
	require.Error(t, expiredErr, "the correct but expired one-time password must be refused")
	wrongErr := login(c, "not-the-password")
	require.Error(t, wrongErr)

	// No new oracle: the caller-visible error is byte-for-byte the wrong-password one.
	assert.Equal(t, wrongErr.Error(), expiredErr.Error())
	assert.Equal(t, "invalid credentials", expiredErr.Error())
	// ...but the server records why, once per expired attempt (the write is async).
	DrainBackgroundGoroutines()
	assert.EqualValues(t, 1, countAudit(t, db, EventOneTimePasswordExpired))
}

// The expired branch must not do the audit insert on the login path: a synchronous
// hash-chained write there only (the wrong-password branch has none) would make an
// expired one-time password measurably slower than a wrong one.
func TestOneTimePassword_ExpiredAuditDoesNotBlockTheLoginPath(t *testing.T) {
	c, db, clock := newLockoutTestCore(t, true)
	setOTPExpiry(t, db, clock.Add(time.Hour))
	*clock = clock.Add(time.Hour + time.Second)

	release := make(chan struct{})
	require.NoError(t, db.Callback().Create().Before("gorm:begin_transaction").
		Register("test:block_otp_expired_audit", func(tx *gorm.DB) {
			if tx.Statement.Table == "audit_events" {
				<-release
			}
		}))

	done := make(chan error, 1)
	go func() { done <- login(c, lockoutTestPassword) }()
	select {
	case err := <-done:
		require.EqualError(t, err, "invalid credentials")
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("the expired-OTP refusal waited for its audit write: it is synchronous on the login path")
	}
	close(release)
	DrainBackgroundGoroutines()
	assert.EqualValues(t, 1, countAudit(t, db, EventOneTimePasswordExpired))
}

func TestOneTimePassword_ExpiredAttemptsCountTowardLockout(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true) // 3 attempts
	setOTPExpiry(t, db, clock.Add(time.Minute))
	*clock = clock.Add(2 * time.Minute)

	for range 3 {
		require.EqualError(t, login(c, lockoutTestPassword), "invalid credentials")
	}
	u := reloadUser(t, db)
	require.NotNil(t, u.LoginLockedUntil, "three expired-OTP attempts lock the account like three wrong passwords")
	assert.Equal(t, 1, u.LoginLockoutCount)
	assert.ErrorContains(t, login(c, lockoutTestPassword), "temporarily locked")
}

func TestOneTimePassword_RefusedAtTheExpiryInstant(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)
	setOTPExpiry(t, db, *clock) // expires exactly now

	assert.EqualError(t, login(c, lockoutTestPassword), "invalid credentials", "expires_at is the first instant it no longer works")
}

func TestOneTimePassword_OrdinaryPasswordNeverExpires(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)
	*clock = clock.Add(10 * 365 * 24 * time.Hour)

	require.NoError(t, login(c, lockoutTestPassword), "a password with no recorded OTP expiry is unaffected")
	assert.Zero(t, countAudit(t, db, EventOneTimePasswordExpired))
}

func TestOneTimePassword_NewPasswordClearsTheExpiry(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)
	setOTPExpiry(t, db, clock.Add(time.Hour))

	u := reloadUser(t, db)
	require.NoError(t, c.applyNewPassword(context.Background(), u, "Brand#New-Passw0rd-99"))

	assert.Nil(t, reloadUser(t, db).OneTimePasswordExpiresAt, "the expiry belongs to the one-time password and must not outlive it")
	*clock = clock.Add(100 * 24 * time.Hour)
	_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: "Brand#New-Passw0rd-99"})
	require.NoError(t, err, "the user's chosen password works long after the one-time password's expiry")
}

func TestCreateUserWithOneTimePassword_RecordsExpiry(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()

	for name, tc := range map[string]struct {
		ttl  time.Duration // 0 = leave unset
		want time.Duration
	}{
		"default is 72h":         {ttl: 0, want: 72 * time.Hour},
		"configured value":       {ttl: 6 * time.Hour, want: 6 * time.Hour},
		"non-positive means 72h": {ttl: -time.Hour, want: 72 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			ms := new(MockStorage)
			c := NewKeyorixCore(ms)
			fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			c.now = func() time.Time { return fixed }
			if tc.ttl != 0 {
				c.SetOneTimePasswordExpiry(tc.ttl)
			}
			anyAudit(ms)
			ms.On("GetUserByUsername", ctx, "dana").Return(nil, assertNotFoundErr())
			ms.On("GetUserByEmail", ctx, "dana@acme.io").Return(nil, assertNotFoundErr())
			var captured *models.User
			ms.On("CreateUser", ctx, mock.Anything).Run(func(args mock.Arguments) { captured = args.Get(1).(*models.User) }).
				Return(&models.User{ID: 11, Username: "dana", Email: "dana@acme.io"}, nil)
			ms.On("AddPasswordHistory", ctx, uint(11), mock.AnythingOfType("string"), mock.Anything).Return(nil)
			ms.On("GetRoleByName", ctx, "system_viewer").Return(nil, assertNotFoundErr())

			_, otp, err := c.CreateUserWithOneTimePassword(ctx, &CreateUserRequest{Username: "dana", Email: "dana@acme.io", DisplayName: "Dana"}, 7)
			require.NoError(t, err)

			want := fixed.Add(tc.want)
			assert.True(t, otp.ExpiresAt.Equal(want), "result reports the expiry: got %s want %s", otp.ExpiresAt, want)
			require.NotNil(t, captured)
			require.NotNil(t, captured.OneTimePasswordExpiresAt, "the expiry is persisted in the same insert as the password")
			assert.True(t, captured.OneTimePasswordExpiresAt.Equal(want))
		})
	}
}
