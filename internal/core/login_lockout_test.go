package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const lockoutTestPassword = "Secret#Pass123"

// newLockoutTestCore builds a real-SQLite core with login lockout enabled
// (3 attempts / 15m window / 5m base / 1h max) and a user "alice". The returned
// clock pointer lets a test advance time to cross the cooldown.
func newLockoutTestCore(t *testing.T, enabled bool) (*KeyorixCore, *gorm.DB, *time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// One connection: ":memory:" is per-connection, and the expired-OTP audit write
	// runs in a goroutine (goSafe) that must see the same database as the test.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))
	hash, err := bcrypt.GenerateFromPassword([]byte(lockoutTestPassword), int(bcryptCost.Load()))
	require.NoError(t, err)
	// UsernameFolded is what GetUserByUsername actually queries (#1642); "alice" is already its own folded form.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", PasswordHash: string(hash), AccountState: AccountActive}).Error)

	clock := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return clock }, passwordPolicy: DefaultPasswordPolicy()}
	if enabled {
		c.SetLoginLockoutPolicy(LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: 15 * time.Minute, BaseCooldown: 5 * time.Minute, MaxCooldown: time.Hour})
	}
	return c, db, &clock
}

func login(c *KeyorixCore, password string) error {
	_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: password})
	return err
}

func reloadUser(t *testing.T, db *gorm.DB) *models.User {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	return &u
}

func TestLoginLockout_LocksAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	c, db, _ := newLockoutTestCore(t, true)

	// 3 wrong-password attempts → still "invalid credentials", then locked.
	for range 3 {
		require.ErrorContains(t, login(c, "wrong"), "invalid credentials")
	}
	u := reloadUser(t, db)
	require.NotNil(t, u.LoginLockedUntil, "account should be locked after 3 failures")
	assert.Equal(t, 1, u.LoginLockoutCount)

	// A correct password is still refused while locked.
	require.ErrorContains(t, login(c, lockoutTestPassword), "temporarily locked")
}

func TestLoginLockout_ExpiryThenExponentialBackoff(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)

	for range 3 {
		_ = login(c, "wrong")
	}
	first := reloadUser(t, db)
	require.NotNil(t, first.LoginLockedUntil)
	assert.Equal(t, (*clock).Add(5*time.Minute), first.LoginLockedUntil.UTC(), "first lockout = base cooldown")

	// Advance past the cooldown → correct password succeeds and clears the state.
	*clock = clock.Add(6 * time.Minute)
	require.NoError(t, login(c, lockoutTestPassword))
	u := reloadUser(t, db)
	assert.Nil(t, u.LoginLockedUntil)
	assert.Equal(t, 0, u.FailedLoginAttempts)
	assert.Equal(t, 0, u.LoginLockoutCount, "a successful login resets the backoff counter")
}

func TestLoginLockout_BackoffGrowsAcrossLockouts(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)
	// Don't let a successful login reset the counter between lockouts: lock, wait out
	// the cooldown, then lock again — the 2nd cooldown should be 2× the first.
	for range 3 {
		_ = login(c, "wrong")
	}
	assert.Equal(t, (*clock).Add(5*time.Minute), reloadUser(t, db).LoginLockedUntil.UTC())

	*clock = clock.Add(6 * time.Minute) // lock expired, but no successful login
	for range 3 {
		_ = login(c, "wrong")
	}
	u := reloadUser(t, db)
	assert.Equal(t, 2, u.LoginLockoutCount)
	assert.Equal(t, (*clock).Add(10*time.Minute), u.LoginLockedUntil.UTC(), "second lockout = 2× base")
}

func TestLoginLockout_WindowResetsStaleFailures(t *testing.T) {
	t.Parallel()
	c, db, clock := newLockoutTestCore(t, true)
	_ = login(c, "wrong")
	_ = login(c, "wrong") // 2 failures, under the threshold

	*clock = clock.Add(20 * time.Minute) // past the 15m window
	_ = login(c, "wrong")                // stale failures dropped → this is failure #1
	u := reloadUser(t, db)
	assert.Equal(t, 1, u.FailedLoginAttempts)
	assert.Nil(t, u.LoginLockedUntil, "stale failures shouldn't accumulate into a lock")
}

func TestLoginLockout_SuccessResetsCounter(t *testing.T) {
	t.Parallel()
	c, db, _ := newLockoutTestCore(t, true)
	_ = login(c, "wrong")
	_ = login(c, "wrong")
	require.NoError(t, login(c, lockoutTestPassword))
	assert.Equal(t, 0, reloadUser(t, db).FailedLoginAttempts)
}

func TestLoginLockout_UnlockUserClearsState(t *testing.T) {
	t.Parallel()
	c, db, _ := newLockoutTestCore(t, true)
	for range 3 {
		_ = login(c, "wrong")
	}
	require.NotNil(t, reloadUser(t, db).LoginLockedUntil)

	require.NoError(t, c.UnlockUser(context.Background(), 99, 1))
	u := reloadUser(t, db)
	assert.Nil(t, u.LoginLockedUntil)
	assert.Equal(t, 0, u.LoginLockoutCount)
	require.NoError(t, login(c, lockoutTestPassword), "login works again after unlock")
}

func TestLoginLockout_DisabledNeverLocks(t *testing.T) {
	t.Parallel()
	c, db, _ := newLockoutTestCore(t, false)
	for range 10 {
		_ = login(c, "wrong")
	}
	assert.Nil(t, reloadUser(t, db).LoginLockedUntil, "no lockout when the policy is disabled")
	require.NoError(t, login(c, lockoutTestPassword))
}
