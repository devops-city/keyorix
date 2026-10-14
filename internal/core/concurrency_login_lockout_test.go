package core_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_LoginLockout_NoLostIncrements is the per-account lockout invariant under
// load: the failed-attempt counter must not lose increments when many wrong-password
// logins race for one account, so the account locks at the threshold and a single burst
// produces exactly one lockout (not several from a check-then-act re-trip). recordFailedLogin
// serializes the read-increment-write (process mutex + a Postgres FOR UPDATE row lock via
// LockUserForUpdate); before that fix two concurrent failures could both read the same count
// and write back the same value, losing an increment and letting an account exceed its
// guess budget. This drives many concurrent wrong logins against a real file-backed SQLite
// and asserts the account ends up locked exactly once.
func TestConcurrency_LoginLockout_NoLostIncrements(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "lockout.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))

	const password = "Secret#Pass123"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost) // MinCost: keep the race tight
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", PasswordHash: string(hash), AccountState: core.AccountActive}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	const maxAttempts = 5
	c.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: maxAttempts,
		Window: 15 * time.Minute, BaseCooldown: 5 * time.Minute, MaxCooldown: time.Hour,
	})

	const attackers = 40 // many more than the threshold
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range attackers {
		wg.Go(func() {
			<-start
			// Wrong password every time → each call reaches recordFailedLogin (unless the
			// account is already locked, in which case the gate rejects it first).
			_, _, _ = c.Login(context.Background(), &core.LoginRequest{Username: "alice", Password: "wrong"})
		})
	}
	close(start) // release all attackers at once
	wg.Wait()

	// The account must be locked, exactly once — a lost increment would push the lock
	// later (or, combined with a check-then-act re-trip, lock several times and inflate
	// the backoff). The counter resets to 0 when the lock trips, and the burst's
	// stragglers short-circuit on the active lock rather than counting.
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	require.NotNil(t, u.LoginLockedUntil, "account must be locked after a burst past the threshold")
	assert.True(t, time.Now().Before(*u.LoginLockedUntil), "lock must still be active")
	assert.Equal(t, 1, u.LoginLockoutCount, "a single burst must lock exactly once, not re-trip the backoff")
	assert.Equal(t, 0, u.FailedLoginAttempts, "the window counter resets when the lock trips")

	// Exactly one account.locked event was written (the lock is audited once).
	var lockEvents int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", core.EventAccountLocked).Count(&lockEvents).Error)
	assert.Equal(t, int64(1), lockEvents, "the lockout must be audited exactly once")

	// And a correct password is now refused while locked (the gate holds).
	_, _, err = c.Login(context.Background(), &core.LoginRequest{Username: "alice", Password: password})
	require.ErrorContains(t, err, "locked")
}
