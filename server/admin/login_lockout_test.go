package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	storelib "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// newClearLockoutTestDB is one in-memory database with the tables
// performClearLoginLockout touches, a single connection, user 1 "alice", a
// full IP budget for 203.0.113.9 (the IP to clear) and some attempts from an
// unrelated IP that must survive.
func newClearLockoutTestDB(t *testing.T) (*gorm.DB, *storelib.LocalStorage) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	// Unique DB, one connection, closed on cleanup (#3009's fixture rule).
	db := sqlitetest.OpenWithDialector(t, "clear_lockout_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.LoginAttempt{}, &models.AuditEvent{}, &models.AuditCheckpoint{}))

	locked := time.Now().Add(time.Hour)
	last := time.Now()
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "alice", UsernameFolded: "alice", Email: "alice@example.com", EmailFolded: "alice@example.com",
		PasswordHash: "x", AccountState: "active", IsActive: true,
		FailedLoginAttempts: 5, LastFailedLoginAt: &last, LoginLockedUntil: &locked, LoginLockoutCount: 2,
	}).Error)

	st := storelib.NewLocalStorage(db)
	for range core.LoginMaxAttempts {
		require.NoError(t, st.RecordLoginAttempt(context.Background(), "203.0.113.9", time.Now()))
	}
	for range 3 {
		require.NoError(t, st.RecordLoginAttempt(context.Background(), "198.51.100.7", time.Now()))
	}
	return db, st
}

func countAttempts(t *testing.T, db *gorm.DB, ip string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", ip).Count(&n).Error)
	return n
}

// TestClearLoginLockout_ClearsTheIPBudgetAndIsAudited is #2936's "the clear
// command works and is audited": the IP that was over budget is not rate
// limited afterwards, an unrelated IP's attempts are untouched, and an
// admin_cli audit event names what was cleared.
func TestClearLoginLockout_ClearsTheIPBudgetAndIsAudited(t *testing.T) {
	db, st := newClearLockoutTestDB(t)
	ctx := context.Background()
	c := core.NewKeyorixCore(st)
	require.True(t, c.IsLoginRateLimited(ctx, "203.0.113.9"), "setup: the IP must start over budget")

	// A non-canonical spelling of the same address (with a port) must clear the
	// same bucket the handlers count under.
	summary, err := performClearLoginLockout(ctx, db, st, "203.0.113.9:51234", "")
	require.NoError(t, err)
	assert.Contains(t, summary, "cleared 10 counted login attempt(s) for IP 203.0.113.9")

	assert.Zero(t, countAttempts(t, db, "203.0.113.9"))
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.9"), "the cleared IP must be able to log in again")
	assert.EqualValues(t, 3, countAttempts(t, db, "198.51.100.7"), "another IP's budget must not be touched")

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, 5, u.FailedLoginAttempts, "--ip alone must not touch any account's lockout")

	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "admin.login_lockout_cleared").First(&ev).Error)
	assert.Equal(t, adminActorType, ev.ActorType)
	assert.Contains(t, ev.Description, "203.0.113.9")
}

// TestClearLoginLockout_ClearsTheAccountLockoutAndIsAudited: --user resets the
// per-account counters (the same four columns core.UnlockUser resets) and the
// audit event is attributed to that user.
func TestClearLoginLockout_ClearsTheAccountLockoutAndIsAudited(t *testing.T) {
	db, st := newClearLockoutTestDB(t)
	ctx := context.Background()

	_, err := performClearLoginLockout(ctx, db, st, "", "alice@example.com")
	require.NoError(t, err)

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Zero(t, u.FailedLoginAttempts)
	assert.Nil(t, u.LastFailedLoginAt)
	assert.Nil(t, u.LoginLockedUntil)
	assert.Zero(t, u.LoginLockoutCount)
	assert.EqualValues(t, core.LoginMaxAttempts, countAttempts(t, db, "203.0.113.9"), "--user alone must not touch any IP budget")

	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "admin.login_lockout_cleared").First(&ev).Error)
	require.NotNil(t, ev.UserID)
	assert.EqualValues(t, 1, *ev.UserID)
	assert.Equal(t, adminActorType, ev.ActorType)
}

// TestClearLoginLockout_RejectsBadInputBeforeChangingAnything: an invalid IP
// or an unknown user fails the whole command with nothing changed and nothing
// audited -- a typo in one half must not leave the other half applied.
func TestClearLoginLockout_RejectsBadInputBeforeChangingAnything(t *testing.T) {
	db, st := newClearLockoutTestDB(t)
	ctx := context.Background()

	_, err := performClearLoginLockout(ctx, db, st, "not-an-ip", "alice@example.com")
	require.Error(t, err)
	_, err = performClearLoginLockout(ctx, db, st, "203.0.113.9", "nobody@example.com")
	require.Error(t, err)

	assert.EqualValues(t, core.LoginMaxAttempts, countAttempts(t, db, "203.0.113.9"))
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, 5, u.FailedLoginAttempts)
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "admin.login_lockout_cleared").Count(&n).Error)
	assert.Zero(t, n)
}

// auditFaultStorage fails LogAuditEvent (and/or UpdateLoginLockoutState) so the
// ordering of clear vs audit can be observed.
type auditFaultStorage struct {
	*storelib.LocalStorage
	failAudit  bool
	failUpdate bool
}

func (s *auditFaultStorage) LogAuditEvent(ctx context.Context, ev *models.AuditEvent) error {
	if s.failAudit {
		return errors.New("injected audit fault")
	}
	return s.LocalStorage.LogAuditEvent(ctx, ev)
}

func (s *auditFaultStorage) UpdateLoginLockoutState(ctx context.Context, id uint, a int, b, c *time.Time, d int) error {
	if s.failUpdate {
		return errors.New("injected lockout-update fault")
	}
	return s.LocalStorage.UpdateLoginLockoutState(ctx, id, a, b, c, d)
}

// TestClearLoginLockout_AuditWriteFailureClearsNothing (#2956 follow-up): the
// audit is written BEFORE anything is cleared, so a failing audit write leaves
// both the IP budget and the account lockout in place and fails the command.
// Before the fix the clear ran first and the operator was told "cleared -- but
// the audit event could not be written": an unaudited lift of a lockout.
func TestClearLoginLockout_AuditWriteFailureClearsNothing(t *testing.T) {
	db, st := newClearLockoutTestDB(t)
	faulty := &auditFaultStorage{LocalStorage: st, failAudit: true}

	_, err := performClearLoginLockout(context.Background(), db, faulty, "203.0.113.9", "alice@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nothing was cleared")

	assert.EqualValues(t, core.LoginMaxAttempts, countAttempts(t, db, "203.0.113.9"), "IP budget must survive an audit failure")
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, 5, u.FailedLoginAttempts, "account lockout must survive an audit failure")
	assert.NotNil(t, u.LoginLockedUntil)
}

// TestClearLoginLockout_ClearFailureIsAuditedAsFailed: the intent event is
// already in the chain when the account clear faults, so a failure event must
// follow it -- the chain must not claim a lift that did not happen.
func TestClearLoginLockout_ClearFailureIsAuditedAsFailed(t *testing.T) {
	db, st := newClearLockoutTestDB(t)
	faulty := &auditFaultStorage{LocalStorage: st, failUpdate: true}

	_, err := performClearLoginLockout(context.Background(), db, faulty, "", "alice@example.com")
	require.Error(t, err)

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, 5, u.FailedLoginAttempts, "the faulted clear must not have applied")

	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", "admin.login_lockout_clear_failed").First(&ev).Error)
	require.NotNil(t, ev.Success)
	assert.False(t, *ev.Success)
	assert.Contains(t, ev.Description, "injected lockout-update fault")
}
