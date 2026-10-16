// account_current_password_lockout_test.go — AUTH-PW-BUDGET: POST
// /auth/change-password and PUT /auth/profile (email change) check the caller's
// current password. They used a bare bcrypt comparison, so a stolen session could
// guess the password with no bound. They now go through verifyCurrentPassword:
// the same per-account lockout counter a password login feeds, with the same
// semantics (counted on a wrong password, refused while locked even with the
// right one, re-checked after a match, cleared only once the change committed
// and only where the password is full authentication).
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	curPwOld = "Current#Passw0rd!x"
	curPwNew = "Brandnew#Passw0rd!y"
)

// newCurrentPasswordCore is a real-SQLite core (full schema) with one active
// account, alice (ID 1, no second factor), and the login lockout at 3 attempts.
func newCurrentPasswordCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // ":memory:" is per connection
	require.NoError(t, kxstorage.MigrateExisting(db))
	hash, err := bcrypt.GenerateFromPassword([]byte(curPwOld), int(bcryptCost.Load()))
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice",
		Email: "alice@old.example", EmailFolded: "alice@old.example",
		PasswordHash: string(hash), AccountState: AccountActive, IsActive: true}).Error)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetLoginLockoutPolicy(postVerdictParityPolicy) // 3 attempts / 1h window
	return c, db
}

// currentPasswordOps are the two endpoints' core calls, each changing something
// observable only when the current password was accepted.
var currentPasswordOps = []struct {
	name    string
	call    func(c *KeyorixCore, password string) error
	changed func(t *testing.T, db *gorm.DB) bool
}{
	{
		name: "change_password",
		call: func(c *KeyorixCore, password string) error {
			return c.ChangePassword(context.Background(), 1, password, curPwNew, "")
		},
		changed: func(t *testing.T, db *gorm.DB) bool {
			var u models.User
			require.NoError(t, db.First(&u, 1).Error)
			return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(curPwNew)) == nil
		},
	},
	{
		name: "email_change",
		call: func(c *KeyorixCore, password string) error {
			_, err := c.UpdateOwnProfile(context.Background(), 1, "", "alice@new.example", password)
			return err
		},
		changed: func(t *testing.T, db *gorm.DB) bool {
			var u models.User
			require.NoError(t, db.First(&u, 1).Error)
			return u.Email == "alice@new.example"
		},
	},
}

// Wrong current passwords lock the account exactly as wrong login passwords do,
// and the lock then refuses the RIGHT password on this endpoint and on login.
func TestCurrentPassword_WrongGuessesLockTheAccount(t *testing.T) {
	t.Parallel()
	for _, op := range currentPasswordOps {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			c, db := newCurrentPasswordCore(t)
			for i := range postVerdictParityPolicy.MaxAttempts {
				err := op.call(c, "wrong-guess")
				require.ErrorIs(t, err, ErrIncorrectCurrentPassword, "guess %d", i+1)
			}
			st := readLockoutState(t, db, 1)
			require.True(t, st.Locked, "MaxAttempts wrong current passwords must lock the account like wrong logins: %+v", st)

			err := op.call(c, curPwOld)
			require.ErrorIs(t, err, ErrIncorrectCurrentPassword, "a locked account refuses even the correct password, answered like a wrong one")
			assert.False(t, op.changed(t, db), "nothing may change while the account is locked")

			_, _, lerr := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: curPwOld})
			require.Error(t, lerr)
			assert.Contains(t, lerr.Error(), "locked", "the lock is the login's lock: one counter")
		})
	}
}

// One counter: failed logins and failed current-password checks add up.
func TestCurrentPassword_SharesTheLoginCounter(t *testing.T) {
	t.Parallel()
	for _, op := range currentPasswordOps {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			c, db := newCurrentPasswordCore(t)
			for range postVerdictParityPolicy.MaxAttempts - 1 {
				_, _, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: "wrong-guess"})
				require.Error(t, err)
			}
			require.False(t, readLockoutState(t, db, 1).Locked)
			require.ErrorIs(t, op.call(c, "wrong-guess"), ErrIncorrectCurrentPassword)
			assert.True(t, readLockoutState(t, db, 1).Locked, "threshold-1 failed logins plus one failed current-password check must lock")
		})
	}
}

// Equivalence: a correct password still works, and (no second factor) resets the
// counter like a delivered password login.
func TestCurrentPassword_CorrectPasswordWorksAndClears(t *testing.T) {
	t.Parallel()
	for _, op := range currentPasswordOps {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			c, db := newCurrentPasswordCore(t)
			for range postVerdictParityPolicy.MaxAttempts - 1 {
				require.ErrorIs(t, op.call(c, "wrong-guess"), ErrIncorrectCurrentPassword)
			}
			require.Equal(t, postVerdictParityPolicy.MaxAttempts-1, readLockoutState(t, db, 1).FailedAttempts)

			require.NoError(t, op.call(c, curPwOld))
			assert.True(t, op.changed(t, db))
			assert.Equal(t, lockoutState{}, readLockoutState(t, db, 1), "a committed change by the full credential clears the counter, as a delivered login does")
		})
	}
}

// A correct password whose change is then refused (policy) is neither a failure
// nor a completion: the counter is left as it was.
func TestChangePassword_RefusedNewPasswordLeavesTheCounter(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	require.ErrorIs(t, c.ChangePassword(context.Background(), 1, "wrong-guess", curPwNew, ""), ErrIncorrectCurrentPassword)
	err := c.ChangePassword(context.Background(), 1, curPwOld, "short", "")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrIncorrectCurrentPassword)
	assert.Equal(t, 1, readLockoutState(t, db, 1).FailedAttempts)
}

// With a second factor enrolled the password alone is not full authentication,
// so a correct one must not clear the counter the second factor's guesses feed
// (as the password step of an MFA login does not). Otherwise a stolen session
// that knows the password could interleave a correct change-password with a
// refused new password between TOTP guesses on /auth/mfa/stepup.
func TestChangePassword_SecondFactorAccountDoesNotClear(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("mfa_enabled", true).Error)
	for range postVerdictParityPolicy.MaxAttempts - 1 {
		require.ErrorIs(t, c.ChangePassword(context.Background(), 1, "wrong-guess", curPwNew, ""), ErrIncorrectCurrentPassword)
	}
	require.NoError(t, c.ChangePassword(context.Background(), 1, curPwOld, curPwNew, ""))
	assert.Equal(t, postVerdictParityPolicy.MaxAttempts-1, readLockoutState(t, db, 1).FailedAttempts,
		"a password-only change on a second-factor account must leave the counter")
}

// Post-verdict parity (INV-CORE-login-lockout-clear-only-after-delivery): a
// storage fault in the lock re-check after the password matched costs exactly
// what a wrong password costs, is refused like one, and carries
// ErrLoginPostVerdict for the auth.login_error audit.
func TestCurrentPassword_RecheckFaultCostsTheSameAsAWrongPassword(t *testing.T) {
	t.Parallel()
	for _, op := range currentPasswordOps {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			cc, cdb := newCurrentPasswordCore(t)
			putAtThresholdMinusOne(t, cdb, 1)
			require.ErrorIs(t, op.call(cc, "wrong-guess"), ErrIncorrectCurrentPassword)
			control := readLockoutState(t, cdb, 1)

			pc, pdb := newCurrentPasswordCore(t)
			putAtThresholdMinusOne(t, pdb, 1)
			fs, restore := armRecheckFault(pc)
			perr := op.call(pc, curPwOld)
			restore()
			require.True(t, fs.Fired(), "the re-check's LockUserForUpdate must have been reached")
			require.ErrorIs(t, perr, ErrIncorrectCurrentPassword, "answered like a wrong password")
			require.ErrorIs(t, perr, ErrLoginPostVerdict, "the password matched: audited auth.login_error")
			assert.False(t, op.changed(t, pdb))

			requireSameLockoutCost(t, control, readLockoutState(t, pdb, 1), op.name+"/recheck")
		})
	}
}

// requireReauth's refusals carry ErrReauthRejected (the transport keeps the
// per-IP slot for them) without changing their text; its pre-verdict storage
// failure does not (nothing was evaluated, so the slot goes back).
func TestRequireReauth_RejectionsCarryTheSentinel(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	// WebAuthn-only: the password branch is evaluated, no TOTP secret is loaded.
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("web_authn_enabled", true).Error)
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	require.True(t, u.WebAuthnEnabled)

	err := c.requireReauth(context.Background(), &u, "wrong-guess", "email_change")
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Equal(t, "invalid code or password", err.Error(), "the text must not change")

	until := time.Now().Add(time.Hour)
	locked := u
	locked.LoginLockedUntil = &until
	err = c.requireReauth(context.Background(), &locked, "wrong-guess", "email_change")
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Equal(t, "account temporarily locked due to repeated failed logins; try again later", err.Error())

	// TOTP enrolled but its secret cannot be loaded: pre-verdict, no sentinel.
	totpUser := u
	totpUser.MFAEnabled = true
	err = c.requireReauth(context.Background(), &totpUser, "wrong-guess", "email_change")
	require.ErrorIs(t, err, ErrMFAVerificationStorageFailure)
	assert.False(t, errors.Is(err, ErrReauthRejected))
}

// AUTH-2 sweep (pre-existing on main): a PANIC in the post-commit PAT revocation
// answered 500 over a committed password change. It now takes the error's
// branch: the change succeeds and the failed revocation is audited loudly.
func TestChangePassword_PATRevocationPanicAfterCommitIsAuditedNotEscaped(t *testing.T) {
	t.Parallel()
	c, db := newCurrentPasswordCore(t)
	base := c.storage
	c.storage = faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "RevokeAllPersonalAccessTokensForUser", NthCall: 1, Kind: faultstorage.KindPanic,
	})
	require.NotPanics(t, func() {
		require.NoError(t, c.ChangePassword(context.Background(), 1, curPwOld, curPwNew, ""))
	})
	c.storage = base
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(curPwNew)))
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventPasswordChangePATRevokeFailed).Count(&n).Error)
	assert.EqualValues(t, 1, n)
}
