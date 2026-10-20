// setup_consume_atomic_test.go — AUTH-2 item 1 (#3298): a setup-token consume
// that fails at any write leaves NOTHING behind (the token still active, the old
// password, every PAT live, no session, no MFA challenge), so the same link
// works on a retry; one that succeeds leaves the full effect. Driven over real
// SQLite through faultstorage, every write of the transaction × every fault kind.
package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	setupAtomicOldPassword = "Old!Password#Before-2026"
	setupAtomicNewPassword = "Brand!New#Setup-Passw0rd"
	setupAtomicRawToken    = setupPrefix + "atomic-consume"
)

// newSetupAtomicCore is newCurrentPasswordCore plus a setup token for alice
// (pending_first_login) and one live PAT. mfa enrols TOTP (flag only: the
// consume reads nothing else).
func newSetupAtomicCore(t *testing.T, mfa bool) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	c, db := newCurrentPasswordCore(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(setupAtomicOldPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Updates(map[string]any{
		"password_hash": string(hash), "account_state": AccountPendingFirstLogin, "mfa_enabled": mfa,
	}).Error)
	uid := uint(1)
	require.NoError(t, db.Create(&models.SetupToken{
		TokenHash: sha256Hex(setupAtomicRawToken), Purpose: SetupPurposeAccountSetup,
		SubjectUserID: &uid, SubjectEmail: "alice@old.example", State: SetupTokenActive,
		ExpiresAt: time.Now().Add(time.Hour),
	}).Error)
	require.NoError(t, db.Create(&models.PersonalAccessToken{UserID: 1, Name: "ci", TokenHash: "pat-hash-1"}).Error)
	return c, db
}

type setupState struct {
	tokenState    string
	oldPassword   bool
	accountState  string
	patRevoked    bool
	sessions      int64
	mfaChallenges int64
}

func readSetupState(t *testing.T, db *gorm.DB) setupState {
	t.Helper()
	var st setupState
	var tok models.SetupToken
	require.NoError(t, db.Where("token_hash = ?", sha256Hex(setupAtomicRawToken)).First(&tok).Error)
	st.tokenState = tok.State
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	st.oldPassword = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(setupAtomicOldPassword)) == nil
	st.accountState = u.AccountState
	var pat models.PersonalAccessToken
	require.NoError(t, db.Where("token_hash = ?", "pat-hash-1").First(&pat).Error)
	st.patRevoked = pat.Revoked
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&st.sessions).Error)
	require.NoError(t, db.Model(&models.MFAChallenge{}).Where("user_id = ?", 1).Count(&st.mfaChallenges).Error)
	return st
}

// completeSetupRecovering calls CompleteSetup and turns a panic into an error,
// as the HTTP layer's Recovery does with a 500.
func completeSetupRecovering(c *KeyorixCore) (res *SetupConsumeResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("panicked: %v", r)
		}
	}()
	return c.CompleteSetup(context.Background(), setupAtomicRawToken, setupAtomicNewPassword, "ua", "198.51.100.7")
}

func TestCompleteSetup_FaultAtAnyWriteLeavesNothingAndTheLinkStillWorks(t *testing.T) {
	t.Parallel()
	for _, mfa := range []bool{false, true} {
		methods := []string{"WithTransaction", "MarkSetupTokenConsumed", "SetPasswordHash", "SetAccountState", "RevokeAllPersonalAccessTokensForUser"}
		if mfa {
			methods = append(methods, "CreateMFAChallenge")
		} else {
			methods = append(methods, "CreateSession", "GetUserRoles", "GetUserPermissions")
		}
		for _, method := range methods {
			for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic, faultstorage.KindEffectThenError} {
				t.Run(fmt.Sprintf("mfa=%v/%s/%s", mfa, method, kind), func(t *testing.T) {
					t.Parallel()
					c, db := newSetupAtomicCore(t, mfa)
					before := readSetupState(t, db)
					require.Equal(t, SetupTokenActive, before.tokenState)

					base := c.storage
					fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
						Method: method, NthCall: 1, Kind: kind, Err: errors.New("injected: " + method),
					})
					c.storage = fs
					res, err := completeSetupRecovering(c)
					c.storage = base
					require.True(t, fs.Fired(), "the %s fault must have been reached", method)
					if method == "WithTransaction" && kind == faultstorage.KindEffectThenError {
						// The commit landed and reported an error: read back and
						// delivered, never reported as failed over a spent link.
						if mfa {
							require.ErrorIs(t, err, ErrMFARequired)
							assert.NotEmpty(t, res.MFAChallenge)
						} else {
							require.NoError(t, err)
							require.NotNil(t, res.Session)
						}
						got := readSetupState(t, db)
						assert.Equal(t, SetupTokenConsumed, got.tokenState)
						assert.False(t, got.oldPassword)
						assert.True(t, got.patRevoked)
						return
					}
					require.Error(t, err, "a faulted consume must be reported as failed")
					assert.Equal(t, before, readSetupState(t, db), "a failed consume must leave nothing behind")

					// The same link still works.
					res, err = c.CompleteSetup(context.Background(), setupAtomicRawToken, setupAtomicNewPassword, "ua", "198.51.100.7")
					if mfa {
						require.ErrorIs(t, err, ErrMFARequired)
						assert.NotEmpty(t, res.MFAChallenge)
					} else {
						require.NoError(t, err)
						require.NotNil(t, res.Session)
					}
					after := readSetupState(t, db)
					assert.Equal(t, SetupTokenConsumed, after.tokenState)
					assert.False(t, after.oldPassword)
					assert.True(t, after.patRevoked)
				})
			}
		}
	}
}

// The full effect on success, in one step: consumed, new password, active,
// PATs revoked, exactly one session (or challenge), identity returned.
func TestCompleteSetup_SuccessIsTheFullEffect(t *testing.T) {
	t.Parallel()
	c, db := newSetupAtomicCore(t, false)
	res, err := c.CompleteSetup(context.Background(), setupAtomicRawToken, setupAtomicNewPassword, "ua", "198.51.100.7")
	require.NoError(t, err)
	require.NotNil(t, res.Session)
	assert.NotNil(t, res.Identity.Roles)
	assert.Equal(t, setupState{tokenState: SetupTokenConsumed, accountState: AccountActive, patRevoked: true, sessions: 1},
		readSetupState(t, db))

	_, err = c.CompleteSetup(context.Background(), setupAtomicRawToken, setupAtomicNewPassword, "ua", "198.51.100.7")
	require.Error(t, err, "single use: a spent link is refused")
}

// The second-factor shape: the challenge is created in the transaction and
// holds the transport's login slot, so the second factor hands it back.
func TestCompleteSetup_SecondFactorChallengeHoldsTheSlot(t *testing.T) {
	t.Parallel()
	c, db := newSetupAtomicCore(t, true)
	slot := uint(42)
	res, err := c.CompleteSetupHoldingLoginSlot(context.Background(), setupAtomicRawToken, setupAtomicNewPassword, "ua", "198.51.100.7", &slot)
	require.ErrorIs(t, err, ErrMFARequired)
	require.NotEmpty(t, res.MFAChallenge)
	assert.Nil(t, res.Session)
	var ch models.MFAChallenge
	require.NoError(t, db.Where("token_hash = ?", sha256Hex(res.MFAChallenge)).First(&ch).Error)
	require.NotNil(t, ch.LoginAttemptID)
	assert.EqualValues(t, 42, *ch.LoginAttemptID)
	assert.Equal(t, setupState{tokenState: SetupTokenConsumed, accountState: AccountActive, patRevoked: true, mfaChallenges: 1},
		readSetupState(t, db))
}
