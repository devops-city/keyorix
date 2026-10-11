// login_budget_mfa_slot_release_test.go — #2936 item 4 and the #2956 review's
// WebAuthn-Begin point.
//
// The per-IP budget counts FAILED credential attempts only. Before this, the
// password step of an MFA login kept its slot (one slot per successful MFA
// login), so a handful of ordinary MFA logins from one office IP still locked
// everyone behind it out. Now each kept slot of a multi-request flow (the
// password step's, bound to the MFA challenge; a WebAuthn Begin's, bound to its
// ceremony row) is handed back by core's LoginCompletion.Succeeded, i.e. only
// when the flow delivers a session, and at most once because both rows are
// single-use. A failed, expired or abandoned second factor keeps them counted.
package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// mfaPasswordStep posts the password and returns the MFA challenge.
func (e *lockoutOracleEnv) mfaPasswordStep(t *testing.T) string {
	t.Helper()
	w := e.postLogin(t, lockoutOracleTestPassword)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			MFARequired  bool   `json:"mfa_required"`
			MFAChallenge string `json:"mfa_challenge"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.Data.MFARequired, "setup: alice has TOTP enrolled")
	return resp.Data.MFAChallenge
}

// nextTOTP moves the env's clock one TOTP step on (each code is single-use per
// step) and returns the code for it.
func (e *lockoutOracleEnv) nextTOTP(t *testing.T) string {
	t.Helper()
	e.clock = e.clock.Add(30 * time.Second)
	code, err := totp.GenerateCode(e.totpSecret, e.clock)
	require.NoError(t, err)
	return code
}

func budgetSlots(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", lockoutOracleTestIP).Count(&n).Error)
	return n
}

// TestLoginBudget_SuccessfulMFALoginsNeverHitTheLimit is item 4's repro: twice
// LoginMaxAttempts ordinary TOTP logins from one IP all succeed and leave no
// slot counted.
func TestLoginBudget_SuccessfulMFALoginsNeverHitTheLimit(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)
	for i := 0; i < 2*core.LoginMaxAttempts; i++ {
		ch := env.mfaPasswordStep(t)
		v := env.postVerify(t, ch, env.nextTOTP(t))
		require.Equal(t, http.StatusOK, v.Code,
			"MFA login %d of %d from one IP was refused (%s): a delivered MFA login must not keep any slot (#2936 item 4)",
			i+1, 2*core.LoginMaxAttempts, v.Body.String())
	}
	assert.Zero(t, budgetSlots(t, env.db), "no failure happened, so no slot may stay counted")
}

// TestLoginBudget_FailedOrAbandonedMFAStillCounts: a wrong code keeps both the
// password step's slot and its own; a password step whose flow is abandoned
// keeps its slot. The per-account counter still moves on the wrong code.
func TestLoginBudget_FailedOrAbandonedMFAStillCounts(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)

	ch := env.mfaPasswordStep(t)
	require.EqualValues(t, 1, budgetSlots(t, env.db), "the password step reserves and keeps one slot")
	v := env.postVerify(t, ch, "000000")
	require.Equal(t, http.StatusUnauthorized, v.Code)
	assert.EqualValues(t, 2, budgetSlots(t, env.db), "a wrong code is a failure: both slots stay counted")
	var u models.User
	require.NoError(t, env.db.First(&u, 1).Error)
	assert.Equal(t, 1, u.FailedLoginAttempts, "the per-account lockout still counts a wrong second factor")

	_ = env.mfaPasswordStep(t) // abandoned: never verified
	assert.EqualValues(t, 3, budgetSlots(t, env.db), "an abandoned MFA flow keeps its password-step slot")
}

// TestLoginBudget_ConsumedOrExpiredChallengeCannotReleaseASlot: the release is
// bound to the single-use challenge, so replaying a challenge that already
// delivered a login cannot release anything again, and an expired challenge
// never releases its slot.
func TestLoginBudget_ConsumedOrExpiredChallengeCannotReleaseASlot(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)

	ch := env.mfaPasswordStep(t)
	require.Equal(t, http.StatusOK, env.postVerify(t, ch, env.nextTOTP(t)).Code)
	require.Zero(t, budgetSlots(t, env.db))

	// Two genuine failures, then a replay of the spent challenge with a fresh,
	// valid code: the replay is refused and adds its own slot; nothing earlier
	// is handed back.
	require.Equal(t, http.StatusUnauthorized, env.postLogin(t, "wrong-password-1").Code)
	require.Equal(t, http.StatusUnauthorized, env.postLogin(t, "wrong-password-2").Code)
	require.EqualValues(t, 2, budgetSlots(t, env.db))
	require.Equal(t, http.StatusUnauthorized, env.postVerify(t, ch, env.nextTOTP(t)).Code, "a spent challenge is refused")
	assert.EqualValues(t, 3, budgetSlots(t, env.db), "a replayed challenge must not release a slot twice")

	// Expired: the password step's slot stays, and so does the late verify's.
	ch2 := env.mfaPasswordStep(t)
	env.clock = env.clock.Add(10 * time.Minute)
	code, err := totp.GenerateCode(env.totpSecret, env.clock)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, env.postVerify(t, ch2, code).Code, "an expired challenge is refused")
	assert.EqualValues(t, 5, budgetSlots(t, env.db), "an expired challenge never releases its password-step slot")
}

// --- WebAuthn second factor and passwordless --------------------------------

// newPasskeyBudgetEnv is newWebAuthnCompletionEnv plus a password for alice,
// so the full password -> Begin -> Finish flow can be driven over HTTP.
func newPasskeyBudgetEnv(t *testing.T) (*AuthHandler, *gorm.DB) {
	t.Helper()
	h, _, db := newWebAuthnCompletionEnv(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(lockoutOracleTestPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("password_hash", string(hash)).Error)
	return h, db
}

func postJSONTo(t *testing.T, handler func(http.ResponseWriter, *http.Request), path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)))
	return w
}

// beginPasskey drives a Begin endpoint and returns its ceremony token, then
// re-points the ceremony row at the spec vector's challenge (the vector is
// signed over a fixed challenge, so Begin's random one can never verify). The
// row -- and the slot bound to it -- is the one Begin wrote.
func beginPasskey(t *testing.T, db *gorm.DB, w *httptest.ResponseRecorder, discoverable bool) string {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			Session string `json:"webauthn_session"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	_, challenge := wcAssertionJSON(t, false)
	sd := &webauthn.SessionData{Challenge: challenge}
	if !discoverable {
		sd.UserID = wcWebAuthnID(1)
	}
	data, err := json.Marshal(sd)
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(resp.Data.Session))
	res := db.Model(&models.WebAuthnSession{}).Where("token_hash = ?", hex.EncodeToString(sum[:])).Update("data", data)
	require.NoError(t, res.Error)
	require.EqualValues(t, 1, res.RowsAffected, "Begin's ceremony row must exist")
	return resp.Data.Session
}

// TestLoginBudget_PasskeyMFALoginLeavesNoSlot: password -> Begin -> Finish
// with a verifying assertion, repeated past the budget, keeps nothing.
func TestLoginBudget_PasskeyMFALoginLeavesNoSlot(t *testing.T) {
	h, db := newPasskeyBudgetEnv(t)
	cred, _ := wcAssertionJSON(t, false)
	for i := 0; i < core.LoginMaxAttempts+2; i++ {
		lw := postJSONTo(t, h.Login, "/auth/login", map[string]string{"username": "alice", "password": lockoutOracleTestPassword})
		require.Equal(t, http.StatusOK, lw.Code, "login %d: %s", i+1, lw.Body.String())
		var lr struct {
			Data struct {
				MFAChallenge string `json:"mfa_challenge"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(lw.Body.Bytes(), &lr))
		tok := beginPasskey(t, db, postJSONTo(t, h.BeginWebAuthnLogin, "/auth/webauthn/login/begin",
			map[string]string{"mfa_challenge": lr.Data.MFAChallenge}), false)
		fw := postFinishWebAuthnLogin(t, h, lr.Data.MFAChallenge, tok, cred)
		require.Equal(t, http.StatusOK, fw.Code, "passkey MFA login %d of %d: %s", i+1, core.LoginMaxAttempts+2, fw.Body.String())
	}
	assert.Zero(t, budgetSlots(t, db), "a delivered passkey MFA login keeps no slot (password step, Begin and Finish all handed back)")
}

// TestLoginBudget_WebAuthnBeginKeepsItsSlotUntilDelivered is the review point:
// Begin does not consume the MFA challenge, so a slot handed back on every
// successful Begin let one valid challenge drive unlimited ceremony writes at
// no budget cost. Begin's slot is now kept (bound to the ceremony), so
// repeated Begins run into the limit.
func TestLoginBudget_WebAuthnBeginKeepsItsSlotUntilDelivered(t *testing.T) {
	h, _ := newPasskeyBudgetEnv(t)
	lw := postJSONTo(t, h.Login, "/auth/login", map[string]string{"username": "alice", "password": lockoutOracleTestPassword})
	require.Equal(t, http.StatusOK, lw.Code, lw.Body.String())
	var lr struct {
		Data struct {
			MFAChallenge string `json:"mfa_challenge"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(lw.Body.Bytes(), &lr))

	refused := false
	for i := 0; i < core.LoginMaxAttempts+1; i++ {
		w := postJSONTo(t, h.BeginWebAuthnLogin, "/auth/webauthn/login/begin", map[string]string{"mfa_challenge": lr.Data.MFAChallenge})
		if w.Code == http.StatusTooManyRequests {
			refused = true
			break
		}
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	assert.True(t, refused, "one valid MFA challenge must not buy unlimited Begin calls: each Begin keeps its slot until a login is delivered")
}

// TestLoginBudget_PasswordlessLoginLeavesNoSlot: Begin (kept, bound to the
// ceremony) + Finish (delivered) -> nothing counted; a Begin that is never
// finished stays counted.
func TestLoginBudget_PasswordlessLoginLeavesNoSlot(t *testing.T) {
	h, db := newPasskeyBudgetEnv(t)
	cred, _ := wcAssertionJSONWithUserHandle(t, false)
	for i := 0; i < core.LoginMaxAttempts+2; i++ {
		tok := beginPasskey(t, db, postJSONTo(t, h.BeginWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/begin", map[string]string{}), true)
		fw := postJSONTo(t, h.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
			map[string]any{"webauthn_session": tok, "credential": cred})
		require.Equal(t, http.StatusOK, fw.Code, "passwordless login %d: %s", i+1, fw.Body.String())
	}
	assert.Zero(t, budgetSlots(t, db))

	_ = postJSONTo(t, h.BeginWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/begin", map[string]string{})
	assert.EqualValues(t, 1, budgetSlots(t, db), "an unfinished passwordless Begin keeps its slot")
}
