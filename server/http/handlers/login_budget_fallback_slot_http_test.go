// login_budget_fallback_slot_http_test.go — #3023 / #3029 review: a login
// slot taken by the in-memory fallback (core/login_budget_fallback.go) while
// ReserveLoginAttempt fails is a per-process id with the top bit set. It used
// to be persisted into mfa_challenges / web_authn_sessions login_attempt_id;
// SQLite then could not read the row back into a uint, so the second factor
// (or the passwordless Finish) of a user with the right credentials failed,
// and the MFA verify path charged a lockout strike for it. MFA and passkey
// logins broke during the very outage the fallback exists for.
//
// Here the reservation alone fails once (the password step's, or Begin's), and
// the rest of the flow runs against healthy storage: it must deliver a session.
package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestLoginBudgetFallbackSlot_TOTPLoginStillCompletes(t *testing.T) {
	env := newLockoutOracleEnvWithMFA(t)
	env.fs.Arm(&faultstorage.FaultSpec{
		Method: "ReserveLoginAttempt", NthCall: 1, Kind: faultstorage.KindError, Err: errLoginAttemptsStoreDown,
	})
	ch := env.mfaPasswordStep(t)
	require.True(t, env.fs.Fired(), "calibration: the password step's reservation went to the in-memory fallback")
	env.fs.Arm(nil)

	v := env.postVerify(t, ch, env.nextTOTP(t))
	require.Equal(t, http.StatusOK, v.Code,
		"a correct TOTP after a password step whose slot came from the fallback must log in: %s", v.Body.String())

	var u models.User
	require.NoError(t, env.db.First(&u, 1).Error)
	assert.Zero(t, u.FailedLoginAttempts, "a correct password and a correct code must not cost a lockout strike")
	assert.Nil(t, u.LoginLockedUntil)
}

func TestLoginBudgetFallbackSlot_PasswordlessLoginStillCompletes(t *testing.T) {
	h, fs, db := newWebAuthnCompletionEnv(t)
	cred, _ := wcAssertionJSONWithUserHandle(t, false)

	fs.Arm(&faultstorage.FaultSpec{
		Method: "ReserveLoginAttempt", NthCall: 1, Kind: faultstorage.KindError, Err: errLoginAttemptsStoreDown,
	})
	tok := beginPasskey(t, db, postJSONTo(t, h.BeginWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/begin", map[string]string{}), true)
	require.True(t, fs.Fired(), "calibration: Begin's reservation went to the in-memory fallback")
	fs.Arm(nil)

	var ws models.WebAuthnSession
	require.NoError(t, db.First(&ws).Error, "Begin's ceremony row must be readable")
	assert.Nil(t, ws.LoginAttemptID, "a per-process fallback slot id must not be persisted to the shared ceremony row")

	fw := postJSONTo(t, h.FinishWebAuthnPasswordlessLogin, "/auth/webauthn/passwordless/finish",
		map[string]any{"webauthn_session": tok, "credential": cred})
	require.Equal(t, http.StatusOK, fw.Code,
		"a verifying passkey after a Begin whose slot came from the fallback must log in: %s", fw.Body.String())
}
