// otp_expiry_login_test.go — OTP-EXPIRY-1 over the real router: an expired
// one-time password gets exactly the response a wrong password gets (status and
// body: no new oracle), and a recover-admin / admin-created one-time password
// still logs in until it expires.
package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestLogin_ExpiredOneTimePassword_SameResponseAsWrongPassword(t *testing.T) {
	for name, mk := range setupStates {
		if name == "admin-forced password reset" || name == "pending first login" {
			continue // not one-time passwords: no expiry is recorded for them
		}
		t.Run(name, func(t *testing.T) {
			e := newSetupGateEnv(t)
			username, otp := mk(e)
			ctx := context.Background()
			user, err := e.core.Storage().GetUserByUsername(ctx, username)
			require.NoError(t, err)

			if name == "recover-admin" {
				// recoverAdminState mirrors the account state recover-admin leaves behind;
				// give it the expiry recover-admin now records.
				soon := time.Now().Add(time.Hour)
				require.NoError(t, e.core.Storage().SetOneTimePasswordExpiry(ctx, user.ID, &soon, time.Now()))
			}

			// Before expiry the one-time password logs in.
			ok := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": username, "password": otp})
			require.Equal(t, http.StatusOK, ok.status, ok.raw)

			// After expiry it is refused like a wrong password.
			past := time.Now().Add(-time.Second)
			require.NoError(t, e.core.Storage().SetOneTimePasswordExpiry(ctx, user.ID, &past, time.Now()))
			expired := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": username, "password": otp})
			wrong := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": username, "password": "Not-the-password-1"})

			assert.Equal(t, http.StatusUnauthorized, wrong.status)
			assert.Equal(t, wrong.status, expired.status, "expired one-time password must get the wrong-password status")
			assert.Equal(t, wrong.raw, expired.raw, "expired one-time password must get the wrong-password body")
			assert.Equal(t, comparableHeaders(wrong.header), comparableHeaders(expired.header),
				"expired one-time password must get the wrong-password headers (Retry-After, Set-Cookie, WWW-Authenticate, ...)")
			assert.Nil(t, expired.data()["token"], "no session for an expired one-time password")
		})
	}
}

// comparableHeaders drops the headers that legitimately differ between two
// otherwise identical responses (time, per-request ids).
func comparableHeaders(h http.Header) http.Header {
	out := h.Clone()
	for _, k := range []string{"Date", "X-Request-Id", "X-Request-ID", "Traceparent"} {
		out.Del(k)
	}
	return out
}

// A password the user chose themselves is never subject to the one-time expiry,
// even long after the one-time password's own expiry.
func TestLogin_ChosenPasswordOutlivesOneTimePasswordExpiry(t *testing.T) {
	e := newSetupGateEnv(t)
	username, otp := setupStates["one-time-password user"](e)
	ctx := context.Background()

	token, _ := e.passwordLogin(username, otp)
	require.NotEmpty(t, token)
	cp := e.do(http.MethodPost, "/api/v1/auth/change-password", token,
		map[string]string{"current_password": otp, "new_password": setupGateNewPassword})
	require.Equal(t, http.StatusOK, cp.status, cp.raw)

	user, err := e.core.Storage().GetUserByUsername(ctx, username)
	require.NoError(t, err)
	assert.Nil(t, user.OneTimePasswordExpiresAt, "changing the password clears the one-time expiry")
	assert.Equal(t, core.AccountActive, user.AccountState)
}
