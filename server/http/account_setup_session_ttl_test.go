// account_setup_session_ttl_test.go — #3024: the setup-only session is
// short-lived and survives refresh only as a setup-only session.
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

// TestAccountSetup_SetupSessionIsShortLived: the restricted session a
// factor-less account gets under require_mfa has a hard ceiling of minutes,
// carried through refresh, not the normal session lifetime.
func TestAccountSetup_SetupSessionIsShortLived(t *testing.T) {
	e := newSetupGateEnv(t)
	username, otp := e.recoverAdminState()
	token, _ := e.passwordLogin(username, otp)
	require.NotEmpty(t, token)

	sess, err := e.core.Storage().GetSession(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, sess.AbsoluteExpiresAt, "a setup session must have an absolute ceiling")
	assert.WithinDuration(t, time.Now().Add(core.SetupSessionTTL), *sess.AbsoluteExpiresAt, time.Minute)
	assert.LessOrEqual(t, time.Until(*sess.AbsoluteExpiresAt), core.SetupSessionTTL+time.Second)
	assert.True(t, sess.SetupOnly)

	r := e.do(http.MethodPost, "/auth/refresh", token, map[string]string{})
	require.Equal(t, http.StatusOK, r.status, r.raw)
	newTok, _ := r.data()["token"].(string)
	require.NotEmpty(t, newTok)
	rotated, err := e.core.Storage().GetSession(context.Background(), newTok)
	require.NoError(t, err)
	assert.True(t, rotated.SetupOnly, "refresh must not launder a setup session into a normal one")
	require.NotNil(t, rotated.AbsoluteExpiresAt)
	assert.False(t, rotated.AbsoluteExpiresAt.After(*sess.AbsoluteExpiresAt), "refresh must not extend the setup ceiling")
}

// TestAccountSetup_LiveSessionForcedReset: an admin forces a reset on a
// factor-less user whose ordinary session is live. That session now owes both
// steps but is not a setup session, so the gate sends it to re-authenticate;
// its refresh comes back as a short-lived setup session that can finish setup,
// and finishing still ends in a normal MFA login.
func TestAccountSetup_LiveSessionForcedReset(t *testing.T) {
	e := newSetupGateEnv(t)
	ctx := context.Background()
	u, err := e.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "live_user", Email: "live_user@example.com", Password: setupGateOTP,
	})
	require.NoError(t, err)
	token, _ := e.passwordLogin("live_user", setupGateOTP)
	require.NotEmpty(t, token)
	r := e.do(http.MethodGet, "/api/v1/projects", token, nil)
	require.Equal(t, http.StatusForbidden, r.status, r.raw)
	assert.Equal(t, []string{"enroll_mfa"}, r.pendingSteps())

	admin, err := e.core.Storage().GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	require.NoError(t, e.core.RequirePasswordReset(ctx, admin.ID, u.ID))

	r = e.do(http.MethodPost, "/api/v1/auth/change-password", token,
		map[string]string{"current_password": setupGateOTP, "new_password": setupGateNewPassword})
	// 401 either from the restriction's own cache tombstone (setAccountState) or,
	// once that lapses, from the setup gate's ReauthenticationRequired.
	require.Equal(t, http.StatusUnauthorized, r.status, r.raw)

	r = e.do(http.MethodPost, "/auth/refresh", token, map[string]string{})
	require.Equal(t, http.StatusOK, r.status, r.raw)
	setupTok, _ := r.data()["token"].(string)
	sess, err := e.core.Storage().GetSession(ctx, setupTok)
	require.NoError(t, err)
	assert.True(t, sess.SetupOnly)
	require.NotNil(t, sess.AbsoluteExpiresAt)
	assert.LessOrEqual(t, time.Until(*sess.AbsoluteExpiresAt), core.SetupSessionTTL+time.Second)

	cp := e.do(http.MethodPost, "/api/v1/auth/change-password", setupTok,
		map[string]string{"current_password": setupGateOTP, "new_password": setupGateNewPassword})
	require.Equal(t, http.StatusOK, cp.status, cp.raw)
	recovery, act := e.enrolTOTP(setupTok, setupGateNewPassword)
	assert.Equal(t, true, act.data()["reauthentication_required"], act.raw)
	assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/api/v1/auth/profile", setupTok, nil).status)

	_, chal := e.passwordLogin("live_user", setupGateNewPassword)
	require.NotEmpty(t, chal)
	v := e.do(http.MethodPost, "/auth/mfa/verify", "", map[string]string{"mfa_challenge": chal, "code": recovery})
	require.Equal(t, http.StatusOK, v.status, v.raw)
}
