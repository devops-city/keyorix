// account_setup_mfa_grace_test.go -- #2923 at the HTTP layer: during ADR-112's
// require_mfa upgrade grace period users without a second factor sign in and
// are told how long they have (mfa_grace on login and profile); the first
// administrator MFA enrolment ends it while the server runs, and from then on
// the same users are confined to MFA enrolment (not locked out). The 30-day
// deadline does the same.
package http

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

const graceUserPassword = "Grace#User-Passw0rd-5"

func (e *setupGateEnv) startMFAGrace(start time.Time) {
	e.t.Helper()
	e.core.StartMFAUpgradeGrace(core.MFAUpgradeGraceWindow{
		Start: start, Deadline: start.Add(config.ADR112RequireMFAGracePeriod), Floor: start,
		EnforcedMarkerKey: config.ADR112RequireMFAEnforcedMarker, ClockKey: config.ADR112RequireMFAGraceClockKey,
	})
}

func (e *setupGateEnv) createGraceUser() {
	e.t.Helper()
	_, err := e.core.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "grace_user", Email: "grace_user@example.com", Password: graceUserPassword,
	})
	require.NoError(e.t, err)
}

func graceOf(t *testing.T, m map[string]any) (map[string]any, bool) {
	t.Helper()
	g, ok := m["mfa_grace"].(map[string]any)
	return g, ok
}

func TestMFAGrace_FirstAdminEnrolmentEndsItWhileRunning(t *testing.T) {
	e := newSetupGateEnv(t)
	e.createGraceUser()
	e.startMFAGrace(time.Now().Add(-24 * time.Hour))

	// During the grace period: both sign in without a second factor, see the
	// days left, and reach ordinary routes.
	adminLogin := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": "testadmin", "password": "TestPassword123!"})
	require.Equal(t, http.StatusOK, adminLogin.status, adminLogin.raw)
	adminToken, _ := adminLogin.data()["token"].(string)
	require.NotEmpty(t, adminToken, "an admin without MFA signs in during the grace period")
	grace, ok := graceOf(t, adminLogin.data())
	require.True(t, ok, "login must report the grace period: %s", adminLogin.raw)
	assert.EqualValues(t, 29, grace["days_left"])
	assert.NotEmpty(t, grace["ends_at"])
	assert.Empty(t, adminLogin.data()["pending_steps"])

	userToken, _ := e.passwordLogin("grace_user", graceUserPassword)
	require.NotEmpty(t, userToken)
	profile := e.do(http.MethodGet, "/api/v1/auth/profile", userToken, nil)
	require.Equal(t, http.StatusOK, profile.status, profile.raw)
	_, ok = graceOf(t, profile.data())
	assert.True(t, ok, "profile must carry the grace period for the banner: %s", profile.raw)
	r := e.do(http.MethodGet, "/api/v1/projects", userToken, nil)
	assert.NotEqual(t, http.StatusForbidden, r.status, "no MFA confinement during the grace period: %s", r.raw)

	cfgResp := e.do(http.MethodGet, "/api/v1/system/auth-config", adminToken, nil)
	require.Equal(t, http.StatusOK, cfgResp.status, cfgResp.raw)
	assert.Equal(t, false, cfgResp.data()["require_mfa"], "auth-config reports what is enforced now")
	assert.NotNil(t, cfgResp.data()["require_mfa_grace"])

	// The first administrator enrols: the grace period ends, without a restart.
	_, _ = e.enrolTOTP(adminToken, "TestPassword123!")

	r = e.do(http.MethodGet, "/api/v1/projects", userToken, nil)
	require.Equal(t, http.StatusForbidden, r.status, "after the grace period a user without MFA is confined: %s", r.raw)
	assert.Equal(t, "MFAEnrollmentRequired", r.body["error"])
	assert.Equal(t, []string{core.SetupStepEnrollMFA}, r.pendingSteps())

	profile = e.do(http.MethodGet, "/api/v1/auth/profile", userToken, nil)
	require.Equal(t, http.StatusOK, profile.status, profile.raw)
	_, ok = graceOf(t, profile.data())
	assert.False(t, ok, "no grace banner once it ended")

	enrol := e.do(http.MethodPost, "/api/v1/auth/mfa/enroll", userToken, map[string]string{})
	assert.Equal(t, http.StatusOK, enrol.status, "enrolment must stay reachable (not a lockout): %s", enrol.raw)

	relogin := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": "grace_user", "password": graceUserPassword})
	require.Equal(t, http.StatusOK, relogin.status, relogin.raw)
	assert.Contains(t, relogin.raw, core.SetupStepEnrollMFA)
	_, ok = graceOf(t, relogin.data())
	assert.False(t, ok)

	_, found, err := e.core.Storage().GetSystemMetadata(context.Background(), config.ADR112RequireMFAEnforcedMarker)
	require.NoError(t, err)
	assert.True(t, found, "the end is recorded, so no later boot grants the grace period again")
}

func TestMFAGrace_DeadlineEnforces(t *testing.T) {
	e := newSetupGateEnv(t)
	e.createGraceUser()
	e.startMFAGrace(time.Now().Add(-config.ADR112RequireMFAGracePeriod - time.Minute))

	login := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": "grace_user", "password": graceUserPassword})
	require.Equal(t, http.StatusOK, login.status, login.raw)
	_, ok := graceOf(t, login.data())
	assert.False(t, ok)
	token, _ := login.data()["token"].(string)
	require.NotEmpty(t, token)
	r := e.do(http.MethodGet, "/api/v1/projects", token, nil)
	assert.Equal(t, http.StatusForbidden, r.status, "past the deadline a user without MFA is confined: %s", r.raw)
	enrol := e.do(http.MethodPost, "/api/v1/auth/mfa/enroll", token, map[string]string{})
	assert.Equal(t, http.StatusOK, enrol.status, "enrolment must stay reachable: %s", enrol.raw)
}
