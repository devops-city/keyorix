package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestEnforceAccountSetup covers the unified setup gate (#3024), which replaced
// the separate EnforceAccountRestriction / EnforceMFAEnrollment gates that each
// refused the other's endpoint.
func TestEnforceAccountSetup(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	run := func(requireMFA bool, userCtx *UserContext, method, path string) *httptest.ResponseRecorder {
		nextCalled = false
		h := EnforceAccountSetup(requireMFA)(next)
		req := httptest.NewRequest(method, path, nil)
		if userCtx != nil {
			req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	body := func(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
		t.Helper()
		var out map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		return out
	}

	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true}
	restrictedSetupSession := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, Restricted: true, SetupOnly: true}

	t.Run("no user context passes through (auth handles it)", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, run(true, nil, http.MethodGet, "/api/v1/secrets").Code)
		assert.True(t, nextCalled)
	})

	t.Run("nothing pending passes through", func(t *testing.T) {
		ok := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}
		assert.Equal(t, http.StatusOK, run(true, ok, http.MethodGet, "/api/v1/secrets").Code)
		assert.True(t, nextCalled)
		assert.Equal(t, http.StatusOK, run(false, sessionNoMFA, http.MethodGet, "/api/v1/secrets").Code, "policy off: no MFA step")
	})

	t.Run("restricted only: change-password and profile read, nothing else", func(t *testing.T) {
		restricted := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, Restricted: true, MFAEnabled: true}
		assert.Equal(t, http.StatusOK, run(true, restricted, http.MethodPost, "/api/v1/auth/change-password").Code)
		assert.Equal(t, http.StatusOK, run(true, restricted, http.MethodGet, "/api/v1/auth/profile").Code)
		rr := run(true, restricted, http.MethodGet, "/api/v1/secrets")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.False(t, nextCalled)
		b := body(t, rr)
		assert.Equal(t, "PasswordChangeRequired", b["error"])
		assert.Equal(t, []interface{}{core.SetupStepChangePassword}, b["pending_steps"])
		assert.Equal(t, http.StatusForbidden, run(true, restricted, http.MethodPost, "/api/v1/auth/mfa/enroll").Code,
			"MFA enrolment is not a setup step for an account that already has a factor")
	})

	t.Run("MFA only: enrolment endpoints, not change-password", func(t *testing.T) {
		for _, route := range [][2]string{
			{http.MethodPost, "/api/v1/auth/mfa/enroll"},
			{http.MethodPost, "/api/v1/auth/mfa/activate"},
			{http.MethodPost, "/api/v1/auth/webauthn/register/begin"},
			{http.MethodPost, "/api/v1/auth/webauthn/register/finish"},
			{http.MethodGet, "/api/v1/auth/webauthn/credentials"},
			{http.MethodGet, "/api/v1/auth/profile"},
		} {
			assert.Equalf(t, http.StatusOK, run(true, sessionNoMFA, route[0], route[1]).Code, "%s %s", route[0], route[1])
		}
		rr := run(true, sessionNoMFA, http.MethodPost, "/api/v1/auth/change-password")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		b := body(t, rr)
		assert.Equal(t, "MFAEnrollmentRequired", b["error"])
		assert.Equal(t, []interface{}{core.SetupStepEnrollMFA}, b["pending_steps"])
	})

	t.Run("both pending in a setup-only session: either step, nothing else", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, run(true, restrictedSetupSession, http.MethodPost, "/api/v1/auth/change-password").Code)
		assert.Equal(t, http.StatusOK, run(true, restrictedSetupSession, http.MethodPost, "/api/v1/auth/mfa/enroll").Code)
		assert.Equal(t, http.StatusOK, run(true, restrictedSetupSession, http.MethodPost, "/api/v1/auth/webauthn/register/finish").Code)
		rr := run(true, restrictedSetupSession, http.MethodGet, "/api/v1/projects")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		b := body(t, rr)
		assert.Equal(t, "PasswordChangeRequired", b["error"], "existing clients route a password-owing account to change-password first")
		assert.Equal(t, []interface{}{core.SetupStepChangePassword, core.SetupStepEnrollMFA}, b["pending_steps"])
	})

	t.Run("matching is exact on method and full path", func(t *testing.T) {
		for _, route := range [][2]string{
			{http.MethodGet, "/api/v1/auth/change-password"},
			{http.MethodPut, "/api/v1/auth/profile"},
			{http.MethodPost, "/api/v1/projects/1/auth/change-password"},
			{http.MethodPost, "/api/v1/auth/change-password/"},
			{http.MethodPost, "/api/v1/auth/mfa/disable"},
			{http.MethodDelete, "/api/v1/auth/webauthn/credentials/1"},
			{http.MethodPost, "/api/v1/auth/tokens"},
		} {
			assert.Equalf(t, http.StatusForbidden, run(true, restrictedSetupSession, route[0], route[1]).Code, "%s %s", route[0], route[1])
			assert.False(t, nextCalled)
		}
	})

	t.Run("both pending in an ordinary session: re-authenticate", func(t *testing.T) {
		live := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, Restricted: true}
		rr := run(true, live, http.MethodPost, "/api/v1/auth/change-password")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.False(t, nextCalled)
		assert.Equal(t, "ReauthenticationRequired", body(t, rr)["error"])
	})

	t.Run("setup-only session with nothing left: re-authenticate (backstop)", func(t *testing.T) {
		done := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, SetupOnly: true, MFAEnabled: true}
		for _, path := range []string{"/api/v1/projects", "/api/v1/auth/profile"} {
			rr := run(true, done, http.MethodGet, path)
			assert.Equal(t, http.StatusUnauthorized, rr.Code, path)
			assert.False(t, nextCalled)
		}
	})

	t.Run("impersonation session keeps the plain 403 confinement", func(t *testing.T) {
		admin := uint(9)
		imp := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, Restricted: true, ImpersonatedBy: &admin}
		rr := run(true, imp, http.MethodGet, "/api/v1/projects")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("PAT on a restricted account: change-password only; MFA policy exempt", func(t *testing.T) {
		pat := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: false, Restricted: true}
		assert.Equal(t, http.StatusOK, run(true, pat, http.MethodPost, "/api/v1/auth/change-password").Code)
		assert.Equal(t, http.StatusForbidden, run(true, pat, http.MethodPost, "/api/v1/auth/mfa/enroll").Code)
		rr := run(true, pat, http.MethodGet, "/api/v1/secrets")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, []interface{}{core.SetupStepChangePassword}, body(t, rr)["pending_steps"])
		unrestricted := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: false}
		assert.Equal(t, http.StatusOK, run(true, unrestricted, http.MethodGet, "/api/v1/secrets").Code,
			"PAT/automation must not be confined by the MFA policy")
	})

	t.Run("machine identity: exempt", func(t *testing.T) {
		mid := uint(5)
		machine := &UserContext{MachineIdentityID: &mid, ActorType: core.ActorTypeMachine}
		assert.Equal(t, http.StatusOK, run(true, machine, http.MethodGet, "/api/v1/secrets").Code)
		assert.True(t, nextCalled)
	})
}
