// account_setup_gate_test.go — #3024: a restricted account (recover-admin,
// one-time-password user, admin-forced reset, pending first login) under the
// default security.require_mfa must be able to finish exactly the two setup
// steps (set a new password, enrol a second factor) in either order, reach
// nothing else meanwhile, and then be sent through a normal MFA login.
//
// Before the fix the two gates waited for each other: EnforceAccountRestriction
// refused /auth/mfa/enroll with PasswordChangeRequired and EnforceMFAEnrollment
// refused /auth/change-password with MFAEnrollmentRequired, so the documented
// recover-admin runbook ended in a permanent lockout.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

const (
	setupGateOTP         = "Temp#Otp-Passw0rd-91"
	setupGateNewPassword = "Brand#New-Passw0rd-77"
)

// setupGateEnv is a real router over a real core with require_mfa on, at-rest
// encryption enabled (TOTP enrolment refuses without it) and the auth-cache
// invalidator wired as in production.
type setupGateEnv struct {
	t      *testing.T
	core   *core.KeyorixCore
	server *httptest.Server
	router http.Handler
}

func newSetupGateEnv(t *testing.T) *setupGateEnv {
	t.Helper()
	return newSetupGateEnvWrapped(t, nil)
}

// newSetupGateEnvWrapped is newSetupGateEnv over a storage wrapper (see
// newTestCoreWrapped).
func newSetupGateEnvWrapped(t *testing.T, wrap func(storage.Storage) storage.Storage) *setupGateEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c := newTestCoreWrapped(t, wrap)
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)
	c.SetTokenCacheClearer(customMiddleware.ClearTokenCacheIfCached)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "sg-dek.key", SaltPath: "sg-kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("setup-gate-passphrase"))
	c.SetAuthEncryptor(enc)
	createTestToken(t, c) // bootstrap testadmin + roles

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}
	cfg.Security.RequireMFA = true
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return &setupGateEnv{t: t, core: c, server: srv, router: router}
}

type setupGateResp struct {
	status int
	body   map[string]interface{}
	raw    string
}

func (e *setupGateEnv) do(method, path, token string, body interface{}) setupGateResp {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(e.t, err)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, e.server.URL+path, rd)
	require.NoError(e.t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close() //nolint:errcheck
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	out := setupGateResp{status: resp.StatusCode, raw: buf.String()}
	_ = json.Unmarshal(buf.Bytes(), &out.body)
	return out
}

func (r setupGateResp) data() map[string]interface{} {
	d, _ := r.body["data"].(map[string]interface{})
	return d
}

func (r setupGateResp) pendingSteps() []string {
	raw, _ := r.body["pending_steps"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if str, ok := s.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// passwordLogin performs POST /auth/login and returns the session token
// (empty when the account needs a second factor) and the MFA challenge.
func (e *setupGateEnv) passwordLogin(username, password string) (token, challenge string) {
	e.t.Helper()
	r := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": username, "password": password})
	require.Equal(e.t, http.StatusOK, r.status, "login %s: %s", username, r.raw)
	d := r.data()
	token, _ = d["token"].(string)
	challenge, _ = d["mfa_challenge"].(string)
	return token, challenge
}

// enrolTOTP drives enroll + activate and returns one recovery code (used for
// the follow-up MFA login, so the test never waits for a fresh TOTP step).
func (e *setupGateEnv) enrolTOTP(token, password string) (recoveryCode string, activate setupGateResp) {
	e.t.Helper()
	r := e.do(http.MethodPost, "/api/v1/auth/mfa/enroll", token, map[string]string{})
	require.Equal(e.t, http.StatusOK, r.status, "mfa enroll: %s", r.raw)
	secret, _ := r.data()["secret"].(string)
	require.NotEmpty(e.t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(e.t, err)
	activate = e.do(http.MethodPost, "/api/v1/auth/mfa/activate", token, map[string]string{"code": code, "password": password})
	require.Equal(e.t, http.StatusOK, activate.status, "mfa activate: %s", activate.raw)
	codes, _ := activate.data()["recovery_codes"].([]interface{})
	require.NotEmpty(e.t, codes)
	recoveryCode, _ = codes[0].(string)
	return recoveryCode, activate
}

// recoverAdminState puts the bootstrap admin into exactly the state
// `keyorix-server admin recover-admin` leaves it in (server/admin/
// recover_admin_logic.go): password_reset_required, a one-time password, MFA
// and passkeys cleared, every session revoked.
func (e *setupGateEnv) recoverAdminState() (username, otp string) {
	e.t.Helper()
	ctx := context.Background()
	st := e.core.Storage()
	admin, err := st.GetUserByUsername(ctx, "testadmin")
	require.NoError(e.t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte(setupGateOTP), bcrypt.MinCost)
	require.NoError(e.t, err)
	now := time.Now()
	require.NoError(e.t, st.SetAccountState(ctx, admin.ID, core.AccountPasswordResetRequired, now))
	require.NoError(e.t, st.SetPasswordHash(ctx, admin.ID, string(hash), now))
	require.NoError(e.t, st.SetUserMFAEnabled(ctx, admin.ID, false))
	require.NoError(e.t, st.DeleteMFAForUser(ctx, admin.ID))
	require.NoError(e.t, st.DeleteSessionsForUserExcept(ctx, admin.ID, 0))
	return "testadmin", setupGateOTP
}

// setupStates builds each restricted, factor-less population #3024 names.
var setupStates = map[string]func(e *setupGateEnv) (username, password string){
	"recover-admin": func(e *setupGateEnv) (string, string) { return e.recoverAdminState() },
	"one-time-password user": func(e *setupGateEnv) (string, string) {
		_, res, err := e.core.CreateUserWithOneTimePassword(context.Background(), &core.CreateUserRequest{
			Username: "otp_user", Email: "otp_user@example.com",
		}, 0)
		require.NoError(e.t, err)
		return "otp_user", res.OTPValue
	},
	"admin-forced password reset": func(e *setupGateEnv) (string, string) {
		ctx := context.Background()
		u, err := e.core.CreateUser(ctx, &core.CreateUserRequest{
			Username: "forced_user", Email: "forced_user@example.com", Password: setupGateOTP,
		})
		require.NoError(e.t, err)
		admin, err := e.core.Storage().GetUserByUsername(ctx, "testadmin")
		require.NoError(e.t, err)
		require.NoError(e.t, e.core.RequirePasswordReset(ctx, admin.ID, u.ID))
		return "forced_user", setupGateOTP
	},
	"pending first login": func(e *setupGateEnv) (string, string) {
		_, err := e.core.CreateUser(context.Background(), &core.CreateUserRequest{
			Username: "pending_user", Email: "pending_user@example.com", Password: setupGateOTP,
			AccountState: core.AccountPendingFirstLogin,
		})
		require.NoError(e.t, err)
		return "pending_user", setupGateOTP
	},
}

// TestAccountSetup_EitherOrder_EndsInMFALogin is the runbook journey at the
// HTTP layer, for every restricted population and both step orders.
func TestAccountSetup_EitherOrder_EndsInMFALogin(t *testing.T) {
	for name, mk := range setupStates {
		for _, order := range []string{"mfa-first", "password-first"} {
			t.Run(name+"/"+order, func(t *testing.T) {
				e := newSetupGateEnv(t)
				username, otp := mk(e)

				token, challenge := e.passwordLogin(username, otp)
				require.NotEmpty(t, token, "a restricted, factor-less account logs in with its one-time password")
				require.Empty(t, challenge)

				// Everything but the two setup steps is refused, with the reason.
				r := e.do(http.MethodGet, "/api/v1/projects", token, nil)
				require.Equal(t, http.StatusForbidden, r.status, r.raw)
				assert.ElementsMatch(t, []string{"change_password", "enroll_mfa"}, r.pendingSteps(), r.raw)

				var recovery string
				var last setupGateResp
				if order == "mfa-first" {
					var act setupGateResp
					recovery, act = e.enrolTOTP(token, otp)
					assert.NotEqual(t, true, act.data()["reauthentication_required"], "password still pending: the session continues")
					r = e.do(http.MethodGet, "/api/v1/projects", token, nil)
					require.Equal(t, http.StatusForbidden, r.status, r.raw)
					assert.Equal(t, "PasswordChangeRequired", r.body["error"], r.raw)
					assert.Equal(t, []string{"change_password"}, r.pendingSteps(), r.raw)
					last = e.do(http.MethodPost, "/api/v1/auth/change-password", token,
						map[string]string{"current_password": otp, "new_password": setupGateNewPassword})
					require.Equal(t, http.StatusOK, last.status, last.raw)
				} else {
					cp := e.do(http.MethodPost, "/api/v1/auth/change-password", token,
						map[string]string{"current_password": otp, "new_password": setupGateNewPassword})
					require.Equal(t, http.StatusOK, cp.status, cp.raw)
					assert.NotEqual(t, true, cp.data()["reauthentication_required"], "MFA still pending: the session continues")
					r = e.do(http.MethodGet, "/api/v1/projects", token, nil)
					require.Equal(t, http.StatusForbidden, r.status, r.raw)
					assert.Equal(t, "MFAEnrollmentRequired", r.body["error"], r.raw)
					assert.Equal(t, []string{"enroll_mfa"}, r.pendingSteps(), r.raw)
					recovery, last = e.enrolTOTP(token, setupGateNewPassword)
				}
				assert.Equal(t, true, last.data()["reauthentication_required"], "the last setup step ends the session: %s", last.raw)

				// The setup session is gone: it never gains full access.
				r = e.do(http.MethodGet, "/api/v1/auth/profile", token, nil)
				assert.Equal(t, http.StatusUnauthorized, r.status, "setup session must be revoked after the last step: %s", r.raw)
				r = e.do(http.MethodGet, "/api/v1/projects", token, nil)
				assert.Equal(t, http.StatusUnauthorized, r.status, r.raw)

				// The one-time password is dead; the new password alone is not enough.
				bad := e.do(http.MethodPost, "/auth/login", "", map[string]string{"username": username, "password": otp})
				assert.Equal(t, http.StatusUnauthorized, bad.status, bad.raw)
				tok, chal := e.passwordLogin(username, setupGateNewPassword)
				require.Empty(t, tok, "the next login must require the second factor")
				require.NotEmpty(t, chal)

				v := e.do(http.MethodPost, "/auth/mfa/verify", "", map[string]string{"mfa_challenge": chal, "code": recovery})
				require.Equal(t, http.StatusOK, v.status, v.raw)
				full, _ := v.data()["token"].(string)
				require.NotEmpty(t, full)
				r = e.do(http.MethodGet, "/api/v1/auth/profile", full, nil)
				assert.Equal(t, http.StatusOK, r.status, r.raw)
				r = e.do(http.MethodGet, "/api/v1/notifications", full, nil)
				assert.Equal(t, http.StatusOK, r.status, "a normal MFA session is unconfined: %s", r.raw)
			})
		}
	}
}

// setupAllowedRoutes is the exact set a session with both setup steps pending
// may reach (beyond the public, unauthenticated routes outside /api/v1).
var setupAllowedRoutes = map[string]bool{
	"POST /api/v1/auth/change-password":          true,
	"GET /api/v1/auth/profile":                   true,
	"POST /api/v1/auth/mfa/enroll":               true,
	"POST /api/v1/auth/mfa/activate":             true,
	"POST /api/v1/auth/webauthn/register/begin":  true,
	"POST /api/v1/auth/webauthn/register/finish": true,
	"GET /api/v1/auth/webauthn/credentials":      true,
}

// TestAccountSetupGate_EveryOtherRouteDenied is the guard over the route
// registry: walks every route the real router registers under /api/v1 and
// asserts a setup session gets 403 with the pending steps on every one of
// them except setupAllowedRoutes, which must pass the gate. A new route is
// covered automatically; widening the allowlist needs an edit here.
func TestAccountSetupGate_EveryOtherRouteDenied(t *testing.T) {
	e := newSetupGateEnv(t)
	username, otp := e.recoverAdminState()
	token, _ := e.passwordLogin(username, otp)
	require.NotEmpty(t, token)

	routes, ok := e.router.(chi.Routes)
	require.True(t, ok)
	seenAllowed := map[string]bool{}
	var denied int
	var public []string
	require.NoError(t, chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/api/v1/") {
			return nil // public or separately-authenticated (SCIM bearer, health, login)
		}
		key := method + " " + route
		path := routeParamRe.ReplaceAllString(route, "1")
		if anon := e.do(method, path, "", map[string]string{}); anon.status != http.StatusUnauthorized {
			public = append(public, key) // registered outside the authenticated group
			return nil
		}
		if setupAllowedRoutes[key] {
			seenAllowed[key] = true
			return nil // exercised below, without side effects from a blind call
		}
		r := e.do(method, path, token, map[string]string{})
		if assert.Equalf(t, http.StatusForbidden, r.status, "%s must be refused for a setup session: %s", key, r.raw) {
			assert.ElementsMatchf(t, []string{"change_password", "enroll_mfa"}, r.pendingSteps(),
				"%s: the 403 must name the pending steps: %s", key, r.raw)
		}
		denied++
		return nil
	}))
	assert.Greater(t, denied, 100, "sanity: the walk must cover the API surface")
	// Only these /api/v1 routes are public; anything else answering an anonymous
	// caller without 401 would bypass this gate along with authentication.
	assert.ElementsMatch(t, []string{"GET /api/v1/version"}, public)
	for k := range setupAllowedRoutes {
		assert.Truef(t, seenAllowed[k], "allowlisted route %s is no longer registered: drop it from the allowlist", k)
	}

	// The allowlisted reads pass the gate.
	r := e.do(http.MethodGet, "/api/v1/auth/profile", token, nil)
	assert.Equal(t, http.StatusOK, r.status, r.raw)
	r = e.do(http.MethodGet, "/api/v1/auth/webauthn/credentials", token, nil)
	assert.NotContains(t, r.raw, "pending_steps", "credential listing must pass the setup gate")
	// Profile is read-only for a setup session: changing identity fields is not a setup step.
	r = e.do(http.MethodPut, "/api/v1/auth/profile", token, map[string]string{"display_name": "x"})
	assert.Equal(t, http.StatusForbidden, r.status, r.raw)
}

// TestAccountSetup_OnlyMFAPendingCannotChangePassword: a factor-less but
// otherwise active account (first admin on a fresh install) is confined to
// enrolment only; change-password is a setup step only while it is pending.
func TestAccountSetup_OnlyMFAPendingCannotChangePassword(t *testing.T) {
	e := newSetupGateEnv(t)
	token, _ := e.passwordLogin("testadmin", "TestPassword123!")
	require.NotEmpty(t, token)
	r := e.do(http.MethodPost, "/api/v1/auth/change-password", token,
		map[string]string{"current_password": "TestPassword123!", "new_password": setupGateNewPassword})
	require.Equal(t, http.StatusForbidden, r.status, r.raw)
	assert.Equal(t, "MFAEnrollmentRequired", r.body["error"])
	assert.Equal(t, []string{"enroll_mfa"}, r.pendingSteps(), r.raw)

	// Fresh-install first admin: enrolment keeps the session (#2978), no deadlock.
	_, act := e.enrolTOTP(token, "TestPassword123!")
	assert.NotEqual(t, true, act.data()["reauthentication_required"])
	r = e.do(http.MethodGet, "/api/v1/notifications", token, nil)
	assert.Equal(t, http.StatusOK, r.status, r.raw)
}
