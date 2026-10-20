// reauth_budget_test.go — AUTH-2 item 4: the authenticated second-factor
// re-checks (MFA activate / disable / recovery-code regenerate, step-up,
// passkey delete) take a guessable code or password and fed only the
// per-account lockout. They now spend the same per-IP login budget as
// /auth/login: a rejected code keeps its slot, any other outcome hands it back.
// (Passkey register-finish is pinned by the route guard; its body needs a
// parsed attestation before the check is reached.)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newReauthBudgetEnv is setupMFAStepUpTest plus the login_attempts table, with
// TOTP activated for alice. The account lockout stays off (NewKeyorixCore's
// default), so the per-IP budget is what these tests see.
func newReauthBudgetEnv(t *testing.T) (*AuthHandler, *gorm.DB, string) {
	t.Helper()
	h, coreService, db := setupMFAStepUpTest(t)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}, &models.WebAuthnCredential{}))
	secret, _ := activateMFAForStepUpTest(t, coreService)
	return h, db, secret
}

func reauthRequest(t *testing.T, method, path string, body any, urlParams map[string]string) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	r := withUserContext(httptest.NewRequest(method, path, bytes.NewReader(raw)), 1)
	if len(urlParams) > 0 {
		rctx := chi.NewRouteContext()
		for k, v := range urlParams {
			rctx.URLParams.Add(k, v)
		}
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	}
	return r
}

type reauthRoute struct {
	name    string
	handler func(h *AuthHandler) http.HandlerFunc
	method  string
	path    string
	params  map[string]string
}

var reauthBudgetRoutes = []reauthRoute{
	{"activate", func(h *AuthHandler) http.HandlerFunc { return h.ActivateMFA }, http.MethodPost, "/auth/mfa/activate", nil},
	{"disable", func(h *AuthHandler) http.HandlerFunc { return h.DisableMFA }, http.MethodPost, "/auth/mfa/disable", nil},
	{"regenerate", func(h *AuthHandler) http.HandlerFunc { return h.RegenerateRecoveryCodes }, http.MethodPost, "/auth/mfa/recovery-codes/regenerate", nil},
	{"stepup", func(h *AuthHandler) http.HandlerFunc { return h.MFAStepUp }, http.MethodPost, "/auth/mfa/stepup", nil},
	{"webauthn_delete", func(h *AuthHandler) http.HandlerFunc { return h.DeleteWebAuthnCredential }, http.MethodDelete, "/auth/webauthn/credentials/7", map[string]string{"id": "7"}},
}

func TestReauthRoutes_WrongCodesSpendTheLoginBudget(t *testing.T) {
	for _, rt := range reauthBudgetRoutes {
		t.Run(rt.name, func(t *testing.T) {
			h, db, _ := newReauthBudgetEnv(t)
			wrong := map[string]string{"code": "000000", "password": "wrong-guess"}
			for i := range core.LoginMaxAttempts {
				w := httptest.NewRecorder()
				rt.handler(h)(w, reauthRequest(t, rt.method, rt.path, wrong, rt.params))
				require.NotEqual(t, http.StatusTooManyRequests, w.Code, "guess %d: %s", i+1, w.Body.String())
				require.NotEqual(t, http.StatusOK, w.Code, "guess %d: %s", i+1, w.Body.String())
			}
			require.EqualValues(t, core.LoginMaxAttempts, loginAttemptsFor(t, db), "every rejected guess keeps its slot")

			w := httptest.NewRecorder()
			rt.handler(h)(w, reauthRequest(t, rt.method, rt.path, wrong, rt.params))
			require.Equal(t, http.StatusTooManyRequests, w.Code, "budget spent: %s", w.Body.String())
			require.Equal(t, http.StatusTooManyRequests, postLoginAs(t, h, "wrong-guess").Code, "one budget, shared with /auth/login")
		})
	}
}

// Equivalence: a correct code still works and costs no slot.
func TestMFAStepUp_CorrectCodeReturnsTheSlot(t *testing.T) {
	h, db, secret := newReauthBudgetEnv(t)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.MFAStepUp(w, reauthRequest(t, http.MethodPost, "/auth/mfa/stepup", map[string]string{"code": code}, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, loginAttemptsFor(t, db))
}

// A refusal that evaluated no credential (MFA not enabled) hands the slot back.
func TestDisableMFA_NotEnabledReturnsTheSlot(t *testing.T) {
	h, _, db := setupMFAStepUpTest(t)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}))
	w := httptest.NewRecorder()
	h.DisableMFA(w, reauthRequest(t, http.MethodPost, "/auth/mfa/disable", map[string]string{"code": "000000"}, nil))
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Zero(t, loginAttemptsFor(t, db))
}
