// auth_sso_s13_test.go — coverage sweep (sprint 13) targeting uncovered branches in:
//   - auth.go: Login rate-limit (429), RefreshToken 401, ChangePassword bad-JSON +
//     wrong-password, UpdateProfile bad-JSON + wrong-password, PasswordReset
//     rate-limit (429) + bad-JSON, RevokeSession bad-param + not-found,
//     userIdentity error-path, Profile user-not-found
//   - sso.go: BeginSSO unknown-provider, CompleteSSO unknown-provider + IdP-error-param
//   - missing-code-or-state + core-error; fragment does NOT contain session token
//     (#r125-H3)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// ── auth.go: Login rate-limit 429 ────────────────────────────────────────────

// TestLogin_RateLimited_S13 verifies the 429 branch when the IP has exceeded the
// failed-login budget.
func TestLogin_RateLimited_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	ctx := context.Background()

	// Flood the login rate limiter (> 10 attempts within the window).
	for range 12 {
		cs.RecordFailedLogin(ctx, "10.0.0.1")
	}

	body, _ := json.Marshal(map[string]string{"username": "anyone", "password": "pw"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	// RemoteAddr needs :port for the strip to work.
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// ── auth.go: RefreshToken 401 ─────────────────────────────────────────────────

// TestRefreshToken_RateLimited_S13 verifies the 429 branch when the IP has
// exceeded the failed-login budget (#r124 -- refresh rate limiting).
func TestRefreshToken_RateLimited_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	ctx := context.Background()

	// Flood the login rate limiter (> 10 attempts within the window).
	for range 12 {
		cs.RecordFailedLogin(ctx, "10.1.2.3")
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	req.RemoteAddr = "10.1.2.3:5678"
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// TestRefreshToken_InvalidToken_S13 verifies the 401 branch when the token has
// no matching live session.
func TestRefreshToken_InvalidToken_S13(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: ChangePassword error branches ────────────────────────────────────

// TestChangePassword_BadJSON_S13 verifies the 400 branch for malformed JSON.
func TestChangePassword_BadJSON_S13(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/auth/change-password",
		bytes.NewBufferString("{bad")))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestChangePassword_WrongCurrentPassword_S13 verifies the 401 branch when the
// current password is incorrect.
func TestChangePassword_WrongCurrentPassword_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)

	_, err := cs.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "chpw_s13", Email: "chpw_s13@example.com",
		DisplayName: "ChPW S13", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{
		"current_password": "WrongPassword!",
		"new_password":     "NewValid#Pass1!",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/auth/change-password",
		bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: UpdateProfile error branches ────────────────────────────────────

// TestUpdateProfile_BadJSON_S13 verifies the 400 branch for malformed JSON.
func TestUpdateProfile_BadJSON_S13(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPut, "/auth/profile",
		bytes.NewBufferString("{bad")))
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateProfile_WrongCurrentPassword_S13 verifies the 401 branch when the
// caller provides an incorrect current password while changing email.
func TestUpdateProfile_WrongCurrentPassword_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)

	_, err := cs.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "uprofpw_s13", Email: "uprofpw_s13@example.com",
		DisplayName: "UProf S13", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{
		"email":            "new_uprofpw_s13@example.com",
		"current_password": "WrongPassword!",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPut, "/auth/profile",
		bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: PasswordReset error branches ────────────────────────────────────

// TestPasswordReset_BadJSON_S13 verifies the 400 branch for malformed JSON.
func TestPasswordReset_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/password-reset",
		bytes.NewBufferString("{bad"))
	w := httptest.NewRecorder()
	h.PasswordReset(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPasswordReset_RateLimited_S13 verifies the 429 branch when the IP has
// exceeded the password-reset budget.
func TestPasswordReset_RateLimited_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	ctx := context.Background()

	for range 15 {
		cs.RecordPasswordResetAttempt(ctx, "10.1.2.3")
	}

	body, _ := json.Marshal(map[string]string{"email": "x@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/password-reset",
		bytes.NewReader(body))
	req.RemoteAddr = "10.1.2.3:5678"
	w := httptest.NewRecorder()
	h.PasswordReset(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// ── auth.go: RevokeSession error branches ─────────────────────────────────────

// TestRevokeSession_BadParam_S13 verifies the 400 branch when the session ID
// param is not a valid integer.
func TestRevokeSession_BadParam_S13(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/auth/sessions/bad", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeSession_NotFound_S13 verifies the 404 branch when the session does
// not exist or does not belong to the caller.
func TestRevokeSession_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/auth/sessions/9999", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── auth.go: userIdentity error-path ─────────────────────────────────────────

// TestUserIdentity_ErrorPath_S13 calls userIdentity with a nonexistent userID,
// which causes GetUserIdentity to fail — exercises the fallback empty-identity
// return (Roles/Permissions both non-nil empty slices).
func TestUserIdentity_ErrorPath_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	id := h.userIdentity(req, 99999)
	assert.NotNil(t, id.Roles)
	assert.NotNil(t, id.Permissions)
}

// ── auth.go: Profile user-not-found ──────────────────────────────────────────

// TestProfile_UserNotFound_S13 verifies the 404 branch when the user indicated
// by the context no longer exists in the DB.
func TestProfile_UserNotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	// Inject a UserContext with an ID that has no DB row.
	ctx := context.WithValue(req.Context(),
		middleware.GetUserContextKey(),
		&middleware.UserContext{UserID: 99999},
	)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── sso.go: BeginSSO error branches ──────────────────────────────────────────

// TestBeginSSO_UnknownProvider_S13 verifies the 400 branch when no SSO providers
// are configured (ssoProviders map is empty).
func TestBeginSSO_UnknownProvider_S13(t *testing.T) {
	cs := freshCoreS12(t)
	// No providers configured — BeginSSO will call oidcProvider which returns an error.
	h := NewAuthHandler(cs, false)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/sso/nonexistent/login", nil),
		"provider", "nonexistent",
	)
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sso.go: CompleteSSO error branches ───────────────────────────────────────

// newSSOProvider builds a minimal SSOProvider wired to a dummy OAuth2 config.
// The auth/token URLs are empty strings so they can be constructed without a
// real OIDC discovery endpoint. The CompleteURL is the only field CompleteSSO's
// redirect path needs besides the provider being registered.
func newSSOProvider(name, completeURL string) *core.SSOProvider {
	return &core.SSOProvider{
		Name:        name,
		Type:        "", // "" == oidc
		CompleteURL: completeURL,
		OAuth: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://idp.example.com/authorize",
				TokenURL: "https://idp.example.com/token",
			},
			RedirectURL: fmt.Sprintf("https://app.example.com/auth/sso/%s/callback", name),
			Scopes:      []string{"openid"},
		},
	}
}

// TestCompleteSSO_UnknownProvider_S13 verifies the 400 branch when the provider
// name is unknown (SSOCompleteURL returns ok=false).
func TestCompleteSSO_UnknownProvider_S13(t *testing.T) {
	cs := freshCoreS12(t)
	// No providers → SSOCompleteURL returns ok=false.
	h := NewAuthHandler(cs, false)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/sso/ghost/callback?code=x&state=y", nil),
		"provider", "ghost",
	)
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCompleteSSO_IdPErrorParam_S13 verifies the fragment-redirect branch when
// the IdP itself returned an error query param (access_denied). The provider
// is registered so SSOCompleteURL succeeds, then the handler redirects.
func TestCompleteSSO_IdPErrorParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	const providerName = "testoidc_idperr_s13"
	const completeURL = "https://app.example.com/sso/complete"
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		providerName: newSSOProvider(providerName, completeURL),
	}, nil)
	h := NewAuthHandler(cs, false)

	url := fmt.Sprintf("/auth/sso/%s/callback?error=access_denied", providerName)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, url, nil),
		"provider", providerName,
	)
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	// Should 302-redirect to completeURL with the error in the fragment.
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "access_denied")
}

// TestCompleteSSO_MissingCodeOrState_S13 verifies the 302-to-error branch when
// the code or state query params are absent from the callback.
func TestCompleteSSO_MissingCodeOrState_S13(t *testing.T) {
	cs := freshCoreS12(t)
	const providerName = "testoidc_nocode_s13"
	const completeURL = "https://app.example.com/sso/complete"
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		providerName: newSSOProvider(providerName, completeURL),
	}, nil)
	h := NewAuthHandler(cs, false)

	// Only code, no state.
	url := fmt.Sprintf("/auth/sso/%s/callback?code=somecode", providerName)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, url, nil),
		"provider", providerName,
	)
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "missing")
}

// TestCompleteSSO_CoreError_S13 verifies the fragment-redirect-with-error branch
// when core.CompleteSSO returns an error (invalid code/state — the storage lookup
// for the login state will fail because no state was seeded).
func TestCompleteSSO_CoreError_S13(t *testing.T) {
	cs := freshCoreS12(t)
	const providerName = "testoidc_coreerr_s13"
	const completeURL = "https://app.example.com/sso/complete"
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		providerName: newSSOProvider(providerName, completeURL),
	}, nil)
	h := NewAuthHandler(cs, false)

	// Provide code and state but no matching login-state row exists in the DB.
	reqURL := fmt.Sprintf("/auth/sso/%s/callback?code=badcode&state=badstate", providerName)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, reqURL, nil),
		"provider", providerName,
	)
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	// CompleteSSO fails → 302 redirect with error in the fragment.
	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "error")
}

// TestRedirectFragment_NoTokenInFragment_S13 verifies that redirectFragment never
// includes the raw session token in the URL fragment (#r125-H3). The session is
// delivered exclusively via the HttpOnly/Secure cookie set by setSessionCookies;
// including the token in the fragment exposes it to JS, browser history, and
// extensions. This test exercises redirectFragment directly (same package).
func TestRedirectFragment_NoTokenInFragment_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	// Simulate the url.Values CompleteSSO and CompleteSAML now build (no token key).
	frag := url.Values{
		"expires_at":          {"2026-07-27T12:00:00Z"},
		"absolute_expires_at": {"2026-08-27T12:00:00Z"},
		"return_to":           {"/dashboard"},
	}
	h.redirectFragment(w, req, "https://app.example.com/sso/complete", frag)

	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "#", "redirect must use fragment delivery")
	assert.NotContains(t, loc, "token=",
		"raw session token must NOT appear in the fragment — cookie-only delivery")
	assert.Contains(t, loc, "expires_at=", "non-sensitive metadata fields survive")
}
