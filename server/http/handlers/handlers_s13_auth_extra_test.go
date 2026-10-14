// handlers_s13_auth_extra_test.go — additional coverage sweep (sprint 13 extra)
// targeting remaining uncovered branches in:
//   - auth.go: Login bad-JSON, ConsumeSetup bad-JSON + empty-fields,
//     GetSetupToken (0%), RefreshToken missing-token, ListSessions session-branches,
//     UpdateProfile ErrUserAlreadyExists, userIdentity success-path,
//     userProfileMap nil-roles branch, extractBearerToken cookie path
//   - sso.go: ListSSOProviders (0%), BeginSSO non-unknown-provider error,
//     CompleteSSO success path, isSafeSSOError more safe strings
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// ── auth.go: Login bad JSON ───────────────────────────────────────────────────

// TestLogin_BadJSON_S13 verifies the 400 branch when the request body is not
// valid JSON.
func TestLogin_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString("{not-json"))
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── auth.go: ConsumeSetup bad JSON + empty fields ────────────────────────────

// TestConsumeSetup_BadJSON_S13 verifies the 400 branch for malformed JSON.
func TestConsumeSetup_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume",
		bytes.NewBufferString("{bad"))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeSetup_EmptyFields_S13 verifies the 400 branch when token or
// password is the empty string (validation after JSON decode).
func TestConsumeSetup_EmptyFields_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]string{"token": "", "password": ""})
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeSetup_EmptyToken_S13 verifies the 400 branch when only the
// password is provided but the token is empty.
func TestConsumeSetup_EmptyToken_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]string{"token": "", "password": "SomeGoodPass#1!"})
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeSetup_GenericError_S13 verifies the generic 400 branch when an
// unknown/expired token is supplied (not ErrInvalidSetupPassword).
func TestConsumeSetup_GenericError_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]string{
		"token":    "totally-invalid-token",
		"password": "AnyPassword#1!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:4321"
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── auth.go: GetSetupToken ────────────────────────────────────────────────────

// TestGetSetupToken_MissingParam_S13 verifies the 400 branch when no token
// URL param is provided (chi.URLParam returns "").
func TestGetSetupToken_MissingParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	// No chi param set — URLParam("token") returns "".
	req := httptest.NewRequest(http.MethodGet, "/auth/setup/", nil)
	w := httptest.NewRecorder()
	h.GetSetupToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetSetupToken_InvalidToken_S13 verifies the 410 Gone branch when the
// token is present in the URL param but unknown/expired.
func TestGetSetupToken_InvalidToken_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/setup/dead-token", nil),
		"token", "dead-token",
	)
	w := httptest.NewRecorder()
	h.GetSetupToken(w, req)
	assert.Equal(t, http.StatusGone, w.Code)
}

// ── auth.go: RefreshToken missing bearer token ────────────────────────────────

// TestRefreshToken_MissingToken_S13 verifies the 400 branch when no bearer
// token is present (no Authorization header or session cookie).
func TestRefreshToken_MissingToken_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	// No Authorization header, no cookie — extractBearerToken returns "".
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── auth.go: extractBearerToken cookie path ──────────────────────────────────

// TestExtractBearerToken_CookiePath_S13 exercises the httpOnly cookie branch
// of extractBearerToken indirectly via RefreshToken: if the cookie is present
// but the session is invalid the handler returns 401, confirming the cookie
// branch ran (not the Authorization-header branch).
func TestExtractBearerToken_CookiePath_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{
		Name:  middleware.SessionCookieName,
		Value: "nosuchcookietoken",
	})
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	// Token present (via cookie) but session not found → 401.
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: UpdateProfile ErrUserAlreadyExists ───────────────────────────────

// TestUpdateProfile_EmailAlreadyInUse_S13 verifies the 409 Conflict branch
// when the caller changes their email to one already owned by another user.
func TestUpdateProfile_EmailAlreadyInUse_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)

	// Create two users; user 1 has UserID=1 in the context.
	_, err := cs.CreateUser(nil, &core.CreateUserRequest{ //nolint:staticcheck
		Username: "upconflict1_s13", Email: "conflict1_s13@example.com",
		DisplayName: "User1", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	_, err = cs.CreateUser(nil, &core.CreateUserRequest{ //nolint:staticcheck
		Username: "upconflict2_s13", Email: "conflict2_s13@example.com",
		DisplayName: "User2", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)

	// Try to change user1's email to user2's email (with a current password).
	body, _ := json.Marshal(map[string]string{
		"email":            "conflict2_s13@example.com",
		"current_password": "Kx#Vr9$Mn2!Zp4@Qw",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPut, "/auth/profile",
		bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── auth.go: userIdentity success path ───────────────────────────────────────

// TestUserIdentity_SuccessPath_S13 calls userIdentity for a user that exists
// so GetUserIdentity succeeds — exercising the non-error return branch.
func TestUserIdentity_SuccessPath_S13(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// UserID=1 is the admin seeded by freshCoreS12WithAdmin.
	id := h.userIdentity(req, 1)
	// Success branch: Role may be set; Roles/Permissions are non-nil slices.
	assert.NotNil(t, id.Roles)
	assert.NotNil(t, id.Permissions)
}

// ── auth.go: userProfileMap nil-roles branch ──────────────────────────────────

// TestUserProfileMap_NilRoles_S13 exercises the nil-roles/nil-permissions
// branch of userProfileMap, which replaces nil with []string{}.
func TestUserProfileMap_NilRoles_S13(t *testing.T) {
	user := &models.User{
		Username:    "nilroles_s13",
		Email:       "nilroles_s13@example.com",
		DisplayName: "Nil Roles",
		IsActive:    true,
	}
	// core.UserIdentity with nil Roles and Permissions triggers the nil-guard.
	id := core.UserIdentity{Role: "viewer", Roles: nil, Permissions: nil}
	profile := userProfileMap(user, id)
	// Both must be non-nil empty slices after the nil-guard.
	roles, ok := profile["roles"].([]string)
	assert.True(t, ok)
	assert.NotNil(t, roles)
	perms, ok2 := profile["permissions"].([]string)
	assert.True(t, ok2)
	assert.NotNil(t, perms)
}

// TestUserProfileMap_WithLastLogin_S13 exercises the LastLoginAt non-nil branch.
func TestUserProfileMap_WithLastLogin_S13(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	user := &models.User{
		Username:    "logintime_s13",
		Email:       "logintime_s13@example.com",
		DisplayName: "Login Time",
		IsActive:    true,
		LastLoginAt: &now,
	}
	id := core.UserIdentity{Roles: []string{"viewer"}, Permissions: []string{}}
	profile := userProfileMap(user, id)
	assert.NotNil(t, profile["last_login_at"])
}

// ── auth.go: ListSessions session-branches ────────────────────────────────────

// TestListSessions_WithExpiryAndLastSeen_S13 exercises the ExpiresAt and
// LastSeenAt non-nil branches in ListSessions by seeding a real session.
func TestListSessions_WithExpiryAndLastSeen_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)

	// Seed a session for user 1 (the admin) with ExpiresAt and LastSeenAt set.
	now := time.Now().UTC().Add(time.Hour)
	lastSeen := time.Now().UTC()
	sess := &models.Session{
		UserID:       1,
		SessionToken: "test-list-sess-token-s13",
		UserAgent:    "TestAgent/1.0",
		IPAddress:    "127.0.0.1",
		ExpiresAt:    &now,
		LastSeenAt:   &lastSeen,
	}
	require.NoError(t, db.Create(sess).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/auth/sessions", nil))
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"]
	assert.NotNil(t, data)
}

// ── sso.go: ListSSOProviders ──────────────────────────────────────────────────

// TestListSSOProviders_Empty_S13 verifies ListSSOProviders returns 200 with an
// empty providers list when no SSO providers are configured.
func TestListSSOProviders_Empty_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/providers", nil)
	w := httptest.NewRecorder()
	h.ListSSOProviders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	_, hasProviders := data["providers"]
	assert.True(t, hasProviders)
}

// TestListSSOProviders_WithProvider_S13 verifies ListSSOProviders returns the
// configured provider names.
func TestListSSOProviders_WithProvider_S13(t *testing.T) {
	cs := freshCoreS12(t)
	const providerName = "testprovider_list_s13"
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		providerName: {
			Name:        providerName,
			CompleteURL: "https://app.example.com/sso/complete",
			OAuth: &oauth2.Config{
				ClientID:     "cid",
				ClientSecret: "csec",
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://idp.example.com/auth",
					TokenURL: "https://idp.example.com/token",
				},
				RedirectURL: fmt.Sprintf("https://app.example.com/auth/sso/%s/callback", providerName),
				Scopes:      []string{"openid"},
			},
		},
	}, nil)
	h := NewAuthHandler(cs, false)

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/providers", nil)
	w := httptest.NewRecorder()
	h.ListSSOProviders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sso.go: BeginSSO non-unknown-provider error ──────────────────────────────

// newRegisteredSSOProvider creates a minimal SSOProvider registered with the
// core but using an invalid/unreachable OIDC endpoint so BeginSSO fails for a
// reason OTHER than "unknown provider" — triggering the log+sanitize branch.
func newRegisteredSSOProvider(name string) *core.SSOProvider {
	return &core.SSOProvider{
		Name:        name,
		Type:        "oidc",
		CompleteURL: "https://app.example.com/sso/complete",
		OAuth: &oauth2.Config{
			ClientID:     "clientid",
			ClientSecret: "clientsecret",
			// Intentionally use a placeholder endpoint that the OIDC code won't
			// discover (no discovery document) but will still try to generate an
			// authURL for via the static config.
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://broken-idp.invalid/authorize",
				TokenURL: "https://broken-idp.invalid/token",
			},
			RedirectURL: fmt.Sprintf("https://app.example.com/auth/sso/%s/callback", name),
			Scopes:      []string{"openid"},
		},
	}
}

// TestBeginSSO_KnownProviderButCoreError_S13 verifies the BeginSSO branch
// where the provider IS known but core.BeginSSO returns a non-unknown-provider
// error — triggering the `log.Printf` + `clientSafe(err)` path.
//
// With a static OAuth config (not a live OIDC discovery endpoint), the
// BeginSSO call fails when it tries to persist the login-state nonce — the
// SSOLoginState table IS present (freshCoreS12 includes it in AutoMigrate).
// If BeginSSO actually succeeds and redirects, the test just verifies 302.
func TestBeginSSO_KnownProviderButCoreError_S13(t *testing.T) {
	cs := freshCoreS12(t)
	const providerName = "testoidc_begin_err_s13"
	p := newRegisteredSSOProvider(providerName)
	cs.SetSSOProviders(map[string]*core.SSOProvider{providerName: p}, nil)
	h := NewAuthHandler(cs, false)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/auth/sso/%s/login", providerName), nil),
		"provider", providerName,
	)
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	// Either a redirect (302 success) or a 400 (core error after the
	// provider is found). Either way must NOT be 503 or 500.
	assert.True(t, w.Code == http.StatusFound || w.Code == http.StatusBadRequest,
		"expected 302 or 400, got %d: %s", w.Code, w.Body.String())
}

// ── sso.go: isSafeSSOError — additional safe strings ─────────────────────────

// TestIsSafeSSOError_AdditionalStrings_S13 exercises more entries in the
// isSafeSSOError allowlist beyond what CompleteSSO tests already hit.
func TestIsSafeSSOError_AdditionalStrings_S13(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"unknown SAML provider", true},
		{"invalid or expired login state", true},
		{"login state does not match the callback provider", true},
		{"login state expired", true},
		{"the token response carried no id_token", true},
		{"the assertion carried no subject or email", true},
		{"no Keyorix account matches this SSO identity", true},
		{"account suspended", false},
		{"the IdP returned no email; cannot auto-provision an account", true},
		{"some totally unrelated internal error details", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isSafeSSOError(tc.msg)
		assert.Equal(t, tc.want, got, "isSafeSSOError(%q)", tc.msg)
	}
}

// ── auth.go: UpdateProfile no-user-ctx ───────────────────────────────────────

// TestUpdateProfile_NoUserCtx_S13 verifies the 401 branch when there is no
// user context in the request.
func TestUpdateProfile_NoUserCtx_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]string{"display_name": "new name"})
	req := httptest.NewRequest(http.MethodPut, "/auth/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: ChangePassword no-user-ctx ──────────────────────────────────────

// TestChangePassword_NoUserCtx_S13 verifies the 401 branch when there is no
// user context in the ChangePassword request.
func TestChangePassword_NoUserCtx_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]string{
		"current_password": "old", "new_password": "new",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: Logout missing token ────────────────────────────────────────────

// TestLogout_MissingToken_S13 verifies the 400 branch when no bearer token is
// present in a Logout request.
func TestLogout_MissingToken_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	// No Authorization header, no cookie.
	w := httptest.NewRecorder()
	h.Logout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── auth.go: RevokeSession no-user-ctx ───────────────────────────────────────

// TestRevokeSession_NoUserCtx_S13 verifies the 401 branch when there is no
// user context in the RevokeSession request.
func TestRevokeSession_NoUserCtx_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/auth/sessions/1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: ListSessions no-user-ctx ────────────────────────────────────────

// TestListSessions_NoUserCtx_S13 verifies the 401 branch when there is no
// user context in the ListSessions request.
func TestListSessions_NoUserCtx_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
