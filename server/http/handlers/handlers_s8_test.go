// handlers_s8_test.go — sprint-8 coverage sweep: targets functions left at low
// coverage after s3–s7. Uses the same shared-DB pattern from handlers_s4_test.go
// (sharedS4CoreOnce / newHandlerCoreS4) to avoid CI timeout risk.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// freshCoreS8 creates a brand-new in-memory SQLite DB (unique DSN per call).
// Use this for tests that call BootstrapSystem, Login, or any other stateful
// flow that would conflict with the shared s4 DB.
func freshCoreS8(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s8_")
	err := db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
		&models.MFAChallenge{}, &models.SSOLoginState{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.SecretDependency{}, &models.RiskException{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.IdentityProvider{}, &models.ExternalIdentity{},
		&models.LegalHold{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
	)
	require.NoError(t, err)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	cs.SetDynamicAllowPrivateTargets(true) // tests use localhost DSNs; SSRF guard tested in dynamic_secrets_ssrf_test.go
	// ADR-109 step 3: internal/core no longer defaults to dynamic.New internally
	// (that would mean importing internal/dynamic from production code) — wire it
	// explicitly here, exactly as server/main.go's DefaultIntegrations does.
	cs.SetDynamicEngineFactory(func(bt string) (dynamic.CredentialEngine, error) { return dynamic.New(bt, true, false) })
	return cs
}

// bootstrapS8 boots a fresh core and returns a session token for the admin.
func bootstrapS8(t *testing.T, cs *core.KeyorixCore, suffix string) string {
	t.Helper()
	ctx := context.Background()
	token := fmt.Sprintf("s8-%s-boot", suffix)
	cs.SetBootstrapToken(token)
	_, err := cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s8" + suffix,
		Email:    fmt.Sprintf("s8%s@example.com", suffix),
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    token,
	})
	require.NoError(t, err)
	session, _, err := cs.Login(ctx, &core.LoginRequest{
		Username: "s8" + suffix,
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	return session.SessionToken
}

// newDynamicSecretHandlerS8 creates a DynamicSecretHandler backed by the shared s4 DB.
func newDynamicSecretHandlerS8(t *testing.T) *DynamicSecretHandler {
	t.Helper()
	return NewDynamicSecretHandler(newHandlerCoreS4(t))
}

// newImpersonationHandlerS8 creates an ImpersonationHandler backed by the shared s4 DB.
func newImpersonationHandlerS8(t *testing.T) *ImpersonationHandler {
	t.Helper()
	return NewImpersonationHandler(newHandlerCoreS4(t), false)
}

// newAuthHandlerS8 creates an AuthHandler backed by the shared s4 DB.
func newAuthHandlerS8(t *testing.T) *AuthHandler {
	t.Helper()
	return NewAuthHandler(newHandlerCoreS4(t), false)
}

// newCatalogHandlerS8 creates a CatalogHandler backed by the shared s4 DB.
func newCatalogHandlerS8(t *testing.T) *CatalogHandler {
	t.Helper()
	return NewCatalogHandler(newHandlerCoreS4(t))
}

// newGroupHandlerS8 creates a GroupHandler backed by the shared s4 DB.
func newGroupHandlerS8(t *testing.T) *GroupHandler {
	t.Helper()
	h, err := NewGroupHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

// newDashboardHandlerS8 creates a DashboardHandler backed by the shared s4 DB.
func newDashboardHandlerS8(t *testing.T) *DashboardHandler {
	t.Helper()
	return NewDashboardHandler(newHandlerCoreS4(t))
}

// withUserCtxS8 injects a standard user context into the request.
func withUserCtxS8(r *http.Request) *http.Request {
	uc := &middleware.UserContext{
		UserID:   1,
		Username: "testuser",
		Email:    "testuser@example.com",
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// withChiParamS8 injects a single chi URL param into the request.
func withChiParamS8(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// withChiParamsS8 injects multiple chi URL params into the request.
func withChiParamsS8(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// ── dynamic_secrets.go: IssueLease (happy-path via authorized config) ────────

// TestDynamicSecrets_IssueLease_NoUserCtx_S8 tests IssueLease with no user
// context. Depending on whether a config with id=1 exists (shared-DB ordering)
// the handler returns 404 (not found) or 403 (auth denied) — never 200.
func TestDynamicSecrets_IssueLease_NoUserCtx_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withChiParamS8(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestDynamicSecrets_IssueLease_BadID_S8 tests IssueLease with a non-numeric id.
func TestDynamicSecrets_IssueLease_BadID_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ttl_seconds":60}`)),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_IssueLease_NotFound_S8 tests IssueLease with a valid but
// missing config ID.
func TestDynamicSecrets_IssueLease_NotFound_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dynamic_secrets.go: ListLeases ───────────────────────────────────────────

// TestDynamicSecrets_ListLeases_NoUserCtx_S8 tests ListLeases with no user
// context. Returns 404 or 403 depending on shared-DB state — never 200.
func TestDynamicSecrets_ListLeases_NoUserCtx_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withChiParamS8(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestDynamicSecrets_ListLeases_BadID_S8 exercises the bad id parse.
func TestDynamicSecrets_ListLeases_BadID_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notnum"))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_ListLeases_NotFound_S8 exercises the not-found path.
func TestDynamicSecrets_ListLeases_NotFound_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodGet, "/", nil), "id", "88888"))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dynamic_secrets.go: RevokeAllLeases ──────────────────────────────────────

// TestDynamicSecrets_RevokeAllLeases_NoUserCtx_S8 tests RevokeAllLeases with
// no user context. Returns 404 or 403 depending on shared-DB state — never 200.
func TestDynamicSecrets_RevokeAllLeases_NoUserCtx_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withChiParamS8(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestDynamicSecrets_RevokeAllLeases_BadID_S8 tests the bad id branch.
func TestDynamicSecrets_RevokeAllLeases_BadID_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_RevokeAllLeases_NotFound_S8 tests the not-found path.
func TestDynamicSecrets_RevokeAllLeases_NotFound_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodPost, "/", nil), "id", "77777"))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dynamic_secrets.go: ClassifyConfig ───────────────────────────────────────

// TestDynamicSecrets_ClassifyConfig_NoUserCtx_S8 tests ClassifyConfig with no
// user context. Returns 404 or 403 depending on shared-DB state — never 200.
func TestDynamicSecrets_ClassifyConfig_NoUserCtx_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	body := `{"classification":"confidential"}`
	req := withChiParamS8(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestDynamicSecrets_ClassifyConfig_BadID_S8 tests the bad id branch.
func TestDynamicSecrets_ClassifyConfig_BadID_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	body := `{"classification":"confidential"}`
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_ClassifyConfig_NotFound_S8 tests the not-found path.
func TestDynamicSecrets_ClassifyConfig_NotFound_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	body := `{"classification":"confidential"}`
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "66666"))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamicSecrets_ClassifyConfig_BadJSON_S8 tests the bad JSON branch (only
// reachable once loadAuthorizedConfig succeeds — tested via fresh DB + real config).
func TestDynamicSecrets_ClassifyConfig_BadJSON_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewDynamicSecretHandler(cs)
	sessionToken := bootstrapS8(t, cs, "classifyjson")

	// Create a project + environment + config using the core directly.
	ctx := context.Background()
	proj, err := cs.CreateProject(ctx, "s8clsproj", "")
	require.NoError(t, err)
	envs, err := cs.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID := envs[0].ID

	cfg, err := cs.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name:          "s8-classify-cfg",
		ProjectID:     proj.ID,
		EnvironmentID: envID,
		BackendType:   "postgres",
		AdminDSN:      "postgres://fake:fake@localhost/fake",
		CreatedBy:     "s8classifyjson",
		ActorID:       1,
	})
	require.NoError(t, err)

	// Build a router with real auth middleware so the handler sees a populated
	// UserContext (required by loadAuthorizedConfig's authorize()).
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Patch("/configs/{id}/classify", h.ClassifyConfig)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPatch,
		fmt.Sprintf("%s/configs/%d/classify", ts.URL, cfg.ID),
		strings.NewReader("{bad json"),
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── dynamic_secrets.go: SetConfigEnabled ─────────────────────────────────────

// TestDynamicSecrets_SetConfigEnabled_NoUserCtx_S8 tests SetConfigEnabled
// with no user context. Returns 404 or 403 depending on shared-DB state — never 200.
func TestDynamicSecrets_SetConfigEnabled_NoUserCtx_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	body := `{"enabled":true}`
	req := withChiParamS8(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestDynamicSecrets_SetConfigEnabled_BadID_S8 tests the bad id branch.
func TestDynamicSecrets_SetConfigEnabled_BadID_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	body := `{"enabled":true}`
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_SetConfigEnabled_NotFound_S8 tests the not-found path.
func TestDynamicSecrets_SetConfigEnabled_NotFound_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	body := `{"enabled":true}`
	req := withUserCtxS8(withChiParamS8(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "55555"))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamicSecrets_SetConfigEnabled_BadJSON_S8 covers the bad JSON branch
// after a successful loadAuthorizedConfig via a real config in the DB.
func TestDynamicSecrets_SetConfigEnabled_BadJSON_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewDynamicSecretHandler(cs)
	sessionToken := bootstrapS8(t, cs, "setenabledjson")

	ctx := context.Background()
	proj, err := cs.CreateProject(ctx, "s8setenprojA", "")
	require.NoError(t, err)
	envs, err := cs.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	cfg, err := cs.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name:          "s8-enabled-cfg",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		BackendType:   "postgres",
		AdminDSN:      "postgres://fake:fake@localhost/fake",
		CreatedBy:     "s8setenabledjson",
		ActorID:       1,
	})
	require.NoError(t, err)

	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Patch("/configs/{id}/enabled", h.SetConfigEnabled)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPatch,
		fmt.Sprintf("%s/configs/%d/enabled", ts.URL, cfg.ID),
		strings.NewReader("{bad json"),
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestDynamicSecrets_SetConfigEnabled_HappyPath_S8 covers the success branch.
func TestDynamicSecrets_SetConfigEnabled_HappyPath_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewDynamicSecretHandler(cs)
	sessionToken := bootstrapS8(t, cs, "setenabledhappy")

	ctx := context.Background()
	proj, err := cs.CreateProject(ctx, "s8setenprojB", "")
	require.NoError(t, err)
	envs, err := cs.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	cfg, err := cs.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name:          "s8-enabled-happycfg",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		BackendType:   "postgres",
		AdminDSN:      "postgres://fake:fake@localhost/fake",
		CreatedBy:     "s8setenabledhappy",
		ActorID:       1,
	})
	require.NoError(t, err)

	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Patch("/configs/{id}/enabled", h.SetConfigEnabled)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := `{"enabled":false}`
	req, err := http.NewRequest(http.MethodPatch,
		fmt.Sprintf("%s/configs/%d/enabled", ts.URL, cfg.ID),
		strings.NewReader(body),
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── dynamic_secrets.go: ListConfigs happy path ────────────────────────────────

// TestDynamicSecrets_ListConfigs_HappyPath_S8 exercises the success branch of
// ListConfigs when the caller has a valid session and an authorised scope.
func TestDynamicSecrets_ListConfigs_HappyPath_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewDynamicSecretHandler(cs)
	sessionToken := bootstrapS8(t, cs, "listcfghappy")

	ctx := context.Background()
	proj, err := cs.CreateProject(ctx, "s8listcfgprojA", "")
	require.NoError(t, err)
	envs, err := cs.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Get("/dynamic-secrets/configs", h.ListConfigs)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/dynamic-secrets/configs?project_id=%d&environment_id=%d", ts.URL, proj.ID, envs[0].ID),
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── dynamic_secrets.go: RevokeLease ──────────────────────────────────────────

// TestDynamicSecrets_RevokeLease_NoUserCtx_S8 tests RevokeLease with no user
// context in the request → 401.
func TestDynamicSecrets_RevokeLease_NoUserCtx_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withChiParamS8(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "some-uuid")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDynamicSecrets_RevokeLease_NotFound_S8 tests RevokeLease with a lease
// that doesn't exist → 404.
func TestDynamicSecrets_RevokeLease_NotFound_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(
		httptest.NewRequest(http.MethodPost, "/", nil),
		"leaseID", "00000000-0000-0000-0000-000000000000",
	))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dynamic_secrets.go: RenewLease ───────────────────────────────────────────

// TestDynamicSecrets_RenewLease_NoUserCtx_S8 tests RenewLease with no user
// context → 401.
func TestDynamicSecrets_RenewLease_NoUserCtx_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withChiParamS8(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "some-uuid")
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDynamicSecrets_RenewLease_NotFound_S8 tests RenewLease with a lease
// that doesn't exist → 404.
func TestDynamicSecrets_RenewLease_NotFound_S8(t *testing.T) {
	h := newDynamicSecretHandlerS8(t)
	req := withUserCtxS8(withChiParamS8(
		httptest.NewRequest(http.MethodPost, "/", nil),
		"leaseID", "00000000-0000-0000-0000-000000000001",
	))
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── admin_impersonation.go: Start ────────────────────────────────────────────

// TestImpersonationStart_NoUserCtx_S8 tests Start with no user context → 401.
func TestImpersonationStart_NoUserCtx_S8(t *testing.T) {
	h := newImpersonationHandlerS8(t)
	body := `{"user_id":2}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestImpersonationStart_BadJSON_S8 tests Start with malformed body → 400.
func TestImpersonationStart_BadJSON_S8(t *testing.T) {
	h := newImpersonationHandlerS8(t)
	req := withUserCtxS8(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestImpersonationStart_MissingUserID_S8 tests Start with user_id=0 → 400.
func TestImpersonationStart_MissingUserID_S8(t *testing.T) {
	h := newImpersonationHandlerS8(t)
	req := withUserCtxS8(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":0}`)))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestImpersonationStart_ImpersonationWhileImpersonating_S8 tests that you
// cannot start an impersonation from an already-impersonated session → 403.
func TestImpersonationStart_ImpersonationWhileImpersonating_S8(t *testing.T) {
	h := newImpersonationHandlerS8(t)
	adminID := uint(5)
	uc := &middleware.UserContext{
		UserID:         1,
		Username:       "testuser",
		ImpersonatedBy: &adminID,
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":2}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestImpersonationStart_TargetNotFound_S8 tests Start with a valid admin
// session but a non-existent target → 404.
func TestImpersonationStart_TargetNotFound_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewImpersonationHandler(cs, false)
	bootstrapS8(t, cs, "impstart")

	ctx := context.Background()
	admin, err := cs.GetUserByUsername(ctx, "s8impstart")
	require.NoError(t, err)

	uc := &middleware.UserContext{UserID: admin.ID, Username: admin.Username}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":99999}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Start(w, req)
	// Target user does not exist → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestImpersonationStart_CannotImpersonateSelf_S8 tests that an admin
// cannot impersonate themselves → 400.
func TestImpersonationStart_CannotImpersonateSelf_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewImpersonationHandler(cs, false)
	bootstrapS8(t, cs, "impself")

	ctx := context.Background()
	admin, err := cs.GetUserByUsername(ctx, "s8impself")
	require.NoError(t, err)

	uc := &middleware.UserContext{UserID: admin.ID, Username: admin.Username}
	body := fmt.Sprintf(`{"user_id":%d}`, admin.ID)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Start(w, req)
	// Cannot impersonate yourself → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── admin_impersonation.go: End ───────────────────────────────────────────────

// TestImpersonationEnd_NoToken_S8 tests End when no Authorization header is
// present → 400.
func TestImpersonationEnd_NoToken_S8(t *testing.T) {
	h := newImpersonationHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestImpersonationEnd_NotAnImpersonationSession_S8 tests End with a real
// (non-impersonation) session token — expects 400 "not an impersonation session".
func TestImpersonationEnd_NotAnImpersonationSession_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewImpersonationHandler(cs, false)
	sessionToken := bootstrapS8(t, cs, "endnotimpers")

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestImpersonationEnd_WithExpiredAdminCookie_S8 tests End with a fake token
// but also an admin cookie with a non-existent session value — the restore
// branch is exercised (ValidateSessionToken fails → ClearSessionCookie path).
func TestImpersonationEnd_WithExpiredAdminCookie_S8(t *testing.T) {
	h := newImpersonationHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer faketoken-s8end")
	req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookieName, Value: "expired-admin-s8"})
	w := httptest.NewRecorder()
	h.End(w, req)
	// Either 400 (not-impersonation) or 500; not 200.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go: Login ─────────────────────────────────────────────────────────────

// TestLogin_BadJSON_S8 tests Login with a malformed JSON body → 400.
func TestLogin_BadJSON_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestLogin_InvalidCredentials_S8 tests Login with wrong credentials → 401.
func TestLogin_InvalidCredentials_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewAuthHandler(cs, false)
	bootstrapS8(t, cs, "logincreds")

	body := `{"username":"s8logincreds","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestLogin_HappyPath_S8 tests Login with valid credentials → 200 with token.
func TestLogin_HappyPath_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewAuthHandler(cs, false)
	bootstrapS8(t, cs, "loginhappy")

	body := `{"username":"s8loginhappy","password":"Kx#Vr9$Mn2!Zp4@Qw"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, req)
	contracttest.AssertOpenAPIResponse(t, req, w)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── auth.go: ConsumeSetup ─────────────────────────────────────────────────────

// TestConsumeSetup_BadJSON_S8 tests ConsumeSetup with malformed JSON → 400.
func TestConsumeSetup_BadJSON_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeSetup_MissingFields_S8 tests ConsumeSetup with missing token/
// password → 400.
func TestConsumeSetup_MissingFields_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	body := `{"token":"","password":""}`
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeSetup_MissingPassword_S8 tests ConsumeSetup with token but no
// password → 400.
func TestConsumeSetup_MissingPassword_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	body := `{"token":"sometoken","password":""}`
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeSetup_InvalidToken_S8 tests ConsumeSetup with a non-existent
// setup token → 400.
func TestConsumeSetup_InvalidToken_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	body := `{"token":"no-such-token-s8","password":"Kx#Vr9$Mn2!Zp4@Qw"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── auth.go: Logout ───────────────────────────────────────────────────────────

// TestLogout_NoToken_S8 tests Logout without an Authorization header → 400.
func TestLogout_NoToken_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestLogout_InvalidToken_S8 tests Logout with a token that does not exist in
// the DB → 401, not 500 (#N5: previously blanket-mapped ANY Logout error to
// 500, including "session not found" -- a prior logout (double-click, two
// tabs, a client retry) hitting this exact path is an ordinary
// authentication outcome, not a server fault. core.ErrSessionNotFound +
// errors.Is in the handler now distinguish it from a genuine internal
// error.)
func TestLogout_InvalidToken_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer notarealsessiontoken")
	w := httptest.NewRecorder()
	h.Logout(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestLogout_HappyPath_S8 tests Logout with a valid session token → 200.
func TestLogout_HappyPath_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewAuthHandler(cs, false)
	sessionToken := bootstrapS8(t, cs, "logouthappy")

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── auth.go: Profile ─────────────────────────────────────────────────────────

// TestProfile_NoUserCtx_S8 tests Profile with no user context → 401.
func TestProfile_NoUserCtx_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestProfile_UserNotFound_S8 tests Profile when the user ID in the context
// does not exist in the DB → 404.
func TestProfile_UserNotFound_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	uc := &middleware.UserContext{UserID: 99999, Username: "ghost"}
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestProfile_HappyPath_S8 tests Profile with a real authenticated user → 200.
func TestProfile_HappyPath_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewAuthHandler(cs, false)
	bootstrapS8(t, cs, "profilehappy")

	ctx := context.Background()
	user, err := cs.GetUserByUsername(ctx, "s8profilehappy")
	require.NoError(t, err)

	uc := &middleware.UserContext{UserID: user.ID, Username: user.Username}
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestProfile_WithImpersonation_S8 tests Profile when the user context carries
// an ImpersonatedBy value — exercises the impersonation block.
func TestProfile_WithImpersonation_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h := NewAuthHandler(cs, false)
	bootstrapS8(t, cs, "profileimpers")

	ctx := context.Background()
	user, err := cs.GetUserByUsername(ctx, "s8profileimpers")
	require.NoError(t, err)

	adminID := user.ID // pretend the same user is the admin (just to exercise the code path)
	uc := &middleware.UserContext{
		UserID:         user.ID,
		Username:       user.Username,
		ImpersonatedBy: &adminID,
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── auth.go: VerifyMFA ────────────────────────────────────────────────────────

// TestVerifyMFA_BadJSON_S8 tests VerifyMFA with malformed body → 400.
//
// Uses its own distinctive RemoteAddr, not httptest.NewRequest's shared
// default (192.0.2.1) — newAuthHandlerS8's core is the package-wide shared s4
// DB (sharedS4CoreOnce), so every OTHER test in this package that also hits
// one of the 8 endpoints sharing the per-IP login-throttle budget
// (auth.go/webauthn.go's checkLoginRateLimit) via the same default RemoteAddr
// accumulates against the SAME counter this test would otherwise read. Since
// G1 made ConsumeSetup and BeginWebAuthnPasswordlessLogin also reserve a slot
// (login_throttle_fuzz_test.go), that shared default-IP count can now clear
// core.LoginMaxAttempts partway through a full package run, making this
// test's own request 429 depending on unrelated test execution order — not
// what BadJSON's 400 assertion is about.
func TestVerifyMFA_BadJSON_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa", strings.NewReader("{bad"))
	req.RemoteAddr = "198.51.100.201:4001"
	w := httptest.NewRecorder()
	h.VerifyMFA(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVerifyMFA_InvalidChallenge_S8 tests VerifyMFA with an unknown challenge
// → 401 (invalid or expired). Own distinctive RemoteAddr — see
// TestVerifyMFA_BadJSON_S8's doc for why.
func TestVerifyMFA_InvalidChallenge_S8(t *testing.T) {
	h := newAuthHandlerS8(t)
	body := `{"mfa_challenge":"no-such-challenge","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.201:4002"
	w := httptest.NewRecorder()
	h.VerifyMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── catalog.go: ListEnvironments ─────────────────────────────────────────────

// TestListEnvironments_HappyPath_S8 tests ListEnvironments with an empty DB
// → 200 with empty environments slice.
func TestListEnvironments_HappyPath_S8(t *testing.T) {
	h := newCatalogHandlerS8(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil)) // #2780: authorizes in-handler
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── catalog.go: ListProjects ──────────────────────────────────────────────────

// TestListProjects_HappyPath_S8 tests ListProjects with an empty DB → 200.
func TestListProjects_HappyPath_S8(t *testing.T) {
	h := newCatalogHandlerS8(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)) // #2780: authorizes in-handler
	w := httptest.NewRecorder()
	h.ListProjects(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestListProjects_IncludeDeleted_S8 tests ListProjects with ?include_deleted=true.
func TestListProjects_IncludeDeleted_S8(t *testing.T) {
	h := newCatalogHandlerS8(t)
	// #2780: ?include_deleted=true now requires secrets.read at the GLOBAL scope.
	// Project-scoped grants deliberately survive a soft-delete (so RestoreProject
	// works) while GetProject 404s on a deleted project, so a scoped reader cannot
	// read a soft-deleted project through any path and must not see one listed. This
	// fixture seeds no RBAC, so 403 is the correct answer and this test now pins that
	// gate. The 200 path (a real global reader) is covered by
	// catalog_list_scoped_2780_test.go's TestListProjects2780_IncludeDeletedStillRequiresGlobal,
	// which seeds the grant properly rather than relying on the route having no gate.
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects?include_deleted=true", nil))
	w := httptest.NewRecorder()
	h.ListProjects(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── groups_handler.go: ListGroups ────────────────────────────────────────────

// TestListGroups_NoUserCtx_S8 tests ListGroups without a user context → 401.
func TestListGroups_NoUserCtx_S8(t *testing.T) {
	h := newGroupHandlerS8(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListGroups_HappyPath_S8 tests ListGroups with a user context → 200.
func TestListGroups_HappyPath_S8(t *testing.T) {
	h := newGroupHandlerS8(t)
	req := withUserCtxS8(httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil))
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── groups_handler.go: CreateGroup ───────────────────────────────────────────

// TestCreateGroup_NoUserCtx_S8 tests CreateGroup without a user context → 401.
func TestCreateGroup_NoUserCtx_S8(t *testing.T) {
	h := newGroupHandlerS8(t)
	body := `{"name":"s8testgroup","description":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCreateGroup_BadJSON_S8 tests CreateGroup with malformed JSON → 400.
func TestCreateGroup_BadJSON_S8(t *testing.T) {
	h := newGroupHandlerS8(t)
	req := withUserCtxS8(httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateGroup_ValidationError_S8 tests CreateGroup with an empty name → 400.
func TestCreateGroup_ValidationError_S8(t *testing.T) {
	h := newGroupHandlerS8(t)
	body := `{"name":"","description":"test"}`
	req := withUserCtxS8(httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateGroup_HappyPath_S8 tests CreateGroup with a valid body → 201.
func TestCreateGroup_HappyPath_S8(t *testing.T) {
	cs := freshCoreS8(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)

	bootstrapS8(t, cs, "creategrouphappy")
	ctx := context.Background()
	user, err := cs.GetUserByUsername(ctx, "s8creategrouphappy")
	require.NoError(t, err)

	uc := &middleware.UserContext{UserID: user.ID, Username: user.Username}
	body := `{"name":"s8-happygroup","description":"created in s8"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ── dashboard.go: GetCompliancePosture ────────────────────────────────────────

// TestGetCompliancePosture_HappyPath_S8 tests GetCompliancePosture → 200.
func TestGetCompliancePosture_HappyPath_S8(t *testing.T) {
	h := newDashboardHandlerS8(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/posture", nil)
	w := httptest.NewRecorder()
	h.GetCompliancePosture(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── dashboard.go: GetComplianceDigest ────────────────────────────────────────

// TestGetComplianceDigest_HappyPath_S8 tests GetComplianceDigest → 200.
func TestGetComplianceDigest_HappyPath_S8(t *testing.T) {
	h := newDashboardHandlerS8(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/digest", nil)
	w := httptest.NewRecorder()
	h.GetComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── dashboard.go: GetComplianceControls ──────────────────────────────────────

// TestGetComplianceControls_HappyPath_S8 tests GetComplianceControls → 200.
func TestGetComplianceControls_HappyPath_S8(t *testing.T) {
	h := newDashboardHandlerS8(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/controls", nil)
	w := httptest.NewRecorder()
	h.GetComplianceControls(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── dashboard.go: GetComplianceEvidence ──────────────────────────────────────

// TestGetComplianceEvidence_HappyPath_S8 tests GetComplianceEvidence → 200.
func TestGetComplianceEvidence_HappyPath_S8(t *testing.T) {
	h := newDashboardHandlerS8(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence", nil)
	w := httptest.NewRecorder()
	h.GetComplianceEvidence(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities.go: ListOIDCBindings ──────────────────────────────────

// TestListOIDCBindings_NoUserCtx_S8 tests ListOIDCBindings without a user
// context → 401.
func TestListOIDCBindings_NoUserCtx_S8(t *testing.T) {
	h := newCatalogHandlerS8(t)
	req := withChiParamsS8(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "1"},
	)
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListOIDCBindings_BadProjectID_S8 tests ListOIDCBindings with a
// non-numeric project ID → 400.
func TestListOIDCBindings_BadProjectID_S8(t *testing.T) {
	h := newCatalogHandlerS8(t)
	req := withUserCtxS8(withChiParamsS8(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListOIDCBindings_BadMachineID_S8 tests ListOIDCBindings with a
// non-numeric machine ID → 400.
func TestListOIDCBindings_BadMachineID_S8(t *testing.T) {
	h := newCatalogHandlerS8(t)
	req := withUserCtxS8(withChiParamsS8(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListOIDCBindings_NotFound_S8 tests ListOIDCBindings when the machine
// does not exist in the given project → 404 or 200 empty.
func TestListOIDCBindings_NotFound_S8(t *testing.T) {
	h := newCatalogHandlerS8(t)
	req := withUserCtxS8(withChiParamsS8(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "9999", "machineId": "9999"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	// Returns 404 when the machine identity is not found.
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusOK, "unexpected: %d", w.Code)
}

// ── machine_identities.go: machineActionState ─────────────────────────────────

// TestMachineActionState_S8 exercises machineActionState for all valid and
// invalid action strings.
func TestMachineActionState_S8(t *testing.T) {
	state, ok := machineActionState("activate")
	assert.True(t, ok)
	assert.Equal(t, core.MachineActive, state)

	state, ok = machineActionState("suspend")
	assert.True(t, ok)
	assert.Equal(t, core.MachineSuspended, state)

	state, ok = machineActionState("revoke")
	assert.True(t, ok)
	assert.Equal(t, core.MachineRevoked, state)

	state, ok = machineActionState("unknown")
	assert.False(t, ok)
	assert.Empty(t, state)

	state, ok = machineActionState("")
	assert.False(t, ok)
	assert.Empty(t, state)
}
