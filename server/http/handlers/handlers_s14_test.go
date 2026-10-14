// handlers_s14_test.go — coverage sweep for:
//   - secrets_description.go: DescribeSecret bad-param, missing ctx, invalid JSON, not-found
//   - secrets_tags.go: GetTags / SetTags bad-param, missing ctx, invalid JSON, not-found, forbidden
//   - secrets_render.go: RenderTemplate bad-param, missing ctx, invalid JSON, sendRenderTemplateError all branches
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// ── DB/handler setup helpers (S14-local) ─────────────────────────────────────

// freshSecretHandlerS14 opens a unique in-memory DB, migrates all models, seeds
// user 1 + project + env + one secret (owned by user 1), and returns the
// handler and the secret's ID.
func freshSecretHandlerS14(t *testing.T) (*SecretHandler, uint) {
	t.Helper()

	cfg := &config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}
	require.NoError(t, i18n.Initialize(cfg))

	db := sqlitetest.OpenWithConfig(t, "kxhandlers_s14_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{},
		&models.Tag{}, &models.SecretTag{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.AnomalyAlert{}, &models.RotationPolicy{}, &models.Notification{},
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
		&models.LegalHold{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
	))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner_s14", Email: "owner_s14@test.com"}).Error)

	st := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(st)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "proj-s14"})
	require.NoError(t, err)
	// User 1 must be a project member so CheckSecretPermission's IsProjectMember gate passes.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: proj.ID}).Error)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "staging-s14", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name:          "api-key-s14",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Type:          "password",
		OwnerID:       1,
		IsSecret:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)

	handler, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return handler, secret.ID
}

// withUserCtxS14 injects UserID=1 context into a request.
func withUserCtxS14(r *http.Request) *http.Request {
	uctx := &customMiddleware.UserContext{UserID: 1, Username: "owner_s14", Email: "owner_s14@test.com"}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), uctx))
}

// withChiParamS14 adds a single chi URL param without conflicting with other helpers.
func withChiParamS14(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// newSecretHandlerOnlyS14 builds a handler with an empty, schema-less DB — useful
// for testing the user-ctx-absent (401) path where no DB access occurs.
func newSecretHandlerOnlyS14(t *testing.T) *SecretHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	return h
}

// ── DescribeSecret ────────────────────────────────────────────────────────────

// TestDescribeSecret_NoUserCtx_S13 — missing middleware context → 401.
func TestDescribeSecret_NoUserCtx_S13(t *testing.T) {
	h := newSecretHandlerOnlyS14(t)
	body, _ := json.Marshal(map[string]string{"description": "hello"})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/description", bytes.NewReader(body)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDescribeSecret_BadParam_S13 — non-numeric "id" → 400.
func TestDescribeSecret_BadParam_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string]string{"description": "hello"})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/bad/description", bytes.NewReader(body)),
		"id", "not-a-number",
	))
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid secret ID")
}

// TestDescribeSecret_InvalidJSON_S13 — malformed JSON body → 400.
func TestDescribeSecret_InvalidJSON_S13(t *testing.T) {
	h, id := freshSecretHandlerS14(t)
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/description", bytes.NewBufferString("bad{")),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid JSON")
}

// TestDescribeSecret_NotFound_S13 — secret ID that doesn't exist → 404.
func TestDescribeSecret_NotFound_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string]string{"description": "note"})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/99999/description", bytes.NewReader(body)),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDescribeSecret_Success_S13 — owner sets description on their own secret → 200.
func TestDescribeSecret_Success_S13(t *testing.T) {
	h, id := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string]string{"description": "my note"})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/1/description", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetTags ───────────────────────────────────────────────────────────────────

// TestGetTags_NoUserCtx_S13 — missing middleware context → 401.
func TestGetTags_NoUserCtx_S13(t *testing.T) {
	h := newSecretHandlerOnlyS14(t)
	req := withChiParamS14(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/tags", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetTags_BadParam_S13 — non-numeric "id" → 400.
func TestGetTags_BadParam_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/bad/tags", nil),
		"id", "nope",
	))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid secret ID")
}

// TestGetTags_NotFound_S13 — secret 99999 doesn't exist → 404.
func TestGetTags_NotFound_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/99999/tags", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetTags_Success_S13 — owner reads tags on their own secret → 200 with tags array.
func TestGetTags_Success_S13(t *testing.T) {
	h, id := freshSecretHandlerS14(t)
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/tags", nil),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SetTags ───────────────────────────────────────────────────────────────────

// TestSetTags_NoUserCtx_S13 — missing middleware context → 401.
func TestSetTags_NoUserCtx_S13(t *testing.T) {
	h := newSecretHandlerOnlyS14(t)
	body, _ := json.Marshal(map[string][]string{"tags": {"a", "b"}})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1/tags", bytes.NewReader(body)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSetTags_BadParam_S13 — non-numeric "id" → 400.
func TestSetTags_BadParam_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string][]string{"tags": {"a"}})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/bad/tags", bytes.NewReader(body)),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid secret ID")
}

// TestSetTags_InvalidJSON_S13 — malformed JSON body → 400.
func TestSetTags_InvalidJSON_S13(t *testing.T) {
	h, id := freshSecretHandlerS14(t)
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1/tags", bytes.NewBufferString("{{bad")),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetTags_NotFound_S13 — secret 99999 doesn't exist → 404.
func TestSetTags_NotFound_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string][]string{"tags": {"a"}})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/99999/tags", bytes.NewReader(body)),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestSetTags_Success_S13 — owner sets tags on their own secret → 200.
func TestSetTags_Success_S13(t *testing.T) {
	h, id := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string][]string{"tags": {"prod", "critical"}})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1/tags", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTagError_ForbiddenBranch_S13 — user 2 accesses secret owned by user 1
// with no share → not 500 (either 404 or 403 depending on core's oracle-guard).
func TestTagError_ForbiddenBranch_S13(t *testing.T) {
	h, id := freshSecretHandlerS14(t)

	uctx := &customMiddleware.UserContext{UserID: 2, Username: "nobody_s14", Email: "nobody_s14@test.com"}
	req := withChiParamS14(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/tags", nil),
		"id", strconv.Itoa(int(id)),
	)
	req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), uctx))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// TestTagError_InternalBranch_S13 directly calls tagError with a generic error
// string to exercise the default (InternalError) branch of the switch.
func TestTagError_InternalBranch_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	h.tagError(w, errors.New("unexpected storage failure"), "Failed to list tags")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to list tags")
}

// TestTagError_NotFoundBranch_S13 directly calls tagError with a "not found"
// error to exercise that branch.
func TestTagError_NotFoundBranch_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	h.tagError(w, errors.New("secret not found in store"), "Failed to list tags")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestTagError_PermissionBranch_S13 directly calls tagError with a "permission"
// error to exercise the forbidden branch.
func TestTagError_PermissionBranch_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	h.tagError(w, errors.New("permission denied"), "Failed to list tags")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestTagError_ValidationBranch_S13 directly calls tagError with a "at most"
// error to exercise the validation/exceeds branch.
func TestTagError_ValidationBranch_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	h.tagError(w, errors.New("at most 50 tags allowed"), "Failed to set tags")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── RenderTemplate ────────────────────────────────────────────────────────────

// TestRenderTemplate_NoUserCtx_S13 — missing middleware context → 401.
func TestRenderTemplate_NoUserCtx_S13(t *testing.T) {
	h := newSecretHandlerOnlyS14(t)
	body, _ := json.Marshal(map[string]string{"template": "hello"})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", bytes.NewReader(body)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRenderTemplate_BadParam_S13 — non-numeric project "id" → 400.
func TestRenderTemplate_BadParam_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string]string{"template": "hello"})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/bad/secrets/render", bytes.NewReader(body)),
		"id", "not-a-number",
	))
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid project ID")
}

// TestRenderTemplate_InvalidJSON_S13 — malformed JSON body → 400.
func TestRenderTemplate_InvalidJSON_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", bytes.NewBufferString("{bad")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid JSON")
}

// TestRenderTemplate_LiteralTemplate_S13 — no secret references → 200 with literal output.
func TestRenderTemplate_LiteralTemplate_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	body, _ := json.Marshal(map[string]string{"template": "hello world"})
	req := withUserCtxS14(withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", bytes.NewReader(body)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "hello world", data["rendered"])
}

// ── sendRenderTemplateError — all branches ────────────────────────────────────

// renderErrReqS13 builds a request/userCtx pair for sendRenderTemplateError's
// non-ADR-096 branches, where the caller's permissions are irrelevant.
func renderErrReqS13() (*http.Request, *customMiddleware.UserContext) {
	req := withUserCtxS14(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", nil))
	return req, customMiddleware.GetUserFromContext(req.Context())
}

// TestSendRenderTemplateError_ErrSecretRefNotFound_Unprivileged_S13 — sentinel
// error, caller lacks secrets.read at GLOBAL scope → 403, byte-identical to
// the permission-denied branch (ADR-096: RenderTemplate's per-reference
// existence check must not distinguish "no such secret" from "exists, you
// can't read it" for anyone but a globally-privileged caller).
func TestSendRenderTemplateError_ErrSecretRefNotFound_Unprivileged_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, core.ErrSecretRefNotFound)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Not authorized to read a referenced secret")
}

// TestSendRenderTemplateError_ErrSecretRefNotFound_GlobalPermission_S13 — same
// sentinel error, caller holds secrets.read at GLOBAL scope → the narrow
// ADR-096 exception: a genuine 404.
func TestSendRenderTemplateError_ErrSecretRefNotFound_GlobalPermission_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	ctx := context.Background()
	st := h.coreService.Storage()

	perm, err := st.CreatePermission(ctx, &models.Permission{Name: "secrets.read", Description: "read secrets"})
	require.NoError(t, err)
	folded, err := identity.NewFoldedName("global-render-reader-s13")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, folded, "global reader")
	require.NoError(t, err)
	require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, perm.ID))
	globalUser, err := h.coreService.CreateUser(ctx, &core.CreateUserRequest{
		Username: "global_render_s13", Email: "global_render_s13@test.com", DisplayName: "Global Reader", Password: "Xk9#mQ7zLp2!vR4t",
	})
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, globalUser.ID, role.ID, core.Scope{}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", nil)
	uctx := &customMiddleware.UserContext{UserID: globalUser.ID, Username: globalUser.Username, Email: globalUser.Email}
	req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), uctx))

	w := httptest.NewRecorder()
	h.sendRenderTemplateError(w, req, uctx, core.ErrSecretRefNotFound)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Secret not found")
}

// TestSendRenderTemplateError_NotFoundSubstring_S13 — generic "not found" error → 404.
func TestSendRenderTemplateError_NotFoundSubstring_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("project not found"))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestSendRenderTemplateError_PermissionSubstring_S13 — "permission" error → 403.
func TestSendRenderTemplateError_PermissionSubstring_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("permission denied for user"))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSendRenderTemplateError_NotAuthorizedSubstring_S13 — "not authorized" → 403.
func TestSendRenderTemplateError_NotAuthorizedSubstring_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("user is not authorized to read secret"))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSendRenderTemplateError_InvalidReference_S13 — "invalid reference" → 400.
func TestSendRenderTemplateError_InvalidReference_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("invalid reference syntax"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSendRenderTemplateError_Unterminated_S13 — "unterminated" → 400.
func TestSendRenderTemplateError_Unterminated_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("unterminated secret reference"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSendRenderTemplateError_EmptySecretReference_S13 — "empty secret reference" → 400.
func TestSendRenderTemplateError_EmptySecretReference_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("empty secret reference in template"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSendRenderTemplateError_CannotBeSafelySubstituted_S13 — "cannot be safely substituted" → 400.
func TestSendRenderTemplateError_CannotBeSafelySubstituted_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("value cannot be safely substituted"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSendRenderTemplateError_DefaultInternal_S13 — unknown error → 500.
func TestSendRenderTemplateError_DefaultInternal_S13(t *testing.T) {
	h, _ := freshSecretHandlerS14(t)
	w := httptest.NewRecorder()
	req, userCtx := renderErrReqS13()
	h.sendRenderTemplateError(w, req, userCtx, errors.New("some unexpected storage error"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to render template")
}
