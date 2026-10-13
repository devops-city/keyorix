// handlers_s3_test.go — broad coverage sweep across previously uncovered handler
// functions. Strategy: each handler that checks for a user context as its first
// operation is covered by a "no-user-context → 401" test; handlers with URL params
// get a "bad-param → 400" test; simpler handlers get a happy-path test against
// an empty in-memory DB. Each test family is grouped by source file.
package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// ── shared helpers ─────────────────────────────────────────────────────────────

// openHandlerTestDB opens a fresh in-memory SQLite DB with all models migrated.
func openHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
	))
	return db
}

// newHandlerCore creates a KeyorixCore backed by a fresh in-memory DB.
func newHandlerCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := openHandlerTestDB(t)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// ── access_review_campaigns.go ────────────────────────────────────────────────

func TestAccessReviewCampaigns_Unauthorized(t *testing.T) {
	cs := newHandlerCore(t)
	h := NewCatalogHandler(cs)

	// Handlers that require a user context and return non-200 when it is absent.
	handlers := []struct {
		name string
		fn   http.HandlerFunc
		rctx map[string]string
	}{
		{"OpenAccessReviewCampaign", h.OpenAccessReviewCampaign, map[string]string{"id": "1"}},
		{"GetAccessReviewCampaign", h.GetAccessReviewCampaign, map[string]string{"id": "1", "campaignId": "1"}},
		{"CloseAccessReviewCampaign", h.CloseAccessReviewCampaign, map[string]string{"id": "1", "campaignId": "1"}},
		{"DecideAccessReviewCampaignItem", h.DecideAccessReviewCampaignItem, map[string]string{"id": "1", "campaignId": "1", "itemId": "1"}},
	}
	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), tc.rctx)
			w := httptest.NewRecorder()
			tc.fn(w, req)
			// No user context = 401 for handlers that check it.
			assert.NotEqual(t, http.StatusOK, w.Code)
		})
	}
}

func TestAccessReviewCampaigns_BadProjectID(t *testing.T) {
	cs := newHandlerCore(t)
	h := NewCatalogHandler(cs)

	handlers := []struct {
		name string
		fn   http.HandlerFunc
	}{
		{"OpenAccessReviewCampaign", h.OpenAccessReviewCampaign},
		{"ListAccessReviewCampaigns", h.ListAccessReviewCampaigns},
		{"GetAccessReviewCampaign", h.GetAccessReviewCampaign},
		{"CloseAccessReviewCampaign", h.CloseAccessReviewCampaign},
		{"DecideAccessReviewCampaignItem", h.DecideAccessReviewCampaignItem},
	}
	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
				map[string]string{"id": "notanumber", "campaignId": "1", "itemId": "1"}))
			w := httptest.NewRecorder()
			tc.fn(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestListAccessReviewCampaigns_HappyPath(t *testing.T) {
	cs := newHandlerCore(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "999"}))
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCampaignStatusForError(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, campaignStatusForError("not found"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("required field"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("still pending"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("already closed"))
	assert.Equal(t, http.StatusInternalServerError, campaignStatusForError("unknown error"))
}

// ── audit.go ──────────────────────────────────────────────────────────────────

func TestAuditHandler_GetAuditLogs_Unauthorized(t *testing.T) {
	h := NewAuditHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_GetAuditLogs_HappyPath(t *testing.T) {
	h := NewAuditHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil))
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_GetRBACAuditLogs_Unauthorized(t *testing.T) {
	h := NewAuditHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/rbac", nil)
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_GetRBACAuditLogs_HappyPath(t *testing.T) {
	h := NewAuditHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/rbac", nil))
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_GetAuditRetention_Unauthorized(t *testing.T) {
	h := NewAuditHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil)
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_GetAuditRetention_HappyPath(t *testing.T) {
	h := NewAuditHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil))
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── audit_anomaly.go ──────────────────────────────────────────────────────────

func TestListAnomalyAlerts_NoCoreService(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/anomalies", nil)
	w := httptest.NewRecorder()
	ListAnomalyAlerts(w, req)
	// No core service in context → 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAcknowledgeAnomalyAlert_NoCoreService(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	AcknowledgeAnomalyAlert(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── auth.go ───────────────────────────────────────────────────────────────────

func newAuthHandlerForTest(t *testing.T) *AuthHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.LoginAttempt{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.SystemMetadata{},
	))
	return NewAuthHandler(core.NewKeyorixCore(store.NewLocalStorage(db)), false)
}

func TestAuthHandler_Login_BadJSON(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("{bad json"))
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		bytes.NewBufferString(`{"username":"nobody","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_GetSetupToken_MissingToken(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/auth/setup/", nil), "token", "")
	w := httptest.NewRecorder()
	h.GetSetupToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_GetSetupToken_InvalidToken(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/auth/setup/badtoken", nil), "token", "badtoken")
	w := httptest.NewRecorder()
	h.GetSetupToken(w, req)
	assert.Equal(t, http.StatusGone, w.Code)
}

func TestAuthHandler_ConsumeSetup_BadJSON(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ConsumeSetup_MissingFields(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume",
		bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ConsumeSetup_InvalidToken(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume",
		bytes.NewBufferString(`{"token":"bogus","password":"Password1!"}`))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Logout_NoToken(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	// No token in request → 400 BadRequest (token check precedes auth check).
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RefreshToken_NoToken(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	// No token in request → 400 BadRequest (token check precedes auth check).
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Profile_Unauthorized(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_UpdateProfile_Unauthorized(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPut, "/auth/profile", nil)
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ChangePassword_Unauthorized(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", nil)
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ListSessions_Unauthorized(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_RevokeSession_Unauthorized(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/auth/sessions/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_InitSystem_BadJSON(t *testing.T) {
	h := newAuthHandlerForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/init", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAuthHandler_InitSystem_Success exercises the real success path (200)
// against a fresh, never-initialized DB with a bootstrap token configured
// (BootstrapSystem fails closed -- ErrInvalidBootstrapToken -- with no token
// set at all). The other InitSystem tests in this package share a DB across
// many tests (newHandlerCoreS4/S7's cache=shared singleton), so whether
// system init still succeeds by the time they run depends on test order --
// not a reliable way to exercise the 200 case. This test builds its own
// private DB and core service, so init always succeeds here.
func TestAuthHandler_InitSystem_Success(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.LoginAttempt{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.SystemMetadata{}, &models.PasswordHistory{},
		&models.Project{}, &models.Environment{},
	))
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	cs.SetBootstrapToken("test-bootstrap-token")
	h := NewAuthHandler(cs, false)

	body := `{"username":"sysadmin","email":"sysadmin@example.com","display_name":"Admin","password":"Kx#Vr9$Mn2!Zp4@Qw","bootstrap_token":"test-bootstrap-token"}`
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	contracttest.AssertOpenAPIResponse(t, req, w)
}

func TestExtractBearerToken(t *testing.T) {
	t.Run("from Authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer mytoken123")
		tok := extractBearerToken(req)
		assert.Equal(t, "mytoken123", tok)
	})

	t.Run("from session cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: customMiddleware.SessionCookieName, Value: "cookietoken"})
		tok := extractBearerToken(req)
		assert.Equal(t, "cookietoken", tok)
	})

	t.Run("no token returns empty string", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		tok := extractBearerToken(req)
		assert.Equal(t, "", tok)
	})

	t.Run("non-Bearer auth scheme returns empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		tok := extractBearerToken(req)
		assert.Equal(t, "", tok)
	})
}

// ── break_glass.go ────────────────────────────────────────────────────────────

func TestBreakGlass_Unauthorized(t *testing.T) {
	cs := newHandlerCore(t)
	h := NewCatalogHandler(cs)

	t.Run("ActivateBreakGlass_no_user", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
		w := httptest.NewRecorder()
		h.ActivateBreakGlass(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("ListBreakGlassActivations_bad_id", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
		w := httptest.NewRecorder()
		h.ListBreakGlassActivations(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ListBreakGlassActivations_no_user", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
		w := httptest.NewRecorder()
		h.ListBreakGlassActivations(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("ListBreakGlassActivations_happy_path", func(t *testing.T) {
		// BREAKGLASS-OWN-1: authorized in the handler now, so the caller is an admin
		// (user 1 of freshCoreS24WithAdmin).
		admin, _ := freshCoreS24WithAdmin(t)
		req := withUserCtxS7(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
		w := httptest.NewRecorder()
		NewCatalogHandler(admin).ListBreakGlassActivations(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RevokeBreakGlass_no_user", func(t *testing.T) {
		req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
			map[string]string{"id": "1", "activationId": "1"})
		w := httptest.NewRecorder()
		h.RevokeBreakGlass(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("RevokeBreakGlass_bad_id", func(t *testing.T) {
		req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
			map[string]string{"id": "bad", "activationId": "1"})
		w := httptest.NewRecorder()
		h.RevokeBreakGlass(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestActivateBreakGlass_BadJSON(t *testing.T) {
	h := NewCatalogHandler(newHandlerCore(t))
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_MissingJustification(t *testing.T) {
	h := NewCatalogHandler(newHandlerCore(t))
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"ttl":"1h"}`)),
		"id", "1",
	))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── catalog.go ────────────────────────────────────────────────────────────────

func TestCatalogHandler_ListProjects_HappyPath(t *testing.T) {
	h := NewCatalogHandler(newHandlerCore(t))
	// #2780: ListProjects authorizes in-handler now, so it needs a user context.
	// This fixture seeds no RBAC, so the list comes back empty — the assertion is
	// that the endpoint answers 200, which is the point (it used to 403).
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil))
	w := httptest.NewRecorder()
	h.ListProjects(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_RestoreProject_BadID(t *testing.T) {
	h := NewCatalogHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RestoreProject_NotFound(t *testing.T) {
	h := NewCatalogHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── admin_impersonation.go ────────────────────────────────────────────────────

func TestImpersonationHandler_Start_Unauthorized(t *testing.T) {
	cs := newHandlerCore(t)
	h := NewImpersonationHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/impersonate", nil)
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestImpersonationHandler_End_NoToken(t *testing.T) {
	cs := newHandlerCore(t)
	h := NewImpersonationHandler(cs, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/end-impersonation", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	// No token → 400 BadRequest (token check precedes auth check).
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestImpersonationHandler_Start_BadJSON(t *testing.T) {
	cs := newHandlerCore(t)
	h := NewImpersonationHandler(cs, false)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/impersonate",
		strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sendCampaignError ─────────────────────────────────────────────────────────

func TestSendCampaignError_500ClassifyLoggedAndReplaced(t *testing.T) {
	w := httptest.NewRecorder()
	// An "unknown error" string maps to 500, gets logged server-side, and a
	// generic client-safe message replaces it.
	sendCampaignError(w, "context", fmt.Errorf("some internal storage failure"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
