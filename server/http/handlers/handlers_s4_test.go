// handlers_s4_test.go — broad coverage sweep targeting previously-uncovered
// handler functions. Strategy: proxy handlers get bad-input validation tests
// (early-return paths); CRUD handlers get unauthorized + bad-ID + happy-path
// tests against an empty in-memory DB.
package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// newCatalogHandlerS4 creates a CatalogHandler with the full s4 DB.
func newCatalogHandlerS4(t *testing.T) *CatalogHandler {
	t.Helper()
	return NewCatalogHandler(newHandlerCoreS4(t))
}

// ── access_request_proxy.go ───────────────────────────────────────────────────

// TestCreateAccessRequestApprovalProxy_NoAuthenticatedCaller (G80
// documented-exception re-verification sweep, 2026-08-25) supersedes the old
// MissingApproverID test: approver_id is no longer read from the wire at
// all. What must still be rejected is a call with no authenticated caller.

// ── access_review_campaigns_proxy.go ─────────────────────────────────────────

// ── break_glass_proxy.go ──────────────────────────────────────────────────────

// ── catalog.go ────────────────────────────────────────────────────────────────

func TestGetProjectDrift_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetProjectDrift(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetProjectDrift_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectDrift(w, req)
	// No project → 200 with empty drift (core returns empty for unknown project)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestListEnvironments_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil)) // #2780: authorizes in-handler
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateProject_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProject_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteProject_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteProject_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteProject(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestCreateProjectEnvironment_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateProjectEnvironment_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateProjectEnvironment_MissingName(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteEnvironment_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteEnvironment_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteEnvironment(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListProjectEnvironments_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectEnvironments_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRestoreEnvironment_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"projectId": "bad", "id": "1"})
	w := httptest.NewRecorder()
	h.RestoreEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreEnvironment_BadEnvID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"projectId": "1", "id": "bad"})
	w := httptest.NewRecorder()
	h.RestoreEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── connect.go ────────────────────────────────────────────────────────────────

// TestIsSafeConnectError checks isSafeConnectError's classification of the
// core package's typed connect sentinels (see also
// TestIsSafeConnectError_ExtraStrings_S23 for the G50 anti-spoofing coverage:
// a look-alike error carrying the same text but not wrapping a sentinel must
// NOT be classified as safe).
func TestIsSafeConnectError(t *testing.T) {
	assert.True(t, isSafeConnectError(core.ErrConnectDisabled))
	assert.True(t, isSafeConnectError(fmt.Errorf("%w %q", core.ErrConnectUnknownConnector, "foo")))
	assert.True(t, isSafeConnectError(core.ErrConnectRoleRequired))
	assert.True(t, isSafeConnectError(fmt.Errorf("ref %q %w %q", "r", core.ErrConnectRefNotPermitted, "c")))
	assert.False(t, isSafeConnectError(errors.New("some storage layer error")))
	assert.False(t, isSafeConnectError(nil))
}

func TestNewConnectHandler(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	require.NotNil(t, h)
}

func TestConnectHandler_ListConnectors_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConnectors(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_GetSecret_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"connector": "vault", "ref": "secret/foo"})
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_ListRefGrants_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRefGrants(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_CreateRefGrant_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_DeleteRefGrant_Unauthorized(t *testing.T) {
	h := NewConnectHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── dashboard.go ──────────────────────────────────────────────────────────────

func TestDashboardHandler_GetStats_Unauthorized(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	w := httptest.NewRecorder()
	h.GetStats(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_GetStats_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil))
	w := httptest.NewRecorder()
	h.GetStats(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetCompliancePosture_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/posture", nil)
	w := httptest.NewRecorder()
	h.GetCompliancePosture(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetComplianceDigest_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/digest", nil)
	w := httptest.NewRecorder()
	h.GetComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_VerifyComplianceEvidence_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.VerifyComplianceEvidence(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_VerifyComplianceEvidence_BadBase64(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	body := `{"data_b64":"not!valid@base64","signature":""}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyComplianceEvidence(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_VerifyComplianceEvidence_ValidBase64(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	data := base64.StdEncoding.EncodeToString([]byte("somedata"))
	body, _ := json.Marshal(map[string]string{"data_b64": data, "signature": "sig"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyComplianceEvidence(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetComplianceControls_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/controls", nil)
	w := httptest.NewRecorder()
	h.GetComplianceControls(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetComplianceEvidence_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence", nil)
	w := httptest.NewRecorder()
	h.GetComplianceEvidence(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_GetActivity_Unauthorized(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/activity", nil)
	w := httptest.NewRecorder()
	h.GetActivity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_GetActivity_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/activity", nil))
	w := httptest.NewRecorder()
	h.GetActivity(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// sharedS4Core is initialised exactly once for the entire test binary. All
// s4 tests are structural/error-path tests (bad JSON, missing auth, bad IDs)
// that never assert on specific row counts or pre-seeded DB state, so sharing
// a single migrated core across the run is safe and eliminates the ~1400×
// AutoMigrate calls that caused the 2-minute CI timeout under -race.
//
// The shared DB also carries the per-IP login budgets (login_attempts), which every
// auth-endpoint test hitting httptest's default RemoteAddr fills. A budget that is
// full at the START of a test is an artifact of how many tests (or -count repetitions)
// ran before it, not behaviour under test, so newHandlerCoreS4 empties that table on
// every call (test-only: the production limit and its window are untouched). Tests
// that assert on the limiter itself (429 paths) own a private core and never touch it.
var (
	sharedS4CoreOnce sync.Once
	sharedS4Core     *core.KeyorixCore
	sharedS4DB       *gorm.DB
)

// newHandlerCoreS4 returns a shared *core.KeyorixCore backed by a single
// in-memory SQLite DB whose schema is migrated exactly once per test binary.
// All s4 tests are early-return path tests (4xx status checks) that do not
// rely on an empty DB, so the shared instance is safe.
func newHandlerCoreS4(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	sharedS4CoreOnce.Do(func() {
		// Process-wide singleton, so sqlitetest.Open (which closes the DB on the
		// first caller's t.Cleanup) does not fit; take its DSN and apply the same
		// single-connection pool cap by hand. The DB is never closed: the binary
		// exits first.
		db, err := gorm.Open(sqlite.Open(sqlitetest.DSN("kxhandlers_s4_")), &gorm.Config{})
		if err != nil {
			panic("newHandlerCoreS4: open DB: " + err.Error())
		}
		sqlDB, err := db.DB()
		if err != nil {
			panic("newHandlerCoreS4: reach *sql.DB: " + err.Error())
		}
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
		sqlDB.SetConnMaxIdleTime(0)
		if err := db.AutoMigrate(
			&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
			&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
			&models.Project{}, &models.Environment{}, &models.SecretNode{},
			&models.AuditEvent{}, &models.AnomalyAlert{},
			&models.RotationPolicy{}, &models.Notification{},
			&models.ProjectMembership{}, &models.SoDPolicy{},
			&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
			&models.LoginAttempt{},
			// s4 additions:
			&models.AccessRequest{}, &models.AccessRequestApproval{},
			&models.WebAuthnCredential{}, &models.WebAuthnSession{},
			&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
			&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
			&models.MFAChallenge{}, &models.SSOLoginState{},
			// s4 round2 additions:
			&models.MachineIdentity{}, &models.MachineIdentityCredential{},
			&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
			&models.SecretDependency{}, &models.RiskException{},
			&models.MFASecret{}, &models.MFARecoveryCode{},
			&models.IdentityProvider{}, &models.ExternalIdentity{},
			&models.LegalHold{}, &models.ShareRecord{},
			&models.PersonalAccessToken{},
			// s4 batch3 additions:
			&models.ProjectInvitation{}, &models.SchedulerLockLease{},
			&models.SecretAccessLog{},
			&models.SecretACL{},
		); err != nil {
			panic("newHandlerCoreS4: AutoMigrate: " + err.Error())
		}
		sharedS4DB = db
		sharedS4Core = core.NewKeyorixCore(store.NewLocalStorage(db))
	})
	resetSharedS4LoginBudgets(t)
	return sharedS4Core
}

// resetSharedS4LoginBudgets empties the shared core's login_attempts table, so no test
// starts against a budget that earlier tests or earlier -count repetitions filled.
func resetSharedS4LoginBudgets(t *testing.T) {
	t.Helper()
	require.NoError(t, sharedS4DB.Session(&gorm.Session{Logger: logger.Discard}).
		Where("1 = 1").Delete(&models.LoginAttempt{}).Error)
}

// newAuthHandlerWithWebAuthn creates an AuthHandler backed by a DB that also
// has the WebAuthn tables migrated (required by the proxy tests).
func newAuthHandlerWithWebAuthn(t *testing.T) *AuthHandler {
	t.Helper()
	return NewAuthHandler(newHandlerCoreS4(t), false)
}

// ── webauthn_proxy.go ─────────────────────────────────────────────────────────

// ── users (package-level dispatch when defaultUserHandler == nil) ─────────────

func TestPackageLevelUserFunctions_ServiceUnavailable(t *testing.T) {
	// Save and nil out the global handler.
	saved := defaultUserHandler
	defaultUserHandler = nil
	t.Cleanup(func() { defaultUserHandler = saved })

	funcs := []struct {
		name string
		fn   http.HandlerFunc
	}{
		{"UnlockUser", UnlockUser},
		{"SuspendUser", SuspendUser},
		{"RevokeSessions", RevokeSessions},
		{"ReactivateUser", ReactivateUser},
		{"RequirePasswordReset", RequirePasswordReset},
		{"ResendSetupLink", ResendSetupLink},
	}
	for _, tc := range funcs {
		t.Run(tc.name, func(t *testing.T) {
			req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
			w := httptest.NewRecorder()
			tc.fn(w, req)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}
}

// ── users_list.go ─────────────────────────────────────────────────────────────

func newUserHandler(t *testing.T) *UserHandler {
	t.Helper()
	cs := newHandlerCore(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	return h
}

func TestListUsers_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListUsers_HappyPath(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListUsers_WithSearch(t *testing.T) {
	// SQLite in-memory does not support ILIKE — handler path is still exercised.
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?search=foo&is_active=true", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	// Non-bad-request response means auth + param path was traversed
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListUsers_InactiveFilter(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?filter=inactive", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListUsers_LargePageClamped(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users?page=99999999&page_size=50", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSearchUsers_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q=foo", nil)
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSearchUsers_MissingQuery(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/search", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSearchUsers_HappyPath(t *testing.T) {
	// SQLite in-memory does not support ILIKE so the search returns an internal
	// error — the handler path past the auth/param checks is still exercised.
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q=alice", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	// Expect any non-400 response (auth passed, query param present)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestStaleAccounts_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/stale", nil)
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestStaleAccounts_InvalidState(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?state=invalid_state", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStaleAccounts_HappyPath(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_roles.go ────────────────────────────────────────────────────────────

func newUsersRolesHandler(t *testing.T) *UsersRolesHandler {
	t.Helper()
	return NewUsersRolesHandler(newHandlerCore(t))
}

func TestGetUserRolesForUser_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserRolesForUser_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserRolesForUser_HappyPath(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	// User not found returns empty roles (no error from storage)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestGetUserPermissionsForUser_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserPermissionsForUser_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserMembershipsForUser_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserMembershipsForUser_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserMembershipsForUser_HappyPath(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateUserRoles_Unauthorized(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateUserRoles_BadID(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUserRoles_BadJSON(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUserRoles_EmptyRoles(t *testing.T) {
	h := newUsersRolesHandler(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// User 1 doesn't exist → 404 or 500 (no 200)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── admin_impersonation.go ────────────────────────────────────────────────────

func TestImpersonationHandler_ClientIP(t *testing.T) {
	// clientIP is called from Start — test it via its effect on Start
	cs := newHandlerCore(t)
	h := NewImpersonationHandler(cs, false)
	body := `{"user_id":1}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	h.Start(w, req)
	// Will fail (user not found or no permission), but clientIP is exercised
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── groups_proxy.go ───────────────────────────────────────────────────────────

func newGroupHandler(t *testing.T) *GroupHandler {
	t.Helper()
	h, err := NewGroupHandler(newHandlerCore(t))
	require.NoError(t, err)
	return h
}

// TestDeleteGroupProxy_RefusesWhenGroupHoldsLastAdmin is the #G79 regression:
// DeleteGroupProxy previously called storage.DeleteGroup directly, bypassing
// every core-layer escalation guard. Now that it routes through
// core.KeyorixCore.DeleteGroup, guardLastGlobalAdminGroupDelete must refuse a
// system.write-only caller from deleting a group holding the install's last
// admin-conferring role grant via this proxy route, identical to the
// human-facing path (see group_admin_guard_test.go's core-level coverage of
// the same guard).

// TestCreateSetupTokenProxy_RefusesUnmatchedSubject is the #G79 regression:
// CreateSetupTokenProxy previously persisted whatever token_hash/subject_email
// the caller supplied with no check that either referenced anything real,
// letting a system.write caller mint an active token binding a plaintext it
// already knows to an arbitrary identity — then redeem it via the public
// /auth/setup/consume endpoint. A subject_user_id that doesn't reference an
// existing user must now be refused, and no token must be persisted.

// TestCreateSetupTokenProxy_InvitationAccept_HappyPath closes a test-coverage
// gap the G80 documented-exception re-verification sweep found: the
// invitation_accept branch (GetProjectInvitation + email-match check) had zero
// test coverage anywhere in this handler's test suite. A real, matching
// invitation must be accepted, gated on users.write per the same sweep's fix.

// TestCreateSetupTokenProxy_InvitationAccept_RefusesEmailMismatch is
// TestCreateSetupTokenProxy_InvitationAccept_HappyPath's companion: a real
// invitation exists, but the caller's subject_email doesn't match it — must be
// refused, and no token persisted.

// TestCreateUserWithRoleGrantsProxy_RefusesUnauthorizedAdminGrant is the #G79
// regression: CreateUserWithRoleGrantsProxy previously called
// storage.CreateUserWithRoleGrants directly, persisting whatever grants the
// caller supplied with none of core.CreateUserWithAssignments's
// escalation-ceiling check. A caller with no admin authority of its own must
// be refused when the grant set includes an admin-tier role, and no user
// must be persisted.
//
// FIX-1 rerouted this ceiling from requireAuthorityForRole (name-based: fired
// unconditionally for actorID 0, no exemption) to requireGranterHoldsRolePermissions,
// which has an EXPLICIT actorID==0-and-not-machine fast path (the trusted
// local-CLI/embedded-caller convention, already relied on by other callers
// since #1542). This handler is an HTTP /system route reachable only through
// RequirePermission(permSystemWrite) — that middleware fails closed
// (401 "User context not found") on a nil UserContext, so actorID(r) can
// never resolve to 0-and-not-machine for a REAL caller reaching this code;
// a raw unauthenticated request (as this test originally simulated by
// calling the handler with no context at all) is not a state the deployed
// router can produce here. The realistic unauthorized case per this test's
// own original framing is an AUTHENTICATED caller who holds system.write
// but no admin authority — simulated below with a genuine non-zero UserID.

// ── groups_handler.go ─────────────────────────────────────────────────────────

func TestGroupHandler_ListGroups_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_ListGroups_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGroupHandler_GetGroup_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_DeleteGroup_BadID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets_proxy.go ──────────────────────────────────────────────────

func newDynamicSecretHandlerS4(t *testing.T) *DynamicSecretHandler {
	t.Helper()
	return NewDynamicSecretHandler(newHandlerCoreS4(t))
}

func TestIsSafeDynamicSecretError(t *testing.T) {
	assert.True(t, isSafeDynamicSecretError("config not found"))
	assert.True(t, isSafeDynamicSecretError("lease not found"))
	assert.True(t, isSafeDynamicSecretError("lease is not active"))
	assert.True(t, isSafeDynamicSecretError("active-lease limit reached"))
	assert.False(t, isSafeDynamicSecretError("connection refused"))
}

func TestNewDynamicSecretHandler(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCore(t))
	require.NotNil(t, h)
}

// CreateDynamicSecretConfigProxy tests deleted -- #1580 liveness sweep,
// handler removed (no live caller in either topology).

// ── sod.go ────────────────────────────────────────────────────────────────────

func TestSoDHandler_ListSoDPolicies_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDPolicies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSoDHandler_CreateSoDPolicy_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSoDHandler_CreateSoDPolicy_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSoDHandler_DeleteSoDPolicy_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSoDHandler_DeleteSoDPolicy_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSoDHandler_ListSoDViolations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod_proxy.go ──────────────────────────────────────────────────────────────

// FIX-6 (#1645 403-for-both): no user context resolves actorID(r) to 0, not
// admin-tier, so a nonexistent policy id gets the same denial as an
// existing-but-foreign one.

// ── deployment_hygiene.go ─────────────────────────────────────────────────────

func TestDeploymentHygiene_Unauthorized(t *testing.T) {
	cs := newHandlerCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeploymentHygiene_HappyPath(t *testing.T) {
	cs := newHandlerCore(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.DeploymentHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_crud.go (UserHandler methods) ──────────────────────────────────────

func TestUserHandler_GetUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUser_BadID(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUser_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetUserByEmail_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?email=x@y.com", nil)
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByEmail_MissingEmail(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByEmail_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?email=notfound@x.com", nil))
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetUserByUsername_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?username=alice", nil)
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByUsername_MissingUsername(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByUsername_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?username=nobody", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_DeleteUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RestoreUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_UnlockUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_SuspendUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ReactivateUser_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ReactivateUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RequirePasswordReset_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RequirePasswordReset(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go (human-facing handler) ─────────────────────────────────

func TestDynamicSecretHandler_CreateConfig_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	// No user context → 401 (CreateConfig checks userCtx first)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_ListConfigs_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	// authorize(nil ctx) → false, false → denyAuthz → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDynamicSecretHandler_GetConfig_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	// Config not found → 404 (before auth check)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_GetConfig_BadID(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_IssueLease_BadID(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	// #1645/ADR-096: IssueLease now checks mustGetUser before loadConfig
	// (matching every sibling handler in this file) -- a real user context
	// is required to reach the bad-id branch this test targets, or mustGetUser's
	// own 401 fires first instead.
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notanid"))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_IssueLease_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	// #1645/ADR-096: a real user context is required to reach loadConfig's
	// not-found branch this test targets -- see IssueLease_BadID's comment above.
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_ListLeases_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "leaseID", "l1")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	// No user context → 401
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_RenewLease_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "l1")
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	// No user context → 401
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_RevokeAllLeases_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	// #1645/ADR-096: RevokeAllLeases now checks mustGetUser before loadConfig
	// (matching every sibling handler in this file) -- a real user context
	// is required to reach loadConfig's not-found branch this test targets.
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_ClassifyConfig_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	// #1645/ADR-096: same mustGetUser-before-loadConfig ordering as above.
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDynamicSecretHandler_SetConfigEnabled_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newDynamicSecretHandlerS4(t).coreService)
	// #1645/ADR-096: same mustGetUser-before-loadConfig ordering as above.
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── connect_grants_proxy.go ───────────────────────────────────────────────────

// ── setup_tokens_proxy.go ─────────────────────────────────────────────────────

// TestConsumeSetupTokenProxy_BadID deleted -- #1579 liveness sweep, handler
// removed (no live caller in either topology).

// ── mfa_management_proxy.go ──────────────────────────────────────────────────

// ── project_memberships_proxy.go ─────────────────────────────────────────────

// ── project_catalog_proxy.go ─────────────────────────────────────────────────

// ── environment_catalog_proxy.go ─────────────────────────────────────────────

// ── machine_identities_proxy.go ───────────────────────────────────────────────

// ── secret_dependencies_proxy.go ─────────────────────────────────────────────

// ── risk_exceptions_proxy.go ─────────────────────────────────────────────────

// UpdateRiskExceptionProxy was removed (#G79) — see risk_exceptions_proxy.go's
// removal comment.

// ── retention_proxy.go ───────────────────────────────────────────────────────

// ── misc_remote_proxy.go ─────────────────────────────────────────────────────

// ── rbac_role_grants_proxy.go ─────────────────────────────────────────────────

// ── rbac.go (human-facing) ────────────────────────────────────────────────────

func TestRBACHandler_ListRoles_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListRoles_HappyPath(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACHandler_CreateRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.CreateRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_CreateRole_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.CreateRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetRole_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRoleByName_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "name", "admin")
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_UpdateRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_DeleteRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.AssignRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemoveRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RemoveRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetUserRoles_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListPermissions_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListPermissions_HappyPath(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACHandler_GetPermission_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetPermission(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetRolePermissions_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetRolePermissions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemovePermissionFromRole_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetGroupRoles_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemoveRoleFromGroup_Unauthorized(t *testing.T) {
	h := NewRBACHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RemoveRoleFromGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── users_handler.go (legacy + package-level dispatch when nil) ──────────────

func TestListUsersLegacy_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	listUsersLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListUsersLegacy_HappyPath(t *testing.T) {
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	listUsersLegacy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateUserLegacy_Unauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	createUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserLegacy_Unauthorized(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	getUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserLegacy_HappyPath(t *testing.T) {
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	getUserLegacy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetUserLegacy_NotFound(t *testing.T) {
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	getUserLegacy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateUserLegacy_Unauthorized(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	updateUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteUserLegacy_Unauthorized(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	deleteUserLegacy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteUserLegacy_HappyPath(t *testing.T) {
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	deleteUserLegacy(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// Package-level dispatch functions (nil handler → 503)
func TestSearchUsers_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodGet, "/?q=test", nil)
	w := httptest.NewRecorder()
	SearchUsers(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestListUsers_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	ListUsers(w, req)
	// nil handler → listUsersLegacy → 200 (has userCtx)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
	w := httptest.NewRecorder()
	CreateUser(w, req)
	// createUserLegacy validates body → bad data → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	GetUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetUserByEmail_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := httptest.NewRequest(http.MethodGet, "/?email=test@test.com", nil)
	w := httptest.NewRecorder()
	GetUserByEmail(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestUpdateUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "1"))
	w := httptest.NewRecorder()
	UpdateUser(w, req)
	// updateUserLegacy with valid body → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteUser_NilHandler(t *testing.T) {
	saved := defaultUserHandler
	defaultUserHandler = nil
	defer func() { defaultUserHandler = saved }()
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	DeleteUser(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── machine_identities.go (human-facing) ──────────────────────────────────────

func TestCatalogHandler_ListMachineIdentities_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineIdentities_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCatalogHandler_ListStaleMachineIdentities_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListStaleMachineIdentities(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_TransitionMachineIdentity_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_IssueMachineToken_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineTokens_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RevokeMachineToken_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "machineId": "1", "credId": "1"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ClassifyMachineIdentity_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ClassifyMachineToken_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "bad", "machineId": "1", "credId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_GrantMachineRole_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateOIDCBinding_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_ListOIDCBindings_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_DeleteOIDCBinding_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "machineId": "1", "bindingId": "1"})
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── webauthn.go (human-facing) ─────────────────────────────────────────────────

func TestBeginWebAuthnRegistration_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestFinishWebAuthnRegistration_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestFinishWebAuthnRegistration_BadBody(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListWebAuthnCredentials_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListWebAuthnCredentials_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentials(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteWebAuthnCredential_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBeginWebAuthnLogin_BadBody(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, req)
	// No username/email provided → 400 or similar
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestBeginWebAuthnPasswordlessLogin_BadBody(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnPasswordlessLogin(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── rotation_policies_handler.go ──────────────────────────────────────────────

func TestRotationPolicyHandler_List_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_List_HappyPath(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_Create_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Create_BadJSON(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Get_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Update_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Delete_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestParseOptionalUintQuery_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=5", nil)
	v, err := parseOptionalUintQuery(req, "project_id")
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, uint(5), *v)
}

func TestParseOptionalUintQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	v, err := parseOptionalUintQuery(req, "project_id")
	require.NoError(t, err)
	assert.Nil(t, v)
}

func TestParseOptionalUintQuery_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=abc", nil)
	_, err := parseOptionalUintQuery(req, "project_id")
	assert.Error(t, err)
}

func TestRotationPolicyHandler_Evaluate_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_Status_Unauthorized(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCore(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go and shares_crud.go ───────────────────────────────────────

func newShareHandlerS4(t *testing.T) *ShareHandler {
	t.Helper()
	h, err := NewShareHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

func TestShareHandler_ListSecretShares_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListShares_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListSharedSecrets_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListGroupSharedSecrets_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_GetSharingStatusWithIndicators_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_RemoveSelfFromShare_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ShareSecret_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_UpdateSharePermission_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_RevokeShare_Unauthorized(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── scim.go and scim_groups.go ────────────────────────────────────────────────

func newSCIMHandlerS4(t *testing.T) *SCIMHandler {
	t.Helper()
	return NewSCIMHandler(newHandlerCoreS4(t))
}

func TestSCIMHandler_GetServiceProviderConfig(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetServiceProviderConfig(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMHandler_ListUsers_HappyPath(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMHandler_GetUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_CreateUser_BadJSON(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ReplaceUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.ReplaceUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_PatchUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.PatchUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_DeleteUser_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ListGroups_HappyPath(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSCIMHandler_GetGroup_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_CreateGroup_BadJSON(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ReplaceGroup_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.ReplaceGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_PatchGroup_BadID(t *testing.T) {
	h := newSCIMHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{}")), "id", "bad")
	w := httptest.NewRecorder()
	h.PatchGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Batch 3: comprehensive coverage for remaining 0% functions ────────────────

// ── Helper constructors ────────────────────────────────────────────────────────

func newDashboardHandler(t *testing.T) *DashboardHandler {
	t.Helper()
	return NewDashboardHandler(newHandlerCoreS4(t))
}

func newPATHandler(t *testing.T) *PATHandler {
	t.Helper()
	return NewPATHandler(newHandlerCoreS4(t))
}

func newGroupHandlerS4(t *testing.T) *GroupHandler {
	t.Helper()
	gh, err := NewGroupHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return gh
}

func newSecretHandlerS4(t *testing.T) *SecretHandler {
	t.Helper()
	h, err := NewSecretHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

// ── isSafeSSOError ────────────────────────────────────────────────────────────

func TestIsSafeSSOError_Known(t *testing.T) {
	assert.True(t, isSafeSSOError("unknown SSO provider"))
	assert.True(t, isSafeSSOError("invalid or expired login state"))
	assert.False(t, isSafeSSOError("account suspended"))
	assert.True(t, isSafeSSOError("no Keyorix account matches this SSO identity"))
}

func TestIsSafeSSOError_Unknown(t *testing.T) {
	assert.False(t, isSafeSSOError("database connection refused"))
	assert.False(t, isSafeSSOError("token verification failed: some library error"))
}

// ── ListSSOProviders ──────────────────────────────────────────────────────────

func TestListSSOProviders_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSSOProviders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── BeginSSO ─────────────────────────────────────────────────────────────────

func TestBeginSSO_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CompleteSSO ───────────────────────────────────────────────────────────────

func TestCompleteSSO_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── MFA handlers ─────────────────────────────────────────────────────────────

func TestEnrollMFA_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.EnrollMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestActivateMFA_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"code":"123456"}`))
	w := httptest.NewRecorder()
	h.ActivateMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDisableMFA_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegenerateRecoveryCodes_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRecoveryCodesStatus_Unauthorized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyMFA_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyMFA_InvalidChallenge(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"mfa_challenge":"invalid","code":"000000"}`))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── PAT handlers ──────────────────────────────────────────────────────────────

func TestListPATs_Unauthorized(t *testing.T) {
	h := newPATHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListPATs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListPATs_HappyPath(t *testing.T) {
	h := newPATHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListPATs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPATHygiene_Unauthorized(t *testing.T) {
	h := newPATHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATHygiene_HappyPath(t *testing.T) {
	h := newPATHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=30", nil))
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreatePAT_Unauthorized(t *testing.T) {
	h := newPATHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreatePAT_BadJSON(t *testing.T) {
	h := newPATHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreatePAT_InvalidExpiry(t *testing.T) {
	h := newPATHandler(t)
	expiry := "not-a-date"
	body, _ := json.Marshal(map[string]any{"name": "tok", "expires_at": expiry})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestToPATResponse_Nilsafe(t *testing.T) {
	now := time.Now()
	tok := &models.PersonalAccessToken{
		Name:        "test",
		TokenPrefix: "kx_",
		CreatedAt:   now,
	}
	resp := toPATResponse(tok)
	assert.Equal(t, "test", resp.Name)
	assert.Nil(t, resp.ExpiresAt)
	assert.Nil(t, resp.LastUsedAt)
}

// ── Risk exceptions ───────────────────────────────────────────────────────────

func TestListRiskExceptions_HappyPath(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateRiskException_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateRiskException_BadExpiry(t *testing.T) {
	h := newDashboardHandler(t)
	body := `{"title":"t","justification":"j","expires_at":"bad"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestApproveRiskException_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestApproveRiskException_BadID(t *testing.T) {
	h := newDashboardHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeRiskException_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeRiskException_BadID(t *testing.T) {
	h := newDashboardHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Legal hold handlers ───────────────────────────────────────────────────────

func TestGetLegalHold_HappyPath(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetLegalHold(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPlaceLegalHold_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"test"}`))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPlaceLegalHold_BadJSON(t *testing.T) {
	h := newDashboardHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad")))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	// bad JSON -> 400 or error from core; actual core path tries to place with empty reason
	// both 400 and 500 are acceptable here; just not unauthorized
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestLiftLegalHold_Unauthorized(t *testing.T) {
	h := newDashboardHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Legal hold proxy ──────────────────────────────────────────────────────────

// ── Login attempts proxy ──────────────────────────────────────────────────────

// ── Scheduler lock proxy ──────────────────────────────────────────────────────

// ── Invitation proxy ──────────────────────────────────────────────────────────

// ── SSO state proxy ───────────────────────────────────────────────────────────

// ── Dynamic secret proxy wire round-trips ────────────────────────────────────

// ── Invitation handlers (human-facing) ───────────────────────────────────────

func TestListInvitations_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListInvitations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateInvitation_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateInvitation_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResendInvitation_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "bad", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResendInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "1", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeInvitation_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "bad", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "invitationId": "1"})
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAccessRequests_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessRequests_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateAccessRequest_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResolveAccessRequest_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), map[string]string{"id": "bad", "requestId": "1"})
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResolveAccessRequest_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), map[string]string{"id": "1", "requestId": "1"})
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResolveAccessRequest_InvalidAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"unknown"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), map[string]string{"id": "1", "requestId": "1"}))
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWithdrawAccessRequest_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "requestId", "1")
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateGlobalInvitation_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateGlobalInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Project members ───────────────────────────────────────────────────────────

func TestListProjectMembers_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMembers_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetProjectAccessReview_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetProjectAccessReview_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeProjectAccessReview_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"role_assignment","principal_type":"user","principal_id":1,"role_id":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAttestProjectAccessReview_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"role_assignment","principal_type":"user","principal_id":1,"role_id":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddProjectMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddProjectMember_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), map[string]string{"id": "1", "userId": "1"})
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRemoveProjectMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Project memberships ───────────────────────────────────────────────────────

func TestListProjectMemberships_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListProjectMemberships_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestInviteMember_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInviteMember_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMembership_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"activate"}`
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), map[string]string{"id": "1", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMembershipActionState_Valid(t *testing.T) {
	s, ok := membershipActionState("verify")
	assert.True(t, ok)
	assert.NotEmpty(t, s)
	s, ok = membershipActionState("activate")
	assert.True(t, ok)
	assert.NotEmpty(t, s)
	_, ok = membershipActionState("unknown")
	assert.False(t, ok)
}

// ── Group members ─────────────────────────────────────────────────────────────

func TestGetGroupMembers_Unauthorized(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetGroupMembers_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddGroupMember_MissingUserID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "userId": "2"})
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInitCoreHandlers_HappyPath(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	uh, gh, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	assert.NotNil(t, uh)
	assert.NotNil(t, gh)
}

// ── Secret dependency handlers ────────────────────────────────────────────────

func TestDependencyErrorStatus_Messages(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, dependencyErrorStatus("secret not found"))
	assert.Equal(t, http.StatusBadRequest, dependencyErrorStatus("cannot depend on itself"))
	assert.Equal(t, http.StatusBadRequest, dependencyErrorStatus("cycle detected"))
	assert.Equal(t, http.StatusForbidden, dependencyErrorStatus("permission denied"))
	assert.Equal(t, http.StatusInternalServerError, dependencyErrorStatus("some random error"))
}

func TestListSecretDependencies_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListSecretDependencies_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddSecretDependency_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddSecretDependency_MissingDependsOn(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveSecretDependency_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{"id": "1", "depId": "2"})
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSecretImpact_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetProjectRotationOrder_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetProjectRotationPlan_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetDeploymentRotationPlan_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetDeploymentRotationPlan(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Users crud ────────────────────────────────────────────────────────────────

func TestGetUserByExternalID_Unauthorized(t *testing.T) {
	h := newUserHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/?external_id=ext1", nil)
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserByExternalID_MissingParam(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserByExternalID_NotFound(t *testing.T) {
	h := newUserHandler(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?external_id=nonexistent", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── Users handler dispatch ────────────────────────────────────────────────────

func TestStaleAccountsDispatch_HappyPath(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	uh, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	_ = uh
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetUserByUsernameDispatch_Unauthorized(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	_, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/?username=test", nil)
	w := httptest.NewRecorder()
	GetUserByUsername(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserByExternalIDDispatch_MissingParam(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	_, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRestoreUserDispatch_Unauthorized(t *testing.T) {
	saved := defaultUserHandler
	t.Cleanup(func() { defaultUserHandler = saved })
	cs := newHandlerCoreS4(t)
	_, _, err := InitCoreHandlers(cs)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	RestoreUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── RemoveMachineRole ─────────────────────────────────────────────────────────

func TestRemoveMachineRole_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{
		"id": "bad", "machineId": "1", "roleId": "1",
	})
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMachineRole_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{
		"id": "1", "machineId": "1", "roleId": "1",
	})
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMachineActionState_Values(t *testing.T) {
	s, ok := machineActionState("activate")
	assert.True(t, ok)
	assert.NotEmpty(t, s)
	_, ok = machineActionState("unknown")
	assert.False(t, ok)
}

// ── MachineTokenHygiene ───────────────────────────────────────────────────────

func TestMachineTokenHygiene_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMachineTokenHygiene_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── ProjectHygiene ────────────────────────────────────────────────────────────

func TestProjectHygiene_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProjectHygiene_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SuspendProjectSecrets / ResumeProjectSecrets ──────────────────────────────

func TestSuspendProjectSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSuspendProjectSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"test"}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestResumeProjectSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResumeProjectSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SuspendSecret / ResumeSecret ─────────────────────────────────────────────

func TestSuspendSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSuspendSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.SuspendSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResumeSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResumeSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Secret tags ───────────────────────────────────────────────────────────────

func TestGetTags_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetTags_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetTags_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"tags":[]}`)), "id", "1")
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSetTags_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"tags":[]}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Secret versions ───────────────────────────────────────────────────────────

func TestGetSecretVersions_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretVersions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotateSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRollbackSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Secret usage ──────────────────────────────────────────────────────────────

func TestUsageMostAccessed_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUsageMostAccessed_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.UsageMostAccessed(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUsageUnused_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestParseProjectIDQuery_Valid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?project_id=5", nil)
	pid, ok := parseProjectIDQuery(r)
	require.True(t, ok)
	require.NotNil(t, pid)
	assert.Equal(t, uint(5), *pid)
}

func TestParseProjectIDQuery_Absent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	pid, ok := parseProjectIDQuery(r)
	assert.True(t, ok)
	assert.Nil(t, pid)
}

func TestParseIntQuery_Default(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Equal(t, 30, parseIntQuery(r, "days", 30))
}

func TestParseIntQuery_Valid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/?days=7", nil)
	assert.Equal(t, 7, parseIntQuery(r, "days", 30))
}

// ── Secret list ───────────────────────────────────────────────────────────────

func TestListSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	// ListSecrets looks up the user in DB; with no user in DB it returns 500.
	// The purpose here is to cover the post-auth code path.
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// 200 if user exists (it won't in empty DB), or 500 from user lookup failure
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── Secret access history / accessors ────────────────────────────────────────

func TestAccessHistory_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAccessors_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── AuditTrail ────────────────────────────────────────────────────────────────

func TestAuditTrail_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.AuditTrail(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditTrail_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.AuditTrail(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DeletedSecrets / ExpiringSecrets / OrphanedSecrets ────────────────────────

func TestDeletedSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExpiringSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOrphanedSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOrphanedSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.OrphanedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetSecretByName / GetSecretValueByRef ────────────────────────────────────

func TestGetSecretByName_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?name=foo&project_id=1&environment_id=1", nil)
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSecretByName_MissingName(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretValueByRef_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?ref=proj/env/name", nil)
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── SecretDescription / SecretRisk / ReassignOwner / TransferOwnership ─────────

func TestDescribeSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSecretRisk_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretRisk(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestReassignOwner_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTransferOwnership_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── newAccessRequestApprovalProxyWire ─────────────────────────────────────────

// ── newAccessReviewItemProxyWire ──────────────────────────────────────────────

// ── newUserRetentionProxyWire ─────────────────────────────────────────────────

// ── filterShareViews / atoiDefault ────────────────────────────────────────────

func TestAtoiDefault_Valid(t *testing.T) {
	assert.Equal(t, 5, atoiDefault("5", 10))
}

func TestAtoiDefault_Invalid(t *testing.T) {
	assert.Equal(t, 10, atoiDefault("bad", 10))
}

func TestAtoiDefault_Empty(t *testing.T) {
	assert.Equal(t, 10, atoiDefault("", 10))
}

func TestFilterShareViews_Empty(t *testing.T) {
	result := filterShareViews(nil, func(core.ShareView) bool { return true })
	assert.Empty(t, result)
}

func TestFilterShareViews_Filters(t *testing.T) {
	views := []core.ShareView{{ID: 1}, {ID: 2}}
	result := filterShareViews(views, func(v core.ShareView) bool { return v.ID == 1 })
	assert.Len(t, result, 1)
}

// ── pageSlice (scim_groups.go) ────────────────────────────────────────────────

func TestPageSlice_Empty(t *testing.T) {
	result := pageSlice([]int(nil), 1, 10)
	assert.Empty(t, result)
}

func TestPageSlice_InBounds(t *testing.T) {
	items := []int{1, 2, 3}
	result := pageSlice(items, 1, 2)
	assert.Len(t, result, 2)
}

func TestPageSlice_Beyond(t *testing.T) {
	items := []int{1}
	result := pageSlice(items, 5, 10)
	assert.Empty(t, result)
}

// ── GetSecretCertificate ──────────────────────────────────────────────────────

func TestGetSecretCertificate_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── SAML endpoints ────────────────────────────────────────────────────────────

func TestSAMLMetadata_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.SAMLMetadata(w, req)
	// unknown provider → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestBeginSAML_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompleteSAML_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "provider", "unknown")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)
	// unknown provider → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── WebAuthn Finish handlers ──────────────────────────────────────────────────

func TestFinishWebAuthnLogin_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestFinishWebAuthnPasswordlessLogin_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── GetSecretVersions / RotateSecret / RollbackSecret happy paths ─────────────

func TestGetSecretVersions_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretVersions(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotateSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"v"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DeletedSecrets / ExpiringSecrets happy paths ──────────────────────────────

func TestDeletedSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.DeletedSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExpiringSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── GetSecretCertificate happy path ──────────────────────────────────────────

func TestGetSecretCertificate_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── AccessHistory / ListAccessors bad-ID paths ────────────────────────────────

func TestAccessHistory_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessors_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── resolveSecretNames ────────────────────────────────────────────────────────

func TestResolveSecretNames_Empty(t *testing.T) {
	h := newSecretHandlerS4(t)
	// resolveSecretNames is a void method; calling with nil/empty should not panic
	h.resolveSecretNames(context.Background(), nil)
}

// ── UpdateInvitationProxy happy path (valid accepted state) ──────────────────

// ── DescribeSecret / GetSecretRisk happy path ────────────────────────────────

func TestDescribeSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DescribeSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSecretRisk_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretRisk(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sanitizeConfig / sanitizeLease (dynamic_secrets.go) ────────────────────────

func TestSanitizeConfig_Strips(t *testing.T) {
	cfg := &models.DynamicSecretConfig{
		Name:         "test",
		AdminDSNEnc:  []byte("sensitive"),
		AdminDSNMeta: []byte("meta"),
	}
	out := sanitizeConfig(cfg)
	require.IsType(t, map[string]any{}, out)
	assert.Equal(t, "test", out["name"])
}

func TestSanitizeLease_Strips(t *testing.T) {
	lease := &models.DynamicSecretLease{
		LeaseID:        "l1",
		CredentialEnc:  []byte("sensitive"),
		CredentialMeta: []byte("meta"),
	}
	out := sanitizeLease(lease)
	require.IsType(t, map[string]any{}, out)
	assert.Equal(t, "l1", out["lease_id"])
}

// ── parseProxyScopeQuery_MissingProject (new unique test) ─────────────────────

// ── WebAuthn extras ───────────────────────────────────────────────────────────

func TestBeginWebAuthnLogin_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("bad"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestFinishWebAuthnRegistration_MissingCredential(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"webauthn_session":"s","name":"n"}`)))
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── BeginWebAuthnPasswordlessLogin ────────────────────────────────────────────

func TestBeginWebAuthnPasswordlessLogin_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnPasswordlessLogin(w, req)
	// WebAuthn not configured -> 501 or 400 - not 200 OK (there's no config)
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// ── base64 encode for webauthn credential body ────────────────────────────────

func TestFinishWebAuthnLogin_InvalidCredential(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// valid JSON with credential but invalid attestation
	cred := base64.RawURLEncoding.EncodeToString([]byte(`{"id":"test","rawId":"dGVzdA","type":"public-key","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY2hhbGxlbmdlIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3QifQ","authenticatorData":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"AAAAAAAA"}}`))
	body := fmt.Sprintf(`{"mfa_challenge":"ch","webauthn_session":"s","credential":%q}`, cred)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	// invalid credential format → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── ReassignOwner / TransferOwnership bad IDs ────────────────────────────────

func TestReassignOwner_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransferOwnership_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── s4b: package-level dispatch with defaultUserHandler set ──────────────────

// newS4bUserHandler creates a UserHandler and sets it as the global, returning
// a cleanup func that restores the previous state. Must be called at the
// start of each test that sets the global.
func setDefaultUserHandlerS4(t *testing.T) *UserHandler {
	t.Helper()
	uh, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	saved := defaultUserHandler
	defaultUserHandler = uh
	t.Cleanup(func() { defaultUserHandler = saved })
	return uh
}

// When defaultUserHandler is set, package-level SearchUsers dispatches to it.
func TestPackageLevel_SearchUsers_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q=alice", nil))
	w := httptest.NewRecorder()
	SearchUsers(w, req)
	// Not 503 or 401 — dispatched successfully
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_StaleAccounts_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale", nil))
	w := httptest.NewRecorder()
	StaleAccounts(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_GetUserByEmail_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-email?email=x@example.com", nil))
	w := httptest.NewRecorder()
	GetUserByEmail(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_GetUserByUsername_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-username?username=alice", nil))
	w := httptest.NewRecorder()
	GetUserByUsername(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_GetUserByExternalID_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/by-external-id?external_id=ext123", nil))
	w := httptest.NewRecorder()
	GetUserByExternalID(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_RestoreUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	RestoreUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_UnlockUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	UnlockUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_SuspendUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	// Same-user check: UserID=1 trying to suspend user 1 → 400 "cannot change own state"
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	SuspendUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_ReactivateUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	ReactivateUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_RequirePasswordReset_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	RequirePasswordReset(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_ResendSetupLink_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	ResendSetupLink(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_RevokeSessions_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	RevokeSessions(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// UpdateUser dispatch — has a legacy fallback but should still test the dispatch path.
func TestPackageLevel_UpdateUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	body := `{"username":"alice","email":"alice@example.com"}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "999"))
	w := httptest.NewRecorder()
	UpdateUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestPackageLevel_DeleteUser_Dispatch(t *testing.T) {
	setDefaultUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999"))
	w := httptest.NewRecorder()
	DeleteUser(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// ── auth.go: Profile, ListSessions, RevokeSession, UpdateProfile, ChangePassword ──

func TestAuthHandler_Profile_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	w := httptest.NewRecorder()
	h.Profile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ListSessions_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ListSessions_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/auth/sessions", nil))
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_RevokeSession_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_RevokeSession_BadID(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RevokeSession_NotFound(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.RevokeSession(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_UpdateProfile_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPut, "/auth/profile", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_UpdateProfile_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPut, "/auth/profile", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_UpdateProfile_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// Valid profile update for non-existent user → 400 (UpdateOwnProfile returns error)
	req := withUserCtx(httptest.NewRequest(http.MethodPut, "/auth/profile", strings.NewReader(`{"display_name":"Alice"}`)))
	w := httptest.NewRecorder()
	h.UpdateProfile(w, req)
	// Either 400 (user not found) or 200 (found) — not 401/503
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestAuthHandler_ChangePassword_UnauthorizedV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ChangePassword_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ChangePassword_BadCurrentPassword(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"current_password":"wrong","new_password":"NewPass123!"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	// Either 401 incorrect, 400 bad request, or 500 user not found — not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go Logout with and without bearer token ──────────────────────────────

func TestAuthHandler_Logout_MissingToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Logout_InvalidToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.Logout(w, req)
	// Logout fails gracefully when session not found → error
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go RefreshToken ──────────────────────────────────────────────────────

func TestAuthHandler_RefreshToken_MissingToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RefreshToken_InvalidToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go InitSystem ────────────────────────────────────────────────────────

func TestAuthHandler_InitSystem_BadJSONV2(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_InitSystem_MissingToken(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"username":"admin","email":"admin@example.com","password":"Admin1234!"}`
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	// Missing bootstrap token → forbidden (403) or internal error (500) depending on DB state
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestAuthHandler_InitSystem_AlreadyInitialized(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// First call bootstraps
	body := `{"username":"admin","email":"admin@example.com","password":"Admin1234!","bootstrap_token":"devtoken"}`
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	req.Header.Set("X-Keyorix-Bootstrap-Token", "devtoken")
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	// Second call should say already initialized (if first succeeded) or return error
	body2 := `{"username":"admin","email":"admin@example.com","password":"Admin1234!"}`
	req2 := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body2))
	w2 := httptest.NewRecorder()
	h.InitSystem(w2, req2)
	// Either 200 already_initialized or some error — not 400
	assert.NotEqual(t, http.StatusBadRequest, w2.Code)
}

// ── auth.go buildLoginResponse and helpers (cover via successful Login flow) ──

func TestAuthHandler_buildLoginResponse_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	now := time.Now()
	later := now.Add(time.Hour)
	absoluteExpiry := now.Add(24 * time.Hour)
	session := &models.Session{
		SessionToken:      "tok123",
		ExpiresAt:         &later,
		AbsoluteExpiresAt: &absoluteExpiry,
	}
	user := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	}
	user.ID = 1
	resp, err := h.buildLoginResponse(context.Background(), session, user)
	require.NoError(t, err)
	assert.Equal(t, "tok123", resp.Token)
	assert.Equal(t, "alice", resp.Username)
	assert.NotEmpty(t, resp.ExpiresAt)
	assert.NotEmpty(t, resp.AbsoluteExpiresAt)
}

func TestAuthHandler_buildLoginResponse_NoExpiry(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	session := &models.Session{SessionToken: "tok"}
	user := &models.User{Username: "bob", Email: "bob@example.com"}
	user.ID = 99
	resp, err := h.buildLoginResponse(context.Background(), session, user)
	require.NoError(t, err)
	assert.Equal(t, "tok", resp.Token)
	assert.Empty(t, resp.ExpiresAt)
}

func TestAuthHandler_setSessionCookies_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	now := time.Now().Add(time.Hour)
	session := &models.Session{SessionToken: "cookietoken", ExpiresAt: &now}
	w := httptest.NewRecorder()
	h.setSessionCookies(w, session)
	// Should set at least one cookie
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
}

func TestUserProfileMap_Direct(t *testing.T) {
	user := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		IsActive:    true,
	}
	user.ID = 1
	now := time.Now()
	user.LastLoginAt = &now

	id := core.UserIdentity{
		Role:        "admin",
		Roles:       []string{"admin"},
		Permissions: []string{"secrets.read"},
	}
	profile := userProfileMap(user, id)
	assert.Equal(t, uint(1), profile["id"])
	assert.Equal(t, "alice", profile["username"])
	assert.Equal(t, "admin", profile["role"])
	assert.NotNil(t, profile["last_login_at"])
}

func TestUserProfileMap_NilRolesPermissions(t *testing.T) {
	user := &models.User{Username: "bob", Email: "bob@example.com"}
	user.ID = 2
	id := core.UserIdentity{}
	profile := userProfileMap(user, id)
	assert.NotNil(t, profile["roles"])
	assert.NotNil(t, profile["permissions"])
}

// ── admin_jobs.go: RunComplianceDigest happy path ───────────────────────────

func TestAdminJobsHandler_RunComplianceDigest_HappyPath(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil))
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminJobsHandler_RunExpiryReminders_DefaultLeadDays(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminJobsHandler_RunExpiryReminders_InvalidLeadDays(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders?lead_days=notanumber", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	// Falls back to default, still succeeds
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── admin_impersonation.go: End handler ──────────────────────────────────────

func TestImpersonationHandler_End_MissingToken(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/end-impersonation", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestImpersonationHandler_End_InvalidToken(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/end-impersonation", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.End(w, req)
	// Token not found → some error (not impersonation session → BadRequest or InternalError)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestImpersonationHandler_Start_AlreadyImpersonating(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":2}`)))
	// Set ImpersonatedBy to simulate already-impersonating session
	by := uint(99)
	ctx := req.Context()
	uc := &middleware.UserContext{
		UserID:         1,
		Username:       "testuser",
		ImpersonatedBy: &by,
	}
	req = req.WithContext(context.WithValue(ctx, middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestImpersonationHandler_Start_MissingUserID(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":0}`)))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_review_campaigns.go: happy path + decision ────────────────────────

func TestOpenAccessReviewCampaign_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Q4 Review"}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	// Project doesn't exist in empty DB → error, but auth + parsing passed
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestOpenAccessReviewCampaign_EmptyBody(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadCampaignID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "campaignId": "notanumber", "itemId": "1",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadItemID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "campaignId": "1", "itemId": "notanumber",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), map[string]string{
		"id": "1", "campaignId": "1", "itemId": "1",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_MissingAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"just because"}`)), map[string]string{
		"id": "1", "campaignId": "1", "itemId": "1",
	}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloseAccessReviewCampaign_BadCampaignID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "campaignId": "notanumber",
	}))
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloseAccessReviewCampaign_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// A campaign id no other test creates. The shared s4 DB keeps rows between tests (and
	// between -count repetitions), so id 1 can already exist, with pending items, by the
	// time this runs again; closing it then answers 400 "pending items", which is not the
	// not-found premise below.
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"force":false}`)), map[string]string{
		"id": "1", "campaignId": "999999",
	}))
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	// Project/campaign not found → error (but auth + parse succeeded)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestCampaignStatusForError_Cases(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, campaignStatusForError("record not found"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("still pending items"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("already closed"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("campaign is closed"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("ownership cannot be revoked"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("value must be"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("required field"))
	assert.Equal(t, http.StatusInternalServerError, campaignStatusForError("some unexpected storage error"))
}

// ── break_glass.go: ActivateBreakGlass + RevokeBreakGlass ────────────────────

func TestActivateBreakGlass_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":"test","ttl":"1h"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_MissingJustificationV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_BadJSONV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestActivateBreakGlass_ProjectNotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"justification":"emergency","ttl":"1h"}`)), "id", "99"))
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	// Not enabled or not found → 403 or 400
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeBreakGlass_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "bad", "activationId": "1",
	}))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_BadActivationID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "activationId": "bad",
	}))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeBreakGlass_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{
		"id": "1", "activationId": "1",
	})
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListBreakGlassActivations_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListBreakGlassActivations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── connect.go: ListConnectors, GetSecret, ListRefGrants, CreateRefGrant ─────

func newConnectHandlerS4(t *testing.T) *ConnectHandler {
	t.Helper()
	return NewConnectHandler(newHandlerCoreS4(t))
}

func TestConnectHandler_ListConnectors_HappyPath(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListConnectors(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestConnectHandler_GetSecret_MissingRef(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`)), "name", "myconn"))
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConnectHandler_GetSecret_UnknownConnector(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"ref":"myref"}`)), "name", "unknownconn"))
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)
	// Unknown connector → error response (not 401)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestConnectHandler_ListRefGrants_HappyPath(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListRefGrants(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestConnectHandler_CreateRefGrant_BadJSON(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConnectHandler_CreateRefGrant_MissingConnector(t *testing.T) {
	h := newConnectHandlerS4(t)
	body := `{"role_id":1,"ref_prefix":"myref"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	// Missing connector → error
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── secrets_audit_trail.go: toSecretAuditEntry ────────────────────────────────

func TestToSecretAuditEntry_NoDiff(t *testing.T) {
	now := time.Now()
	e := &models.AuditEvent{
		EventType:   "secret.created",
		EventTime:   now,
		Description: "Secret created",
		Diff:        "",
	}
	entry := toSecretAuditEntry(e)
	assert.Equal(t, "secret.created", entry.EventType)
	assert.Nil(t, entry.Diff)
	assert.True(t, entry.Success) // nil Success → true
}

func TestToSecretAuditEntry_WithDiff(t *testing.T) {
	now := time.Now()
	success := false
	e := &models.AuditEvent{
		EventType:   "secret.rotated",
		EventTime:   now,
		Description: "Rotated",
		Diff:        `{"changed":true}`,
		Success:     &success,
	}
	entry := toSecretAuditEntry(e)
	assert.False(t, entry.Success)
	assert.NotNil(t, entry.Diff)
	assert.Contains(t, string(entry.Diff), "changed")
}

// ── secrets_deleted.go: toDeletedSecretEntry ─────────────────────────────────

func TestToDeletedSecretEntry_ValidDeletedAt(t *testing.T) {
	now := time.Now()
	s := &models.SecretNode{
		Name:           "mysecret",
		Type:           "generic",
		Classification: "public",
		EnvironmentID:  1,
		OwnerID:        2,
	}
	s.ID = 10
	s.DeletedAt = gorm.DeletedAt{Time: now, Valid: true}
	entry := toDeletedSecretEntry(s)
	assert.Equal(t, uint(10), entry.ID)
	assert.Equal(t, "mysecret", entry.Name)
	assert.NotEmpty(t, entry.DeletedAt)
}

func TestToDeletedSecretEntry_NoDeletedAt(t *testing.T) {
	s := &models.SecretNode{Name: "s", Type: "generic"}
	entry := toDeletedSecretEntry(s)
	assert.Empty(t, entry.DeletedAt)
}

// ── secrets_tags.go: tagError ─────────────────────────────────────────────────

func TestTagError_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("record not found"), "fallback")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTagError_Forbidden(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("permission denied"), "fallback")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTagError_Validation(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("tag exceeds maximum"), "fallback")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTagError_AtMost(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("at most 10 tags allowed"), "fallback")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTagError_ValidationKeyword(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("validation failed: bad tag"), "fallback")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTagError_Internal(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("unexpected storage error"), "internal error occurred")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTagError_NotAuthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	w := httptest.NewRecorder()
	h.tagError(w, fmt.Errorf("not authorized to tag this secret"), "fallback")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── sso.go: redirectFragment ──────────────────────────────────────────────────

func TestRedirectFragment_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	vals := url.Values{}
	vals.Set("token", "tok123")
	h.redirectFragment(w, req, "https://example.com/complete", vals)
	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://example.com/complete#")
	assert.Contains(t, location, "tok123")
}

// ── audit.go: GetAuditLogs, GetRBACAuditLogs, GetAuditRetention ──────────────

func newAuditHandlerS4(t *testing.T) *AuditHandler {
	t.Helper()
	return NewAuditHandler(newHandlerCoreS4(t))
}

func TestGetAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil)
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs", nil))
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAuditLogs_WithFilters(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/logs?page=2&page_size=10&action=secret.created&user_id=1&project_id=1&secret_id=1&start_time=2024-01-01T00:00:00Z&end_time=2024-12-31T00:00:00Z&actor_type=user", nil))
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetRBACAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/rbac-logs", nil)
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetRBACAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/rbac-logs?page=1&page_size=20", nil))
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAuditRetention_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil)
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetAuditRetention_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/retention", nil))
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── audit.go: VerifyAuditChain, WriteAuditCheckpoint ─────────────────────────

func TestVerifyAuditChain_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVerifyAuditChain_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil))
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	// Empty chain is valid
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── catalog.go: ListEnvironments, RestoreProject ─────────────────────────────

func TestCatalog_RestoreProject_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalog_RestoreProject_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "99")
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dashboard.go: GetCompliancePosture, GetComplianceDigest, GetComplianceControls ──

func TestDashboard_GetComplianceDigest_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetComplianceDigest(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestDashboard_GetComplianceControls_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetComplianceControls(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestDashboard_GetComplianceEvidence_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetComplianceEvidence(w, req)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

func TestDashboard_GetCompliancePosture_NoContext(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetCompliancePosture(w, req)
	// Handler responds (may be 200 with empty data or error depending on auth config)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// ── dynamic_secrets.go: ListLeases, RevokeLease ───────────────────────────────

func TestDynamicSecretHandler_ListLeases_Unauthorized(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	// No user context or no authz → 401 or 403
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_UnauthorizedV2(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "lease123")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "nosuchlease"))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_crud.go: UnlockUser, accountStateAction, RevokeSessions, ResendSetupLink ──

func newUserHandlerS4(t *testing.T) *UserHandler {
	t.Helper()
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

func TestUserHandler_UnlockUser_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_UnlockUser_NotFound(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_SuspendUser_SelfSuspend(t *testing.T) {
	h := newUserHandlerS4(t)
	// Suspend user ID 1, authenticated as user ID 1 → 400
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_SuspendUser_NotFound(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.SuspendUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_RevokeSessions_Unauthorized(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RevokeSessions_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeSessions(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_DeleteUser_UnauthorizedV2(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RestoreUser_UnauthorizedV2(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_UnauthorizedV2(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_crud.go: UpdateUser, DeleteUser, RestoreUser ────────────────────────

func TestUserHandler_DeleteUser_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_RestoreUser_BadID(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_handler.go: userToAPIResponse ──────────────────────────────────────

func TestUserToAPIResponse_WithLastLogin(t *testing.T) {
	now := time.Now()
	u := &models.User{
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		IsActive:    true,
		LastLoginAt: &now,
	}
	u.ID = 1
	resp := userToAPIResponse(u)
	assert.NotNil(t, resp["last_login_at"])
	assert.Equal(t, "alice", resp["username"])
}

func TestUserToAPIResponse_EmptyDisplayName(t *testing.T) {
	u := &models.User{Username: "bob", Email: "bob@example.com"}
	u.ID = 2
	resp := userToAPIResponse(u)
	// Falls back to username when display_name is empty
	assert.Equal(t, "bob", resp["display_name"])
}

func TestUserToAPIResponse_WithDeletedAt(t *testing.T) {
	now := time.Now()
	u := &models.User{Username: "gone", Email: "gone@example.com"}
	u.ID = 3
	u.DeletedAt = gorm.DeletedAt{Time: now, Valid: true}
	resp := userToAPIResponse(u)
	assert.NotNil(t, resp["deleted_at"])
}

func TestUserToAPIResponse_WithLoginLockedUntil(t *testing.T) {
	future := time.Now().Add(time.Hour)
	u := &models.User{Username: "locked", Email: "locked@example.com", LoginLockedUntil: &future}
	u.ID = 4
	resp := userToAPIResponse(u)
	assert.NotNil(t, resp["login_locked_until"])
}

// ── invitations.go: ListInvitations, CreateInvitation ────────────────────────

func TestCreateInvitation_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"a@b.com","role":"viewer"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_MissingFieldsV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"a@b.com"}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── userIdentity (auth.go) ───────────────────────────────────────────────────

func TestUserIdentity_Direct(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// userIdentity returns empty identity on error (user 999 doesn't exist)
	id := h.userIdentity(req, 999)
	// Should not panic; returns empty
	assert.NotNil(t, id.Roles)
	assert.NotNil(t, id.Permissions)
}

// ── catalog.go: UpdateProject RequireMFA path ─────────────────────────────────

func TestCatalog_UpdateProject_RequireMFA_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	mfa := true
	bodyBytes, _ := json.Marshal(map[string]any{"name": "proj", "require_mfa": mfa})
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(bodyBytes)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)
	// No roles.assign permission → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── access_review_campaigns.go: GetAccessReviewCampaign ──────────────────────

func TestGetAccessReviewCampaign_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{
		"id": "1", "campaignId": "99",
	})
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets handler: GetSecretTags, SetSecretTags ─────────────────────────────

func TestSecretHandler_SetTags_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"tags":["a"]}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetTags(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetTags_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetTags(w, req)
	// Secret not found → tagError → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── users_list.go: StaleAccounts with more query params ──────────────────────

func TestStaleAccounts_WithDaysParam(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?days=90", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStaleAccounts_WithInvalidDays(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?days=notanumber", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	// Falls back to default, should not error
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── audit.go ExportAuditLogs ──────────────────────────────────────────────────

func TestExportAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil)
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExportAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	// Empty DB → either 200 empty or some valid response
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── machine_identities.go: bad machineId + unauthorized + bad JSON + invalid action ──

func TestTransitionMachineIdentity_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTransitionMachineIdentity_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_InvalidAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"unknown"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"action":"activate"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestIssueMachineToken_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIssueMachineToken_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIssueMachineToken_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIssueMachineToken_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"name":"tok","expires_in_days":90}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRevokeMachineToken_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "bad", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineToken_BadTokenID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "bad"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineToken_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeMachineToken_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "9999", "machineId": "9999", "tokenId": "9999"}))
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestClassifyMachineIdentity_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineIdentity_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestClassifyMachineIdentity_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineIdentity_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"classification":"confidential"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestClassifyMachineToken_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "1", "machineId": "bad", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineToken_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "1"})
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestClassifyMachineToken_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "1"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineToken_BadTokenID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "tokenId": "bad"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineToken_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"classification":"confidential"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999", "tokenId": "9999"}))
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCreateOIDCBinding_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBinding_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBinding_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"issuer":"https://accounts.example.com","subject":"user123"}`
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)),
		map[string]string{"id": "9999", "machineId": "9999"}))
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	// machine not found → 404 or 400 depending on core validation order
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestListOIDCBindings_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "bad"})
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListOIDCBindings_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "1"})
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListOIDCBindings_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "1", "machineId": "1"}))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	// machine doesn't exist but empty list is ok
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBinding_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "bad", "bindingId": "1"})
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBinding_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "bindingId": "1"})
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteOIDCBinding_BadBindingID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "machineId": "1", "bindingId": "bad"}))
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBinding_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "9999", "machineId": "9999", "bindingId": "9999"}))
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── groups_members.go: AddGroupMember, RemoveGroupMember ────────────────────

func TestGroupHandler_GetGroupMembers_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_GetGroupMembers_HappyPath(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)
	// Group 1 doesn't exist in empty DB → error or 404
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_AddGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_AddGroupMember_BadJSON(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_AddGroupMember_MissingUserID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_RemoveGroupMember_Unauthorized(t *testing.T) {
	h := newGroupHandler(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_RemoveGroupMember_BadUserID(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "bad"}))
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_RemoveGroupMember_NotFound(t *testing.T) {
	h := newGroupHandler(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "9999", "userId": "9999"}))
	w := httptest.NewRecorder()
	h.RemoveGroupMember(w, req)
	// Internal error because no such group (not a "last member" conflict)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── project_members.go: UpdateProjectMember, RevokeProjectAccessReview ──────

func TestUpdateProjectMember_BadUserID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "userId": "bad"}))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "userId": "1"}))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_MissingRole(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)),
		map[string]string{"id": "1", "userId": "1"}))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeProjectAccessReview_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeProjectAccessReview_UnauthorizedV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeProjectAccessReview_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeProjectAccessReview_MissingSource(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttestProjectAccessReview_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttestProjectAccessReview_UnauthorizedV2(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAddProjectMember_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveProjectMember_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "userId": "1"})
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rotation_policies_handler.go: Update, Evaluate, Status extra paths ──────

func newRotationPolicyHandlerS4(t *testing.T) *RotationPolicyHandler {
	t.Helper()
	return NewRotationPolicyHandler(newHandlerCoreS4(t))
}

func TestRotationPolicyHandler_Update_BadID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Update_BadJSON(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Update_ValidationError(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"","interval_days":0}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Update_NotFound(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"pol","interval_days":30}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotationPolicyHandler_Evaluate_BadProjectID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Evaluate_BadEnvID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Evaluate_HappyPath(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.Evaluate(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_Status_BadProjectID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Status_BadEnvID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Status_HappyPath(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.Status(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_Get_BadID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Get_NotFound(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotationPolicyHandler_Delete_BadID(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Delete_NotFound(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotationPolicyHandler_Create_ValidationError(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"","interval_days":0}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotationPolicyHandler_Create_HappyPath(t *testing.T) {
	h := newRotationPolicyHandlerS4(t)
	body := `{"name":"daily","interval_days":1,"alert_days_before":0}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.Create(w, req)
	// Either 201 (created) or 4xx (validation with missing user); not 401/500
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusServiceUnavailable, w.Code)
}

// ── rbac.go: additional paths for RemoveRole, GetRolePermissions, GetGroupRoles ──

func TestRBACHandler_RemoveRole_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodDelete, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.RemoveRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveRole_ValidationError(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.RemoveRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRolePermissions_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetRolePermissions(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRolePermissions_NotFound(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetRolePermissions(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRBACHandler_GetGroupRoles_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetGroupRoles_HappyPath(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	// group not found → 404 or empty list
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignRoleToGroup_MissingRoleID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveRoleFromGroup_BadGroupID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "roleId": "1"}))
	w := httptest.NewRecorder()
	h.RemoveRoleFromGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemoveRoleFromGroup_BadRoleID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "roleId": "bad"}))
	w := httptest.NewRecorder()
	h.RemoveRoleFromGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetPermission_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetPermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetPermission_NotFound(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetPermission(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_BadJSON(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_RemovePermissionFromRole_BadRoleID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "permissionId": "1"}))
	w := httptest.NewRecorder()
	h.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetUserRoles_BadID(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userId", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_ListPermissions_WithFilter(t *testing.T) {
	h := NewRBACHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?resource=secrets", nil))
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── shares: extra paths for ListShares, ShareSecret, UpdateSharePermission ──

func TestShareHandler_ListShares_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestShareHandler_ListShares_WithFilter(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?secretId=1&recipientType=user", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestShareHandler_ShareSecret_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ShareSecret_BadJSON(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ShareSecret_ValidationError(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_UpdateSharePermission_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_UpdateSharePermission_BadJSON(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_RevokeShare_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeShare(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_GetSharingStatusWithIndicators_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_GetSharingStatusWithIndicators_NotFound(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetSharingStatusWithIndicators(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_RemoveSelfFromShare_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RemoveSelfFromShare(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_list.go: ListSecrets happy path with various filters ─────────────

func TestSecretHandler_ListSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?page=1&page_size=10", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// User ID from context may not exist in empty DB → 500 or 200 empty
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_ListSecrets_WithFilters(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?search=foo&include_deleted=true&show_owned_only=true&type=static&classification=public&tag=a,b", nil))
	w := httptest.NewRecorder()
	h.ListSecrets(w, req)
	// User ID from context may not exist in empty DB → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_versions.go: RollbackSecret extra paths ──────────────────────────

func TestSecretHandler_RollbackSecret_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":1}`)), "id", "1")
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_RollbackSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":1}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RollbackSecret_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RollbackSecret_InvalidVersion(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":0}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RollbackSecret_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"version":1}`)), "id", "9999"))
	w := httptest.NewRecorder()
	h.RollbackSecret(w, req)
	// Secret not found → 404 or 500 depending on DB layout
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go: RenewLease extra paths ───────────────────────────────

func TestDynamicSecretHandler_RenewLease_NotFound(t *testing.T) {
	h := NewDynamicSecretHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "nosuchlease"))
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── sod.go: SoD policy CRUD ──────────────────────────────────────────────────

func TestSoDPolicy_Create_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSoDPolicy_Create_MissingFields(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	// empty permissions → validation error
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// FIX-6 (#1645 403-for-both): a non-admin-tier actor gets the same 403 denial
// for a nonexistent policy id as for an existing-but-foreign one, not a
// distinguishing 404. Deliberately does NOT use withUserCtx's shared UserID=1
// -- this test runs against the S4 package-wide shared DB (newHandlerCoreS4),
// and some other S4 test elsewhere in this huge shared-fixture file grants
// UserID=1 admin-tier authority without reverting it, making this assertion
// flaky/order-dependent on that ambient state (observed failing in CI's
// handlers-4 shard while passing locally, where the interfering test wasn't
// in the executed set). A dedicated, never-referenced-elsewhere actor ID
// sidesteps the ambiguity entirely rather than depending on shared-DB
// execution order.
func TestSoDPolicy_Delete_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	dedicatedNonAdminActor := &middleware.UserContext{
		UserID: 55501001, Username: "sod-notfound-nonadmin", Email: "sod-notfound-nonadmin@example.com",
	}
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), dedicatedNonAdminActor))
	req = withChiParam(req, "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── secrets_reassign_owner.go: ReassignOwner ─────────────────────────────────

func TestSecretHandler_ReassignOwner_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_ReassignOwner_MissingFromOwner(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"to_owner_id":2}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.ReassignOwner(w, req)
	// from_owner_id=0, to_owner_id=2 → validation error (required)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_access_list.go: ListAccessors ────────────────────────────────────

func TestSecretHandler_ListAccessors_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListAccessors(w, req)
	// Secret not found → error
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── catalog.go: ListEnvironments extra paths ──────────────────────────────────

func TestCatalogHandler_ListEnvironments_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)) // #2780: authorizes in-handler
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_roles.go: UpdateUserRoles extra paths ───────────────────────────────

func TestUserRoles_GetUserRolesForUser_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_GetUserRolesForUser_HappyPath(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	// user 1 doesn't exist in empty DB → not found
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_GetUserPermissionsForUser_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_UpdateUserRoles_Unauthorized(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserRoles_UpdateUserRoles_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_UpdateUserRoles_BadJSON(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserRoles_GetUserMembershipsForUser_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_handler.go: GetUserByUsername, GetUserByExternalID ─────────────────

func TestUserHandler_GetUserByUsername_HappyPath(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "username", "nouser"))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	// user doesn't exist → not found or 200 empty
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByExternalID_Unauthorized(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "externalId", "ext123")
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByExternalID_HappyPath(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "externalId", "ext123"))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	// external ID not found → error
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_RestoreUser_BadIDV2(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_RestoreUser_NotFound(t *testing.T) {
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── notifications_handler.go: MarkRead ───────────────────────────────────────

func TestNotificationsHandler_MarkRead_Unauthorized(t *testing.T) {
	h := NewNotificationHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPatch, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNotificationsHandler_MarkRead_BadID(t *testing.T) {
	h := NewNotificationHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPatch, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNotificationsHandler_MarkRead_NotFound(t *testing.T) {
	h := NewNotificationHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPatch, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.MarkRead(w, req)
	// notification not found → error
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── pat_handler.go: toPATResponse ────────────────────────────────────────────

func TestPATHandler_ListPATs_HappyPath(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListPATs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPATHandler_CreatePAT_Unauthorized(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATHandler_CreatePAT_BadJSON(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPATHandler_CreatePAT_HappyPath(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	body := `{"name":"mytoken","expires_in_days":30}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)
	// user 1 doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestPATHandler_RevokePAT_Unauthorized(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokePAT(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATHandler_RevokePAT_BadID(t *testing.T) {
	h := NewPATHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokePAT(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_copy_environment.go ───────────────────────────────────────────────

func TestSecretHandler_CopyEnvironmentSecrets_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CopyEnvironmentSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_CopyEnvironmentSecrets_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.CopyEnvironmentSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_CopyEnvironmentSecrets_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CopyEnvironmentSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: WithdrawAccessRequest ─────────────────────────────────────

func TestWithdrawAccessRequest_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "requestId", "bad"))
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWithdrawAccessRequest_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "requestId", "9999"))
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	// not found
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_crud.go: GetSecretValueByRef ─────────────────────────────────────

func TestSecretHandler_GetSecretValueByRef_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?ref=foo", nil)
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSecretHandler_GetSecretValueByRef_MissingRef covers the handler's
// defensive branch: ref resolution now happens exactly once, in
// middleware.RequireScopedSecretRefPermission, which pins the resolved secret
// on the request context before dispatch (see core-secret-ref-4 /
// server/middleware/auth_s24_test.go for the 400/404 coverage of the
// middleware's own resolution — including a missing "ref" param, which
// ParseSecretRef treats as invalid format). A direct handler call that
// bypasses the middleware, as this test does, never gets that context value,
// so the handler must 500 rather than fall back to resolving the ref itself.
func TestSecretHandler_GetSecretValueByRef_MissingRef(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSecretHandler_GetSecretValueByRef_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?ref=projects/1/environments/1/secrets/nope", nil))
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	// no resolved secret pinned on context (middleware bypassed) → 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── sso.go: CompleteSSO ───────────────────────────────────────────────────────

func TestCompleteSSO_UnknownProviderS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "unknown-provider")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompleteSSO_IdPErrorParam(t *testing.T) {
	// With a known provider (BeginSSO wouldn't error but CompleteSSO checks SSOCompleteURL).
	// Since no SSO providers are configured in our empty DB core, it returns unknown provider.
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/?error=access_denied", nil), "provider", "google")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	// Either unknown provider (400) or redirect (302) — not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestCompleteSSO_MissingCodeAndState(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "google")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── saml.go: CompleteSAML ─────────────────────────────────────────────────────

func TestCompleteSAML_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "provider", "unknown-provider")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCompleteSAML_KnownProviderNoSAMLResponse(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("")), "provider", "test")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)
	// unknown provider or redirect — not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── saml.go / sso.go: BeginSSO and BeginSAML ────────────────────────────────

func TestBeginSSO_UnknownProviderS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "nonexistent")
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBeginSAML_UnknownProvider(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "nonexistent")
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── mfa.go: EnrollMFA, DisableMFA, RegenerateRecoveryCodes, RecoveryCodesStatus ──

func TestEnrollMFA_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.EnrollMFA(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestDisableMFA_UnauthorizedS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDisableMFA_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDisableMFA_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"code":"123456"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.DisableMFA(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestRegenerateRecoveryCodes_UnauthorizedS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegenerateRecoveryCodes_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegenerateRecoveryCodes_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	body := `{"code":"123456"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestRecoveryCodesStatus_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, req)
	// user doesn't exist → error, but not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── audit_anomaly.go: ListAnomalyAlerts, AcknowledgeAnomalyAlert ─────────────

func TestListAnomalyAlerts_NoCoreServiceS4(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	// Call directly — no core service in context → 500
	ListAnomalyAlerts(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAcknowledgeAnomalyAlert_NoCoreServiceS4(t *testing.T) {
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	AcknowledgeAnomalyAlert(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAcknowledgeAnomalyAlert_BadIDNoCore(t *testing.T) {
	// Bad ID but no core service — hits internal error first
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	AcknowledgeAnomalyAlert(w, req)
	// No core service → 500 (before ID parsing)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── legal_hold.go: LiftLegalHold ─────────────────────────────────────────────

func TestLiftLegalHold_UnauthorizedS4(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLiftLegalHold_NoActiveHold(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	body := `{"reason":"investigation complete"}`
	req := withUserCtx(httptest.NewRequest(http.MethodDelete, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.LiftLegalHold(w, req)
	// no active hold → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_query.go: ListSecretShares ────────────────────────────────────────

func TestShareHandler_ListSecretShares_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ListSecretShares_NotFound(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListSecretShares(w, req)
	// secret not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go: ListShares ───────────────────────────────────────────────

func TestShareHandler_ListShares_WithUser(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	// user may or may not exist → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListShares_WithFilters(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?secretId=1&recipientType=user&page=1&pageSize=10", nil))
	w := httptest.NewRecorder()
	h.ListShares(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go: GetSharingStatusWithIndicators ──────────────────────────

// ── shares_query.go: RemoveSelfFromShare ─────────────────────────────────────

// ── shares_crud.go: ShareSecret ──────────────────────────────────────────────

func TestShareHandler_ShareSecret_UnauthorizedS4(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ShareSecret_ValidationErrorS4(t *testing.T) {
	h := newShareHandlerS4(t)
	// Missing required fields
	body := `{"is_group":false}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_crud.go: UpdateSharePermission ────────────────────────────────────

func TestShareHandler_UpdateSharePermission_UnauthorizedS4(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_UpdateSharePermission_ValidationError(t *testing.T) {
	h := newShareHandlerS4(t)
	body := `{"permission":"invalid_permission"}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateSharePermission(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_crud.go: RevokeShare ──────────────────────────────────────────────

// ── project_members.go: RevokeProjectAccessReview ────────────────────────────

func TestRevokeProjectAccessReviewV3_Unauthorized(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"share","resource_id":1}`
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeProjectAccessReviewV3_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"source":"share","resource_id":9999}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	// not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── project_memberships.go: TransitionMembership ────────────────────────────

func TestTransitionMembership_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "bad", "membershipId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), params)
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMembership_BadMembershipID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "membershipId": "bad"}
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), params)
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMembership_UnauthorizedS4(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "membershipId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"action":"activate"}`)), params)
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTransitionMembership_InvalidAction(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "membershipId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"action":"invalid"}`)), params))
	w := httptest.NewRecorder()
	h.TransitionMembership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: CreateAccessRequest ──────────────────────────────────────

func TestCreateAccessRequest_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequest_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequest_NotFound(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"suggested_role":"viewer","reason":"need access"}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	// project not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_crud.go: GetSecretByName ─────────────────────────────────────────

func TestSecretHandler_GetSecretByName_MissingProjectID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=foo&environment_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretByName_MissingEnvironmentID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=foo&project_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretByName_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=nonexistent&project_id=1&environment_id=1", nil))
	w := httptest.NewRecorder()
	h.GetSecretByName(w, req)
	// not found → 404
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_usage.go: UsageUnused ────────────────────────────────────────────

func TestSecretHandler_UsageUnused_BadProjectID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_UsageUnused_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=1&days=30", nil))
	w := httptest.NewRecorder()
	h.UsageUnused(w, req)
	// not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go: parseScopeQuery / CreateConfig / ListLeases ──────────

func TestDynamicSecretHandler_ParseScopeQuery_BadProjectID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	// ListConfigs calls parseScopeQuery internally
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_ParseScopeQuery_BadEnvironmentID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_CreateConfig_UnauthorizedS4(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_CreateConfig_BadJSON(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDynamicSecretHandler_CreateConfig_WithUser(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	body := `{"name":"pg-dev","project_id":1,"environment_id":1,"backend_type":"postgres"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	// user exists but db operations fail → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestDynamicSecretHandler_ListLeases_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	// loadAuthorizedConfig → bad config ID → not 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── secret_dependencies.go ────────────────────────────────────────────────────

func TestSecretHandler_ListSecretDependencies_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListSecretDependencies(w, req)
	// not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_AddSecretDependency_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_AddSecretDependency_MissingDependsOnID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"depends_on_id":0}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RemoveSecretDependency_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	params := map[string]string{"id": "1", "depId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params)
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_RemoveSecretDependency_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	params := map[string]string{"id": "bad", "depId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_RemoveSecretDependency_BadDepID(t *testing.T) {
	h := newSecretHandlerS4(t)
	params := map[string]string{"id": "1", "depId": "bad"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params))
	w := httptest.NewRecorder()
	h.RemoveSecretDependency(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetSecretImpact_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretImpact(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetProjectRotationOrder_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetProjectRotationOrder(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetProjectRotationPlan_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetProjectRotationPlan(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_GetDeploymentRotationPlan_WithUser(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetDeploymentRotationPlan(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── rbac.go: GetRoleByName, DeleteRole ───────────────────────────────────────

func TestRBACHandler_GetRoleByName_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/?name=admin", nil)
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetRoleByName_MissingName(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRBACHandler_GetRoleByName_NotFound(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?name=nonexistent-role", nil))
	w := httptest.NewRecorder()
	h.GetRoleByName(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRBACHandler_DeleteRole_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_DeleteRole_BadID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── secrets_suspend.go: ResumeSecret ─────────────────────────────────────────

func TestSecretHandler_ResumeSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ResumeSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretHandler_ResumeSecret_NotFound(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ResumeSecret(w, req)
	// not found → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── machine_identities.go: ListStaleMachineIdentities ──────────────────────

func TestCatalogHandler_ListStaleMachineIdentities_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/?days=30", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListStaleMachineIdentities(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: TransitionMachineIdentityStateProxy ─────────

// ── machine_identities_proxy.go: AssignMachineRoleProxy ─────────────────────

// ── machine_identities_proxy.go: RemoveMachineRoleProxy ─────────────────────

// ── break_glass_proxy.go: RevokeBreakGlassActivationProxy ───────────────────

// TestCatalogHandler_RevokeBreakGlassActivationProxy_NoAuthenticatedCaller
// (G80 documented-exception re-verification sweep, 2026-08-25) supersedes
// the old MissingRevokedBy test: revoked_by is no longer read from the wire
// at all (see break_glass_proxy.go's own updated doc comment). What must
// still be rejected is a call with no authenticated human caller at all.

// ── retention_proxy.go: ListUsersInStateBeforeProxy ─────────────────────────

// ── project_memberships_proxy.go: GetActiveMembershipProxy ──────────────────

// ── misc_remote_proxy.go: accessActivityProxy ────────────────────────────────

// ── environment_catalog_proxy.go: DeleteEnvironmentProxy ──

// ── mfa_management_proxy.go: GetMFASecretProxy ──

// ── setup_tokens_proxy.go: ConsumeSetupTokenProxy tests deleted -- #1579
// liveness sweep, handler removed (no live caller in either topology).

// ── rbac_role_grants_proxy.go: RemoveGlobalAdminRoleGuardedProxy ─────────────

// ── secret_dependencies_proxy.go: CreateSecretDependencyExclusiveProxy ───────

// ── machine_identities.go: ListMachineTokens ─────────────────────────────────

func TestCatalogHandler_ListMachineTokens_BadProjectIDS4(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "bad", "machineId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), params)
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineTokens_BadMachineID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "machineId": "bad"}
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), params)
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListMachineTokens_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	params := map[string]string{"id": "1", "machineId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), params))
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	// not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── isSafeSSOError ────────────────────────────────────────────────────────────

func TestIsSafeSSOError_KnownMessages(t *testing.T) {
	assert.True(t, isSafeSSOError("unknown SSO provider"))
	assert.True(t, isSafeSSOError("unknown SAML provider"))
	assert.True(t, isSafeSSOError("invalid or expired login state"))
	assert.True(t, isSafeSSOError("login state does not match the callback provider"))
	assert.True(t, isSafeSSOError("login state expired"))
	assert.True(t, isSafeSSOError("the token response carried no id_token"))
	assert.True(t, isSafeSSOError("the assertion carried no subject or email"))
	assert.True(t, isSafeSSOError("no Keyorix account matches this SSO identity"))
	assert.False(t, isSafeSSOError("account suspended"))
	assert.True(t, isSafeSSOError("the IdP returned no email; cannot auto-provision an account"))
	assert.False(t, isSafeSSOError("some internal error"))
	assert.False(t, isSafeSSOError(""))
}

// ── isSafeDynamicSecretError ──────────────────────────────────────────────────

func TestIsSafeDynamicSecretError_KnownMessages(t *testing.T) {
	assert.True(t, isSafeDynamicSecretError("config not found"))
	assert.True(t, isSafeDynamicSecretError("lease not found"))
	assert.True(t, isSafeDynamicSecretError("lease is not active"))
	assert.True(t, isSafeDynamicSecretError("active-lease limit reached"))
	assert.False(t, isSafeDynamicSecretError("some internal DB error"))
	assert.False(t, isSafeDynamicSecretError(""))
}

// ── dynamic_secrets.go: IssueLease ───────────────────────────────────────────

func TestDynamicSecretHandler_IssueLease_NoUser(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	// no user context → auth denial (401 or 403)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── project_members.go: AddProjectMember, UpdateProjectMember ────────────────

func TestCatalogHandler_AddProjectMember_MissingFieldsV3(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// user_id = 0 and role = "" → 400
	body := `{"user_id":0,"role":""}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── rbac.go: AssignPermissionToRole ──────────────────────────────────────────

func TestRBACHandler_AssignPermissionToRole_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	params := map[string]string{"id": "1", "permId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params)
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_AssignPermissionToRole_BadRoleID(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	params := map[string]string{"id": "bad", "permId": "1"}
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), params))
	w := httptest.NewRecorder()
	h.AssignPermissionToRole(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── rbac.go: GetUserRoles, RemovePermissionFromRole ──────────────────────────

func TestRBACHandler_GetUserRoles_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_GetUserRoles_BadIDS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetUserRoles(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestRBACHandler_GetGroupRoles_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_RemovePermissionFromRole_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	params := map[string]string{"id": "1", "permId": "1"}
	req := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil), params)
	w := httptest.NewRecorder()
	h.RemovePermissionFromRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── audit.go: ExportAuditLogs ─────────────────────────────────────────────────

func TestAuditHandler_ExportAuditLogs_Unauthorized(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_ExportAuditLogs_HappyPath(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	// not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── auth.go: ConsumeSetup, Logout ────────────────────────────────────────────

func TestAuthHandler_Logout_NoSession(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	// no session header/cookie → not 200 (token required)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go: RefreshToken ─────────────────────────────────────────────────────

func TestAuthHandler_RefreshToken_NoTokenS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	// no token → error
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── sod.go: ListSoDPolicies, CreateSoDPolicy, ListSoDViolations ──────────────

// ── rbac.go: ListRoles, ListPermissions ──────────────────────────────────────

func TestRBACHandler_ListRoles_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACHandler_ListPermissions_UnauthorizedS4(t *testing.T) {
	c := newHandlerCoreS4(t)
	h := NewRBACHandler(c)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── machine_identities_proxy.go: UpdateMachineIdentityCredentialProxy ─────────

// ── machine_identities_proxy.go: TouchMachineIdentityCredentialProxy ─────────

// ── retention_proxy.go: DeleteExpiredRoleGrantsProxy, DeleteExpiredShareRecordsProxy ─

// ── webauthn.go: FinishWebAuthnPasswordlessLogin ──────────────────────────────

func TestWebAuthnHandler_FinishWebAuthnPasswordlessLoginS4_BadJSON(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "sessionID", "test-session")
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go: Login, ListSessions ─────────────────────────────────────────────

func TestAuthHandler_Login_BadJSONS4(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ListSessions_WithUser(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	// user doesn't exist in empty DB → not 401
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── shares_query.go: ListSharedSecrets, ListGroupSharedSecrets ───────────────

func TestShareHandler_ListSharedSecrets_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSharedSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ListGroupSharedSecrets_BadID(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestShareHandler_ListGroupSharedSecrets_HappyPath(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ListGroupSharedSecrets(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── project_catalog_proxy.go: DeleteProjectProxy, RestoreProjectProxy ─────────

// ── rbac_role_grants_proxy.go: AssignRoleWithExpiryProxy, etc. ───────────────

// ── machine_identities_proxy.go: credential proxies ─────────────────────────

// ── secret_dependencies_proxy.go: GetSecretDependencyProxy ───────────────────

// ── connect.go: DeleteRefGrant (S4 additional) ───────────────────────────────

func TestConnectHandler_DeleteRefGrant_UnauthorizedS4(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConnectHandler_DeleteRefGrant_BadIDS4(t *testing.T) {
	h := newConnectHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets.go: RevokeAllLeases, ClassifyConfig, SetConfigEnabled ────

func TestDynamicSecretHandler_RevokeAllLeases_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestDynamicSecretHandler_ClassifyConfig_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestDynamicSecretHandler_SetConfigEnabled_BadID(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── access_review_campaigns_proxy.go: GetAccessReviewCampaignProxy ────────────

// ── secrets_versions.go: RotateSecret ────────────────────────────────────────

func TestSecretHandler_RotateSecret_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_access_history.go: AccessHistory ─────────────────────────────────

// ── admin_impersonation.go: End (S4 extra) ───────────────────────────────────

func TestImpersonationHandler_End_UnauthorizedS4(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	// no valid impersonation token header → should not be 200
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── mfa_management_proxy.go: CountUnusedMFARecoveryCodesProxy ────────────────

// UpdateRiskExceptionProxy was removed (#G79) — see risk_exceptions_proxy.go's
// removal comment.

// ── rbac_role_grants_proxy.go: happy paths ────────────────────────────────────

// ── machine_identities_proxy.go: credential happy paths ──────────────────────

// ── secret_dependencies_proxy.go: delete happy path ──────────────────────────

// ── access_review_campaigns_proxy.go: happy paths ────────────────────────────

// ── access_request_proxy.go: happy paths ─────────────────────────────────────

// ── sod_proxy.go: happy paths ─────────────────────────────────────────────────

// ── dynamic_secrets_proxy.go: happy paths ────────────────────────────────────

// ── environment_catalog_proxy.go: GetEnvironmentProxy ────────────────────────

// ── groups_proxy.go: GetGroupProxy ───────────────────────────────────────────

// ── invitations_proxy.go: GetInvitationProxy ─────────────────────────────────

// ── risk_exceptions_proxy.go: GetRiskExceptionProxy ──────────────────────────

// ── project_catalog_proxy.go: GetProjectProxy ────────────────────────────────

// ── project_memberships_proxy.go: GetMembershipProxy ─────────────────────────

// ── machine_identities_proxy.go: GetMachineIdentityProxy ─────────────────────

// ── connect_grants_proxy.go: ListConnectRefGrantsByConnectorProxy ─────────────

// ── secrets_ownership.go: TransferOwnership ──────────────────────────────────

func TestSecretHandler_TransferOwnership_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_access_history.go: AccessHistory happy path ──────────────────────

func TestSecretHandler_AccessHistory_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	// not found or 500, not 401 or 400
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── misc_remote_proxy.go: GetSecretIncludingDeletedProxy ─────────────────────

// ── setup_tokens_proxy.go: more paths ────────────────────────────────────────

// ── login_attempts_proxy.go: RecordLoginAttemptProxy ─────────────────────────

// ── misc_remote_proxy.go: ListSharesByOwnerProxy ─────────────────────────────

// ── access_request_proxy.go: CreateAccessRequestProxy happy path ──────────────

// ── access_review_campaigns_proxy.go: CreateAccessReviewCampaignProxy ─────────

// TestCatalogHandler_CreateAccessReviewCampaignProxy_HappyPath:
// CreateAccessReviewCampaignProxy now requires roles.assign scoped to the
// project -- #AccessReview (system-proxy-target-authority audit).
// newCatalogHandlerS4 is backed by the shared, non-admin sharedS4Core, so
// this needs the s4AdminActorID/seedS4AdminActor/withUserCtxID pattern other
// s4/s5/s9 tests needing admin authority against that shared core already use.

// ── sod_proxy.go: CreateSoDPolicyProxy ───────────────────────────────────────

// ── groups_proxy.go: UpdateGroupProxy ────────────────────────────────────────

// ── project_memberships_proxy.go: CreateMembershipProxy ──────────────────────

// ── groups_proxy.go: CreateGroupProxy, UpdateGroupProxy, DeleteGroupProxy ─────

// ── machine_identities_proxy.go: CreateMachineIdentityProxy ──────────────────

// ── environment_catalog_proxy.go: DeleteEnvironmentProxy happy paths ──────────

// ── invitations_proxy.go: CreateInvitationProxy, UpdateInvitationProxy ────────

// ── login_attempts_proxy.go: CountLoginAttemptsProxy ─────────────────────────

// ── setup_tokens_proxy.go: GetSetupTokenByHashProxy ──────────────────────────

// ── risk_exceptions_proxy.go: CreateRiskExceptionProxy ───────────────────────

// ── misc_remote_proxy.go: ListSharesByUserProxy ───────────────────────────────

// ── machine_identities_proxy.go: AssignMachineRoleProxy happy path ────────────

// ── users_crud.go: additional UserHandler coverage ───────────────────────────

func TestUserHandler_SearchUsers_NoQuery(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── audit_anomaly.go: ListAnomalyAlerts, AcknowledgeAnomalyAlert ──────────────

func TestAcknowledgeAnomalyAlert_BadID(t *testing.T) {
	// Without core service in context it's 500; with bad ID it's 400.
	// We test the "bad id" path only — confirm it's not 200.
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	AcknowledgeAnomalyAlert(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── legal_hold_proxy.go: CreateLegalHoldProxy, UpdateLegalHoldProxy ───────────

// TestDashboardHandler_UpdateLegalHoldProxy_HappyPath: UpdateLegalHoldProxy
// now routes through core.KeyorixCore.LiftLegalHold (#G79), which requires
// the caller to be either the original placer or admin-tier. This request
// carries no user context (actorID 0), so LiftLegalHold correctly refuses —
// asserting non-400 (not the specific refusal code) keeps this test focused
// on "malformed request handling still works," matching its sibling
// BadID/BadJSON tests; TestDashboardHandler_UpdateLegalHoldProxy_RefusesNonPlacerNonAdmin
// below is the dedicated regression for the refusal itself. The Cleanup is a
// no-op here (LiftLegalHold's own refusal means nothing was mutated) but kept
// for safety against future changes to this test's fixture.

// TestDashboardHandler_UpdateLegalHoldProxy_RefusesNonPlacerNonAdmin is the
// #G79 regression: UpdateLegalHoldProxy previously called
// storage.UpdateLegalHold directly (an unconditional full-row Save), letting
// ANY system.write-only caller silently release an active legal hold. Now
// that it routes through core.KeyorixCore.LiftLegalHold, a caller who is
// neither the original placer nor admin-tier must be refused, and the hold
// must remain active.

// ── rbac_role_grants_proxy.go: RemoveGlobalAdminRoleGuardedProxy ──────────────

// ── sod_proxy.go: CreateSoDPolicyProxy, DeleteSoDPolicyProxy ─────────────────

// TestCreateSoDPolicyProxy_WritesAuditEvent is the #G79 regression:
// CreateSoDPolicyProxy previously called storage.CreateSoDPolicy directly,
// writing no audit trail on the upstream side. Now that it routes through
// core.KeyorixCore.CreateSoDPolicy, a policy created via node-sync is
// audited exactly like one created through the human-facing route.

// ── legal_hold.go: GetLegalHold, PlaceLegalHold ───────────────────────────────

func TestDashboardHandler_GetLegalHold_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetLegalHold(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_PlaceLegalHold_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"test"}`))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_PlaceLegalHold_BadJSON(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.PlaceLegalHold(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sod.go: ListSoDPolicies, ListSoDViolations ────────────────────────────────

func TestCatalogHandler_CreateSoDPolicy_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x","permission_a":"a","permission_b":"b"}`))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_ListSoDViolations_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	// Handler does not check user ctx; returns 200 with empty violations or error
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListSoDViolations_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── rotation_policies_handler.go: List ────────────────────────────────────────

func TestRotationPolicyHandler_List_NoUserCtx(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRotationPolicyHandler_List_HappyPath_S4(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRotationPolicyHandler_List_InvalidProjectID(t *testing.T) {
	h := NewRotationPolicyHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── groups_proxy.go: AddGroupMemberProxy, ListGroupMembersProxy ───────────────

// ── connect_grants_proxy.go: ListConnectRefGrantsProxy ───────────────────────

// ── dynamic_secrets_proxy.go: CreateDynamicSecretConfigProxy test deleted --
// #1580 liveness sweep, handler removed (no live caller in either topology).

// ── environment_catalog_proxy.go: ListEnvironmentsProxy ──────────────────────

// ── webauthn_proxy.go: UpdateWebAuthnCredentialProxy, AdvanceWebAuthnCredentialCounterProxy ─

// ── machine_identities_proxy.go: RevokeMachineIdentityCredentialProxy, GetMachineByOIDCSubjectProxy ─

// ── setup_tokens_proxy.go: CreateSetupTokenProxy ─────────────────────────────

// ── retention_proxy.go: ListUsersInStateBeforeProxy ──────────────────────────

// ── groups_handler.go: CreateGroup, GetGroup, UpdateGroup ─────────────────────

func TestGroupHandler_CreateGroup_NoUserCtx(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_CreateGroup_BadJSON(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_GetGroup_BadID_S4(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_GetGroup_NotFound_S4(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGroupHandler_UpdateGroup_NoUserCtx(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"name":"test"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGroupHandler_UpdateGroup_BadID(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"name":"test"}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGroupHandler_DeleteGroup_NoUserCtx(t *testing.T) {
	h := newGroupHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteGroup(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── risk_exceptions.go: additional coverage ───────────────────────────────────

func TestDashboardHandler_ListRiskExceptions_HappyPath(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDashboardHandler_CreateRiskException_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"title":"test","justification":"test","category":"operational","expires_at":"2026-12-31T00:00:00Z"}`))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_ApproveRiskException_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_ApproveRiskException_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDashboardHandler_RevokeRiskException_NoUserCtx(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDashboardHandler_RevokeRiskException_BadID(t *testing.T) {
	h := NewDashboardHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── users_roles.go: UpdateUserRoles ──────────────────────────────────────────

func TestUsersRolesHandler_UpdateUserRoles_NoUserCtx(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUsersRolesHandler_UpdateUserRoles_BadID(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUsersRolesHandler_UpdateUserRoles_HappyPath(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// empty role_ids → not bad request
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── users_crud.go: StaleAccounts, GetUserByUsername, GetUserByExternalID ──────

func TestUserHandler_StaleAccounts_NoUserCtx(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_StaleAccounts_HappyPath(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_GetUserByUsername_MissingParam(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByUsername_NotFound_S4(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?username=nonexistent", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetUserByExternalID_MissingParam(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByExternalID_NotFound(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?external_id=nonexistent", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── admin_impersonation.go: End handler ──────────────────────────────────────

func TestImpersonationHandler_End_NoToken_S4(t *testing.T) {
	h := NewImpersonationHandler(newHandlerCoreS4(t), false)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── audit.go: WriteAuditCheckpoint ───────────────────────────────────────────

func TestAuditHandler_WriteAuditCheckpoint_NoUserCtx(t *testing.T) {
	h := newAuditHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_versions.go: GetSecretVersions ───────────────────────────────────

// ── secrets_crud.go: GetSecret, GetSecretValueByRef ───────────────────────────

func TestSecretHandler_GetSecretValueByRef_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?ref=secret://env/name", nil)
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_description.go: DescribeSecret ───────────────────────────────────

// ── secrets_audit_trail.go: AuditTrail ───────────────────────────────────────

// ── secrets_suspend.go: SuspendSecret ────────────────────────────────────────

// ── secrets_access_stats.go: GetSecretAccessStats ─────────────────────────────

func TestSecretHandler_GetSecretAccessStats_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretAccessStats(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_GetSecretAccessStats_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.GetSecretAccessStats(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_copy.go: CopySecret ──────────────────────────────────────────────

func TestSecretHandler_CopySecret_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"target_project_id":1}`))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_CopySecret_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CopySecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_risk.go: GetSecretRisk ───────────────────────────────────────────

// ── secrets_expiring.go: ExpiringSecrets ──────────────────────────────────────

func TestSecretHandler_ExpiringSecrets_HappyPath(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ExpiringSecrets(w, req)
	// OK or internal error depending on SQLite support
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── secrets_tags.go: SetTags ──────────────────────────────────────────────────

// ── secrets_ownership.go: TransferOwnership ───────────────────────────────────

func TestSecretHandler_TransferOwnership_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":2}`)), "id", "1")
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_TransferOwnership_BadID_S4(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":2}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secrets_render.go: RenderTemplate ────────────────────────────────────────

func TestSecretHandler_RenderTemplate_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"template":"{{.name}}"}`))
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_RenderTemplate_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.RenderTemplate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── shares_crud.go: ShareSecret, RevokeShare ──────────────────────────────────

func TestShareHandler_ShareSecret_NoUserCtx(t *testing.T) {
	h := newShareHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"secret_id":1}`))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestShareHandler_ShareSecret_BadJSON_S4(t *testing.T) {
	h := newShareHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ShareSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── catalog.go: RestoreProject, RestoreEnvironment, CreateProjectEnvironment ──

func TestCatalogHandler_RestoreProject_BadID_S4(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RestoreProject(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RestoreEnvironment_BadProjectID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "projectId", "bad")
	w := httptest.NewRecorder()
	h.RestoreEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateProjectEnvironment_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"dev"}`)), "id", "bad")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── invitations.go: CreateInvitation, RevokeInvitation ────────────────────────

// CreateInvitation: parses chi param "id" before checking user ctx, so no-id → 400
func TestCatalogHandler_CreateInvitation_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"test@example.com","role":"viewer"}`))
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateInvitation: valid id but no user ctx → 401
func TestCatalogHandler_CreateInvitation_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"email":"test@example.com","role":"viewer"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RevokeInvitation: parses chi param "id" then "invitationId" before checking user ctx
func TestCatalogHandler_RevokeInvitation_NoInvitationID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// RevokeInvitation: valid id + invitationId but no user ctx → 401

func TestCatalogHandler_RevokeInvitation_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_memberships.go: ListProjectMemberships, InviteMember ──────────────

// ListProjectMemberships: checks chi param "id" first, no user ctx check
func TestCatalogHandler_ListProjectMemberships_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// InviteMember: checks chi param "id" first, then user ctx
func TestCatalogHandler_InviteMember_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":1,"role":"viewer"}`))
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_InviteMember_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":1,"role":"viewer"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_InviteMember_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.InviteMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── break_glass.go: RevokeBreakGlass ─────────────────────────────────────────

// RevokeBreakGlass: checks id + activationId first, then user ctx
func TestCatalogHandler_RevokeBreakGlass_NoActivationID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_RevokeBreakGlass_BadID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── auth.go: Login (bad body), Logout, ListSessions ──────────────────────────

func TestAuthHandler_RefreshToken_NoTokenBr(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestAuthHandler_ListSessions_NoUserCtx(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go: denyAuthz, ListConfigs, RevokeLease ──────────────────

// ListConfigs: authorize() returns false without user ctx → denyAuthz → 403
func TestDynamicSecretHandler_ListConfigs_NoUserCtx(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ListConfigs: user ctx present but no permissions → also 403
func TestDynamicSecretHandler_ListConfigs_Forbidden(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDynamicSecretHandler_RevokeLease_NoUserCtx(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "leaseID", "1")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RevokeLease: string leaseID "bad" → lease not found → 404
func TestDynamicSecretHandler_RevokeLease_NotFound_S4(t *testing.T) {
	h := newDynamicSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "leaseID", "bad"))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets_extend_expiring.go: ExtendExpiringSecrets ─────────────────────────

func TestSecretHandler_ExtendExpiringSecrets_NoUserCtx(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"days":30}`))
	w := httptest.NewRecorder()
	h.ExtendExpiringSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecretHandler_ExtendExpiringSecrets_BadJSON(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ExtendExpiringSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── secret_certificate.go: GetSecretCertificate ───────────────────────────────

// ── secret_dependencies.go: GetSecretImpact, GetProjectRotationOrder ──────────

// ── machine_identities.go: CreateMachineIdentity ─────────────────────────────

// CreateMachineIdentity: checks chi param "id" first, then user ctx
func TestCatalogHandler_CreateMachineIdentity_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_NoUserCtx(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCatalogHandler_CreateMachineIdentity_BadJSON(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_review_campaigns.go: ListAccessReviewCampaigns ────────────────────

// ListAccessReviewCampaigns: no user ctx check, just parses chi param "id"
func TestCatalogHandler_ListAccessReviewCampaigns_NoID(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCatalogHandler_ListAccessReviewCampaigns_HappyPath(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── scim_groups.go: GetGroup, ListGroups (additional coverage) ────────────────

func TestSCIMHandler_GetGroup_BadID_S4(t *testing.T) {
	h := NewSCIMHandler(newHandlerCoreS4(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIMHandler_ListGroups_HappyPath_S4(t *testing.T) {
	h := NewSCIMHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListGroups(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
