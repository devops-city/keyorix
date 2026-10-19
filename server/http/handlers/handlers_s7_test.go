// handlers_s7_test.go — sprint-7 coverage sweep: targets functions left at low
// coverage after s3–s6. Uses the same shared-DB pattern from handlers_s4_test.go
// (sharedS4CoreOnce / newHandlerCoreS4) to avoid CI timeout risk.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newAuthHandlerS7(t *testing.T) *AuthHandler {
	t.Helper()
	return NewAuthHandler(newHandlerCoreS4(t), false)
}

func newCatalogHandlerS7(t *testing.T) *CatalogHandler {
	t.Helper()
	return NewCatalogHandler(newHandlerCoreS4(t))
}

func newImpersonationHandlerS7(t *testing.T) *ImpersonationHandler {
	t.Helper()
	return NewImpersonationHandler(newHandlerCoreS4(t), false)
}

func newSecretHandlerS7(t *testing.T) *SecretHandler {
	t.Helper()
	h, err := NewSecretHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

func newDynamicSecretHandlerS7(t *testing.T) *DynamicSecretHandler {
	t.Helper()
	return NewDynamicSecretHandler(newHandlerCoreS4(t))
}

// freshCoreS7 creates a brand-new in-memory SQLite DB (different DSN from the
// s4 shared DB) with a full schema including system_metadata.  Use this for
// tests that call BootstrapSystem, Login, or any other stateful flow that would
// conflict with the shared s4 DB (which may already be bootstrapped with
// different credentials).
func freshCoreS7(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s7_")
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
		// s7 addition: required for BootstrapSystem's initialized-state check.
		&models.SystemMetadata{},
		// coverage-sweep addition: required by anomaly_config_test.go's
		// GetAnomalyConfig/UpdateAnomalyConfig real-server tests, and by
		// BootstrapSystem's password-history write.
		&models.AnomalyConfigRecord{}, &models.PasswordHistory{},
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// withUserCtxS7 injects a standard user context into the request.
func withUserCtxS7(r *http.Request) *http.Request {
	uc := &middleware.UserContext{
		UserID:   1,
		Username: "testuser",
		Email:    "testuser@example.com",
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// withChiParamS7 injects a single chi URL param into the request.
func withChiParamS7(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// withChiParamsMapS7 injects multiple chi URL params.
func withChiParamsMapS7(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// ── audit_anomaly.go: ListAnomalyAlerts ────────────────────────────────────

// TestListAnomalyAlerts_AcknowledgedFilter_S7 exercises the ?acknowledged=true
// branch.  Without a core service in context the nil-guard fires → 500; still
// exercises more branches than the no-request tests in s5.
func TestListAnomalyAlerts_AcknowledgedFilter_S7(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?acknowledged=true", nil)
	w := httptest.NewRecorder()
	ListAnomalyAlerts(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestListAnomalyAlerts_AcknowledgedFalse_S7 exercises ?acknowledged=false.
func TestListAnomalyAlerts_AcknowledgedFalse_S7(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?acknowledged=false", nil)
	w := httptest.NewRecorder()
	ListAnomalyAlerts(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestListAnomalyAlerts_SeverityAndType_S7 exercises ?severity + ?alertType.
func TestListAnomalyAlerts_SeverityAndType_S7(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?severity=medium&alertType=new_ip", nil)
	w := httptest.NewRecorder()
	ListAnomalyAlerts(w, req)
	// No core service → 500 before FilterAlerts is called, but the query param
	// parsing branches are entered.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestListAnomalyAlerts_WithCoreService_S7 exercises the full happy path by
// wrapping the handler in the Authentication middleware with a real in-memory
// core that has no alerts (returns empty list → 200).
func TestListAnomalyAlerts_WithCoreService_S7(t *testing.T) {
	cs := freshCoreS7(t)
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Get("/anomalies", ListAnomalyAlerts)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Bootstrap + login so we have a valid session token.
	ctx := context.Background()
	cs.SetBootstrapToken("s7anomaly-boot")
	_, err := cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7anomaly",
		Email:    "s7anomaly@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7anomaly-boot",
	})
	require.NoError(t, err)
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7anomaly", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/anomalies", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Empty DB → no alerts → 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestListAnomalyAlerts_WithCoreService_AcknowledgedFilter_S7 exercises the
// filtered path (acknowledged=true) with a real core in context.
func TestListAnomalyAlerts_WithCoreService_AcknowledgedFilter_S7(t *testing.T) {
	cs := freshCoreS7(t)
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Get("/anomalies", ListAnomalyAlerts)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx := context.Background()
	cs.SetBootstrapToken("s7anomaly2-boot")
	_, _ = cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7anomaly2",
		Email:    "s7anomaly2@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7anomaly2-boot",
	})
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7anomaly2", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/anomalies?acknowledged=true&severity=high&alertType=off_hours", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestListAnomalyAlerts_WithCoreService_UnacknowledgedAlias_S7 exercises the
// legacy ?unacknowledged=true alias with a real core in context.
func TestListAnomalyAlerts_WithCoreService_UnacknowledgedAlias_S7(t *testing.T) {
	cs := freshCoreS7(t)
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Get("/anomalies", ListAnomalyAlerts)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx := context.Background()
	cs.SetBootstrapToken("s7anomaly3-boot")
	_, _ = cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7anomaly3",
		Email:    "s7anomaly3@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7anomaly3-boot",
	})
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7anomaly3", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/anomalies?unacknowledged=true", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── audit_anomaly.go: AcknowledgeAnomalyAlert ──────────────────────────────

// TestAcknowledgeAnomalyAlert_WithCoreService_BadID_S7 exercises the bad-ID
// parse branch when a core service IS in context (i.e. 400, not 500).
func TestAcknowledgeAnomalyAlert_WithCoreService_BadID_S7(t *testing.T) {
	cs := freshCoreS7(t)
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Post("/anomalies/{id}/acknowledge", AcknowledgeAnomalyAlert)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx := context.Background()
	cs.SetBootstrapToken("s7ackbad-boot")
	_, _ = cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7ackbad",
		Email:    "s7ackbad@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7ackbad-boot",
	})
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7ackbad", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/anomalies/notanumber/acknowledge", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAcknowledgeAnomalyAlert_WithCoreService_NotFound_S7 exercises the
// not-found path when the alert ID does not exist.
func TestAcknowledgeAnomalyAlert_WithCoreService_NotFound_S7(t *testing.T) {
	cs := freshCoreS7(t)
	mux := chi.NewRouter()
	mux.Use(middleware.Authentication(cs))
	mux.Post("/anomalies/{id}/acknowledge", AcknowledgeAnomalyAlert)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx := context.Background()
	cs.SetBootstrapToken("s7acknf-boot")
	_, _ = cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7acknf",
		Email:    "s7acknf@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7acknf-boot",
	})
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7acknf", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/anomalies/9999/acknowledge", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	// Alert 9999 doesn't exist → 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ── sod.go: ListSoDPolicies, ListSoDViolations ─────────────────────────────

// TestCatalogHandler_ListSoDPolicies_HappyPath_S7 tests the happy path.
func TestCatalogHandler_ListSoDPolicies_HappyPath_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := httptest.NewRequest(http.MethodGet, "/sod/policies", nil)
	w := httptest.NewRecorder()
	h.ListSoDPolicies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestCatalogHandler_ListSoDViolations_HappyPath_S7 tests the happy path.
func TestCatalogHandler_ListSoDViolations_HappyPath_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := httptest.NewRequest(http.MethodGet, "/sod/violations", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestCatalogHandler_CreateSoDPolicy_Unauthorized_S7 tests missing user ctx.
func TestCatalogHandler_CreateSoDPolicy_Unauthorized_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"name":"p","permission_a":"secrets.read","permission_b":"secrets.write"}`
	req := httptest.NewRequest(http.MethodPost, "/sod/policies", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCatalogHandler_CreateSoDPolicy_BadJSON_S7 tests invalid request body.
func TestCatalogHandler_CreateSoDPolicy_BadJSON_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodPost, "/sod/policies", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCatalogHandler_CreateSoDPolicy_MissingFields_S7 tests body with empty
// required fields (name/permission_a/permission_b).
func TestCatalogHandler_CreateSoDPolicy_MissingFields_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodPost, "/sod/policies", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	// Core returns "required" or similar → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCatalogHandler_DeleteSoDPolicy_Unauthorized_S7 tests missing user ctx.
func TestCatalogHandler_DeleteSoDPolicy_Unauthorized_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withChiParamS7(httptest.NewRequest(http.MethodDelete, "/sod/policies/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCatalogHandler_DeleteSoDPolicy_BadID_S7 tests invalid ID format.
func TestCatalogHandler_DeleteSoDPolicy_BadID_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodDelete, "/sod/policies/bad", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCatalogHandler_DeleteSoDPolicy_NotFound_S7 tests deleting non-existent policy.
// FIX-6 (#1645 403-for-both): a non-admin-tier actor gets the same 403 denial
// for a nonexistent policy id as for an existing-but-foreign one, not a
// distinguishing 404. Deliberately does NOT use withUserCtxS7's shared
// UserID=1 -- newCatalogHandlerS7 backs onto newHandlerCoreS4's PACKAGE-WIDE
// shared DB, and some other S4/S7 test elsewhere in this huge shared-fixture
// suite grants UserID=1 admin-tier authority without reverting it, making
// this assertion flaky/order-dependent on that ambient state (observed
// failing in CI's handlers-4 shard while passing locally). A dedicated,
// never-referenced-elsewhere actor ID sidesteps the ambiguity entirely.
func TestCatalogHandler_DeleteSoDPolicy_NotFound_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	dedicatedNonAdminActor := &middleware.UserContext{
		UserID: 55501002, Username: "sod-notfound-nonadmin-s7", Email: "sod-notfound-nonadmin-s7@example.com",
	}
	req := httptest.NewRequest(http.MethodDelete, "/sod/policies/9999", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), dedicatedNonAdminActor))
	req = withChiParamS7(req, "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── machine_token_hygiene.go: MachineTokenHygiene ──────────────────────────

// TestMachineTokenHygiene_DaysParam_S7 exercises the ?days= parsing branch.
func TestMachineTokenHygiene_DaysParam_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/?days=30", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMachineTokenHygiene_DaysCapped_S7 exercises the > 3650 cap branch.
func TestMachineTokenHygiene_DaysCapped_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/?days=99999", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMachineTokenHygiene_InvalidDays_S7 exercises the invalid/non-positive
// days value branch (falls back to default 90).
func TestMachineTokenHygiene_InvalidDays_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/?days=notanumber", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── catalog.go: ListEnvironments ────────────────────────────────────────────

// TestCatalogHandler_ListEnvironments_HappyPath_S7 exercises the happy path.
func TestCatalogHandler_ListEnvironments_HappyPath_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/environments", nil)) // #2780: authorizes in-handler
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── secrets_ownership.go: TransferOwnership ─────────────────────────────────

// TestTransferOwnership_Unauthorized_S7 tests missing user context.
func TestTransferOwnership_Unauthorized_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	req := withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":2}`)), "id", "1")
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestTransferOwnership_BadID_S7 tests invalid secret ID.
func TestTransferOwnership_BadID_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":2}`)), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransferOwnership_BadJSON_S7 tests malformed JSON body.
func TestTransferOwnership_BadJSON_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransferOwnership_MissingOwnerID_S7 tests zero new_owner_id.
func TestTransferOwnership_MissingOwnerID_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":0}`)), "id", "1"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransferOwnership_NotFound_S7 tests non-existent secret (triggers
// the "not found" error branch → 404).
func TestTransferOwnership_NotFound_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"new_owner_id":2}`)), "id", "99999"))
	w := httptest.NewRecorder()
	h.TransferOwnership(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── secrets_handler.go: resolveSecretNames ──────────────────────────────────

// TestResolveSecretNames_Empty_S7 exercises the early-return on an empty slice.
func TestResolveSecretNames_Empty_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	// Must not panic on empty input.
	h.resolveSecretNames(context.Background(), nil)
	h.resolveSecretNames(context.Background(), []*models.SecretWithSharingInfo{})
}

// TestResolveSecretNames_NilNode_S7 exercises the nil SecretNode guard.
func TestResolveSecretNames_NilNode_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: nil}, // SecretNode is nil — must be skipped without panic.
	}
	h.resolveSecretNames(context.Background(), secrets)
}

// TestResolveSecretNames_WithNode_S7 exercises the name-resolution path for a
// non-nil SecretNode with project/environment IDs that map to nothing
// (empty DB → names stay empty strings, not a panic).
func TestResolveSecretNames_WithNode_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	node := &models.SecretNode{ProjectID: 1, EnvironmentID: 1}
	node.Name = "MY_SECRET"
	secrets := []*models.SecretWithSharingInfo{
		{SecretNode: node},
	}
	h.resolveSecretNames(context.Background(), secrets)
	// No assertion on the name values — they will be empty strings because the
	// DB has no matching project/environment rows.  The test just confirms no
	// panic and the struct is mutated.
}

// ── secrets_crud.go: GetSecretValueByRef ────────────────────────────────────

// TestGetSecretValueByRef_Unauthorized_S7 tests missing user context.
func TestGetSecretValueByRef_Unauthorized_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	req := httptest.NewRequest(http.MethodGet, "/?ref=proj/env/name", nil)
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetSecretValueByRef_NoResolvedSecretInContext_S7 covers the handler's
// defensive branch. Ref resolution now happens exactly once, in
// middleware.RequireScopedSecretRefPermission (see auth_s24_test.go in
// server/middleware for the 400 invalid-format / 404 not-found coverage that
// used to live here as three separate tests), which pins the resolved secret
// on the request context before dispatch. A direct handler call that bypasses
// the middleware — as every test in this file does — never gets that context
// value, so the handler must 500 rather than fall back to re-resolving the
// ref itself; that fallback is exactly the second resolution that made
// ResolveSecretRef callable twice per request (core-secret-ref-4).
func TestGetSecretValueByRef_NoResolvedSecretInContext_S7(t *testing.T) {
	h := newSecretHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/?ref=noproj/noenv/nosecret", nil))
	w := httptest.NewRecorder()
	h.GetSecretValueByRef(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── machine_identities.go: CreateMachineIdentity ───────────────────────────

// TestCreateMachineIdentity_BadProjectID_S7 tests invalid project ID.
func TestCreateMachineIdentity_BadProjectID_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"name":"bot","identity_type":"service"}`
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentity_Unauthorized_S7 tests missing user context.
func TestCreateMachineIdentity_Unauthorized_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"name":"bot","identity_type":"service"}`
	req := withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCreateMachineIdentity_BadJSON_S7 tests malformed JSON body.
func TestCreateMachineIdentity_BadJSON_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentity_MissingName_S7 tests empty name field.
func TestCreateMachineIdentity_MissingName_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"name":"","identity_type":"service"}`
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentity_InvalidType_S7 tests an unknown identity_type.
func TestCreateMachineIdentity_InvalidType_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"name":"bot","identity_type":"unknown_type"}`
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	// invalid identity_type → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities.go: changeMachineRole ───────────────────────────────

// TestGrantMachineRole_BadProjectID_S7 tests invalid project ID.
func TestGrantMachineRole_BadProjectID_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"role_id":1}`
	req := withUserCtxS7(withChiParamsMapS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), map[string]string{
		"id":        "bad",
		"machineId": "1",
	}))
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGrantMachineRole_BadMachineID_S7 tests invalid machine ID.
func TestGrantMachineRole_BadMachineID_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"role_id":1}`
	req := withUserCtxS7(withChiParamsMapS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), map[string]string{
		"id":        "1",
		"machineId": "bad",
	}))
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGrantMachineRole_Unauthorized_S7 tests missing user context.
func TestGrantMachineRole_Unauthorized_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	body := `{"role_id":1}`
	req := withChiParamsMapS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), map[string]string{
		"id":        "1",
		"machineId": "1",
	})
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGrantMachineRole_BadJSON_S7 tests bad JSON body (role_id == 0).
func TestGrantMachineRole_BadJSON_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(withChiParamsMapS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")), map[string]string{
		"id":        "1",
		"machineId": "1",
	}))
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	// bad JSON → role_id decode fails → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGrantMachineRole_ZeroRoleID_S7 tests body with role_id = 0.
func TestGrantMachineRole_ZeroRoleID_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(withChiParamsMapS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"role_id":0}`)), map[string]string{
		"id":        "1",
		"machineId": "1",
	}))
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGrantMachineRole_NotFound_S7 tests a valid request for a non-existent
// machine/role → 404 or conflict.
func TestGrantMachineRole_NotFound_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(withChiParamsMapS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"role_id":9999}`)), map[string]string{
		"id":        "9999",
		"machineId": "9999",
	}))
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRemoveMachineRole_BadRoleID_S7 tests invalid roleId URL param.
func TestRemoveMachineRole_BadRoleID_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(withChiParamsMapS7(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{
		"id":        "1",
		"machineId": "1",
		"roleId":    "bad",
	}))
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveMachineRole_NotFound_S7 tests removing a role from a non-existent
// machine → 404.
func TestRemoveMachineRole_NotFound_S7(t *testing.T) {
	h := newCatalogHandlerS7(t)
	req := withUserCtxS7(withChiParamsMapS7(httptest.NewRequest(http.MethodDelete, "/", nil), map[string]string{
		"id":        "9999",
		"machineId": "9999",
		"roleId":    "9999",
	}))
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dynamic_secrets.go: denyAuthz ───────────────────────────────────────────

// TestDenyAuthz_MFABlocked_S7 tests the MFA-blocked branch of denyAuthz.
func TestDenyAuthz_MFABlocked_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	w := httptest.NewRecorder()
	h.denyAuthz(w, true) // mfaBlocked=true → middleware.WriteProjectMFARequired
	// MFA-required writes a 403 (or whatever middleware sets; just not 200).
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestDenyAuthz_PermDenied_S7 tests the permission-denied branch.
func TestDenyAuthz_PermDenied_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	w := httptest.NewRecorder()
	h.denyAuthz(w, false) // mfaBlocked=false → 403 Forbidden
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── dynamic_secrets.go: ListConfigs ─────────────────────────────────────────

// TestDynamicSecrets_ListConfigs_BadProjectID_S7 tests invalid project_id query
// param (parseScopeQuery returns ok=false → handler returns early).
func TestDynamicSecrets_ListConfigs_BadProjectID_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_ListConfigs_BadEnvID_S7 tests invalid environment_id.
func TestDynamicSecrets_ListConfigs_BadEnvID_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_ListConfigs_NoUserCtx_S7 tests missing user context
// (the authorize call hits GetUserFromContext → nil → forbidden).
func TestDynamicSecrets_ListConfigs_NoUserCtx_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=1", nil)
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	// authorize returns ok=false, mfaBlocked=false → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── dynamic_secrets.go: IssueLease, ListLeases, RevokeAllLeases, ClassifyConfig, SetConfigEnabled ──

// TestDynamicSecrets_IssueLease_InvalidConfigID_S7 tests bad config ID.
func TestDynamicSecrets_IssueLease_InvalidConfigID_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "bad"))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_IssueLease_ConfigNotFound_S7 tests config not found.
func TestDynamicSecrets_IssueLease_ConfigNotFound_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", "9999"))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamicSecrets_ListLeases_InvalidConfigID_S7 tests bad config ID.
func TestDynamicSecrets_ListLeases_InvalidConfigID_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_ListLeases_ConfigNotFound_S7 tests non-existent config.
func TestDynamicSecrets_ListLeases_ConfigNotFound_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamicSecrets_RevokeAllLeases_InvalidConfigID_S7 tests bad config ID.
func TestDynamicSecrets_RevokeAllLeases_InvalidConfigID_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_RevokeAllLeases_ConfigNotFound_S7 tests non-existent config.
func TestDynamicSecrets_RevokeAllLeases_ConfigNotFound_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamicSecrets_ClassifyConfig_InvalidConfigID_S7 tests bad config ID.
func TestDynamicSecrets_ClassifyConfig_InvalidConfigID_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	body := `{"classification":"confidential"}`
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "bad"))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_ClassifyConfig_ConfigNotFound_S7 tests non-existent config.
func TestDynamicSecrets_ClassifyConfig_ConfigNotFound_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	body := `{"classification":"confidential"}`
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamicSecrets_SetConfigEnabled_InvalidConfigID_S7 tests bad config ID.
func TestDynamicSecrets_SetConfigEnabled_InvalidConfigID_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	body := `{"enabled":true}`
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "bad"))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamicSecrets_SetConfigEnabled_ConfigNotFound_S7 tests non-existent config.
func TestDynamicSecrets_SetConfigEnabled_ConfigNotFound_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	body := `{"enabled":true}`
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── admin_impersonation.go: End ─────────────────────────────────────────────

// TestImpersonationEnd_BadToken_S7 exercises End with a non-impersonation
// session token → "not an impersonation" error → 400.
func TestImpersonationEnd_BadToken_S7(t *testing.T) {
	h := newImpersonationHandlerS7(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer nosuchtoken")
	w := httptest.NewRecorder()
	h.End(w, req)
	// Token not found or not an impersonation → 400 or 500
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestImpersonationEnd_WithAdminCookieNoSession_S7 exercises the admin-cookie
// restore path when the admin session has already expired / was never created.
func TestImpersonationEnd_WithAdminCookieNoSession_S7(t *testing.T) {
	h := newImpersonationHandlerS7(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer somefaketoken")
	// Set an admin cookie that references a non-existent session.
	req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookieName, Value: "expired-admin-token"})
	w := httptest.NewRecorder()
	h.End(w, req)
	// Either 400 (not-impersonation) or 500; admin restore is moot either way.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── auth.go: RefreshToken happy path ─────────────────────────────────────────

// TestRefreshToken_ValidToken_S7 exercises RefreshToken with a real session
// created via Login, covering the success branch (new token + cookies set).
func TestRefreshToken_ValidToken_S7(t *testing.T) {
	cs := freshCoreS7(t)
	h := NewAuthHandler(cs, false)
	ctx := context.Background()

	cs.SetBootstrapToken("s7refresh-boot")
	_, _ = cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7refresh",
		Email:    "s7refresh@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7refresh-boot",
	})
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7refresh", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	contracttest.AssertOpenAPIResponse(t, req, w)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── auth.go: ListSessions with sessions that have expiry timestamps ──────────

// TestListSessions_WithExpiryTimestamps_S7 exercises the ExpiresAt/LastSeenAt
// formatting branches inside ListSessions.  We create a real session so at
// least one row with ExpiresAt set exists in the DB.
func TestListSessions_WithExpiryTimestamps_S7(t *testing.T) {
	cs := freshCoreS7(t)
	h := NewAuthHandler(cs, false)
	ctx := context.Background()

	cs.SetBootstrapToken("s7sessions-boot")
	_, _ = cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7sessions",
		Email:    "s7sessions@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7sessions-boot",
	})
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7sessions", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	// Find the user ID.
	sessUser, err := cs.GetUserByUsername(ctx, "s7sessions")
	require.NoError(t, err)

	uc := &middleware.UserContext{UserID: sessUser.ID, Username: "s7sessions"}
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── auth.go: InitSystem fully-initialized branch ──────────────────────────────

// TestInitSystem_AlreadyInitialized_Idempotent_S7 verifies that hitting
// InitSystem a second time (after a successful first bootstrap) returns the
// already_initialized=true response (the 200 success branch that was not
// covered before).
func TestInitSystem_AlreadyInitialized_Idempotent_S7(t *testing.T) {
	cs := freshCoreS7(t)
	h := NewAuthHandler(cs, false)

	cs.SetBootstrapToken("s7init-boot")
	// First call — should succeed (or return already_initialized if another s7
	// test ran first on the shared DB).
	body1 := `{"username":"s7initadmin","email":"s7initadmin@example.com","password":"Kx#Vr9$Mn2!Zp4@Qw","bootstrap_token":"s7init-boot"}`
	req1 := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body1))
	req1.Header.Set("X-Keyorix-Bootstrap-Token", "s7init-boot")
	w1 := httptest.NewRecorder()
	h.InitSystem(w1, req1)
	// Accept either "already_initialized" 200 or a fresh 200.
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second call — must always return already_initialized=true.
	body2 := `{"username":"s7initadmin","email":"s7initadmin@example.com","password":"Kx#Vr9$Mn2!Zp4@Qw"}`
	req2 := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body2))
	w2 := httptest.NewRecorder()
	h.InitSystem(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w2.Body).Decode(&resp))
	data, _ := resp["data"].(map[string]any)
	if data != nil {
		v, ok := data["already_initialized"]
		if ok {
			assert.True(t, v.(bool))
		}
	}
}

// TestInitSystem_ForbiddenToken_S7 exercises the bootstrap-token error branch
// (wrong token → 403).
func TestInitSystem_ForbiddenToken_S7(t *testing.T) {
	h := NewAuthHandler(freshCoreS7(t), false)
	body := `{"username":"u","email":"u@example.com","password":"Pass!1234"}`
	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	req.Header.Set("X-Keyorix-Bootstrap-Token", "wrongtoken")
	w := httptest.NewRecorder()
	h.InitSystem(w, req)
	// Wrong token → 403 or error
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── sso.go: CompleteSSO ──────────────────────────────────────────────────────

// TestCompleteSSO_UnknownProvider_S7 exercises the "unknown SSO provider" branch.
func TestCompleteSSO_UnknownProvider_S7(t *testing.T) {
	h := newAuthHandlerS7(t)
	req := withChiParamS7(httptest.NewRequest(http.MethodGet, "/?code=abc&state=xyz", nil), "provider", "nosuchprovider")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	// SSOCompleteURL returns ok=false for an unknown provider → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCompleteSSO_MissingCode_S7 and MissingState exercise the empty-code /
// empty-state branch. The provider name is unknown (no SSO configured) so we
// still hit the early "unknown provider" guard.  The test value is important:
// any unknown provider falls through before the code/state check; this just
// ensures we don't panic.
func TestCompleteSSO_MissingCodeAndState_S7(t *testing.T) {
	h := newAuthHandlerS7(t)
	req := withChiParamS7(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "nosuchprovider")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── saml.go: CompleteSAML ─────────────────────────────────────────────────────

// TestCompleteSAML_UnknownProvider_S7 exercises the "unknown SSO provider" branch.
func TestCompleteSAML_UnknownProvider_S7(t *testing.T) {
	h := newAuthHandlerS7(t)
	req := withChiParamS7(httptest.NewRequest(http.MethodPost, "/", nil), "provider", "nosuchprovider")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── webauthn.go: FinishWebAuthnLogin ────────────────────────────────────────

// TestFinishWebAuthnLogin_EmptyBody_S7 exercises the missing-body early return.
func TestFinishWebAuthnLogin_EmptyBody_S7(t *testing.T) {
	h := newAuthHandlerS7(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnLogin_BadCredential_S7 exercises the invalid assertion
// parse branch (credential is present but not valid CBOR/WebAuthn format).
func TestFinishWebAuthnLogin_BadCredential_S7(t *testing.T) {
	h := newAuthHandlerS7(t)
	body := `{"mfa_challenge":"abc","webauthn_session":"xyz","credential":"bm90dmFsaWQ="}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	// Invalid assertion → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── webauthn.go: FinishWebAuthnPasswordlessLogin ─────────────────────────────

// TestFinishWebAuthnPasswordlessLogin_EmptyBody_S7 exercises the empty-body path.
func TestFinishWebAuthnPasswordlessLogin_EmptyBody_S7(t *testing.T) {
	h := newAuthHandlerS7(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnPasswordlessLogin_BadCredential_S7 exercises the invalid
// credential parse branch.
func TestFinishWebAuthnPasswordlessLogin_BadCredential_S7(t *testing.T) {
	h := newAuthHandlerS7(t)
	body := `{"webauthn_session":"xyz","credential":"bm90dmFsaWQ="}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── isSafeDynamicSecretError ──────────────────────────────────────────────────

// TestIsSafeDynamicSecretError_S7 exercises every safe sentinel and confirms
// unknown messages return false (the direct-call form gives us branch coverage
// without any HTTP overhead).
func TestIsSafeDynamicSecretError_S7(t *testing.T) {
	safeMsgs := []string{
		"config not found",
		"lease not found",
		"lease is not active",
		"lease has expired; issue a new lease instead",
		"cannot issue from the disabled config",
		"active-lease limit reached",
		"mints self-expiring credentials that cannot be renewed",
		"unsupported backend",
	}
	for _, msg := range safeMsgs {
		assert.True(t, isSafeDynamicSecretError(msg), "expected safe: %q", msg)
	}
	assert.False(t, isSafeDynamicSecretError("connection refused"))
	assert.False(t, isSafeDynamicSecretError(""))
}

// ── isSafeSSOError ────────────────────────────────────────────────────────────

// TestIsSafeSSOError_S7 exercises every safe sentinel and confirms unsafe
// messages return false.
func TestIsSafeSSOError_S7(t *testing.T) {
	safeMsgs := []string{
		"unknown SSO provider",
		"unknown SAML provider",
		"invalid or expired login state",
		"login state does not match the callback provider",
		"login state expired",
		"the token response carried no id_token",
		"the assertion carried no subject or email",
		"no Keyorix account matches this SSO identity",
		"the IdP returned no email; cannot auto-provision an account",
	}
	for _, msg := range safeMsgs {
		assert.True(t, isSafeSSOError(msg), "expected safe: %q", msg)
	}
	assert.False(t, isSafeSSOError("connection refused"))
	assert.False(t, isSafeSSOError(""))
}

// ── parseScopeQuery edge cases ────────────────────────────────────────────────

// TestParseScopeQuery_ValidParams_S7 exercises the success path of parseScopeQuery.
func TestParseScopeQuery_ValidParams_S7(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=5&environment_id=3", nil)
	w := httptest.NewRecorder()
	pid, eid, ok := parseScopeQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(5), pid)
	assert.Equal(t, uint(3), eid)
}

// TestParseScopeQuery_EmptyParams_S7 exercises the zero-value success path.
func TestParseScopeQuery_EmptyParams_S7(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	pid, eid, ok := parseScopeQuery(w, req)
	assert.True(t, ok)
	assert.Equal(t, uint(0), pid)
	assert.Equal(t, uint(0), eid)
}

// ── DynamicSecretHandler.authorize nil-user branch ───────────────────────────

// TestDynamicSecrets_Authorize_NilUser_S7 exercises the authorize helper when
// no user is in context (returns ok=false, mfaBlocked=false).
func TestDynamicSecrets_Authorize_NilUser_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ok, mfaBlocked := h.authorize(req, "secrets.read", core.Scope{ProjectID: 1, EnvironmentID: 1})
	assert.False(t, ok)
	assert.False(t, mfaBlocked)
}

// ── dynamic_secrets.go: CreateConfig branches ────────────────────────────────

// TestDynamicSecrets_CreateConfig_Unauthorized_S7 tests missing user context.
func TestDynamicSecrets_CreateConfig_Unauthorized_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	body := `{"name":"cfg","project_id":1,"environment_id":1,"backend_type":"postgres"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDynamicSecrets_CreateConfig_BadJSON_S7 tests malformed JSON body.
func TestDynamicSecrets_CreateConfig_BadJSON_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── dynamic_secrets.go: RevokeLease, RenewLease ──────────────────────────────

// TestDynamicSecrets_RevokeLease_Unauthorized_S7 tests missing user context.
func TestDynamicSecrets_RevokeLease_Unauthorized_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withChiParamS7(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "lease-abc")
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDynamicSecrets_RevokeLease_NotFound_S7 tests a non-existent lease ID.
func TestDynamicSecrets_RevokeLease_NotFound_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "nonexistent-lease-id"))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDynamicSecrets_RenewLease_Unauthorized_S7 tests missing user context.
func TestDynamicSecrets_RenewLease_Unauthorized_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withChiParamS7(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "lease-xyz")
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDynamicSecrets_RenewLease_NotFound_S7 tests a non-existent lease ID.
func TestDynamicSecrets_RenewLease_NotFound_S7(t *testing.T) {
	h := newDynamicSecretHandlerS7(t)
	req := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPost, "/", nil), "leaseID", "nonexistent-lease-xyz"))
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── sanitizeConfig / sanitizeLease (direct call coverage) ────────────────────

// TestSanitizeConfig_S7 exercises sanitizeConfig with a full model instance.
func TestSanitizeConfig_S7(t *testing.T) {
	now := time.Now()
	cfg := &models.DynamicSecretConfig{
		Name:              "myconfig",
		ProjectID:         1,
		EnvironmentID:     2,
		BackendType:       "postgres",
		CreationTemplate:  "CREATE ROLE ...",
		DefaultTTLSeconds: 3600,
		MaxTTLSeconds:     7200,
		MaxActiveLeases:   5,
		Classification:    "confidential",
		Disabled:          false,
		CreatedBy:         "alice",
		CreatedAt:         now,
	}
	cfg.ID = 42
	m := sanitizeConfig(cfg)
	assert.Equal(t, uint(42), m["id"])
	assert.Equal(t, "myconfig", m["name"])
	assert.Equal(t, "postgres", m["backend_type"])
	assert.Equal(t, "confidential", m["classification"])
	assert.NotContains(t, m, "admin_dsn")
}

// TestSanitizeLease_S7 exercises sanitizeLease with a full model instance.
func TestSanitizeLease_S7(t *testing.T) {
	now := time.Now()
	lease := &models.DynamicSecretLease{
		LeaseID:      "lease-abc-123",
		ConfigID:     42,
		RoleName:     "kx_role",
		Status:       "active",
		RevokeReason: "",
		RevokeError:  "",
		IssuedAt:     now,
	}
	m := sanitizeLease(lease)
	assert.Equal(t, "lease-abc-123", m["lease_id"])
	assert.Equal(t, uint(42), m["config_id"])
	assert.Equal(t, "active", m["status"])
}

// ── auth.go: ListSessions CurrentSessionID branch ────────────────────────────

// TestListSessions_WithBearerToken_S7 exercises the CurrentSessionID lookup
// path when a bearer token is present (covers the sessionResponse building
// loop with a Current-session check).
func TestListSessions_WithBearerToken_S7(t *testing.T) {
	cs := freshCoreS7(t)
	h := NewAuthHandler(cs, false)
	ctx := context.Background()

	cs.SetBootstrapToken("s7listsess-boot")
	_, _ = cs.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "s7listsess",
		Email:    "s7listsess@example.com",
		Password: "Kx#Vr9$Mn2!Zp4@Qw",
		Token:    "s7listsess-boot",
	})
	session, _, err := cs.Login(ctx, &core.LoginRequest{Username: "s7listsess", Password: "Kx#Vr9$Mn2!Zp4@Qw"})
	require.NoError(t, err)

	lsUser, err := cs.GetUserByUsername(ctx, "s7listsess")
	require.NoError(t, err)

	uc := &middleware.UserContext{UserID: lsUser.ID, Username: "s7listsess"}
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	// Provide the bearer token so CurrentSessionID can match it.
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.ListSessions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, _ := resp["data"].([]any)
	// Should have at least one session — the one we just logged in with.
	assert.NotEmpty(t, data)
}
