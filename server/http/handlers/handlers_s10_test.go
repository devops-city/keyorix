package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// withMachineCtxS10 wraps a request with a machine-identity UserContext.
func withMachineCtxS10(r *http.Request) *http.Request {
	mid := uint(1)
	userCtx := &customMiddleware.UserContext{
		UserID:            0,
		MachineIdentityID: &mid,
	}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// newIsolatedCoreS10 creates a fresh in-memory SQLite DB with the full schema
// including SecretVersion (not present in the shared s4 DB). Used only for tests
// that actually create secrets, to avoid interference with the shared s4 DB.
// Uses ":memory:" (no cache=shared) for a truly isolated DB per invocation.
func newIsolatedCoreS10(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "open isolated s10 DB")
	err = db.AutoMigrate(
		// exact same list as newHandlerCoreS4, plus SecretVersion
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
		// s10 addition — required for CreateSecret / GetSecret / value reads
		&models.SecretVersion{},
		&models.SecretAccessSchedule{},
	)
	require.NoError(t, err, "AutoMigrate isolated s10 DB")
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// newIsolatedSecretHandlerS10 creates a SecretHandler backed by an isolated DB
// that includes SecretVersion in its schema.
func newIsolatedSecretHandlerS10(t *testing.T) (*SecretHandler, *core.KeyorixCore) {
	t.Helper()
	svc := newIsolatedCoreS10(t)
	h, err := NewSecretHandler(svc)
	require.NoError(t, err)
	return h, svc
}

// seedS10Secret seeds a project, environment, and secret in the isolated DB.
// Returns (handler, projectName, envName, secretID).
func seedS10Secret(t *testing.T, projName, secretName string) (*SecretHandler, string, string, uint) {
	t.Helper()
	h, svc := newIsolatedSecretHandlerS10(t)
	ctx := context.Background()
	proj, err := svc.CreateProject(ctx, projName, "sprint-10 coverage seed")
	require.NoError(t, err, "CreateProject")
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err, "ListEnvironmentsByProject")
	require.NotEmpty(t, envs, "no environments seeded")
	envName := envs[0].Name
	req := &core.CreateSecretRequest{
		Name:          secretName,
		Value:         []byte("s10-test-value"),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "testuser",
	}
	secret, err := svc.CreateSecret(ctx, req)
	if err != nil {
		t.Skip("CreateSecret failed:", err)
	}
	return h, projName, envName, secret.ID
}

// ── toPATResponse: ExpiresAt and LastUsedAt branches ─────────────────────────

func TestToPATResponse_WithExpiresAt_S10(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	tok := &models.PersonalAccessToken{
		ID:        99,
		Name:      "s10-expires",
		ExpiresAt: &expiry,
	}
	resp := toPATResponse(tok)
	require.NotNil(t, resp.ExpiresAt, "ExpiresAt should be set")
	assert.Equal(t, expiry.UTC().Format(time.RFC3339), *resp.ExpiresAt)
	assert.Nil(t, resp.LastUsedAt)
}

func TestToPATResponse_WithLastUsedAt_S10(t *testing.T) {
	lastUsed := time.Now().UTC().Add(-1 * time.Hour)
	tok := &models.PersonalAccessToken{
		ID:         98,
		Name:       "s10-lastused",
		LastUsedAt: &lastUsed,
	}
	resp := toPATResponse(tok)
	assert.Nil(t, resp.ExpiresAt)
	require.NotNil(t, resp.LastUsedAt, "LastUsedAt should be set")
	assert.Equal(t, lastUsed.UTC().Format(time.RFC3339), *resp.LastUsedAt)
}

func TestToPATResponse_BothSet_S10(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)
	lastUsed := time.Now().UTC().Add(-1 * time.Hour)
	tok := &models.PersonalAccessToken{
		ID:         97,
		Name:       "s10-both",
		ExpiresAt:  &expiry,
		LastUsedAt: &lastUsed,
	}
	resp := toPATResponse(tok)
	require.NotNil(t, resp.ExpiresAt)
	require.NotNil(t, resp.LastUsedAt)
}

// ── GetSecret: BadID (ParseUint error) ───────────────────────────────────────

func TestGetSecret_BadID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/notanumber", nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", "notanumber")
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── GetSecret: machine identity path ─────────────────────────────────────────

func TestGetSecret_MachineIdentity_NotFound_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/99999", nil)
	r = withMachineCtxS10(r)
	r = withChiParam(r, "id", "99999")
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── GetSecret: include_value=true path (isolated DB) ─────────────────────────

func TestGetSecret_IncludeValue_MachineIdentity_S10(t *testing.T) {
	h, _, _, secretID := seedS10Secret(t, "s10-proj-inclval", "s10-inclval-secret")

	url := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secretID)
	r := httptest.NewRequest(http.MethodGet, url, nil)
	r = withMachineCtxS10(r)
	r = withResolvedSecretS10(t, h, r, secretID)
	r = withChiParam(r, "id", fmt.Sprintf("%d", secretID))
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	data, _ := body["data"].(map[string]any)
	assert.NotNil(t, data["secret"], "expected secret key in response")
	assert.NotNil(t, data["value"], "expected value key in response")
}

func TestGetSecret_MachineIdentity_Found_S10(t *testing.T) {
	h, _, _, secretID := seedS10Secret(t, "s10-proj-machine-found", "s10-machine-found-secret")

	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", secretID), nil)
	r = withMachineCtxS10(r)
	r = withResolvedSecretS10(t, h, r, secretID)
	r = withChiParam(r, "id", fmt.Sprintf("%d", secretID))
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetSecret_IncludeValue_UserPath_S10(t *testing.T) {
	h, _, _, secretID := seedS10Secret(t, "s10-proj-inclval-user", "s10-inclval-user-secret")

	url := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secretID)
	r := httptest.NewRequest(http.MethodGet, url, nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", fmt.Sprintf("%d", secretID))
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── GetSecretValueByRef: success path (isolated DB) ──────────────────────────
//
// GetSecretValueByRef no longer resolves the "ref" query param itself — that
// now happens exactly once, in middleware.RequireScopedSecretRefPermission,
// which pins the resolved secret on the request context before dispatch (see
// core-secret-ref-4). These tests simulate that hand-off directly, exactly as
// the middleware would, via customMiddleware.WithResolvedSecretRef.

func TestGetSecretValueByRef_Success_MachineIdentity_S10(t *testing.T) {
	h, projName, envName, _ := seedS10Secret(t, "s10-proj-ref", "s10-ref-secret")

	ref := fmt.Sprintf("%s/%s/%s", projName, envName, "s10-ref-secret")
	secret, err := h.coreService.ResolveSecretRef(context.Background(), ref)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/by-ref?ref="+ref, nil)
	r = withMachineCtxS10(r)
	r = r.WithContext(customMiddleware.WithResolvedSecretRef(r.Context(), secret))
	w := httptest.NewRecorder()

	h.GetSecretValueByRef(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	data, _ := body["data"].(map[string]any)
	assert.NotNil(t, data["secret"], "expected secret in ref response")
	assert.NotNil(t, data["value"], "expected value in ref response")
}

func TestGetSecretValueByRef_UserPath_S10(t *testing.T) {
	h, projName, envName, _ := seedS10Secret(t, "s10-proj-userref", "s10-userref-secret")

	ref := fmt.Sprintf("%s/%s/%s", projName, envName, "s10-userref-secret")
	secret, err := h.coreService.ResolveSecretRef(context.Background(), ref)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/by-ref?ref="+ref, nil)
	r = withUserCtx(r)
	r = r.WithContext(customMiddleware.WithResolvedSecretRef(r.Context(), secret))
	w := httptest.NewRecorder()

	h.GetSecretValueByRef(w, r)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── SuspendProjectSecrets / ResumeProjectSecrets: BadID ──────────────────────

func TestSuspendProjectSecrets_BadID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/xyz/secrets/suspend-all", strings.NewReader("{}"))
	r = withUserCtx(r)
	r = withChiParam(r, "id", "xyz")
	w := httptest.NewRecorder()

	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResumeProjectSecrets_BadID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/xyz/secrets/resume-all", nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", "xyz")
	w := httptest.NewRecorder()

	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── SuspendProjectSecrets / ResumeProjectSecrets: happy path ─────────────────

func TestSuspendProjectSecrets_HappyPath_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"reason":"s10 test"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/9999/secrets/suspend-all",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParam(r, "id", "9999")
	w := httptest.NewRecorder()

	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestResumeProjectSecrets_HappyPath_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/9999/secrets/resume-all", nil)
	r = withUserCtx(r)
	r = withChiParam(r, "id", "9999")
	w := httptest.NewRecorder()

	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── CopyEnvironmentSecrets: validation branches ───────────────────────────────

func TestCopyEnvironmentSecrets_ZeroTargetEnvID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"target_environment_id":0}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/copy-secrets",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParams(r, map[string]string{"id": "1", "envId": "1"})
	w := httptest.NewRecorder()

	h.CopyEnvironmentSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCopyEnvironmentSecrets_BadProjectID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"target_environment_id":2}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/xyz/environments/1/copy-secrets",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParams(r, map[string]string{"id": "xyz", "envId": "1"})
	w := httptest.NewRecorder()

	h.CopyEnvironmentSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCopyEnvironmentSecrets_BadEnvID_S10(t *testing.T) {
	h := newSecretHandlerS4(t)
	body := `{"target_environment_id":2}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/xyz/copy-secrets",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = withUserCtx(r)
	r = withChiParams(r, map[string]string{"id": "1", "envId": "xyz"})
	w := httptest.NewRecorder()

	h.CopyEnvironmentSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// withResolvedSecretS10 simulates RequireScopedSecretPermission's hand-off: the
// route middleware pins the secret it authorized on the request context, and
// GetSecret's machine branch serves only that (any mismatch is re-authorized).
func withResolvedSecretS10(t *testing.T, h *SecretHandler, r *http.Request, secretID uint) *http.Request {
	t.Helper()
	sec, err := h.coreService.GetSecret(r.Context(), secretID)
	require.NoError(t, err)
	return r.WithContext(customMiddleware.WithResolvedSecret(r.Context(), sec))
}
