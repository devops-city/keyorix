// handlers_s36_test.go — unit coverage sweep for secret_version_diff.go.
//
// Covers all branches of (*SecretHandler).DiffSecretVersions:
//   - No user context → 401
//   - Non-numeric "id" param → 400
//   - Non-numeric "from" param → 400
//   - Non-numeric "to" param → 400
//   - from <= 0 → 400
//   - to <= 0 → 400
//   - Core error containing "not found" → 404
//   - Core validation error ("must differ") → 400
//   - Core generic error → 500
//   - Happy path (success) → 200
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// ── DB helpers ────────────────────────────────────────────────────────────────

// freshCoreS36WithAdmin opens a uniquely-named in-memory SQLite DB, migrates
// all needed models, seeds user 1 as system_admin, and returns the core + DB.
func freshCoreS36WithAdmin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s36a_")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
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
		&models.SecretVersion{},
		&models.SecretACL{},
	))

	adminRole := &models.Role{Name: "system_admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	testUser := &models.User{Username: "testuser_s36", Email: "testuser_s36@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// withChiParam3_S36 sets three chi URL params at once.
func withChiParam3_S36(r *http.Request, k1, v1, k2, v2, k3, v3 string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(k1, v1)
	rctx.URLParams.Add(k2, v2)
	rctx.URLParams.Add(k3, v3)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// seedVersionDiffFixtureS36 creates a project, environment, secret node with
// two versions, and returns the secret's node ID.
func seedVersionDiffFixtureS36(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-s36"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env-s36"}).Error)
	now := time.Now()
	node := &models.SecretNode{
		ID:            100,
		Name:          "s36-secret",
		ProjectID:     1,
		EnvironmentID: 1,
		IsSecret:      true,
		Type:          "password",
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, db.Create(node).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 100, VersionNumber: 1, EncryptedValue: []byte("cv1"), ReadCount: 5,
		CreatedAt: now,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 100, VersionNumber: 2, EncryptedValue: []byte("cv2"), ReadCount: 10,
		CreatedAt: now,
	}).Error)
	return node.ID
}

// newDiffHandlerS36 returns a (*SecretHandler, *gorm.DB) pre-seeded with an
// admin user and two secret versions ready for diffing.
func newDiffHandlerS36(t *testing.T) (*SecretHandler, *gorm.DB, uint) {
	t.Helper()
	cs, db := freshCoreS36WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	sid := seedVersionDiffFixtureS36(t, db)
	return h, db, sid
}

// ── DiffSecretVersions: no user context → 401 ────────────────────────────────

func TestDiffSecretVersions_NoUserCtx_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/100/versions/1/diff/2", nil),
		"id", fmt.Sprintf("%d", sid), "from", "1", "to", "2",
	)
	// deliberately NO user context injected
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── DiffSecretVersions: bad "id" param → 400 ─────────────────────────────────

func TestDiffSecretVersions_BadID_S36(t *testing.T) {
	h, _, _ := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/notanumber/versions/1/diff/2", nil),
		"id", "notanumber", "from", "1", "to", "2",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// ── DiffSecretVersions: bad "from" param → 400 ───────────────────────────────

func TestDiffSecretVersions_BadFrom_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/bad/diff/2", sid), nil),
		"id", fmt.Sprintf("%d", sid), "from", "bad", "to", "2",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// ── DiffSecretVersions: from <= 0 → 400 ──────────────────────────────────────

func TestDiffSecretVersions_FromZero_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/0/diff/2", sid), nil),
		"id", fmt.Sprintf("%d", sid), "from", "0", "to", "2",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DiffSecretVersions: bad "to" param → 400 ─────────────────────────────────

func TestDiffSecretVersions_BadTo_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/bad", sid), nil),
		"id", fmt.Sprintf("%d", sid), "from", "1", "to", "bad",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// ── DiffSecretVersions: to <= 0 → 400 ────────────────────────────────────────

func TestDiffSecretVersions_ToZero_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/0", sid), nil),
		"id", fmt.Sprintf("%d", sid), "from", "1", "to", "0",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DiffSecretVersions: not found → 404 ──────────────────────────────────────

// TestDiffSecretVersions_NotFound_S36 exercises the "not found" error branch by
// requesting a version number that does not exist in the DB.
func TestDiffSecretVersions_NotFound_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/99", sid), nil),
		"id", fmt.Sprintf("%d", sid), "from", "1", "to", "99",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── DiffSecretVersions: validation error ("must differ") → 400 ───────────────

// TestDiffSecretVersions_SameVersions_S36 exercises the validation error branch
// by requesting from==to (core returns "must differ" → 400).
func TestDiffSecretVersions_SameVersions_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/1", sid), nil),
		"id", fmt.Sprintf("%d", sid), "from", "1", "to", "1",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DiffSecretVersions: generic internal error → 500 ─────────────────────────

// TestDiffSecretVersions_InternalError_S36 exercises the default 500 branch by
// temporarily switching the i18n locale to French so error messages (e.g.
// "Secret non trouvé") do not contain "not found", bypassing the 404 branch and
// falling through to the 500 default.
func TestDiffSecretVersions_InternalError_S36(t *testing.T) {
	// Switch i18n locale to French for this test so "Secret non trouvé" is used.
	// ResetForTesting + InitializeForTesting restores English at the end.
	loc := i18n.GetLocalizer()
	loc.SetLanguage("fr")
	defer loc.SetLanguage("en")

	cs, db := freshCoreS36WithAdmin(t)
	// Close the DB so GetSecret returns a storage error.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/versions/1/diff/2", nil),
		"id", "1", "from", "1", "to", "2",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── DiffSecretVersions: happy path → 200 ─────────────────────────────────────

// TestDiffSecretVersions_HappyPath_S36 exercises the success branch: valid
// secret with two existing versions → 200 with expected fields.
func TestDiffSecretVersions_HappyPath_S36(t *testing.T) {
	h, _, sid := newDiffHandlerS36(t)
	r := withUserCtx(withChiParam3_S36(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions/1/diff/2", sid), nil),
		"id", fmt.Sprintf("%d", sid), "from", "1", "to", "2",
	))
	w := httptest.NewRecorder()
	h.DiffSecretVersions(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "secret_id")
	assert.Contains(t, body, "changes")
}
