// secret_read_aggregation_handler_test.go — tests for GET /api/v1/secrets/{id}/read-summary.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// newSecretReadAggCore opens a fresh in-memory SQLite DB with all tables needed
// by the read-aggregation handler and returns the core + raw DB for seeding.
func newSecretReadAggCore(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhdlr_readagg_")
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
		&models.Role{},
		&models.UserRole{},
		&models.Permission{},
		&models.RolePermission{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.SecretACL{},
	))
	// #G10: GetSecretReadSummary now self-authorizes (secrets.manage); withUserCtx's
	// UserID 1 is granted global admin so these handler tests keep exercising the glue
	// logic (param parsing, status-code mapping), not authorization.
	role := &models.Role{Name: "admin", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: role.ID, ProjectID: 0, EnvironmentID: 0}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seedReadAuditEvent inserts a "secret.read" audit event for a given secret and user.
func seedReadAuditEvent(t *testing.T, db *gorm.DB, secretID, userID uint, at time.Time) {
	t.Helper()
	evt := &models.AuditEvent{
		EventType:    "secret.read",
		UserID:       &userID,
		SecretNodeID: &secretID,
		EventTime:    at,
	}
	success := true
	evt.Success = &success
	require.NoError(t, db.Create(evt).Error)
}

// ── 401 Unauthorized ──────────────────────────────────────────────────────────

func TestGetSecretReadSummary_Unauthorized(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── 400 invalid ID ────────────────────────────────────────────────────────────

func TestGetSecretReadSummary_BadID(t *testing.T) {
	h := newSecretHandlerS4(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "not-a-number"))
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── 400 since >= until ────────────────────────────────────────────────────────

func TestGetSecretReadSummary_InvalidTimeRange(t *testing.T) {
	c, _ := newSecretReadAggCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)

	now := time.Now().UTC()
	url := fmt.Sprintf("/?since=%s&until=%s",
		now.Format(time.RFC3339),
		now.Add(-time.Hour).Format(time.RFC3339),
	)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, url, nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── 200 happy path — no reads ─────────────────────────────────────────────────

func TestGetSecretReadSummary_NoReads(t *testing.T) {
	c, db := newSecretReadAggCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)
	// #G10: GetSecretReadSummary now resolves the secret to authorize against its scope,
	// so it must exist — matching the router's own RequireScopedSecretPermission gate,
	// which also requires the secret to exist before this handler is ever reached.
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "s1", IsSecret: true}).Error)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "total_reads")
	assert.Contains(t, w.Body.String(), "entries")
}

// ── 200 happy path — seeded reads ────────────────────────────────────────────

func TestGetSecretReadSummary_HappyPath(t *testing.T) {
	c, db := newSecretReadAggCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)

	secretID := uint(7)
	userID := uint(1)
	now := time.Now().UTC()
	require.NoError(t, db.Create(&models.SecretNode{ID: secretID, Name: "s7", IsSecret: true}).Error)

	// Seed 3 reads for user 1 in the last hour.
	for i := range 3 {
		seedReadAuditEvent(t, db, secretID, userID, now.Add(-time.Duration(i+1)*time.Minute))
	}

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", secretID)))
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "total_reads")
	// The 3 reads should be reflected.
	assert.Contains(t, body, `"secret_id":7`)
}

// TestGetSecretReadSummary_NotFound -- #1645: a nonexistent secret ID must
// surface 404, matching this endpoint's 7 read-metadata siblings (tags,
// versions, access-history/list/stats/audit-trail). AuthorizeSecretPrincipal
// resolves the secret before checking permission, so the wrapped error text
// is "not found", not "permission"/"not authorized" -- without the dedicated
// branch it fell through to a generic 500.
func TestGetSecretReadSummary_NotFound(t *testing.T) {
	c, _ := newSecretReadAggCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── limit=60 is silently capped at 50 by core ────────────────────────────────

func TestGetSecretReadSummary_LimitCappedAt50(t *testing.T) {
	c, db := newSecretReadAggCore(t)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "s1", IsSecret: true}).Error)

	// limit=60 in URL; core caps it at 50 transparently — still 200.
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/?limit=60", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── 500 storage error ─────────────────────────────────────────────────────────

// failingReadAggStore wraps LocalStorage and fails GetSecretReadCounts.
type failingReadAggStore struct {
	*store.LocalStorage
}

func (s *failingReadAggStore) GetSecretReadCounts(_ context.Context, _ uint, _, _ time.Time, _ int) ([]storage.SecretReadEntry, error) {
	return nil, errors.New("simulated read-agg outage")
}

func TestGetSecretReadSummary_StorageError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhdlr_readagg_fail_")
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))

	c := core.NewKeyorixCore(&failingReadAggStore{store.NewLocalStorage(db)})
	h, err := NewSecretHandler(c)
	require.NoError(t, err)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetSecretReadSummary(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
