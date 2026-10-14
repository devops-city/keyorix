package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newComplianceDigestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// The migration set GetCompliancePosture (which the digest builds on) reads from.
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.AuditEvent{}, &models.AnomalyAlert{}, &models.LegalHold{},
		&models.SoDPolicy{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{}, &models.AccessRequest{}, &models.RiskException{},
	))
	return db
}

func TestGetComplianceDigestHandler(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(newComplianceDigestDB(t))))

	t.Run("returns the on-demand digest title and body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/digest", nil)
		w := httptest.NewRecorder()
		h.GetComplianceDigest(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, `"title"`)
		assert.Contains(t, body, `"body"`)
		// The digest title + posture summary lines come through.
		assert.Contains(t, body, "Keyorix compliance digest")
		assert.Contains(t, body, "Controls:")
		assert.Contains(t, body, "Classification:")
	})
}

func TestSendComplianceDigestHandler(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(newComplianceDigestDB(t))))

	t.Run("returns sent=false when no notification sink is wired", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/digest/send", nil)
		w := httptest.NewRecorder()
		h.SendComplianceDigest(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, `"sent"`)
		// No notification sink is wired in the test core, so sent must be false.
		assert.Contains(t, body, `false`)
	})
}

// TestGetComplianceDigestHandler_Shape validates the response JSON shape.
func TestGetComplianceDigestHandler_Shape(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(newComplianceDigestDB(t))))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/digest", nil)
	w := httptest.NewRecorder()
	h.GetComplianceDigest(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	// Content-Type must be application/json.
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data.Title, "digest title must not be empty")
	assert.NotEmpty(t, resp.Data.Body, "digest body must not be empty")
}

// TestSendComplianceDigestHandler_Shape validates the sent field is a bool false.
func TestSendComplianceDigestHandler_Shape(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(newComplianceDigestDB(t))))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/digest/send", nil)
	w := httptest.NewRecorder()
	h.SendComplianceDigest(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Sent bool `json:"sent"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
	assert.False(t, resp.Data.Sent, "sent must be false when no notification sink is wired")
}

// TestGetComplianceDigestHandler_Idempotent calls the handler twice and confirms
// both calls return the same structure (no state mutation between calls).
func TestGetComplianceDigestHandler_Idempotent(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	h := NewDashboardHandler(core.NewKeyorixCore(store.NewLocalStorage(newComplianceDigestDB(t))))

	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/digest", nil)
		w := httptest.NewRecorder()
		h.GetComplianceDigest(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "call %d failed", i+1)
		assert.Contains(t, w.Body.String(), `"title"`)
	}
}
