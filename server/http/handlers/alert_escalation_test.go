// alert_escalation_test.go — unit tests for AlertEscalationHandler exercised
// directly in the handlers package (not via the HTTP router).
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func newAlertEscalationHandlerDB(t *testing.T) (*AlertEscalationHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AlertEscalationPolicy{},
		&models.AnomalyAlert{},
		&models.NotificationChannel{},
	))
	return NewAlertEscalationHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

// ── isEscalationValidationError ───────────────────────────────────────────────

func TestIsEscalationValidationError(t *testing.T) {
	assert.True(t, isEscalationValidationError(fmt.Errorf("alert escalation policy name is required")))
	assert.True(t, isEscalationValidationError(fmt.Errorf("invalid min_severity %q", "x")))
	assert.True(t, isEscalationValidationError(fmt.Errorf("escalate_after_minutes must be positive")))
	assert.False(t, isEscalationValidationError(fmt.Errorf("record not found")))
	assert.False(t, isEscalationValidationError(fmt.Errorf("database error")))
}

// ── Create ─────────────────────────────────────────────────────────────────────

func TestAlertEscalationHandler_Create_NilUser(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"pol","min_severity":"high","escalate_after_minutes":30}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAlertEscalationHandler_Create_BadJSON(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`not json`)))
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAlertEscalationHandler_Create_ValidationError(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	// Empty name triggers core validation error.
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"","min_severity":"high","escalate_after_minutes":30}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAlertEscalationHandler_Create_Success(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	body := `{"name":"on-call","min_severity":"high","escalate_after_minutes":30,"channel_ids":"1,2","enabled":true}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, "on-call", d["name"])
}

func TestAlertEscalationHandler_Create_DefaultEnabled(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	// enabled not set → defaults to true
	body := `{"name":"default-enabled","min_severity":"medium","escalate_after_minutes":15}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, true, d["enabled"])
}

// ── List ───────────────────────────────────────────────────────────────────────

func TestAlertEscalationHandler_List_Empty(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.Empty(t, d["policies"])
}

func TestAlertEscalationHandler_List_WithRecords(t *testing.T) {
	h, db := newAlertEscalationHandlerDB(t)
	require.NoError(t, db.Create(&models.AlertEscalationPolicy{
		Name: "pol1", MinSeverity: "high", EscalateAfterMinutes: 30, Enabled: true,
	}).Error)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	pols, ok := d["policies"].([]any)
	require.True(t, ok)
	assert.Len(t, pols, 1)
}

// ── Get ────────────────────────────────────────────────────────────────────────

func TestAlertEscalationHandler_Get_NotFound(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAlertEscalationHandler_Get_Success(t *testing.T) {
	h, db := newAlertEscalationHandlerDB(t)
	pol := &models.AlertEscalationPolicy{Name: "get-me", MinSeverity: "low", EscalateAfterMinutes: 60, Enabled: true}
	require.NoError(t, db.Create(pol).Error)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", pol.ID))
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, "get-me", d["name"])
}

func TestAlertEscalationHandler_Get_InvalidID(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "abc")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Update ─────────────────────────────────────────────────────────────────────

func TestAlertEscalationHandler_Update_BadJSON(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`not json`))), "id", "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAlertEscalationHandler_Update_NotFound(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	body, _ := json.Marshal(map[string]any{"name": "new-name"})
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))), "id", "999")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAlertEscalationHandler_Update_ValidationError(t *testing.T) {
	h, db := newAlertEscalationHandlerDB(t)
	pol := &models.AlertEscalationPolicy{Name: "upd-pol", MinSeverity: "medium", EscalateAfterMinutes: 30, Enabled: true}
	require.NoError(t, db.Create(pol).Error)
	// min_severity to invalid value → validation error
	body, _ := json.Marshal(map[string]any{"min_severity": "extreme"})
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))), "id", fmt.Sprintf("%d", pol.ID))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAlertEscalationHandler_Update_Success(t *testing.T) {
	h, db := newAlertEscalationHandlerDB(t)
	pol := &models.AlertEscalationPolicy{Name: "before", MinSeverity: "low", EscalateAfterMinutes: 10, Enabled: true}
	require.NoError(t, db.Create(pol).Error)
	body, _ := json.Marshal(map[string]any{"name": "after"})
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))), "id", fmt.Sprintf("%d", pol.ID))
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, "after", d["name"])
}

// ── Delete ─────────────────────────────────────────────────────────────────────

func TestAlertEscalationHandler_Delete_NotFound(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)), "id", "999")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAlertEscalationHandler_Delete_Success(t *testing.T) {
	h, db := newAlertEscalationHandlerDB(t)
	pol := &models.AlertEscalationPolicy{Name: "del-me", MinSeverity: "low", EscalateAfterMinutes: 5, Enabled: true}
	require.NoError(t, db.Create(pol).Error)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)), "id", fmt.Sprintf("%d", pol.ID))
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── RunEscalation ─────────────────────────────────────────────────────────────

func TestAlertEscalationHandler_RunEscalation_NilUser(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RunEscalation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAlertEscalationHandler_RunEscalation_Success(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.RunEscalation(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.EqualValues(t, 0, d["evaluated"])
	assert.EqualValues(t, 0, d["escalated"])
}

// newAlertEscalationHandlerClosedDB returns a handler backed by a migrated but
// immediately-closed SQLite database, so that all storage calls return errors.
func newAlertEscalationHandlerClosedDB(t *testing.T) *AlertEscalationHandler {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AlertEscalationPolicy{},
		&models.AnomalyAlert{},
		&models.NotificationChannel{},
	))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return NewAlertEscalationHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

// ── Create internal error ──────────────────────────────────────────────────────

func TestAlertEscalationHandler_Create_InternalError(t *testing.T) {
	h := newAlertEscalationHandlerClosedDB(t)
	body := `{"name":"pol","min_severity":"high","escalate_after_minutes":30}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── List internal error ────────────────────────────────────────────────────────

func TestAlertEscalationHandler_List_InternalError(t *testing.T) {
	h := newAlertEscalationHandlerClosedDB(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Get internal error ─────────────────────────────────────────────────────────

func TestAlertEscalationHandler_Get_InternalError(t *testing.T) {
	h := newAlertEscalationHandlerClosedDB(t)
	// ID 1 doesn't exist but DB is closed — any non-"not found" error → 500.
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.Get(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Update invalid ID and internal error ──────────────────────────────────────

func TestAlertEscalationHandler_Update_InvalidID(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	body, _ := json.Marshal(map[string]any{"name": "x"})
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))), "id", "abc")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAlertEscalationHandler_Update_InternalError(t *testing.T) {
	h := newAlertEscalationHandlerClosedDB(t)
	body, _ := json.Marshal(map[string]any{"name": "x"})
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))), "id", "1")
	w := httptest.NewRecorder()
	h.Update(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Delete invalid ID and internal error ──────────────────────────────────────

func TestAlertEscalationHandler_Delete_InvalidID(t *testing.T) {
	h, _ := newAlertEscalationHandlerDB(t)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)), "id", "abc")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAlertEscalationHandler_Delete_InternalError(t *testing.T) {
	h := newAlertEscalationHandlerClosedDB(t)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.Delete(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── RunEscalation internal error ──────────────────────────────────────────────

func TestAlertEscalationHandler_RunEscalation_InternalError(t *testing.T) {
	h := newAlertEscalationHandlerClosedDB(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.RunEscalation(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
