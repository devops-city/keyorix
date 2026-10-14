package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newNotifChannelHandler(t *testing.T) (*NotificationChannelHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "nc_")
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}))
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	cs.SetWebhookURLValidator(func(_ string) error { return nil })
	return NewNotificationChannelHandler(cs), db
}

// ── List ──────────────────────────────────────────────────────────────────────

func TestNotifChannel_List_Empty(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notification-channels", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	channels, ok := d["channels"].([]any)
	require.True(t, ok)
	assert.Empty(t, channels)
}

func TestNotifChannel_List_WithChannels(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	require.NoError(t, db.Create(&models.NotificationChannel{
		Name: "slack-alerts", Type: "slack", URL: "https://hooks.slack.com/x", Enabled: true,
	}).Error)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notification-channels", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	channels, ok := d["channels"].([]any)
	require.True(t, ok)
	assert.Len(t, channels, 1)
	ch := channels[0].(map[string]any)
	assert.Equal(t, "slack-alerts", ch["name"])
	assert.Equal(t, "slack", ch["type"])
}

// ── Create ────────────────────────────────────────────────────────────────────

func TestNotifChannel_Create_Webhook(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	body := map[string]any{
		"name": "pagerduty-wh", "type": "webhook", "url": "https://events.pagerduty.com/x",
	}
	b, _ := json.Marshal(body)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, "pagerduty-wh", d["name"])
	assert.Equal(t, "webhook", d["type"])
}

func TestNotifChannel_Create_Email(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	body := map[string]any{
		"name": "ops-email", "type": "email", "email": "ops@example.com",
	}
	b, _ := json.Marshal(body)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
}

func TestNotifChannel_Create_EnabledDefault(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	// enabled field omitted → defaults to true
	body := map[string]any{
		"name": "teams-ch", "type": "teams", "url": "https://outlook.office.com/webhook/x",
	}
	b, _ := json.Marshal(body)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, true, d["enabled"])
}

func TestNotifChannel_Create_WithEvents(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	body := map[string]any{
		"name": "events-ch", "type": "slack", "url": "https://hooks.slack.com/y",
		"events": "secret.rotated,anomaly.detected",
	}
	b, _ := json.Marshal(body)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, "secret.rotated,anomaly.detected", d["events"])
}

func TestNotifChannel_Create_Unauthorized(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	b, _ := json.Marshal(map[string]any{"name": "x", "type": "slack", "url": "https://x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNotifChannel_Create_BadJSON(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels",
		bytes.NewReader([]byte("not-json"))))
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNotifChannel_Create_ValidationError_NoName(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	body := map[string]any{"name": "", "type": "slack", "url": "https://hooks.slack.com/z"}
	b, _ := json.Marshal(body)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNotifChannel_Create_ValidationError_InvalidType(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	body := map[string]any{"name": "bad-type", "type": "sms", "url": "https://example.com"}
	b, _ := json.Marshal(body)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Get ───────────────────────────────────────────────────────────────────────

func TestNotifChannel_Get_Found(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	ch := models.NotificationChannel{Name: "get-me", Type: "webhook", URL: "https://example.com", Enabled: true}
	require.NoError(t, db.Create(&ch).Error)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", itoa(ch.ID))
	w := httptest.NewRecorder()
	h.Get(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, "get-me", d["name"])
}

func TestNotifChannel_Get_NotFound(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "99999")
	w := httptest.NewRecorder()
	h.Get(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNotifChannel_Get_BadID(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "not-a-number")
	w := httptest.NewRecorder()
	h.Get(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Update ────────────────────────────────────────────────────────────────────

func TestNotifChannel_Update_Found(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	ch := models.NotificationChannel{Name: "update-me", Type: "slack", URL: "https://old.url", Enabled: true}
	require.NoError(t, db.Create(&ch).Error)

	body := map[string]any{"url": "https://new.url", "name": "update-me", "type": "slack"}
	b, _ := json.Marshal(body)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b))), "id", itoa(ch.ID))
	w := httptest.NewRecorder()
	h.Update(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestNotifChannel_Update_NotFound(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	body := map[string]any{"name": "x", "type": "slack", "url": "https://x"}
	b, _ := json.Marshal(body)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b))), "id", "99999")
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNotifChannel_Update_Unauthorized(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	ch := models.NotificationChannel{Name: "upd-noauth", Type: "webhook", URL: "https://x", Enabled: true}
	require.NoError(t, db.Create(&ch).Error)

	body := map[string]any{"name": "x"}
	b, _ := json.Marshal(body)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", itoa(ch.ID))
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNotifChannel_Update_BadJSON(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	ch := models.NotificationChannel{Name: "upd-bad", Type: "webhook", URL: "https://x", Enabled: true}
	require.NoError(t, db.Create(&ch).Error)

	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/x",
		bytes.NewReader([]byte("not-json")))), "id", itoa(ch.ID))
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNotifChannel_Update_ValidationError(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	ch := models.NotificationChannel{Name: "upd-valid", Type: "slack", URL: "https://x", Enabled: true}
	require.NoError(t, db.Create(&ch).Error)

	// set an invalid type → validation error (non-empty type gets applied, then fails validation)
	body := map[string]any{"type": "fax"}
	b, _ := json.Marshal(body)
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b))), "id", itoa(ch.ID))
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestNotifChannel_Delete_Found(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	ch := models.NotificationChannel{Name: "del-me", Type: "webhook", URL: "https://example.com", Enabled: true}
	require.NoError(t, db.Create(&ch).Error)

	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/x", nil)), "id", itoa(ch.ID))
	w := httptest.NewRecorder()
	h.Delete(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	d := decodeData(t, w)
	assert.Equal(t, true, d["deleted"])
}

func TestNotifChannel_Delete_NotFound(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/x", nil)), "id", "99999")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestNotifChannel_Delete_BadID(t *testing.T) {
	h, _ := newNotifChannelHandler(t)

	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodDelete, "/x", nil)), "id", "bad")
	w := httptest.NewRecorder()
	h.Delete(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNotifChannel_Delete_Unauthorized(t *testing.T) {
	h, db := newNotifChannelHandler(t)

	ch := models.NotificationChannel{Name: "del-noauth", Type: "webhook", URL: "https://x", Enabled: true}
	require.NoError(t, db.Create(&ch).Error)

	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", itoa(ch.ID))
	w := httptest.NewRecorder()
	h.Delete(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── isValidationError ─────────────────────────────────────────────────────────

func TestIsValidationError_True(t *testing.T) {
	assert.True(t, isValidationError(errors.New("notification channel name is required")))
	assert.True(t, isValidationError(errors.New("invalid notification channel type")))
}

func TestIsValidationError_False(t *testing.T) {
	assert.False(t, isValidationError(errors.New("record not found")))
	assert.False(t, isValidationError(errors.New("database error")))
}
