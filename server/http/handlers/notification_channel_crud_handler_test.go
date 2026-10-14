// notification_channel_crud_handler_test.go — unit-level handler tests for the
// notification-channel CRUD endpoints (List, Create, Get, Update, Delete).
// These tests call the handler methods directly (without a router) to cover
// branches that the full-router tests in server/http/ leave uncovered:
//
//   - Create: u == nil → 401
//   - Create: body.Enabled != nil (explicit enabled=true/false value)
//   - Get:    not-found path
//   - Update: bad JSON body
//   - Delete: not-found path
//   - isValidationError helper
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// freshNCCore opens a unique in-memory SQLite DB migrated for notification channels
// and returns a ready-to-use KeyorixCore.
func freshNCCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_nc_crud_")
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
		&models.NotificationChannel{},
	))
	return ncCore(db)
}

// ncCore builds the KeyorixCore these handler tests drive. The webhook URL
// validator is stubbed to accept: these tests exercise the CRUD handlers, not
// the SSRF guard (core's own tests cover validateWebhookURL), and the real
// validator resolves example.com over the network, so with no DNS the tests
// failed 400 for reasons unrelated to what they assert. Same stub as
// newNotifChannelHandler.
func ncCore(db *gorm.DB) *core.KeyorixCore {
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	cs.SetWebhookURLValidator(func(_ string) error { return nil })
	return cs
}

// freshNCCoreWithChannel opens a DB, migrates, seeds one channel, and returns
// the core together with the seeded channel's ID.
func freshNCCoreWithChannel(t *testing.T) (*core.KeyorixCore, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_nc_crud_ch_")
	require.NoError(t, db.AutoMigrate(
		&models.User{},
		&models.AuditEvent{},
		&models.NotificationChannel{},
	))
	// URLEnc, not URL (#2433): URL is gorm:"-" (not a persisted column) -- a raw
	// db.Create setting only URL would silently persist no URL at all, and
	// UpdateNotificationChannel (which TestNCUpdate_Success below drives) would
	// then decrypt an empty URLEnc, failing webhook URL validation on any
	// update that doesn't itself touch "url".
	//
	// Wrapped with the plaintext format tag (#2468), not the bare bytes: url_enc
	// is self-describing now, and a raw URL there is an unrecognised format byte
	// that the read path correctly refuses. This core has no encryptor wired, so
	// plaintext-tagged is exactly what its own write path would have produced.
	ch := &models.NotificationChannel{
		Name:    "test-channel",
		Type:    "webhook",
		URLEnc:  ports.WrapNotificationChannelURL(ports.NotificationChannelURLTagPlaintext, []byte("https://example.com/hook")),
		Enabled: true,
	}
	require.NoError(t, db.Create(ch).Error)
	return ncCore(db), ch.ID
}

// ── Create ────────────────────────────────────────────────────────────────────

// TestNCCreate_NoAuth exercises the u == nil → 401 branch in Create.
func TestNCCreate_NoAuth(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"name": "hook", "type": "webhook", "url": "https://example.com"})
	// No withUserCtx — user context is absent.
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNCCreate_EnabledExplicit exercises the body.Enabled != nil branch (line 89-91)
// where the caller explicitly provides "enabled": true in the request body.
func TestNCCreate_EnabledExplicit(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	enabled := true
	body, _ := json.Marshal(map[string]any{
		"name":    "explicit-enabled",
		"type":    "webhook",
		"url":     "https://example.com/hook",
		"enabled": enabled,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, true, data["enabled"])
}

// TestNCCreate_EnabledExplicitFalse exercises body.Enabled != nil with enabled=false.
// Note: GORM's default:true on the Enabled column means the DB sets true even when
// the struct carries false (zero value), so the response reflects the DB value (true).
// The goal of this test is to verify the body.Enabled != nil branch is taken without
// error, not to assert the persisted boolean value.
func TestNCCreate_EnabledExplicitFalse(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	enabled := false
	body, _ := json.Marshal(map[string]any{
		"name":    "disabled-channel",
		"type":    "webhook",
		"url":     "https://example.com/hook",
		"enabled": enabled,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	// The handler must succeed (201) even when enabled=false is explicitly provided.
	assert.Equal(t, http.StatusCreated, w.Code)
}

// ── Get ───────────────────────────────────────────────────────────────────────

// TestNCGet_NotFound exercises the strings.Contains(err.Error(), channelNotFound) → 404
// branch inside Get.
func TestNCGet_NotFound(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.Get(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── Update ────────────────────────────────────────────────────────────────────

// TestNCUpdate_BadJSON exercises the json.Decode error → 400 branch in Update.
func TestNCUpdate_BadJSON(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader([]byte("not-json")))),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNCUpdate_NotFound exercises the channelNotFound → 404 branch in Update.
func TestNCUpdate_NotFound(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"events": "anomaly.detected"})
	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))),
		"id", "9999",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestNCUpdate_ValidationError exercises the isValidationError → 400 branch in Update.
func TestNCUpdate_ValidationError(t *testing.T) {
	t.Parallel()
	cs, chanID := freshNCCoreWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	// Set type to an invalid value → validation error.
	body, _ := json.Marshal(map[string]any{"type": "fax"})
	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))),
		"id", fmt.Sprintf("%d", chanID),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Delete ────────────────────────────────────────────────────────────────────

// TestNCDelete_NotFound exercises the channelNotFound → 404 branch in Delete.
func TestNCDelete_NotFound(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.Delete(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── List ──────────────────────────────────────────────────────────────────────

// TestNCList_Empty exercises the List handler with an empty store — verifies the
// happy path that returns 200 with an empty channels array.
func TestNCList_Empty(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	channels := data["channels"].([]any)
	assert.Empty(t, channels)
}

// TestNCList_WithChannel verifies List returns the seeded channel in the response.
func TestNCList_WithChannel(t *testing.T) {
	t.Parallel()
	cs, _ := freshNCCoreWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	channels := data["channels"].([]any)
	assert.Len(t, channels, 1)
}

// TestNCList_StorageError exercises the error path in List when storage fails.
func TestNCList_StorageError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_nc_list_err_")
	// No AutoMigrate — table missing to force a real DB error.
	cs := ncCore(db)
	h := NewNotificationChannelHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Create additional branches ─────────────────────────────────────────────────

// TestNCCreate_BadJSON exercises the json.Decode error → 400 path in Create.
func TestNCCreate_BadJSON(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not-json"))))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNCCreate_EnabledOmitted exercises the else branch (ch.Enabled = true) when
// the "enabled" field is absent from the request body.
func TestNCCreate_EnabledOmitted(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	// Omit "enabled" — body.Enabled will be nil, taking the else branch.
	body, _ := json.Marshal(map[string]any{
		"name": "omitted-enabled",
		"type": "webhook",
		"url":  "https://example.com/hook",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestNCCreate_ValidationError exercises the isValidationError → 400 path in Create
// (e.g., bad channel type).
func TestNCCreate_ValidationError(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{
		"name": "fax-channel",
		"type": "fax",
		"url":  "https://example.com",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNCCreate_StorageError exercises the InternalError path in Create when
// storage returns a non-validation error.
func TestNCCreate_StorageError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_nc_create_err_")
	// No AutoMigrate — table missing to force a real DB error on create.
	cs := ncCore(db)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{
		"name": "hook",
		"type": "webhook",
		"url":  "https://example.com/hook",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Create(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Get additional branches ────────────────────────────────────────────────────

// TestNCGet_BadID exercises the parseUintParam failure → 400 path in Get.
func TestNCGet_BadID(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "not-a-number",
	)
	w := httptest.NewRecorder()
	h.Get(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNCGet_StorageError exercises the InternalError path in Get (error is not "not found").
func TestNCGet_StorageError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_nc_get_err_")
	// Migrate the table so it exists, then close the connection to cause a real error.
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}))
	ch := &models.NotificationChannel{Name: "ch", Type: "webhook", URL: "https://x.com", Enabled: true}
	require.NoError(t, db.Create(ch).Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", ch.ID),
	)
	w := httptest.NewRecorder()
	h.Get(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestNCGet_Success exercises the happy path in Get (200 + channel data).
func TestNCGet_Success(t *testing.T) {
	t.Parallel()
	cs, chanID := freshNCCoreWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", chanID),
	)
	w := httptest.NewRecorder()
	h.Get(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "test-channel", data["name"])
}

// ── Update additional branches ────────────────────────────────────────────────

// TestNCUpdate_BadID exercises the parseUintParam failure → 400 path in Update.
func TestNCUpdate_BadID(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"events": "anomaly.detected"})
	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))),
		"id", "not-a-number",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNCUpdate_StorageError exercises the InternalError path in Update (error is neither
// not-found nor validation).
func TestNCUpdate_StorageError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_nc_upd_err_")
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}))
	ch := &models.NotificationChannel{Name: "ch", Type: "webhook", URL: "https://x.com", Enabled: true}
	require.NoError(t, db.Create(ch).Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"events": "anomaly.detected"})
	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))),
		"id", fmt.Sprintf("%d", ch.ID),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestNCUpdate_Success exercises the happy path in Update (200 + updated data).
func TestNCUpdate_Success(t *testing.T) {
	t.Parallel()
	cs, chanID := freshNCCoreWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	body, _ := json.Marshal(map[string]any{"events": "secret.rotated"})
	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))),
		"id", fmt.Sprintf("%d", chanID),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Update(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "secret.rotated", data["events"])
}

// ── Delete additional branches ────────────────────────────────────────────────

// TestNCDelete_BadID exercises the parseUintParam failure → 400 path in Delete.
func TestNCDelete_BadID(t *testing.T) {
	t.Parallel()
	cs := freshNCCore(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)),
		"id", "not-a-number",
	)
	w := httptest.NewRecorder()
	h.Delete(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNCDelete_StorageError exercises the InternalError path in Delete (error is not "not found").
func TestNCDelete_StorageError(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kx_nc_del_err_")
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}))
	ch := &models.NotificationChannel{Name: "ch", Type: "webhook", URL: "https://x.com", Enabled: true}
	require.NoError(t, db.Create(ch).Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)),
		"id", fmt.Sprintf("%d", ch.ID),
	)
	w := httptest.NewRecorder()
	h.Delete(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestNCDelete_Success exercises the happy path in Delete (200 + deleted:true).
func TestNCDelete_Success(t *testing.T) {
	t.Parallel()
	cs, chanID := freshNCCoreWithChannel(t)
	h := NewNotificationChannelHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/", nil)),
		"id", fmt.Sprintf("%d", chanID),
	)
	w := httptest.NewRecorder()
	h.Delete(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, true, data["deleted"])
}

// #2779: a duplicate channel name is a client error with a message naming the conflict,
// not a 500 telling the operator to contact support. Real unique index (AutoMigrate'd
// in-memory SQLite through the production LocalStorage), so the driver's own error text
// is what the mapping has to cope with.
func TestNCCreate_DuplicateNameIs409(t *testing.T) {
	t.Parallel()
	h := NewNotificationChannelHandler(freshNCCore(t))
	create := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"name": "ops-alerts", "type": "email", "email": "ops@example.com"})
		req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.Create(w, req)
		return w
	}
	require.Equal(t, http.StatusCreated, create().Code)

	w := create()
	require.Equal(t, http.StatusConflict, w.Code, "response body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "already exists")
	assert.NotContains(t, w.Body.String(), "contact support")
	assert.NotContains(t, w.Body.String(), "UNIQUE", "the raw driver error must not reach the client")
}
