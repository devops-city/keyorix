// notification_channels_handler_test.go — handler-level integration tests for
// the notification channel CRUD endpoints (feat/notification-channels).
// All routes live under /api/v1/notification-channels and are gated on
// system.write (admin only).
package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newNotificationChannelCore replicates newTestCore's full AutoMigrate list and
// also migrates &models.NotificationChannel{} so the notification-channel
// handler tests have a database that matches the real production schema.
func newNotificationChannelCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	err := db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.ShareRecord{},
		&models.AuditEvent{},
		&models.Session{},
		&models.Project{},
		&models.Environment{},
		&models.Permission{},
		&models.RolePermission{},
		&models.SystemMetadata{},
		&models.LoginAttempt{},
		&models.PasswordHistory{},
		&models.PersonalAccessToken{},
		&models.Tag{},
		&models.SecretTag{},
		&models.ProjectInvitation{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.Notification{},
		&models.SetupToken{},
		&models.ProjectMembership{},
		&models.MFASecret{},
		&models.MFARecoveryCode{},
		&models.MFAChallenge{},
		&models.SecretDependency{},
		&models.MachineIdentity{},
		&models.MachineIdentityCredential{},
		&models.MachineIdentityRole{},
		&models.MachineIdentityOIDCBinding{},
		&models.WebAuthnCredential{},
		&models.WebAuthnSession{},
		&models.LegalHold{},
		&models.AccessReviewCampaign{},
		&models.AccessReviewItem{},
		&models.BreakGlassActivation{},
		&models.RiskException{},
		&models.SoDPolicy{},
		&models.ConnectRefGrant{},
		&models.AnomalyAlert{},
		&models.AccessRequest{},
		&models.AccessRequestApproval{},
		&models.SSOLoginState{},
		&models.SchedulerLockLease{},
		&models.SecretACL{},
		&models.AnomalyConfigRecord{},
		&models.NotificationChannel{},
		&models.StatsSnapshot{},
		&models.DeploymentStatsSnapshot{},
	)
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// notificationChannelTestSetup is a convenience helper that initialises i18n,
// builds a core, mints an admin token, and starts a real httptest.Server. It
// returns the server and the admin bearer token. Cleanup is registered with t.
func notificationChannelTestSetup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c := newNotificationChannelCore(t)
	c.SetWebhookURLValidator(func(_ string) error { return nil })
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, token
}

// TestNotificationChannelList_Empty verifies that an admin GET on the list
// endpoint returns 200 with a "data" field that wraps an empty channels array.
func TestNotificationChannelList_Empty(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body, "data")

	// The handler wraps the list as {"channels": [...]} inside "data".
	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "data must be an object")
	channels, ok := data["channels"].([]any)
	require.True(t, ok, "data.channels must be an array")
	assert.Empty(t, channels)
}

// TestNotificationChannelCreate_Webhook verifies that POSTing a valid webhook
// channel returns 201 with the created record in response data (including an id).
func TestNotificationChannelCreate_Webhook(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload := map[string]any{
		"name":   "ops-hook",
		"type":   "webhook",
		"url":    "https://hook.example.com",
		"events": "anomaly.detected",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var respBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	data, ok := respBody["data"].(map[string]any)
	require.True(t, ok, "data must be an object")
	assert.NotNil(t, data["id"], "created channel must have an id")
	assert.Equal(t, "ops-hook", data["name"])
	assert.Equal(t, "webhook", data["type"])
	assert.Equal(t, "https://hook.example.com", data["url"])
	assert.Equal(t, "anomaly.detected", data["events"])
}

// TestNotificationChannelCreate_InvalidType verifies that POSTing a channel
// with an unsupported type returns 400.
func TestNotificationChannelCreate_InvalidType(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload := map[string]any{
		"name": "fax-channel",
		"type": "fax",
		"url":  "https://fax.example.com",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestNotificationChannelCreate_WebhookMissingURL verifies that creating a
// webhook channel without a URL returns 400.
func TestNotificationChannelCreate_WebhookMissingURL(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload := map[string]any{
		"name": "no-url-hook",
		"type": "webhook",
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestNotificationChannelDelete verifies the delete-then-get-404 flow:
// create a channel, DELETE it (→ 200), then GET it (→ 404).
func TestNotificationChannelDelete(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	// Create a channel to delete.
	createPayload, err := json.Marshal(map[string]any{
		"name":   "to-delete",
		"type":   "webhook",
		"url":    "https://delete.example.com",
		"events": "secret.rotated",
	})
	require.NoError(t, err)

	createReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels", bytes.NewReader(createPayload))
	require.NoError(t, err)
	createReq.Header.Set("Authorization", "Bearer "+token)
	createReq.Header.Set("Content-Type", "application/json")

	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	defer func() { _ = createResp.Body.Close() }()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var createBody map[string]any
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	data, ok := createBody["data"].(map[string]any)
	require.True(t, ok)
	// id comes back as a JSON number (float64 when decoded into interface{}).
	idFloat, ok := data["id"].(float64)
	require.True(t, ok, "id must be a number")
	id := int(idFloat)

	// DELETE the channel.
	delReq, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/notification-channels/"+itoa(id), nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+token)

	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	defer func() { _ = delResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, delResp.StatusCode)

	// GET must now return 404.
	getReq, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels/"+itoa(id), nil)
	require.NoError(t, err)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	defer func() { _ = getResp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

// TestNotificationChannels_Unauthenticated verifies that the list endpoint
// returns 401 when no Authorization header is present.
func TestNotificationChannels_Unauthenticated(t *testing.T) {
	srv, _ := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels", nil)
	require.NoError(t, err)
	// Deliberately omit the Authorization header.

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestNotificationChannelCreate_BadJSON verifies that a malformed JSON body returns 400.
func TestNotificationChannelCreate_BadJSON(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestNotificationChannelList_WithChannels verifies that a non-empty list is returned correctly.
func TestNotificationChannelList_WithChannels(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	createPayload, err := json.Marshal(map[string]any{
		"name": "list-test", "type": "slack", "url": "https://hooks.slack.com/test",
	})
	require.NoError(t, err)
	createReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(createPayload))
	require.NoError(t, err)
	createReq.Header.Set("Authorization", "Bearer "+token)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	_ = createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	listReq, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels", nil)
	require.NoError(t, err)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	require.NoError(t, err)
	defer func() { _ = listResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, listResp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	channels := data["channels"].([]any)
	assert.Len(t, channels, 1)
}

// TestNotificationChannelGet_Found verifies that GET /{id} returns the channel.
func TestNotificationChannelGet_Found(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	createPayload, err := json.Marshal(map[string]any{
		"name": "get-test", "type": "webhook", "url": "https://hook.example.com",
	})
	require.NoError(t, err)
	createReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(createPayload))
	require.NoError(t, err)
	createReq.Header.Set("Authorization", "Bearer "+token)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	var createBody map[string]any
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	_ = createResp.Body.Close()
	id := int(createBody["data"].(map[string]any)["id"].(float64))

	getReq, err := http.NewRequest(http.MethodGet,
		srv.URL+"/api/v1/notification-channels/"+itoa(id), nil)
	require.NoError(t, err)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	defer func() { _ = getResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)
}

// TestNotificationChannelUpdate_Success verifies that PUT updates the channel.
func TestNotificationChannelUpdate_Success(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	createPayload, err := json.Marshal(map[string]any{
		"name": "upd-test", "type": "webhook", "url": "https://original.example.com",
	})
	require.NoError(t, err)
	createReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(createPayload))
	require.NoError(t, err)
	createReq.Header.Set("Authorization", "Bearer "+token)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	var createBody map[string]any
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	_ = createResp.Body.Close()
	id := int(createBody["data"].(map[string]any)["id"].(float64))

	updatePayload, err := json.Marshal(map[string]any{"events": "secret.rotated"})
	require.NoError(t, err)
	updateReq, err := http.NewRequest(http.MethodPut,
		srv.URL+"/api/v1/notification-channels/"+itoa(id),
		bytes.NewReader(updatePayload))
	require.NoError(t, err)
	updateReq.Header.Set("Authorization", "Bearer "+token)
	updateReq.Header.Set("Content-Type", "application/json")
	updateResp, err := http.DefaultClient.Do(updateReq)
	require.NoError(t, err)
	defer func() { _ = updateResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, updateResp.StatusCode)
}

// TestNotificationChannelUpdate_NotFound verifies that PUT on a non-existent channel returns 404.
func TestNotificationChannelUpdate_NotFound(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	updatePayload, err := json.Marshal(map[string]any{"events": "anomaly.detected"})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut,
		srv.URL+"/api/v1/notification-channels/9999",
		bytes.NewReader(updatePayload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestNotificationChannelUpdate_BadJSON verifies that a malformed PUT body returns 400.
func TestNotificationChannelUpdate_BadJSON(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodPut,
		srv.URL+"/api/v1/notification-channels/1",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestNotificationChannelDelete_NotFound verifies that deleting a non-existent channel returns 404.
func TestNotificationChannelDelete_NotFound(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodDelete,
		srv.URL+"/api/v1/notification-channels/9999", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// itoa converts an int to its decimal string representation. Used to build URL
// path segments without importing strconv or fmt in every test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// ── broken-DB helpers ─────────────────────────────────────────────────────────

// newBrokenNotificationChannelCore returns a *core.KeyorixCore backed by an
// in-memory SQLite DB that does NOT have the notification_channels table, so
// all notification-channel storage calls return a real DB error (not "not found").
func newBrokenNotificationChannelCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	// Full migration first (needed for auth to work), then drop only the NC table.
	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	err := db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.ShareRecord{},
		&models.AuditEvent{},
		&models.Session{},
		&models.Project{},
		&models.Environment{},
		&models.Permission{},
		&models.RolePermission{},
		&models.SystemMetadata{},
		&models.LoginAttempt{},
		&models.PasswordHistory{},
		&models.PersonalAccessToken{},
		&models.Tag{},
		&models.SecretTag{},
		&models.ProjectInvitation{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.Notification{},
		&models.SetupToken{},
		&models.ProjectMembership{},
		&models.MFASecret{},
		&models.MFARecoveryCode{},
		&models.MFAChallenge{},
		&models.SecretDependency{},
		&models.MachineIdentity{},
		&models.MachineIdentityCredential{},
		&models.MachineIdentityRole{},
		&models.MachineIdentityOIDCBinding{},
		&models.WebAuthnCredential{},
		&models.WebAuthnSession{},
		&models.LegalHold{},
		&models.AccessReviewCampaign{},
		&models.AccessReviewItem{},
		&models.BreakGlassActivation{},
		&models.RiskException{},
		&models.SoDPolicy{},
		&models.ConnectRefGrant{},
		&models.AnomalyAlert{},
		&models.AccessRequest{},
		&models.AccessRequestApproval{},
		&models.SSOLoginState{},
		&models.SchedulerLockLease{},
		&models.SecretACL{},
		&models.AnomalyConfigRecord{},
		// Intentionally omit &models.NotificationChannel{} so the table is absent.
		&models.StatsSnapshot{},
		&models.DeploymentStatsSnapshot{},
	)
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_project_memberships_active "+
		"ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_legal_holds_active "+
		"ON legal_holds (released) WHERE released = false").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_break_glass_active_project_user "+
		"ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	cs.SetWebhookURLValidator(func(_ string) error { return nil })
	return cs
}

// notificationChannelBrokenDBSetup builds a server backed by a DB that lacks
// the notification_channels table so every storage call returns a hard error.
func notificationChannelBrokenDBSetup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c := newBrokenNotificationChannelCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, token
}

// ── storage-error (500) path tests ────────────────────────────────────────────

// TestNotificationChannelList_StorageError verifies that when ListNotificationChannels
// returns a DB error (non-not-found) the List handler returns 500.
func TestNotificationChannelList_StorageError(t *testing.T) {
	srv, token := notificationChannelBrokenDBSetup(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestNotificationChannelCreate_StorageError verifies that when validation
// passes but CreateNotificationChannel returns a non-validation DB error the
// Create handler returns 500.
func TestNotificationChannelCreate_StorageError(t *testing.T) {
	srv, token := notificationChannelBrokenDBSetup(t)

	payload, err := json.Marshal(map[string]any{
		"name": "hook",
		"type": "webhook",
		"url":  "https://hook.example.com",
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestNotificationChannelCreate_EnabledDefaultsTrue verifies that when the
// request body omits the "enabled" field the channel is created with Enabled=true.
func TestNotificationChannelCreate_EnabledDefaultsTrue(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	// Explicitly omit the "enabled" key.
	payload, err := json.Marshal(map[string]any{
		"name":   "no-enabled-field",
		"type":   "webhook",
		"url":    "https://hook.example.com",
		"events": "anomaly.detected",
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	assert.Equal(t, true, data["enabled"], "enabled must default to true when omitted from request")
}

// TestNotificationChannelGet_StorageError verifies that a non-not-found DB
// error on Get returns 500.
func TestNotificationChannelGet_StorageError(t *testing.T) {
	srv, token := notificationChannelBrokenDBSetup(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/notification-channels/1", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestNotificationChannelUpdate_ValidationError verifies that an update body
// that triggers core validation (e.g., invalid type) returns 400.
func TestNotificationChannelUpdate_ValidationError(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	// First create a valid channel.
	createPayload, err := json.Marshal(map[string]any{
		"name": "valid-hook",
		"type": "webhook",
		"url":  "https://hook.example.com",
	})
	require.NoError(t, err)
	createReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(createPayload))
	require.NoError(t, err)
	createReq.Header.Set("Authorization", "Bearer "+token)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	var createBody map[string]any
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	_ = createResp.Body.Close()
	id := int(createBody["data"].(map[string]any)["id"].(float64))

	// Update with an invalid type — triggers core validation error → 400.
	updatePayload, err := json.Marshal(map[string]any{"type": "fax"})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut,
		srv.URL+"/api/v1/notification-channels/"+itoa(id),
		bytes.NewReader(updatePayload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestNotificationChannelUpdate_StorageError verifies that a non-not-found DB
// error on Update returns 500.
func TestNotificationChannelUpdate_StorageError(t *testing.T) {
	srv, token := notificationChannelBrokenDBSetup(t)

	payload, err := json.Marshal(map[string]any{"events": "anomaly.detected"})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/notification-channels/1",
		bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestNotificationChannelDelete_StorageError verifies that a non-not-found DB
// error on Delete returns 500.
func TestNotificationChannelDelete_StorageError(t *testing.T) {
	srv, token := notificationChannelBrokenDBSetup(t)

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/notification-channels/1", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestNotificationChannelGet_NotFound verifies that GET on a non-existent id
// returns 404.
func TestNotificationChannelGet_NotFound(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	req, err := http.NewRequest(http.MethodGet,
		srv.URL+"/api/v1/notification-channels/9999", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestNotificationChannelCreate_Email verifies creating an email-type channel.
func TestNotificationChannelCreate_Email(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload, err := json.Marshal(map[string]any{
		"name":  "email-ops",
		"type":  "email",
		"email": "ops@example.com",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data := body["data"].(map[string]any)
	assert.Equal(t, "email", data["type"])
	assert.Equal(t, "ops@example.com", data["email"])
}

// TestNotificationChannelCreate_Teams verifies creating a teams-type channel.
func TestNotificationChannelCreate_Teams(t *testing.T) {
	srv, token := notificationChannelTestSetup(t)

	payload, err := json.Marshal(map[string]any{
		"name": "teams-alerts",
		"type": "teams",
		"url":  "https://outlook.office.com/webhook/abc",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/notification-channels",
		bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}
