// bulk_access_handler_test.go — handler-level integration tests for the bulk
// access-request approve/reject endpoints and the rejection-reason template CRUD
// endpoints (ADR-024 extension).
package http

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

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// bulkAccessTestSetup creates an httptest.Server backed by newTestCore (which
// already AutoMigrates RejectionReasonTemplate via models.AllTestModels), mints
// an admin token, and registers cleanup.
func bulkAccessTestSetup(t *testing.T) (*httptest.Server, *core.KeyorixCore, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, c, token
}

// ── Rejection-reason template tests ──────────────────────────────────────────

func TestRejectionReasonTemplates_CreateList(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	// POST — create a template.
	payload, err := json.Marshal(map[string]string{
		"name":   "not-qualified",
		"reason": "The requester does not meet the role requirements.",
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/rejection-reason-templates",
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
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	tmpl, ok := data["template"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "not-qualified", tmpl["name"])

	// GET — list templates.
	listReq, err := http.NewRequest(http.MethodGet,
		srv.URL+"/api/v1/rejection-reason-templates", nil)
	require.NoError(t, err)
	listReq.Header.Set("Authorization", "Bearer "+token)

	listResp, err := http.DefaultClient.Do(listReq)
	require.NoError(t, err)
	defer func() { _ = listResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, listResp.StatusCode)

	var listBody map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listBody))
	listData, ok := listBody["data"].(map[string]any)
	require.True(t, ok)
	templates, ok := listData["templates"].([]any)
	require.True(t, ok)
	assert.Len(t, templates, 1)
}

func TestRejectionReasonTemplates_Delete(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	// Create a template.
	payload, err := json.Marshal(map[string]string{"name": "to-del", "reason": "gone"})
	require.NoError(t, err)
	createReq, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/rejection-reason-templates", bytes.NewReader(payload))
	require.NoError(t, err)
	createReq.Header.Set("Authorization", "Bearer "+token)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	var createBody map[string]any
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&createBody))
	_ = createResp.Body.Close()
	tmpl := createBody["data"].(map[string]any)["template"].(map[string]any)
	id := int(tmpl["id"].(float64))

	// DELETE it.
	delReq, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/api/v1/rejection-reason-templates/%d", srv.URL, id), nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	defer func() { _ = delResp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode)
}

func TestRejectionReasonTemplates_DeleteNotFound(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	req, err := http.NewRequest(http.MethodDelete,
		srv.URL+"/api/v1/rejection-reason-templates/9999", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestRejectionReasonTemplates_CreateEmptyName(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	payload, err := json.Marshal(map[string]string{"name": "", "reason": "some reason"})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/rejection-reason-templates", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRejectionReasonTemplates_CreateEmptyReason(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	payload, err := json.Marshal(map[string]string{"name": "my-tmpl", "reason": ""})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/rejection-reason-templates", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRejectionReasonTemplates_CreateBadJSON(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/rejection-reason-templates",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRejectionReasonTemplates_DeleteInvalidID(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	req, err := http.NewRequest(http.MethodDelete,
		srv.URL+"/api/v1/rejection-reason-templates/notanumber", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRejectionReasonTemplates_Unauthenticated(t *testing.T) {
	srv, _, _ := bulkAccessTestSetup(t)

	req, err := http.NewRequest(http.MethodGet,
		srv.URL+"/api/v1/rejection-reason-templates", nil)
	require.NoError(t, err)
	// No Authorization header.
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ── Bulk approve tests ────────────────────────────────────────────────────────

func TestBulkApproveAccessRequests_EmptyIDs_Handler(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	payload, err := json.Marshal(map[string]any{"request_ids": []uint{}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-approve", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkApproveAccessRequests_BadJSON_Handler(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-approve",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkApproveAccessRequests_Unauthenticated(t *testing.T) {
	srv, _, _ := bulkAccessTestSetup(t)

	payload, err := json.Marshal(map[string]any{"request_ids": []uint{1}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-approve", bytes.NewReader(payload))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBulkApproveAccessRequests_WithIDs_Handler(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	// IDs that don't exist → BulkApprove returns a result with failures, not an error.
	payload, err := json.Marshal(map[string]any{"request_ids": []uint{9999}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-approve", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, data, "result")
}

// ── Bulk reject tests ─────────────────────────────────────────────────────────

func TestBulkRejectAccessRequests_EmptyIDs_Handler(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	payload, err := json.Marshal(map[string]any{
		"request_ids": []uint{},
		"reason":      "denied",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-reject", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkRejectAccessRequests_EmptyReason_Handler(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	payload, err := json.Marshal(map[string]any{
		"request_ids": []uint{1},
		"reason":      "",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-reject", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkRejectAccessRequests_BadJSON_Handler(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-reject",
		bytes.NewReader([]byte("not-json")))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBulkRejectAccessRequests_Unauthenticated(t *testing.T) {
	srv, _, _ := bulkAccessTestSetup(t)

	payload, err := json.Marshal(map[string]any{
		"request_ids": []uint{1},
		"reason":      "no",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-reject", bytes.NewReader(payload))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBulkRejectAccessRequests_WithIDs_Handler(t *testing.T) {
	srv, _, token := bulkAccessTestSetup(t)

	// IDs that don't exist → result has failures but no top-level error.
	payload, err := json.Marshal(map[string]any{
		"request_ids": []uint{9999},
		"reason":      "not qualified",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-reject", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, data, "result")
}

// ── broken-DB helpers (500-path tests) ───────────────────────────────────────

// newBulkAccessBrokenCore returns a *core.KeyorixCore backed by an in-memory
// SQLite DB that is missing the access_requests and rejection_reason_templates
// tables, so every bulk-access and template storage call returns a DB error.
func newBulkAccessBrokenCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db := sqlitetest.OpenWithConfig(t, "kxtest_", &gorm.Config{})
	// Migrate everything EXCEPT access_requests, access_request_approvals, and
	// rejection_reason_templates so those table calls return "no such table".
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
		&models.SSOLoginState{},
		&models.SchedulerLockLease{},
		&models.SecretACL{},
		&models.RotationPolicy{},
		&models.NotificationChannel{},
		&models.AnomalyConfigRecord{},
		&models.StatsSnapshot{},
		&models.DeploymentStatsSnapshot{},
		&models.CompliancePostureSnapshot{},
		&models.SecretAccessSchedule{},
		&models.HygieneTrendSnapshot{},
		&models.SecretVersionComment{},
		// Intentionally omit: AccessRequest, AccessRequestApproval, RejectionReasonTemplate
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// bulkAccessBrokenSetup builds a server backed by a DB that lacks the
// access_requests and rejection_reason_templates tables.
func bulkAccessBrokenSetup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	c := newBulkAccessBrokenCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, token
}

func TestBulkApproveAccessRequests_StorageError(t *testing.T) {
	srv, token := bulkAccessBrokenSetup(t)

	payload, err := json.Marshal(map[string]any{"request_ids": []uint{1}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-approve", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestBulkRejectAccessRequests_StorageError(t *testing.T) {
	srv, token := bulkAccessBrokenSetup(t)

	payload, err := json.Marshal(map[string]any{
		"request_ids": []uint{1},
		"reason":      "no",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/access-requests/bulk-reject", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestRejectionReasonTemplates_CreateStorageError(t *testing.T) {
	srv, token := bulkAccessBrokenSetup(t)

	payload, err := json.Marshal(map[string]string{"name": "x", "reason": "y"})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/api/v1/rejection-reason-templates", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestRejectionReasonTemplates_ListStorageError(t *testing.T) {
	srv, token := bulkAccessBrokenSetup(t)

	req, err := http.NewRequest(http.MethodGet,
		srv.URL+"/api/v1/rejection-reason-templates", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestRejectionReasonTemplates_DeleteStorageError(t *testing.T) {
	srv, token := bulkAccessBrokenSetup(t)

	req, err := http.NewRequest(http.MethodDelete,
		srv.URL+"/api/v1/rejection-reason-templates/1", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	// A "no such table" error from SQLite is not "not found" — expect 500.
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
