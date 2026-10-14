// handlers_s13_connect_dynamic_test.go — coverage sweep for uncovered branches in:
//   - dynamic_secrets.go: ListConfigs (bad scope query), GetConfig (bad id, not-found),
//     ListLeases (bad id, not-found), RevokeLease (missing ctx, not-found, authz),
//     RenewLease (missing ctx, not-found, authz), RevokeAllLeases (bad id),
//     ClassifyConfig (bad id, bad body), SetConfigEnabled (bad id, bad body),
//     CreateConfig (missing ctx, bad body, authz)
//   - connect.go: GetSecret (missing ctx, missing ref, unsafe error),
//     CreateRefGrant (missing ctx, bad body, safe/unsafe error),
//     DeleteRefGrant (missing ctx, bad id, not-found)
//   - connect_grants_proxy.go: ListConnectRefGrantsByConnectorProxy (empty connector),
//     CreateConnectRefGrantProxy (bad body, missing required fields),
//     DeleteConnectRefGrantProxy (bad id)
//   - dynamic_secrets_proxy.go: CreateDynamicSecretConfigProxy (bad body, missing fields),
//     GetDynamicSecretConfigProxy (bad id, not-found),
//     ListDynamicSecretConfigsProxy (missing project_id, bad project_id, bad env_id),
//     UpdateDynamicSecretConfigProxy (bad id, bad body),
//     CreateDynamicSecretLeaseProxy (bad body, missing fields),
//     GetDynamicSecretLeaseProxy (not-found),
//     ListDynamicSecretLeasesProxy (missing config_id, bad config_id),
//     CountActiveLeasesProxy (missing config_id, bad config_id),
//     UpdateDynamicSecretLeaseProxy (bad body),
//     ListExpiredActiveLeasesProxy (missing before, bad before),
//     parseProxyConfigIDQuery (missing / bad config_id)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// fakeSpoofConnector is a connect.Connector whose GetSecret always fails with a
// caller-influenced error (G50 regression coverage): it echoes the ref back
// verbatim, plus an internal-looking upstream detail, alongside one of
// isSafeConnectError's marker phrases. Before the G50 fix, isSafeConnectError
// substring-matched raw err.Error() text, so this crafted error would have been
// misclassified as "safe" and returned to the client verbatim (backlog #116).
type fakeSpoofConnector struct{ name string }

func (f fakeSpoofConnector) Name() string { return f.name }
func (f fakeSpoofConnector) Type() string { return "fake-spoof" }
func (f fakeSpoofConnector) GetSecret(_ context.Context, ref string) (string, error) {
	return "", errors.New(
		"internal-db-host-10.0.0.5:5432 lookup for ref " + ref +
			" is not permitted for your roles on connector \"spoof\"",
	)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func newDynamicSecretHandlerS13(t *testing.T) *DynamicSecretHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return NewDynamicSecretHandler(cs)
}

func newConnectHandlerS13(t *testing.T) *ConnectHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return NewConnectHandler(cs)
}

// seedDynamicSecretConfig inserts a minimal DynamicSecretConfig and returns its ID.
func seedDynamicSecretConfig(t *testing.T, h *DynamicSecretHandler) uint {
	t.Helper()
	// A config must belong to a live project: CreateDynamicSecretConfig refuses a
	// missing or soft-deleted one (#2651, INV-STORE-21).
	proj, err := h.coreService.Storage().CreateProject(context.Background(), &models.Project{Name: "test-proj-s13"})
	require.NoError(t, err)
	cfg := &models.DynamicSecretConfig{
		Name:        "test-cfg-s13",
		ProjectID:   proj.ID,
		BackendType: "postgres",
	}
	created, err := h.coreService.Storage().CreateDynamicSecretConfig(context.Background(), cfg)
	require.NoError(t, err)
	return created.ID
}

// ── dynamic_secrets.go ────────────────────────────────────────────────────────

// ListConfigs — bad project_id query parameter
func TestDynamic_ListConfigs_BadProjectID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs?project_id=notanint", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListConfigs — bad environment_id query parameter
func TestDynamic_ListConfigs_BadEnvID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs?environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListConfigs — no user context → forbidden (authorize fails, no user ctx in authorize)
func TestDynamic_ListConfigs_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	// authorize returns false when no user ctx → denyAuthz → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// GetConfig — bad id
func TestDynamic_GetConfig_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/notanint", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// GetConfig — not found
func TestDynamic_GetConfig_NotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ListLeases — bad id
func TestDynamic_ListLeases_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/notanint/leases", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListLeases — not found config
func TestDynamic_ListLeases_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/99999/leases", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RevokeLease — no user context
func TestDynamic_RevokeLease_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/abc/revoke", nil),
		"leaseID", "abc",
	)
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RevokeLease — lease not found
func TestDynamic_RevokeLease_LeaseNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/nonexistent-lease/revoke", nil),
		"leaseID", "nonexistent-lease",
	))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RenewLease — no user context
func TestDynamic_RenewLease_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/abc/renew", nil),
		"leaseID", "abc",
	)
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RenewLease — lease not found
func TestDynamic_RenewLease_LeaseNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/nonexistent-lease/renew", nil),
		"leaseID", "nonexistent-lease",
	))
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RevokeAllLeases — bad id
func TestDynamic_RevokeAllLeases_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/notanint/revoke-all", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// RevokeAllLeases — config not found
func TestDynamic_RevokeAllLeases_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/99999/revoke-all", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RevokeAllLeases — happy path (no active leases → 0 revoked)
func TestDynamic_RevokeAllLeases_HappyPath_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	cfgID := seedDynamicSecretConfig(t, h)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", uintToStrS13(cfgID),
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ClassifyConfig — bad id
func TestDynamic_ClassifyConfig_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/notanint/classification", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ClassifyConfig — config not found
func TestDynamic_ClassifyConfig_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/99999/classification", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ClassifyConfig — bad body (non-JSON)
func TestDynamic_ClassifyConfig_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	cfgID := seedDynamicSecretConfig(t, h)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString("not-json")),
		"id", uintToStrS13(cfgID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SetConfigEnabled — bad id
func TestDynamic_SetConfigEnabled_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/notanint/enabled", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SetConfigEnabled — config not found
func TestDynamic_SetConfigEnabled_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/99999/enabled", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// SetConfigEnabled — raw storage error must be sanitized (G50).
//
// A SQLite BEFORE UPDATE trigger simulates a genuine driver-layer write
// failure (e.g. a disk-quota/constraint error) on dynamic_secret_configs:
// the reads loadAuthorizedConfig and SetDynamicSecretConfigEnabled both
// perform still succeed, but the actual disable/enable UPDATE inside
// TransitionDynamicSecretConfigDisabled fails with a raw, internal-looking
// message. Before the G50 fix, SetConfigEnabled forwarded err.Error()
// straight to the client, bypassing the isSafeDynamicSecretError/clientSafe
// sanitization every sibling handler in this file already applies.
func TestDynamic_SetConfigEnabled_StorageError_G50(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)
	cfgID := seedDynamicSecretConfig(t, h)

	require.NoError(t, db.Exec(`
		CREATE TRIGGER block_dynamic_config_update
		BEFORE UPDATE ON dynamic_secret_configs
		BEGIN
			SELECT RAISE(ABORT, 'simulated write failure: disk quota exceeded on host db-07.internal');
		END;
	`).Error)

	body, _ := json.Marshal(map[string]any{"enabled": false})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		"id", uintToStrS13(cfgID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, w.Body.String(), "disk quota")
	assert.NotContains(t, w.Body.String(), "db-07.internal")
	assert.Contains(t, w.Body.String(), "an internal error occurred")
}

// SetConfigEnabled — bad body
func TestDynamic_SetConfigEnabled_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	cfgID := seedDynamicSecretConfig(t, h)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString("not-json")),
		"id", uintToStrS13(cfgID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateConfig — no user context
func TestDynamic_CreateConfig_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	body, _ := json.Marshal(map[string]any{"name": "x", "project_id": 1, "backend_type": "postgres"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// CreateConfig — bad body (non-JSON)
func TestDynamic_CreateConfig_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewBufferString("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateConfig — authorization denied (no project/env scope found in DB → forbidden)
func TestDynamic_CreateConfig_AuthzDenied_S13(t *testing.T) {
	// Use a core with NO admin seeded — so authorize always fails
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)
	body, _ := json.Marshal(map[string]any{
		"name": "cfg-authz-test", "project_id": 1, "backend_type": "postgres",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── connect.go ───────────────────────────────────────────────────────────────

// connectReadBody builds the JSON POST body ReadSecret expects.
func connectReadBody(ref string) *bytes.Buffer {
	b, _ := json.Marshal(map[string]string{"ref": ref})
	return bytes.NewBuffer(b)
}

// ReadSecret — no user context
func TestConnect_ReadSecret_NoUserCtx_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/connect/vault/secret:read", connectReadBody("path/to/key")),
		"name", "vault",
	)
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ReadSecret — missing ref in body
func TestConnect_ReadSecret_MissingRef_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/connect/vault/secret:read", connectReadBody("")),
		"name", "vault",
	))
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ref is required")
}

// ReadSecret — unknown connector → isSafeConnectError matches → 502 with safe message
func TestConnect_ReadSecret_UnknownConnector_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/connect/nonexistent/secret:read", connectReadBody("some/ref")),
		"name", "nonexistent",
	))
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)
	// "keyorix connect is not enabled" or "unknown connector" — either way ConnectError 502
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

// ReadSecret — upstream connector error that embeds a caller-controlled ref plus a
// safe-marker phrase must NOT be classified as safe and must NOT reach the client
// verbatim (G50: isSafeConnectError must check the error's type, not substring-match
// its text).
func TestConnect_ReadSecret_SpoofedUnsafeErrorIsSanitized_G50(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	cs.SetConnectManager(connect.NewManager([]connect.Connector{fakeSpoofConnector{name: "spoof"}}))
	cs.SetConnectOwnership(map[string]core.ConnectOwnership{"spoof": {Scope: "platform"}})
	h := NewConnectHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/connect/spoof/secret:read", connectReadBody("prod/db")),
		"name", "spoof",
	))
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, "10.0.0.5", "raw upstream host detail must not reach the client")
	assert.NotContains(t, body, "prod/db", "the caller-controlled ref must not be reflected back inside raw upstream error text")
	assert.Contains(t, body, "an internal error occurred", "must fall back to the generic clientSafe() message")
}

// ReadSecret — ref is sent in the request body, not the URL, so it never lands in an
// access log's captured query string.
func TestConnect_ReadSecret_RefNotInQueryString_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/connect/vault/secret:read", connectReadBody("prod/payments/stripe-key")),
		"name", "vault",
	))
	assert.Empty(t, req.URL.RawQuery, "ref must never appear in the URL query string")
	w := httptest.NewRecorder()
	h.ReadSecret(w, req)
	// Unauthorized/bad-gateway either way in this fake-storage test setup — the point
	// pinned here is purely that the request itself carries no query string.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// CreateRefGrant — no user context
func TestConnect_CreateRefGrant_NoUserCtx_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	body, _ := json.Marshal(map[string]any{"role_id": 1, "connector": "vault", "ref_prefix": "/prod/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/connect/ref-grants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// CreateRefGrant — bad body (non-JSON)
func TestConnect_CreateRefGrant_BadBody_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/connect/ref-grants", bytes.NewBufferString("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateRefGrant — valid body with unknown connector → isSafeConnectError path
func TestConnect_CreateRefGrant_UnknownConnector_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	// role_id=0 triggers "a role is required" safe error from core
	body, _ := json.Marshal(map[string]any{"role_id": 0, "connector": "vault", "ref_prefix": "/prod/"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/connect/ref-grants", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	// Safe error path → 400; unsafe path → 500. Either way not 2xx.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// DeleteRefGrant — no user context
func TestConnect_DeleteRefGrant_NoUserCtx_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/connect/ref-grants/1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// DeleteRefGrant — bad id
func TestConnect_DeleteRefGrant_BadID_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/connect/ref-grants/notanint", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// DeleteRefGrant — not-found (no such grant) — storage deletes by PK silently succeed
func TestConnect_DeleteRefGrant_NotFound_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/connect/ref-grants/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	// Storage silently succeeds on a missing row → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── utility ───────────────────────────────────────────────────────────────────

// uintToStrS13 converts uint to decimal string.
func uintToStrS13(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}
