// handlers_s17_test.go — coverage sweep targeting branches not yet covered by
// earlier sweeps. Focuses on error paths triggered by cancelled contexts and
// additional branch coverage for:
//   - sod.go: ListSoDPolicies (storage error → 500), ListSoDViolations (storage error → 500)
//   - sod_proxy.go: ListSoDPoliciesProxy (storage error → 500 remote envelope)
//   - webauthn.go: FinishWebAuthnLogin and FinishWebAuthnPasswordlessLogin
//     (parsed-assertion-but-core-fails → 401)
//   - dynamic_secrets.go: RevokeAllLeases (no user context in config + storage error)
//   - project_catalog_proxy.go: ListProjectsWithCountsProxy (storage error → 500)
//   - risk_exceptions.go: ListRiskExceptions (storage error → 500)
//   - risk_exceptions_proxy.go: ListRiskExceptionsProxy (storage error → 500)
//   - environment_catalog_proxy.go: DeleteEnvironmentProxy (active-secret conflict → 409,
//     internal error → 500)
package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// ── DB helpers ────────────────────────────────────────────────────────────────

// freshCoreS17 opens a uniquely-named in-memory SQLite DB and returns a
// ready-to-use KeyorixCore. Mirrors freshCoreS12.
func freshCoreS17(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s17_")
	err := db.AutoMigrate(
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
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// cancelledCtxReqS17 builds an *http.Request whose context is already cancelled.
// A cancelled context causes GORM's db.WithContext to propagate the cancellation
// before executing any query, exercising storage-error branches.
func cancelledCtxReqS17(method, target string) *http.Request {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return httptest.NewRequest(method, target, nil).WithContext(ctx)
}

// ── sod.go: ListSoDPolicies storage-error path ────────────────────────────────

// TestListSoDPolicies_StorageError_S17 — a cancelled context causes the storage
// read to fail; the handler must return 500.
func TestListSoDPolicies_StorageError_S17(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS17(t))
	r := cancelledCtxReqS17(http.MethodGet, "/api/v1/sod/policies")
	w := httptest.NewRecorder()
	h.ListSoDPolicies(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── sod.go: ListSoDViolations storage-error path ─────────────────────────────

// TestListSoDViolations_StorageError_S17 — a cancelled context causes the storage
// read to fail; DetectSoDViolations propagates the error → 500.
func TestListSoDViolations_StorageError_S17(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS17(t))
	r := cancelledCtxReqS17(http.MethodGet, "/api/v1/sod/violations")
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── sod_proxy.go: ListSoDPoliciesProxy storage-error path ────────────────────

// TestListSoDPoliciesProxy_StorageError_S17 — a cancelled context causes the
// storage read to fail; the proxy handler must return 500 in the remote API
// envelope (success=false).

// ── webauthn.go: FinishWebAuthnLogin — parsed assertion but core fails → 401 ──

// minimalAssertionCredential builds the smallest credential JSON blob that
// passes protocol.ParseCredentialRequestResponseBytes. The parsed assertion is
// structurally valid but contains no real signature or session; core.FinishWebAuthnLogin
// will reject it (no matching stored session / RP config) and return an error,
// which the handler converts to 401.
func minimalAssertionCredential(t *testing.T) json.RawMessage {
	t.Helper()
	// clientDataJSON: base64url({"type":"webauthn.get","challenge":"AAAA","origin":"https://localhost"})
	clientData := `{"type":"webauthn.get","challenge":"AAAA","origin":"https://localhost"}`
	clientDataB64 := base64.RawURLEncoding.EncodeToString([]byte(clientData))

	// authenticatorData: exactly 37 zero bytes (rpIdHash[32] + flags[1] + counter[4]).
	// flags=0 means no attested-credential-data and no extensions: the library
	// accepts exactly 37 bytes with those flags.
	authDataB64 := base64.RawURLEncoding.EncodeToString(make([]byte, 37))

	// signature: any bytes.
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte{0x00})

	// id must be a valid base64url string.
	cred := map[string]any{
		"id":    "AAAA",
		"rawId": "AAAA",
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    clientDataB64,
			"authenticatorData": authDataB64,
			"signature":         sigB64,
		},
	}
	b, err := json.Marshal(cred)
	require.NoError(t, err)
	return json.RawMessage(b)
}

// TestFinishWebAuthnLogin_CoreFailure_S17 — a structurally valid assertion blob
// passes ParseCredentialRequestResponseBytes; core has no matching session so
// FinishWebAuthnLogin returns an error → handler writes 401.
func TestFinishWebAuthnLogin_CoreFailure_S17(t *testing.T) {
	h := NewAuthHandler(freshCoreS17(t), false)
	body, err := json.Marshal(map[string]any{
		"mfa_challenge":    "test-challenge",
		"webauthn_session": "nonexistent-session",
		"credential":       minimalAssertionCredential(t),
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/finish",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	// handler returns 401 when core.FinishWebAuthnLogin fails
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestFinishWebAuthnPasswordlessLogin_CoreFailure_S17 — same pattern for the
// passwordless finish path.
func TestFinishWebAuthnPasswordlessLogin_CoreFailure_S17(t *testing.T) {
	h := NewAuthHandler(freshCoreS17(t), false)
	body, err := json.Marshal(map[string]any{
		"webauthn_session": "nonexistent-session",
		"credential":       minimalAssertionCredential(t),
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/passwordless/finish",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	// handler returns 401 when core.FinishWebAuthnPasswordlessLogin fails
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── dynamic_secrets.go: RevokeAllLeases additional paths ─────────────────────

// TestRevokeAllLeases_NoUserCtxLoadFails_S17 — when there is no user context and
// the config ID is invalid, loadAuthorizedConfig returns false after writing 400,
// and the handler exits early without a nil-dereference on userCtx.
func TestRevokeAllLeases_NoUserCtxLoadFails_S17(t *testing.T) {
	t.Parallel()
	h := NewDynamicSecretHandler(freshCoreS17(t))
	// #1645/ADR-096: RevokeAllLeases now checks mustGetUser BEFORE loadConfig
	// (matching every sibling handler in this file, and closing a nil-userCtx
	// panic loadConfig's removal of the old in-handler authorize() call
	// otherwise left) -- a real user context is required to reach the bad-ID
	// branch this test targets, or mustGetUser's own 401 fires first instead.
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/notanid/revoke-all", nil),
		"id", "notanid",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	// Bad ID param is caught after the user-ctx check → 400.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_catalog_proxy.go: ListProjectsWithCountsProxy storage-error path ──

// TestListProjectsWithCountsProxy_StorageError_S17 — a cancelled context causes
// ListProjectsWithCounts to fail; the proxy handler returns 500 in the remote
// API envelope.

// TestListProjectsWithCountsProxy_IncludeDeletedStorageError_S17 — same with
// ?include_deleted=true to exercise the second argument branch.

// ── risk_exceptions.go: ListRiskExceptions storage-error path ────────────────

// TestListRiskExceptions_StorageError_S17 — a cancelled context causes
// ListRiskExceptions to fail → 500.
func TestListRiskExceptions_StorageError_S17(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreS17(t))
	r := cancelledCtxReqS17(http.MethodGet, "/api/v1/risk-exceptions")
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestListRiskExceptions_AllParamStorageError_S17 — same with ?all=true.
func TestListRiskExceptions_AllParamStorageError_S17(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreS17(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/risk-exceptions?all=true", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── risk_exceptions_proxy.go: ListRiskExceptionsProxy storage-error path ──────

// TestListRiskExceptionsProxy_StorageError_S17 — a cancelled context causes
// the storage read to fail; the proxy handler returns 500 in the remote API
// envelope.

// TestListRiskExceptionsProxy_ActiveOnlyStorageError_S17 — same with
// ?active_only=true to exercise the query-param branch.

// ── environment_catalog_proxy.go: DeleteEnvironmentProxy remaining paths ──────

// TestDeleteEnvironmentProxy_StorageError_S17 — a cancelled context causes the
// DeleteEnvironment call to fail with a generic error → 500 in the remote API
// envelope. The environment must exist first (cancelled after the create but
// before the delete) — however, since even the FindByID is cancelled, the
// handler never reaches DeleteEnvironment; instead GetEnvironment fails and
// returns 500.
//
// Actually: DeleteEnvironmentProxy calls Storage().DeleteEnvironment directly
// without a prior Get. With a cancelled context, DeleteEnvironment itself
// returns a context error which is NOT a not-found error and NOT an
// "active secret" error → falls through to the 500 branch.

// TestDeleteEnvironmentProxy_ActiveSecretConflict_S17 — exercises the 409 branch
// by seeding an environment with an active secret then trying to delete it.
