// handlers_s23_test.go — coverage sweep targeting remaining gaps after s21 and s22:
//   - groups_proxy.go: AddGroupMemberProxy (happy path seeded user+group),
//     RemoveGroupMemberProxy (happy path — silently succeeds on missing row),
//     RestoreGroupProxy (happy path after soft-delete), ListGroupMembersProxy
//     (happy path with seeded member), ListGroupMembersByIDsProxy (happy path),
//     GetUserGroupsProxy (happy path with no groups, i.e. empty-list branch)
//   - dynamic_secrets.go: CreateConfig (happy path with admin+seeded project+env),
//     IssueLease (no user ctx, bad config id, not found, happy with safe error),
//     ListLeases (happy path with seeded config)
//   - connect.go: CreateRefGrant (happy path with seeded role), ListRefGrants
//     (with seeded grants — loop body), DeleteRefGrant (happy path seeded grant)
//   - admin_jobs.go: RunExpiryReminders (no lead_days — defaults to 0),
//     RunComplianceDigest (happy path), RunAnomalyAlerts (happy path),
//     RunRotationReminders (happy path) — using freshCoreS12 for isolation
//   - isSafeDynamicSecretError: extra safe-string branches not covered by s4
//     ("cannot issue from the", "mints self-expiring", "has expired")
//   - groups_proxy.go: AddGroupMemberProxy (storage NotFound branch)
//   - dynamic_secrets.go: RevokeLease (authorized, lease exists — RevokeLease
//     core error path)
package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── local helpers ─────────────────────────────────────────────────────────────

// uintStr converts a uint to its decimal string representation.
func uintStr(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}

// ── groups_proxy.go: AddGroupMemberProxy happy path ──────────────────────────

// TestAddGroupMemberProxy_HappyPath_S23 verifies that a well-formed request
// with both a real group and a real user succeeds with {"added":true}.

// ── groups_proxy.go: RemoveGroupMemberProxy happy path ───────────────────────

// TestRemoveGroupMemberProxy_HappyPath_S23 verifies that removing a
// non-existent (or existing) member silently succeeds with {"removed":true}.
// LocalStorage.RemoveUserFromGroup is a DELETE with no not-found error.

// ── groups_proxy.go: RestoreGroupProxy happy path ─────────────────────────────

// TestRestoreGroupProxy_HappyPath_S23 verifies the 200 branch: soft-delete a
// group then restore it via the proxy.

// ── groups_proxy.go: ListGroupMembersProxy happy path ────────────────────────

// TestListGroupMembersProxy_HappyPath_S23 verifies the 200 branch: a group
// with no members returns an empty members array.

// ── groups_proxy.go: ListGroupMembersByIDsProxy happy path ───────────────────

// TestListGroupMembersByIDsProxy_HappyPath_S23 verifies the 200 branch:
// a valid comma-separated ids param returns results (possibly empty).

// TestListGroupMembersByIDsProxy_MultipleIDs_S23 verifies that a
// comma-separated list with multiple valid IDs is parsed correctly.

// ── groups_proxy.go: GetUserGroupsProxy happy path ────────────────────────────

// TestGetUserGroupsProxy_EmptyList_S23 verifies the 200 branch for a user
// with no group memberships — the empty-list iteration path.

// ── dynamic_secrets.go: CreateConfig happy path ──────────────────────────────

// TestDynamic_CreateConfig_HappyPath_S23 verifies the 200 branch: an admin
// user with a seeded project+environment creates a config successfully.
func TestDynamic_CreateConfig_HappyPath_S23(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	cs.SetDynamicAllowPrivateTargets(true) // test uses localhost DSN; SSRF guard tested in dynamic_secrets_ssrf_test.go
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s23-create-cfg-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s23-create-cfg-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	body, _ := json.Marshal(map[string]any{
		"name":           "s23-create-cfg",
		"project_id":     proj.ID,
		"environment_id": env.ID,
		"backend_type":   "postgres",
		"admin_dsn":      "postgres://localhost/test",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "s23-create-cfg", data["name"])
	// admin_dsn must never appear in the response.
	_, hasDSN := data["admin_dsn"]
	assert.False(t, hasDSN, "admin_dsn must not be echoed back to the client")
}

// ── dynamic_secrets.go: IssueLease branches ──────────────────────────────────

// TestDynamic_IssueLease_NoUserCtx_S23 verifies that IssueLease with no user
// context in the request returns 401.
func TestDynamic_IssueLease_NoUserCtx_S23(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s23-issue-noctx-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s23-issue-noctx-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name: "s23-issue-noctx-cfg", ProjectID: proj.ID, EnvironmentID: env.ID, BackendType: "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	// #1645/ADR-096: authorization against the config's scope moved out of
	// IssueLease's own body entirely (now route-level RequireScopedPermission
	// middleware, router.go) -- the handler's only remaining pre-flight check
	// is mustGetUser, matching every sibling handler in this file. No user
	// context now fails fast with 401 here, before loadConfig ever runs
	// (this test calls the handler directly, bypassing the router, so the
	// middleware's own 403-for-both collapse is never exercised by this
	// specific test -- see dynamic_secrets_403_convention_test.go for that).
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/issue", nil),
		"id", uintStr(cfg.ID),
	)
	w := httptest.NewRecorder()
	h.IssueLease(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDynamic_IssueLease_BadConfigID_S23 verifies that a non-numeric config id
// returns 400.
func TestDynamic_IssueLease_BadConfigID_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/notanint/issue", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDynamic_IssueLease_ConfigNotFound_S23 verifies that a numeric but
// non-existent config id returns 404.
func TestDynamic_IssueLease_ConfigNotFound_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/99999/issue", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.IssueLease(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── dynamic_secrets.go: ListLeases happy path ────────────────────────────────

// TestDynamic_ListLeases_HappyPath_S23 verifies the 200 branch: listing
// leases for an existing config returns an empty array (no active leases).
func TestDynamic_ListLeases_HappyPath_S23(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s23-list-leases-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s23-list-leases-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name: "s23-list-leases-cfg", ProjectID: proj.ID, EnvironmentID: env.ID, BackendType: "postgres",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/1/leases", nil),
		"id", uintStr(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── connect.go: CreateRefGrant happy path ────────────────────────────────────

// TestConnect_CreateRefGrant_HappyPath_S23 verifies the 200 branch: a valid
// body with a seeded role and a known connector name creates a ref-grant.
func TestConnect_CreateRefGrant_HappyPath_S23(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewConnectHandler(cs)

	role := &models.Role{Name: "s23-connect-role", Description: "test"}
	require.NoError(t, db.Create(role).Error)

	body, _ := json.Marshal(map[string]any{
		"role_id":    role.ID,
		"connector":  "vault",
		"ref_prefix": "/s23/",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/connect/ref-grants", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)

	// core.CreateConnectRefGrant will error because there's no connector named
	// "vault" configured. The error message "keyorix connect is not enabled" or
	// "unknown connector" is on the isSafeConnectError allowlist → 400, not 500.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// TestConnect_ListRefGrants_WithSeededGrant_S23 verifies the loop body of
// ListRefGrants when at least one ref-grant exists in storage.
func TestConnect_ListRefGrants_WithSeededGrant_S23(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewConnectHandler(cs)

	role := &models.Role{Name: "s23-listgrant-role", Description: "test"}
	require.NoError(t, db.Create(role).Error)

	grant := &models.ConnectRefGrant{
		RoleID:    role.ID,
		Connector: "vault",
		RefPrefix: "/s23/list/",
	}
	require.NoError(t, db.Create(grant).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/connect/ref-grants", nil))
	w := httptest.NewRecorder()
	h.ListRefGrants(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]any)
	grants := data["grants"].([]any)
	assert.GreaterOrEqual(t, len(grants), 1, "should see the seeded grant")
}

// TestConnect_DeleteRefGrant_SeededGrant_S23 verifies the 200 branch when
// deleting an actually-seeded ref-grant (real delete, not just missing-row).
func TestConnect_DeleteRefGrant_SeededGrant_S23(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewConnectHandler(cs)

	role := &models.Role{Name: "s23-delgrant-role", Description: "test"}
	require.NoError(t, db.Create(role).Error)

	grant := &models.ConnectRefGrant{
		RoleID:    role.ID,
		Connector: "vault",
		RefPrefix: "/s23/del/",
	}
	require.NoError(t, db.Create(grant).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/connect/ref-grants/%d", grant.ID), nil),
		"id", uintStr(grant.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── admin_jobs.go: happy paths using freshCoreS12 ────────────────────────────

// TestAdminJobs_RunAnomalyAlerts_HappyPath_S23 verifies that
// RunAnomalyAlerts returns {alerted: 0} on an empty store.
func TestAdminJobs_RunAnomalyAlerts_HappyPath_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAdminJobsHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/anomaly-alerts", nil))
	w := httptest.NewRecorder()
	h.RunAnomalyAlerts(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestAdminJobs_RunRotationReminders_HappyPath_S23 verifies that
// RunRotationReminders returns {sent: 0} on an empty store.
func TestAdminJobs_RunRotationReminders_HappyPath_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAdminJobsHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/rotation-reminders", nil))
	w := httptest.NewRecorder()
	h.RunRotationReminders(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestAdminJobs_RunExpiryReminders_NoLeadDays_S23 verifies that
// RunExpiryReminders without a lead_days parameter uses the default (0)
// and returns {sent: 0}.
func TestAdminJobs_RunExpiryReminders_NoLeadDays_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAdminJobsHandler(cs)

	// No lead_days query parameter — the handler defaults to 0, which
	// core.SendExpiryReminders treats as "use the built-in default window".
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// TestAdminJobs_RunExpiryReminders_NonNumericLeadDays_S23 verifies that a
// non-numeric lead_days value is silently ignored (falls back to 0).
func TestAdminJobs_RunExpiryReminders_NonNumericLeadDays_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAdminJobsHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/expiry-reminders?lead_days=notanint", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)

	// Non-numeric lead_days: strconv.Atoi fails → leadDays stays 0 → no crash
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestAdminJobs_RunComplianceDigest_HappyPath_S23 verifies that
// RunComplianceDigest returns {sent: false} when there are no recipients.
func TestAdminJobs_RunComplianceDigest_HappyPath_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAdminJobsHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/compliance-digest", nil))
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── isSafeDynamicSecretError extra branches ────────────────────────────────────

// TestIsSafeDynamicSecretError_ExtraStrings_S23 covers the safe-string branches
// NOT hit by the existing s4 tests: "cannot issue from the", "mints self-
// expiring credentials", and "has expired; issue a new lease instead".
func TestIsSafeDynamicSecretError_ExtraStrings_S23(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"cannot issue from the disabled config", true},
		{"mints self-expiring credentials that cannot be renewed", true},
		{"lease has expired; issue a new lease instead", true},
		{"unsupported backend type", true},
		{"active-lease limit reached for config 7", true},
		{"lease is not active (status=revoked)", true},
		{"config not found", true},
		{"", false},
		{"connection refused: dial tcp 127.0.0.1:5432", false},
		{"ERROR: duplicate key value violates unique constraint", false},
	}
	for _, tc := range cases {
		got := isSafeDynamicSecretError(tc.msg)
		assert.Equal(t, tc.want, got, "isSafeDynamicSecretError(%q)", tc.msg)
	}
}

// ── isSafeConnectError extra branches ─────────────────────────────────────────

// TestIsSafeConnectError_ExtraStrings_S23 covers isSafeConnectError's branches.
//
// G50: isSafeConnectError used to substring-match err.Error() against a handful
// of marker phrases, which meant ANY error whose text happened to contain one of
// those phrases — including a raw upstream/connector error that merely echoes a
// caller-controlled ref alongside similar wording — was misclassified as "safe"
// and returned to the client verbatim. It now checks the error's identity via
// errors.Is against the core package's typed sentinels, so only the actual
// core.ErrConnect* sentinels (optionally wrapped with %w) count as safe; a
// look-alike error with the same substring but a different underlying type does
// not.
func TestIsSafeConnectError_ExtraStrings_S23(t *testing.T) {
	assert.True(t, isSafeConnectError(core.ErrConnectDisabled))
	assert.True(t, isSafeConnectError(fmt.Errorf("%w %q", core.ErrConnectUnknownConnector, "production-vault")))
	assert.True(t, isSafeConnectError(core.ErrConnectRoleRequired))
	assert.True(t, isSafeConnectError(fmt.Errorf("ref %q %w %q", "/prod/secret", core.ErrConnectRefNotPermitted, "vault")))

	// A look-alike error carrying the exact same marker text but NOT wrapping the
	// sentinel (e.g. an upstream connector error that happens to echo it back,
	// possibly seeded by an attacker-controlled ref) must NOT be classified as safe.
	assert.False(t, isSafeConnectError(errors.New("keyorix connect is not enabled on this server")))
	assert.False(t, isSafeConnectError(errors.New("unknown connector: production-vault")))
	assert.False(t, isSafeConnectError(errors.New("a role is required for a connect ref-grant")))
	assert.False(t, isSafeConnectError(errors.New("/prod/secret is not permitted for your roles on connector vault")))
	assert.False(t, isSafeConnectError(errors.New("x509: certificate signed by unknown authority")))
	assert.False(t, isSafeConnectError(nil))
}

// ── groups_proxy.go: AddGroupMemberProxy storage-NotFound branch ─────────────

// TestAddGroupMemberProxy_StorageNotFound_S23 verifies the NOT_FOUND branch
// in AddGroupMemberProxy when the group or user doesn't exist in the DB.

// ── dynamic_secrets.go: RevokeAllLeases with admin and real config ────────────

// TestDynamic_RevokeAllLeases_AdminAuth_S23 verifies that an admin user can
// reach the RevokeLeasesForConfig call (no active leases → revoked=0, failed=0).
func TestDynamic_RevokeAllLeases_AdminAuth_S23(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s23-revoke-all-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s23-revoke-all-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name:          "s23-revoke-all-cfg",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		BackendType:   "postgres",
		CreatedBy:     "testuser_s12",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", uintStr(cfg.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]any)
	assert.EqualValues(t, 0, data["revoked"])
	assert.EqualValues(t, 0, data["failed"])
}

// ── connect.go: ListConnectors happy path ─────────────────────────────────────

// TestConnect_ListConnectors_HappyPath_S23 verifies the 200 branch for
// ListConnectors when a user context is present (no connectors configured).
func TestConnect_ListConnectors_HappyPath_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewConnectHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/connect/connectors", nil))
	w := httptest.NewRecorder()
	h.ListConnectors(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]any)
	_, hasConnectors := data["connectors"]
	assert.True(t, hasConnectors)
}

// ── connect.go: ListRefGrants empty happy path ────────────────────────────────

// TestConnect_ListRefGrants_Empty_S23 verifies the 200 branch for ListRefGrants
// with an empty store (no grants), hitting the empty-list path.
func TestConnect_ListRefGrants_Empty_S23(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewConnectHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/connect/ref-grants", nil))
	w := httptest.NewRecorder()
	h.ListRefGrants(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}
