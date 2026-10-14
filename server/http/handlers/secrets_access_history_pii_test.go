// secrets_access_history_pii_test.go — regression coverage for the PII
// redaction fix in secrets_access_history.go: AccessHistory used to send raw
// models.SecretAccessLog rows straight to JSON, so any caller who merely held
// secrets.read on the secret (the route's own gate) could see IPAddress and
// UserAgent for EVERY OTHER USER who had read it. See
// docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	piiTestCanaryIP = "203.0.113.77" // TEST-NET-3 (RFC 5737), never a real address
	piiTestCanaryUA = "canary-user-agent/1.0"
)

// nonAdminProjectMemberRole seeds a role with ZERO permissions (not in
// adminRoleNames, BypassesPermissionChecks defaults to false) and grants it to
// userID at projectID's scope -- enough to satisfy IsProjectMember (live
// membership), so combined with the secret's OwnerID == userID,
// EnforceSecretReadPermission grants access via ownership alone. This user
// holds no role with audit.read (or any permission at all): the "any reader of
// the secret" caller AccessHistory's route gate actually allows in production.
func nonAdminProjectMemberRole(t *testing.T, db *gorm.DB, userID, projectID uint) {
	t.Helper()
	role := &models.Role{Name: fmt.Sprintf("no-perms-%d", userID), Description: "zero permissions, non-admin"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID, ProjectID: projectID}).Error)
}

// TestAccessHistory_NonPrivilegedReader_NeverSeesIPOrUserAgent is the core
// regression: a caller who holds secrets.read ONLY (via ownership, not any
// audit.read-bearing role) must not see another session's IP/user-agent.
func TestAccessHistory_NonPrivilegedReader_NeverSeesIPOrUserAgent(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "pii-proj-nonpriv"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "pii-env-nonpriv", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	const readerID = 2
	sec := &models.SecretNode{
		Name: "pii-sec-nonpriv", ProjectID: proj.ID, EnvironmentID: env.ID,
		OwnerID: readerID, Type: "static",
	}
	require.NoError(t, db.Create(sec).Error)
	nonAdminProjectMemberRole(t, db, readerID, proj.ID)
	logRow := &models.SecretAccessLog{
		SecretNodeID: sec.ID, AccessedBy: "someone-else", Action: "secret.read",
		IPAddress: piiTestCanaryIP, UserAgent: piiTestCanaryUA, AccessTime: time.Now(),
	}
	require.NoError(t, db.Create(logRow).Error)

	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtxID(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", sec.ID),
	), readerID, "reader")
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.NotContains(t, body, piiTestCanaryIP, "the canary IP must not appear in the response at all")
	assert.NotContains(t, body, piiTestCanaryUA, "the canary user-agent must not appear in the response at all")
	assert.NotContains(t, body, `"ip_address"`)
	assert.NotContains(t, body, `"IPAddress"`)
	assert.NotContains(t, body, `"user_agent"`)
	assert.NotContains(t, body, `"UserAgent"`)

	var decoded struct {
		Data struct {
			AccessLog []map[string]any `json:"access_log"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decoded))
	require.Len(t, decoded.Data.AccessLog, 1)
	assert.Equal(t, "someone-else", decoded.Data.AccessLog[0]["accessed_by"])
}

// TestAccessHistory_AuditReadCallerSeesIPAndUserAgent confirms the gate is a
// real gate, not just always-off: a caller who separately holds audit.read
// (the admin fixture's global bypass role) sees the full fields.
func TestAccessHistory_AuditReadCallerSeesIPAndUserAgent(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "pii-proj-admin"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "pii-env-admin", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	sec := &models.SecretNode{Name: "pii-sec-admin", ProjectID: proj.ID, EnvironmentID: env.ID, OwnerID: 1, Type: "static"}
	require.NoError(t, db.Create(sec).Error)
	logRow := &models.SecretAccessLog{
		SecretNodeID: sec.ID, AccessedBy: "someone-else", Action: "secret.read",
		IPAddress: piiTestCanaryIP, UserAgent: piiTestCanaryUA, AccessTime: time.Now(),
	}
	require.NoError(t, db.Create(logRow).Error)

	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", sec.ID),
	))
	w := httptest.NewRecorder()
	h.AccessHistory(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var decoded struct {
		Data struct {
			AccessLog []map[string]any `json:"access_log"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decoded))
	require.Len(t, decoded.Data.AccessLog, 1)
	assert.Equal(t, piiTestCanaryIP, decoded.Data.AccessLog[0]["ip_address"])
	assert.Equal(t, piiTestCanaryUA, decoded.Data.AccessLog[0]["user_agent"])
}
