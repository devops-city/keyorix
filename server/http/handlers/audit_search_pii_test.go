// audit_search_pii_test.go — regression coverage for the redaction fix in
// audit_search.go: SearchAuditLogs used to send raw models.AuditEvent rows
// straight to JSON, leaking IPAddress and the tamper-evidence hash chain
// (PrevHash/EntryHash) that its sibling GetAuditLogs deliberately never
// includes. See docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
package handlers

import (
	"encoding/json"
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
	auditPIICanaryIP        = "203.0.113.88" // TEST-NET-3 (RFC 5737)
	auditPIICanaryPrevHash  = "canary-prev-hash-do-not-leak"
	auditPIICanaryEntryHash = "canary-entry-hash-do-not-leak"
)

func seedAuditEventWithHashChain(t *testing.T, db *gorm.DB, username string) *models.User {
	t.Helper()
	u := &models.User{Username: username, Email: username + "@example.com"}
	require.NoError(t, db.Create(u).Error)
	success := true
	e := &models.AuditEvent{
		EventType: "secret.read", UserID: &u.ID, IPAddress: auditPIICanaryIP,
		Success: &success, EventTime: time.Now(),
		PrevHash: auditPIICanaryPrevHash, EntryHash: auditPIICanaryEntryHash,
	}
	require.NoError(t, db.Create(e).Error)
	return u
}

// TestSearchAuditLogs_NeverLeaksIPOrHashChain is the core regression: the
// response must carry neither the raw IP nor the tamper-chain hashes, and
// must resolve the actor to a username, exactly like GetAuditLogs.
func TestSearchAuditLogs_NeverLeaksIPOrHashChain(t *testing.T) {
	cs, db := freshAuditSearchCore(t)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	u := seedAuditEventWithHashChain(t, db, "canary-user")

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/search", nil))
	w := httptest.NewRecorder()
	h.SearchAuditLogs(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.NotContains(t, body, auditPIICanaryIP)
	assert.NotContains(t, body, auditPIICanaryPrevHash)
	assert.NotContains(t, body, auditPIICanaryEntryHash)
	assert.NotContains(t, body, `"IPAddress"`)
	assert.NotContains(t, body, `"ip_address"`)
	assert.NotContains(t, body, `"PrevHash"`)
	assert.NotContains(t, body, `"EntryHash"`)
	assert.NotContains(t, body, `"prev_hash"`)
	assert.NotContains(t, body, `"entry_hash"`)

	var decoded struct {
		Data struct {
			Events []map[string]any `json:"events"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decoded))
	require.Len(t, decoded.Data.Events, 1)
	assert.Equal(t, u.Username, decoded.Data.Events[0]["actor"], "actor ID must be resolved to a username, like GetAuditLogs")
	assert.Equal(t, "secret.read", decoded.Data.Events[0]["event_type"])
}
