package http

// SUSPEND-AUDIT-LOUD over the real router: a plain suspend answers 200 and blocks
// reads while the audit log refuses its secret.suspended row; an administrator sees
// the owed row in GET /api/v1/system/info (security.audit_owed), and the backfill
// writes it once the audit log recovers.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSuspendSecret_PlainSuspendAuditOwed_OverTheRouter(t *testing.T) {
	w := buildRefusalFamilyWorld(t)
	ctx := context.Background()
	sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "owed-plain", Value: []byte("OWED-plaintext"),
		ProjectID: w.projID, EnvironmentID: w.envID,
		Type: "password", CreatedBy: "guardadmin", OwnerID: w.adminID,
	})
	require.NoError(t, err)

	owed := func() (pending int64, failures uint64) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)
		req.Header.Set("Authorization", "Bearer "+w.tokens["session"])
		rec := httptest.NewRecorder()
		w.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var env struct {
			Data struct {
				Security struct {
					AuditOwed *struct {
						Pending  int64  `json:"pending"`
						Failures uint64 `json:"failures_since_start"`
					} `json:"audit_owed"`
				} `json:"security"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
		require.NotNil(t, env.Data.Security.AuditOwed, "an administrator must see audit_owed: %s", rec.Body.String())
		return env.Data.Security.AuditOwed.Pending, env.Data.Security.AuditOwed.Failures
	}
	suspendEvents := func() int64 {
		t.Helper()
		var n int64
		require.NoError(t, w.db.Model(&models.AuditEvent{}).
			Where("event_type = ? AND secret_node_id = ?", core.EventSecretSuspended, sec.ID).Count(&n).Error)
		return n
	}

	pending, failuresBefore := owed()
	require.Equal(t, int64(0), pending)

	require.NoError(t, w.db.Exec(fmt.Sprintf(
		`CREATE TRIGGER refuse_owed_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = '%s' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`,
		core.EventSecretSuspended)).Error)
	res := postJSON(w, fmt.Sprintf("/api/v1/secrets/%d/suspend", sec.ID), w.tokens["session"], map[string]any{"reason": "breach"})
	require.Equal(t, http.StatusOK, res.code, "revocation is never blocked by the audit log: %s", res.body)
	var stored models.SecretNode
	require.NoError(t, w.db.First(&stored, sec.ID).Error)
	assert.Equal(t, core.SecretStatusSuspended, stored.Status)
	assert.Zero(t, suspendEvents())

	pending, failures := owed()
	assert.Equal(t, int64(1), pending, "the administrator sees the missing row")
	assert.Equal(t, failuresBefore+1, failures)

	require.NoError(t, w.db.Exec(`DROP TRIGGER refuse_owed_audit`).Error)
	n, err := w.c.BackfillPendingAuditEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, int64(1), suspendEvents(), "written exactly once after recovery")
	pending, _ = owed()
	assert.Equal(t, int64(0), pending, "the warning clears once the row is written")
}
