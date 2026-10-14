package http

// SUSPEND-PURGE-1: suspending a secret with clear_synced_copies=true over the real
// router. The request flag is stored and audited, needs exactly the permission a
// plain suspend needs, and reaches the operator / k8s-sync as
// details.clear_synced_copies on the SecretSuspended refusal — to callers who may
// read the secret, never to ones who may not. Resume removes it.

import (
	"bytes"
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

type suspendCallResult struct {
	code int
	body string
}

func postJSON(w *guardParityWorld, path, token string, body any) suspendCallResult {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, path, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	return suspendCallResult{code: rec.Code, body: rec.Body.String()}
}

// refusalDetails reads a machine token's by-ref value read and returns the status,
// the error code and whether the refusal's details carry clear_synced_copies=true.
func refusalDetails(t *testing.T, w *guardParityWorld, token, ref string) (status int, code string, clear bool, raw string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	var env struct {
		Error   string `json:"error"`
		Details struct {
			ClearSyncedCopies bool `json:"clear_synced_copies"`
		} `json:"details"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return rec.Code, env.Error, env.Details.ClearSyncedCopies, rec.Body.String()
}

func TestSuspendSecret_ClearSyncedCopies_OverTheRouter(t *testing.T) {
	w := buildRefusalFamilyWorld(t)
	ctx := context.Background()
	newSecret := func(t *testing.T, name string) *models.SecretNode {
		t.Helper()
		sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("SUSPEND-PURGE-plaintext"),
			ProjectID: w.projID, EnvironmentID: w.envID,
			Type: "password", CreatedBy: "guardadmin", OwnerID: w.adminID,
		})
		require.NoError(t, err)
		return sec
	}
	stored := func(t *testing.T, id uint) models.SecretNode {
		t.Helper()
		var s models.SecretNode
		require.NoError(t, w.db.First(&s, id).Error)
		return s
	}
	ref := func(sec *models.SecretNode) string { return "guardproj/prod/" + sec.Name }
	suspendPath := func(sec *models.SecretNode) string { return fmt.Sprintf("/api/v1/secrets/%d/suspend", sec.ID) }
	resumePath := func(sec *models.SecretNode) string { return fmt.Sprintf("/api/v1/secrets/%d/resume", sec.ID) }

	t.Run("flag stored, audited, and visible to a permitted reader only", func(t *testing.T) {
		sec := newSecret(t, "purge-flag")
		res := postJSON(w, suspendPath(sec), w.tokens["session"], map[string]any{"reason": "leaked", "clear_synced_copies": true})
		require.Equal(t, http.StatusOK, res.code, res.body)
		assert.True(t, stored(t, sec.ID).SuspendClearSyncedCopies)

		var evs []models.AuditEvent
		require.NoError(t, w.db.Where("event_type = ? AND secret_node_id = ?", core.EventSecretSuspended, sec.ID).Find(&evs).Error)
		require.Len(t, evs, 1)
		assert.Contains(t, evs[0].Description, "clear_synced_copies=true")

		status, code, clear, raw := refusalDetails(t, w, w.tokens["machine"], ref(sec))
		assert.Equal(t, http.StatusConflict, status, raw)
		assert.Equal(t, "SecretSuspended", code, raw)
		assert.True(t, clear, "the operator must be able to see the choice: %s", raw)

		// An outsider learns neither the state nor the choice.
		status, code, clear, raw = refusalDetails(t, w, w.tokens["outsider-machine"], ref(sec))
		assert.NotEqual(t, http.StatusConflict, status, raw)
		assert.NotEqual(t, "SecretSuspended", code, raw)
		assert.False(t, clear, raw)
		assert.NotContains(t, raw, "clear_synced_copies")
	})

	t.Run("a plain suspend answers exactly as before", func(t *testing.T) {
		sec := newSecret(t, "purge-plain")
		res := postJSON(w, suspendPath(sec), w.tokens["session"], map[string]any{"reason": "maintenance"})
		require.Equal(t, http.StatusOK, res.code, res.body)
		assert.False(t, stored(t, sec.ID).SuspendClearSyncedCopies)

		status, code, clear, raw := refusalDetails(t, w, w.tokens["machine"], ref(sec))
		assert.Equal(t, http.StatusConflict, status, raw)
		assert.Equal(t, "SecretSuspended", code, raw)
		assert.False(t, clear, raw)
		assert.NotContains(t, raw, "details", "no details member unless the choice was made")
	})

	t.Run("same permission as suspend: a caller without it cannot set the flag", func(t *testing.T) {
		sec := newSecret(t, "purge-denied")
		for _, tok := range []string{"outsider-session", "outsider-machine"} {
			res := postJSON(w, suspendPath(sec), w.tokens[tok], map[string]any{"clear_synced_copies": true})
			assert.GreaterOrEqual(t, res.code, 400, "%s: %s", tok, res.body)
			assert.Less(t, res.code, 500, "%s: %s", tok, res.body)
			cur := stored(t, sec.ID)
			assert.Equal(t, core.SecretStatusActive, cur.Status, tok)
			assert.False(t, cur.SuspendClearSyncedCopies, tok)
		}
		// The reader-only machine token cannot suspend either (secrets.write is the gate).
		res := postJSON(w, suspendPath(sec), w.tokens["machine"], map[string]any{"clear_synced_copies": true})
		assert.GreaterOrEqual(t, res.code, 400, res.body)
		assert.Equal(t, core.SecretStatusActive, stored(t, sec.ID).Status)

		var n int64
		require.NoError(t, w.db.Model(&models.AuditEvent{}).Where("event_type = ? AND secret_node_id = ?", core.EventSecretSuspended, sec.ID).Count(&n).Error)
		assert.Zero(t, n, "a denied request is not a suspension")
	})

	t.Run("resume removes the choice and the value reads again", func(t *testing.T) {
		sec := newSecret(t, "purge-resume")
		require.Equal(t, http.StatusOK, postJSON(w, suspendPath(sec), w.tokens["session"], map[string]any{"clear_synced_copies": true}).code)
		res := postJSON(w, resumePath(sec), w.tokens["session"], nil)
		require.Equal(t, http.StatusOK, res.code, res.body)
		assert.False(t, stored(t, sec.ID).SuspendClearSyncedCopies)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+ref(sec), nil)
		req.Header.Set("Authorization", "Bearer "+w.tokens["machine"])
		rec := httptest.NewRecorder()
		w.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		// A later plain suspension does not inherit the old choice.
		require.Equal(t, http.StatusOK, postJSON(w, suspendPath(sec), w.tokens["session"], nil).code)
		_, _, clear, raw := refusalDetails(t, w, w.tokens["machine"], ref(sec))
		assert.False(t, clear, raw)
	})
}
