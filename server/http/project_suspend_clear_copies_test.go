package http

// FOLLOWUP-ENV-FREEZE: POST /projects/{id}/secrets/suspend-all takes the same
// clear_synced_copies choice as POST /secrets/{id}/suspend, over the real router: same
// permission (secrets.write on the project), one audit event with the choice and the
// count, the per-suspension marker on every affected secret (visible to the operator as
// details.clear_synced_copies on the SecretSuspended refusal), cleared by resume-all.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSuspendProjectSecrets_ClearSyncedCopies_OverTheRouter(t *testing.T) {
	w := buildRefusalFamilyWorld(t)
	ctx := context.Background()
	suspendAll := fmt.Sprintf("/api/v1/projects/%d/secrets/suspend-all", w.projID)
	resumeAll := fmt.Sprintf("/api/v1/projects/%d/secrets/resume-all", w.projID)

	newSecret := func(t *testing.T, name string) *models.SecretNode {
		t.Helper()
		sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("FREEZE-plaintext"),
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
	count := func(t *testing.T, eventType string) int64 {
		t.Helper()
		var n int64
		require.NoError(t, w.db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
		return n
	}
	// The world is shared across subtests: start each from an unfrozen project.
	thaw := func(t *testing.T) {
		t.Helper()
		require.Equal(t, http.StatusOK, postJSON(w, resumeAll, w.tokens["session"], nil).code)
	}

	t.Run("flag marks every affected secret, one project event, visible to the operator", func(t *testing.T) {
		thaw(t)
		a, b := newSecret(t, "freeze-a"), newSecret(t, "freeze-b")
		before := count(t, "secret.bulk_suspend_attempted")

		res := postJSON(w, suspendAll, w.tokens["session"], map[string]any{"reason": "breach", "clear_synced_copies": true})
		require.Equal(t, http.StatusOK, res.code, res.body)
		var env struct {
			Data struct {
				Suspended         int  `json:"suspended"`
				ClearSyncedCopies bool `json:"clear_synced_copies"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(res.body), &env))
		assert.GreaterOrEqual(t, env.Data.Suspended, 2)
		assert.True(t, env.Data.ClearSyncedCopies)

		for _, sec := range []*models.SecretNode{a, b} {
			s := stored(t, sec.ID)
			assert.Equal(t, core.SecretStatusSuspended, s.Status)
			assert.True(t, s.SuspendClearSyncedCopies, sec.Name)
			status, code, clear, raw := refusalDetails(t, w, w.tokens["machine"], "guardproj/prod/"+sec.Name)
			assert.Equal(t, http.StatusConflict, status, raw)
			assert.Equal(t, "SecretSuspended", code, raw)
			assert.True(t, clear, raw)
		}
		assert.Equal(t, before+1, count(t, "secret.bulk_suspend_attempted"), "exactly one project-level event")
		var ev models.AuditEvent
		require.NoError(t, w.db.Where("event_type = ?", "secret.bulk_suspend_attempted").Order("id DESC").First(&ev).Error)
		assert.Contains(t, ev.Description, "clear_synced_copies=true")
		assert.Contains(t, ev.Description, fmt.Sprintf("%d secret(s) targeted", env.Data.Suspended))
	})

	t.Run("a plain freeze answers as before, with no marker", func(t *testing.T) {
		thaw(t)
		sec := newSecret(t, "freeze-plain")
		res := postJSON(w, suspendAll, w.tokens["session"], map[string]any{"reason": "maintenance"})
		require.Equal(t, http.StatusOK, res.code, res.body)
		assert.NotContains(t, res.body, "clear_synced_copies")
		assert.False(t, stored(t, sec.ID).SuspendClearSyncedCopies)
		_, _, clear, raw := refusalDetails(t, w, w.tokens["machine"], "guardproj/prod/"+sec.Name)
		assert.False(t, clear, raw)
	})

	t.Run("same permission as project suspend: callers without it cannot set the flag", func(t *testing.T) {
		thaw(t)
		sec := newSecret(t, "freeze-denied")
		beforeBulk := count(t, "secret.bulk_suspend_attempted")
		beforeEach := count(t, core.EventSecretSuspended)
		for _, tok := range []string{"outsider-session", "outsider-machine", "machine"} {
			res := postJSON(w, suspendAll, w.tokens[tok], map[string]any{"clear_synced_copies": true})
			assert.GreaterOrEqual(t, res.code, 400, "%s: %s", tok, res.body)
			assert.Less(t, res.code, 500, "%s: %s", tok, res.body)
			cur := stored(t, sec.ID)
			assert.Equal(t, core.SecretStatusActive, cur.Status, tok)
			assert.False(t, cur.SuspendClearSyncedCopies, tok)
		}
		assert.Equal(t, beforeBulk, count(t, "secret.bulk_suspend_attempted"), "a denied request is not an attempt")
		assert.Equal(t, beforeEach, count(t, core.EventSecretSuspended))
	})

	t.Run("resume-all clears the marker and value reads work again", func(t *testing.T) {
		thaw(t)
		sec := newSecret(t, "freeze-resume")
		require.Equal(t, http.StatusOK, postJSON(w, suspendAll, w.tokens["session"], map[string]any{"clear_synced_copies": true}).code)
		require.True(t, stored(t, sec.ID).SuspendClearSyncedCopies)

		require.Equal(t, http.StatusOK, postJSON(w, resumeAll, w.tokens["session"], nil).code)
		s := stored(t, sec.ID)
		assert.Equal(t, core.SecretStatusActive, s.Status)
		assert.False(t, s.SuspendClearSyncedCopies)

		// A later plain freeze does not inherit the old choice.
		require.Equal(t, http.StatusOK, postJSON(w, suspendAll, w.tokens["session"], nil).code)
		_, _, clear, raw := refusalDetails(t, w, w.tokens["machine"], "guardproj/prod/"+sec.Name)
		assert.False(t, clear, raw)
	})

	// refuseAudit makes the audit store refuse rows of one event type (a trigger, so the
	// real storage path fails exactly as an unavailable audit store would) until cleanup.
	refuseAudit := func(t *testing.T, eventType string) {
		t.Helper()
		require.NoError(t, w.db.Exec(fmt.Sprintf(
			`CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_events WHEN NEW.event_type = '%s' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`,
			eventType)).Error)
		t.Cleanup(func() { require.NoError(t, w.db.Exec(`DROP TRIGGER IF EXISTS refuse_audit`).Error) })
	}
	activeOnly := func(t *testing.T) {
		t.Helper()
		require.NoError(t, w.db.Model(&models.SecretNode{}).Where("project_id = ?", w.projID).
			Updates(map[string]any{"status": core.SecretStatusActive, "suspend_clear_synced_copies": false}).Error)
	}

	t.Run("bulk audit event refused: 500, nothing suspended", func(t *testing.T) {
		thaw(t)
		a := newSecret(t, "freeze-bulkfail")
		refuseAudit(t, "secret.bulk_suspend_attempted")

		res := postJSON(w, suspendAll, w.tokens["session"], map[string]any{"clear_synced_copies": true})
		assert.Equal(t, http.StatusInternalServerError, res.code, res.body)
		cur := stored(t, a.ID)
		assert.Equal(t, core.SecretStatusActive, cur.Status)
		assert.False(t, cur.SuspendClearSyncedCopies)
	})

	t.Run("per-secret audit refused: 500 with counts, nothing reported as 200, unaudited secrets unchanged", func(t *testing.T) {
		thaw(t)
		activeOnly(t)
		ids := []uint{newSecret(t, "freeze-ps-1").ID, newSecret(t, "freeze-ps-2").ID, newSecret(t, "freeze-ps-3").ID}
		var total int64
		require.NoError(t, w.db.Model(&models.SecretNode{}).Where("project_id = ? AND status = ?", w.projID, core.SecretStatusActive).Count(&total).Error)
		beforeEach := count(t, core.EventSecretSuspended)
		refuseAudit(t, core.EventSecretSuspended)

		res := postJSON(w, suspendAll, w.tokens["session"], map[string]any{"clear_synced_copies": true})
		require.Equal(t, http.StatusInternalServerError, res.code, res.body)
		var env struct {
			Message string `json:"message"`
			Details struct {
				Suspended int `json:"suspended"`
				Failed    int `json:"failed"`
			} `json:"details"`
		}
		require.NoError(t, json.Unmarshal([]byte(res.body), &env), res.body)
		assert.Contains(t, env.Message, "audit event could not be recorded")
		assert.Equal(t, 0, env.Details.Suspended, "every secret's own audit row is refused, so none is suspended")
		assert.Equal(t, int(total), env.Details.Failed, res.body)
		for _, id := range ids {
			cur := stored(t, id)
			assert.Equal(t, core.SecretStatusActive, cur.Status, "secret %d changed without its audit row", id)
			assert.False(t, cur.SuspendClearSyncedCopies)
		}
		assert.Equal(t, beforeEach, count(t, core.EventSecretSuspended), "no suspend event was recorded")
	})

	t.Run("a plain freeze is still 200 when per-secret audit rows are refused", func(t *testing.T) {
		thaw(t)
		activeOnly(t)
		sec := newSecret(t, "freeze-plain-auditdown")
		refuseAudit(t, core.EventSecretSuspended)

		res := postJSON(w, suspendAll, w.tokens["session"], map[string]any{"reason": "breach"})
		require.Equal(t, http.StatusOK, res.code, res.body)
		assert.Equal(t, core.SecretStatusSuspended, stored(t, sec.ID).Status, "revocation is never blocked by audit on a plain suspend")
	})
}
