package http

// SUSPEND-PURGE-1 / #3221: POST /secrets/{id}/suspend with clear_synced_copies commits
// the status change, the marker and the secret.suspended row in one transaction. When the
// audit row cannot be written the request is refused with 500 and nothing takes effect;
// a plain suspend is never blocked by an audit outage (revocation first).

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSuspendSecret_ClearSyncedCopies_AuditUnavailable_OverTheRouter(t *testing.T) {
	w := buildRefusalFamilyWorld(t)
	ctx := context.Background()
	newSecret := func(name string) *models.SecretNode {
		t.Helper()
		sec, err := w.c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("AUDITDOWN-plaintext"),
			ProjectID: w.projID, EnvironmentID: w.envID,
			Type: "password", CreatedBy: "guardadmin", OwnerID: w.adminID,
		})
		require.NoError(t, err)
		return sec
	}
	stored := func(id uint) models.SecretNode {
		t.Helper()
		var s models.SecretNode
		require.NoError(t, w.db.First(&s, id).Error)
		return s
	}
	clearSec, plainSec := newSecret("auditdown-clear"), newSecret("auditdown-plain")
	require.NoError(t, w.db.Migrator().DropTable(&models.AuditEvent{}), "make every audit write fail")

	res := postJSON(w, fmt.Sprintf("/api/v1/secrets/%d/suspend", clearSec.ID), w.tokens["session"],
		map[string]any{"reason": "leaked", "clear_synced_copies": true})
	assert.Equal(t, http.StatusInternalServerError, res.code, res.body)
	cur := stored(clearSec.ID)
	assert.Equal(t, core.SecretStatusActive, cur.Status, "nothing takes effect without its audit row")
	assert.False(t, cur.SuspendClearSyncedCopies)

	res = postJSON(w, fmt.Sprintf("/api/v1/secrets/%d/suspend", plainSec.ID), w.tokens["session"],
		map[string]any{"reason": "maintenance"})
	assert.Equal(t, http.StatusOK, res.code, "a plain suspend stays best-effort on audit: %s", res.body)
	assert.Equal(t, core.SecretStatusSuspended, stored(plainSec.ID).Status)
}
