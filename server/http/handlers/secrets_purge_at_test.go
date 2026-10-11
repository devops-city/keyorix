package handlers

// RETENTION-1: the delete response and the trash listing carry the real purge date, in UTC
// RFC 3339, and the two agree.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteSecret_ReportsPurgeAtHeader_AndTrashListingAgrees(t *testing.T) {
	h, cs, secret, db := freshSecretFixtureS15(t)
	cs.SetSoftDeleteRetentionDays(14)

	r := withAdminCtxS15(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteSecret(w, r)
	require.Equal(t, http.StatusNoContent, w.Code, "status unchanged: existing clients check for 204")

	header := w.Header().Get(purgeAtHeader)
	require.NotEmpty(t, header, "delete reports until when it is undoable")
	purgeAt, err := time.Parse(time.RFC3339, header)
	require.NoError(t, err)
	assert.Equal(t, "Z", header[len(header)-1:], "UTC, not a numeric offset: %s", header)

	var deletedAt time.Time
	require.NoError(t, db.Raw("SELECT deleted_at FROM secret_nodes WHERE id = ?", secret.ID).Row().Scan(&deletedAt))
	assert.WithinDuration(t, deletedAt.UTC().AddDate(0, 0, 14), purgeAt, time.Second, "deleted_at + the configured 14 days")

	// The trash listing for the project says the same thing.
	lr := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", secret.ProjectID)))
	lw := httptest.NewRecorder()
	h.DeletedSecrets(lw, lr)
	require.Equal(t, http.StatusOK, lw.Code)
	var resp struct {
		Data struct {
			Deleted []map[string]interface{} `json:"deleted"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(lw.Body).Decode(&resp))
	require.Len(t, resp.Data.Deleted, 1)
	listed, ok := resp.Data.Deleted[0]["purge_at"].(string)
	require.True(t, ok, "trash entry carries purge_at: %v", resp.Data.Deleted[0])
	assert.Equal(t, header, listed, "delete response and trash listing agree")
}
