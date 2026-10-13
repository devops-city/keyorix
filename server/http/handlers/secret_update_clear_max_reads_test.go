package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3172: max_reads keeps minimum 1 (0 is rejected), and clear_max_reads is the
// explicit way to remove a read limit over REST.
func TestUpdateSecret_ClearMaxReads_3172(t *testing.T) {
	h, _, secret, db := freshSecretFixtureS13(t)
	put := func(payload map[string]interface{}) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		r := withAdminCtxS13(withChiParam(
			httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", secret.ID), bytes.NewReader(body)),
			"id", fmt.Sprintf("%d", secret.ID),
		))
		w := httptest.NewRecorder()
		h.UpdateSecret(w, r)
		return w
	}
	stored := func() *int {
		var s models.SecretNode
		require.NoError(t, db.First(&s, secret.ID).Error)
		return s.MaxReads
	}

	require.Equal(t, http.StatusOK, put(map[string]interface{}{"max_reads": 3}).Code)
	require.NotNil(t, stored())
	require.Equal(t, 3, *stored())

	// 0 is not "unlimited": the contract (minimum: 1) is unchanged.
	w := put(map[string]interface{}{"max_reads": 0})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	require.NotNil(t, stored(), "a rejected update must not touch the limit")

	// The two fields are mutually exclusive.
	w = put(map[string]interface{}{"max_reads": 5, "clear_max_reads": true})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
	require.Equal(t, 3, *stored())

	// clear_max_reads: false is a no-op.
	require.Equal(t, http.StatusOK, put(map[string]interface{}{"clear_max_reads": false, "type": "generic"}).Code)
	require.NotNil(t, stored())

	w = put(map[string]interface{}{"clear_max_reads": true})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Nil(t, stored(), "clear_max_reads must remove the read limit")
}
