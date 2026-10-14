// secrets_bulk_rotate_test.go — coverage for BulkRotateSecrets
// (secrets_bulk_rotate.go), previously untested (0% coverage).
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBulkRotateSecrets_Unauthorized(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate", nil), "id", "1")
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBulkRotateSecrets_InvalidProjectID(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/abc/secrets/bulk-rotate", nil), "id", "abc")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBulkRotateSecrets_BadJSON(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate",
		bytes.NewReader([]byte("{bad json}"))), "id", "1")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBulkRotateSecrets_BatchTooLarge exercises the "exceeds the maximum
// batch size" -> 400 branch (core.maxBulkRotateBatchSize is 500).
func TestBulkRotateSecrets_BatchTooLarge(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	ids := make([]uint, 501)
	for i := range ids {
		ids[i] = uint(i + 1)
	}
	body, _ := json.Marshal(map[string]any{"secret_ids": ids})
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate",
		bytes.NewReader(body)), "id", "1")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBulkRotateSecrets_Success — an empty project (no secrets, no explicit
// secret_ids) is a legal project-wide rotation of zero secrets: 200 with an
// empty Triggered/Failed result.
func TestBulkRotateSecrets_Success(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	body, _ := json.Marshal(map[string]any{})
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rotate",
		bytes.NewReader(body)), "id", "1")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.BulkRotateSecrets(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}
