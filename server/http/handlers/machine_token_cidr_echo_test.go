// machine_token_cidr_echo_test.go — regression test for the IssueMachineToken
// response echoing the client-submitted allowed_cidrs instead of the actual
// persisted value (findings-handlers/handlers-machine-identities.json#1).
//
// encodePATCIDRs (internal/core/pat.go) normalizes the CIDR allowlist server
// side before it is persisted: blank entries are dropped, duplicates are
// removed, and a bare IP is promoted to a /32 (or /128) host route. A handler
// that echoes the raw request body back to the caller can therefore report a
// restriction that does not match what was actually written to the database —
// a false-assurance bug about what network restriction is really in effect on
// the newly-issued token.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssueMachineToken_AllowedCIDRs_ReflectsPersistedValue submits an
// allowed_cidrs list that encodePATCIDRs is guaranteed to normalize (a
// duplicate entry and a bare IP with no prefix) and asserts the HTTP
// response's allowed_cidrs field matches the PERSISTED/normalized value, not
// a byte-for-byte echo of the submitted body.
func TestIssueMachineToken_AllowedCIDRs_ReflectsPersistedValue(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)

	machine, err := h.coreService.Storage().CreateMachineIdentity(context.Background(), &models.MachineIdentity{
		ProjectID: projID,
		Name:      "cidr-echo-test-machine",
		State:     "active",
	})
	require.NoError(t, err)

	// Submitted list: a duplicate and a bare IP lacking a /32 suffix.
	// encodePATCIDRs must dedup and normalize this before persisting.
	submitted := []string{"10.0.0.1", "10.0.0.1", "203.0.113.0/24"}
	wantPersisted := []string{"10.0.0.1/32", "203.0.113.0/24"}
	require.NotEqual(t, submitted, wantPersisted, "test fixture must exercise real normalization")

	reqBody, err := json.Marshal(map[string]any{
		"name":          "cidr-echo-token",
		"allowed_cidrs": submitted,
	})
	require.NoError(t, err)

	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody)),
		map[string]string{"id": machineUintToStr(projID), "machineId": machineUintToStr(machine.ID)},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.IssueMachineToken(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "response body: %s", w.Body.String())

	var resp struct {
		Data struct {
			AllowedCIDRs []string `json:"allowed_cidrs"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.ElementsMatch(t, wantPersisted, resp.Data.AllowedCIDRs,
		"response must reflect the persisted (normalized) allowed_cidrs, not the raw request body")
	assert.NotEqual(t, submitted, resp.Data.AllowedCIDRs,
		"response must not be a byte-for-byte echo of the client-submitted list")
}
