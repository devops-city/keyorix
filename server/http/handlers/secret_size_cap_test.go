// secret_size_cap_test.go — HTTP-layer coverage for the maximum secret-value
// size cap (Item 1): exactly-at-limit is accepted, one byte over the DECODED
// value limit is rejected with 413 (core.SecretValueTooLargeError, via
// trySendSecretSizeError), and a request body large enough to trip the
// wire-level http.MaxBytesReader limit (server/http/router.go's
// secretBodyLimit, derived by config.DeriveMaxRequestBodySize) is also
// rejected with 413 (*http.MaxBytesError). Reuses freshSecretFixtureS15 /
// withAdminCtxS15 from secrets_crud_s15_test.go.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func withChiIDParam(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestCreateSecret_SecretSizeCap_ExactlyAtLimit_Accepted(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	cs.SetMaxSecretSize(100)

	body, err := json.Marshal(map[string]any{
		"name": "at-limit-create", "value": strings.Repeat("a", 100),
		"project_id": uint(1), "environment_id": uint(10), "type": "static",
	})
	require.NoError(t, err)

	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestCreateSecret_SecretSizeCap_OneByteOver_Rejected413(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	cs.SetMaxSecretSize(100)

	body, err := json.Marshal(map[string]any{
		"name": "over-limit-create", "value": strings.Repeat("a", 101),
		"project_id": uint(1), "environment_id": uint(10), "type": "static",
	})
	require.NoError(t, err)

	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateSecret(w, r)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "PayloadTooLarge")
	assert.Contains(t, w.Body.String(), "100")
}

func TestCreateSecret_SecretSizeCap_BodyTooLarge_MaxBytesReaderTrips413(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	cs.SetMaxSecretSize(100)

	// A body far larger than config.DeriveMaxRequestBodySize(100) -- the
	// wire-level limit must trip during json.Decode, before a Go value with a
	// decoded length ever exists (distinct code path from the test above).
	body, err := json.Marshal(map[string]any{
		"name": "wire-limit-create", "value": strings.Repeat("a", 30_000),
		"project_id": uint(1), "environment_id": uint(10), "type": "static",
	})
	require.NoError(t, err)

	limit := config.DeriveMaxRequestBodySize(100)
	require.Less(t, limit, int64(len(body)), "test setup: body must exceed the derived wire-level limit")

	wrapped := middleware.MaxBodyBytes(limit)(http.HandlerFunc(h.CreateSecret))
	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, r)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "PayloadTooLarge")
}

// TestCreateSecret_SecretSizeCap_GenuineMaxSizeSecret_ThroughRealMiddleware_Accepted
// is the actual proof for 1b: every other "accepted" test in this file calls
// h.CreateSecret directly, bypassing the http.MaxBytesReader wire-level limit
// entirely -- a wrong DeriveMaxRequestBodySize (e.g. accidentally wired to the
// raw 65536 rather than the base64+envelope-inflated derivation) would still
// pass those tests, because they never exercise the wire-level limit at all.
// This test sends a genuine config.DefaultMaxSecretSize-byte (64 KiB) secret
// value, base64-inflated by JSON string encoding exactly as a real client
// would send it, through the SAME middleware.MaxBodyBytes(...) wrapping
// server/http/router.go actually applies (same derivation call, same
// production default constant, not a scaled-down test limit) and asserts
// 201 -- if the derivation under-counts the envelope/encoding overhead, the
// real handler's decode fails and this goes red where the others would not.
func TestCreateSecret_SecretSizeCap_GenuineMaxSizeSecret_ThroughRealMiddleware_Accepted(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	// Deliberately NOT calling cs.SetMaxSecretSize: KeyorixCore already
	// defaults to core.DefaultMaxSecretSize on construction, so this exercises
	// the real production default end to end rather than a test-only override.

	value := strings.Repeat("a", config.DefaultMaxSecretSize)
	body, err := json.Marshal(map[string]any{
		"name": "genuine-max-size-secret", "value": value,
		"project_id": uint(1), "environment_id": uint(10), "type": "static",
	})
	require.NoError(t, err)

	limit := config.DeriveMaxRequestBodySize(config.DefaultMaxSecretSize)
	require.Greater(t, limit, int64(len(body)),
		"test setup: the derived limit must actually cover a genuine max-size secret's encoded body -- "+
			"if this fails, DeriveMaxRequestBodySize itself under-counts the encoding/envelope overhead")

	wrapped := middleware.MaxBodyBytes(limit)(http.HandlerFunc(h.CreateSecret))
	r := withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, r)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var resp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	stored, err := cs.GetSecretValue(context.Background(), resp.Data.ID)
	require.NoError(t, err)
	assert.Len(t, stored, config.DefaultMaxSecretSize, "the stored value's decoded length must equal the original, not be truncated by the wire-level limit")
}

func TestUpdateSecret_SecretSizeCap_ExactlyAtLimit_Accepted(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	cs.SetMaxSecretSize(100)

	body, err := json.Marshal(map[string]any{"value": strings.Repeat("b", 100)})
	require.NoError(t, err)

	r := withChiIDParam(withAdminCtxS15(httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1", bytes.NewReader(body))), "1")
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestUpdateSecret_SecretSizeCap_OneByteOver_Rejected413(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	cs.SetMaxSecretSize(100)

	body, err := json.Marshal(map[string]any{"value": strings.Repeat("b", 101)})
	require.NoError(t, err)

	r := withChiIDParam(withAdminCtxS15(httptest.NewRequest(http.MethodPut, "/api/v1/secrets/1", bytes.NewReader(body))), "1")
	w := httptest.NewRecorder()
	h.UpdateSecret(w, r)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "PayloadTooLarge")
}

func TestRotateSecret_SecretSizeCap_ExactlyAtLimit_Accepted(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	cs.SetMaxSecretSize(100)

	body, err := json.Marshal(map[string]any{"new_value": strings.Repeat("c", 100)})
	require.NoError(t, err)

	r := withChiIDParam(withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/rotate", bytes.NewReader(body))), "1")
	w := httptest.NewRecorder()
	h.RotateSecret(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestRotateSecret_SecretSizeCap_OneByteOver_Rejected413(t *testing.T) {
	h, cs, _, _ := freshSecretFixtureS15(t)
	cs.SetMaxSecretSize(100)

	body, err := json.Marshal(map[string]any{"new_value": strings.Repeat("c", 101)})
	require.NoError(t, err)

	r := withChiIDParam(withAdminCtxS15(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/rotate", bytes.NewReader(body))), "1")
	w := httptest.NewRecorder()
	h.RotateSecret(w, r)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "PayloadTooLarge")
}
