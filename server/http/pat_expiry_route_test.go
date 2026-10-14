// pat_expiry_route_test.go — integration tests for:
//
//	GET    /api/v1/auth/tokens/expired
//	DELETE /api/v1/auth/tokens/expired
//
// These drive the full router (newTestCore + NewRouter) so every middleware
// layer (auth, rate-limit, userctx injection) is exercised.
package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPATExpiryRouterSetup(t *testing.T) (serverURL string, sessionToken string, teardown func()) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	c := newTestCore(t)
	sessionToken = createTestToken(t, c) // bootstraps testadmin

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
		},
	}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	return srv.URL, sessionToken, func() {
		srv.Close()
		i18n.ResetForTesting()
	}
}

// TestPATExpiryRoute_ListExpiredPATs_Unauthenticated_Returns401 verifies the
// route is protected.
func TestPATExpiryRoute_ListExpiredPATs_Unauthenticated_Returns401(t *testing.T) {
	serverURL, _, teardown := newPATExpiryRouterSetup(t)
	defer teardown()

	req, err := http.NewRequest(http.MethodGet, serverURL+"/api/v1/auth/tokens/expired", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestPATExpiryRoute_ListExpiredPATs_EmptyList_Returns200 verifies a 200 with
// an empty array when the user has no expired tokens.
func TestPATExpiryRoute_ListExpiredPATs_EmptyList_Returns200(t *testing.T) {
	serverURL, token, teardown := newPATExpiryRouterSetup(t)
	defer teardown()

	req, err := http.NewRequest(http.MethodGet, serverURL+"/api/v1/auth/tokens/expired", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Data []any `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Empty(t, body.Data)
}

// TestPATExpiryRoute_BulkRevokeExpiredPATs_Unauthenticated_Returns401 verifies
// the DELETE route is protected.
func TestPATExpiryRoute_BulkRevokeExpiredPATs_Unauthenticated_Returns401(t *testing.T) {
	serverURL, _, teardown := newPATExpiryRouterSetup(t)
	defer teardown()

	req, err := http.NewRequest(http.MethodDelete, serverURL+"/api/v1/auth/tokens/expired", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestPATExpiryRoute_BulkRevokeExpiredPATs_NoneExpired_Returns204 verifies
// DELETE returns 204 even when there are no expired tokens to revoke.
func TestPATExpiryRoute_BulkRevokeExpiredPATs_NoneExpired_Returns204(t *testing.T) {
	serverURL, token, teardown := newPATExpiryRouterSetup(t)
	defer teardown()

	req, err := http.NewRequest(http.MethodDelete, serverURL+"/api/v1/auth/tokens/expired", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}
