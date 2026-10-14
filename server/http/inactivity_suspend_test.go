package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newInactiviteSuspendServer creates a full HTTP test server for
// inactivity-suspend endpoint tests.
func newInactiviteSuspendServer(t *testing.T) (*httptest.Server, *core.KeyorixCore, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
		},
	}
	c := newTestCore(t)
	adminToken := createTestToken(t, c)

	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server, c, adminToken
}

// decodeSuspendResult decodes the suspend-inactive-users response body.
func decodeSuspendResult(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var out struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out.Data
}

// postSuspendInactive sends a POST to the suspend-inactive-users endpoint.
func postSuspendInactive(t *testing.T, server *httptest.Server, token string, body any) *http.Response {
	t.Helper()
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req, err := http.NewRequest(http.MethodPost,
		server.URL+"/api/v1/admin/jobs/suspend-inactive-users",
		bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// TestInactivitySuspend_NoInactiveUsers verifies the happy path when there are
// no inactive users: the recently-logged-in admin is not returned by ListInactiveUsers.
func TestInactivitySuspend_NoInactiveUsers(t *testing.T) {
	server, _, adminToken := newInactiviteSuspendServer(t)

	resp := postSuspendInactive(t, server, adminToken, map[string]any{"inactive_days": 90})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	data := decodeSuspendResult(t, resp)
	// The bootstrapped admin logged in seconds ago; inactive_days=90 means
	// nobody crossed the threshold. Total=0, skipped=0, suspended=[].
	assert.Equal(t, float64(0), data["total"])
	assert.Equal(t, float64(0), data["skipped"])
	assert.Empty(t, data["suspended"])
}

// TestInactivitySuspend_InactiveUserSuspended verifies that a user whose
// last_login_at is well beyond the threshold appears in the suspended list.
// Since we cannot directly set last_login_at through the public API in an
// integration test, we use a short threshold of 1 day and a user created more
// than 1 day ago relative to the server clock.  As an alternative we create
// the user and verify it shows in total when using a threshold of 0 (rejected)
// vs a valid threshold under which the brand-new user is still active.
// The most we can prove here without DB access is that the endpoint is
// reachable, the admin is exempt, and a fresh regular user is not inactive.
func TestInactivitySuspend_RecentUserNotSuspended(t *testing.T) {
	server, c, adminToken := newInactiviteSuspendServer(t)
	ctx := context.Background()

	// Create a non-admin user who has never logged in but was just created.
	_, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "fresh_user",
		Email:    "fresh@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	// With a 90-day threshold, neither the admin (just logged in) nor the fresh
	// user (just created) is inactive.
	resp := postSuspendInactive(t, server, adminToken, map[string]any{"inactive_days": 90})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	data := decodeSuspendResult(t, resp)
	// Neither user crosses the 90-day threshold.
	assert.Equal(t, float64(0), data["total"])
	assert.Empty(t, data["suspended"])
}

// TestInactivitySuspend_InvalidBody_MissingInactiveDays verifies that a missing
// inactive_days field (which decodes to 0) is rejected with 400.
func TestInactivitySuspend_InvalidBody_MissingInactiveDays(t *testing.T) {
	server, _, adminToken := newInactiviteSuspendServer(t)

	resp := postSuspendInactive(t, server, adminToken, map[string]any{})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestInactivitySuspend_InvalidBody_ZeroDays verifies that inactive_days=0 is rejected.
func TestInactivitySuspend_InvalidBody_ZeroDays(t *testing.T) {
	server, _, adminToken := newInactiviteSuspendServer(t)

	resp := postSuspendInactive(t, server, adminToken, map[string]any{"inactive_days": 0})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestInactivitySuspend_InvalidBody_NegativeDays verifies that negative
// inactive_days is rejected.
func TestInactivitySuspend_InvalidBody_NegativeDays(t *testing.T) {
	server, _, adminToken := newInactiviteSuspendServer(t)

	resp := postSuspendInactive(t, server, adminToken, map[string]any{"inactive_days": -5})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestInactivitySuspend_InvalidJSON verifies that malformed JSON body returns 400.
func TestInactivitySuspend_InvalidJSON(t *testing.T) {
	server, _, adminToken := newInactiviteSuspendServer(t)

	req, err := http.NewRequest(http.MethodPost,
		server.URL+"/api/v1/admin/jobs/suspend-inactive-users",
		bytes.NewReader([]byte("{invalid json")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestInactivitySuspend_Unauthenticated verifies that unauthenticated requests
// are rejected with 401.
func TestInactivitySuspend_Unauthenticated(t *testing.T) {
	server, _, _ := newInactiviteSuspendServer(t)

	resp := postSuspendInactive(t, server, "" /* no token */, map[string]any{"inactive_days": 90})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestInactivitySuspend_InsufficientPermissions verifies that a non-admin user
// (lacking system.write) receives 403.
func TestInactivitySuspend_InsufficientPermissions(t *testing.T) {
	server, c, _ := newInactiviteSuspendServer(t)

	limitedToken := createLimitedToken(t, c)
	resp := postSuspendInactive(t, server, limitedToken, map[string]any{"inactive_days": 90})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
