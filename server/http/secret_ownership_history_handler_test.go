package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedSecretForOwnershipTest creates a secret via the HTTP API and returns its ID.
func seedSecretForOwnershipTest(t *testing.T, client *http.Client, baseURL, token, name string) uint {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name": name, "value": "v", "project_id": 1, "environment_id": 1, "type": "password",
	})
	require.NoError(t, err)
	req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	data := out["data"].(map[string]any)
	return uint(data["id"].(float64))
}

// ownershipHistoryResponse is the decoded response shape for the
// GET /api/v1/secrets/{id}/ownership-history endpoint.
type ownershipHistoryResponse struct {
	Success bool `json:"success"`
	Data    struct {
		OwnershipHistory []map[string]any `json:"ownership_history"`
		Total            float64          `json:"total"`
	} `json:"data"`
}

// doOwnershipHistoryRequest issues a GET ownership-history request and decodes the body.
func doOwnershipHistoryRequest(t *testing.T, client *http.Client, baseURL, token string, secretID uint) (*http.Response, ownershipHistoryResponse) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/secrets/%d/ownership-history", baseURL, secretID)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	var body ownershipHistoryResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	_ = resp.Body.Close()
	return resp, body
}

// grantWriterRoleAtProject assigns the "editor" role to userID at project 1 so they
// hold secrets.write — the write-tier ceiling a transfer target must already meet
// (secrets.read alone, e.g. "viewer", is no longer sufficient — see
// secret_ownership_test.go's exploit-closure regression tests for why).
func grantWriterRoleAtProject(t *testing.T, c *core.KeyorixCore, userID uint) {
	t.Helper()
	ctx := context.Background()
	role, err := c.Storage().GetRoleByName(ctx, "editor")
	require.NoError(t, err)
	require.NoError(t, c.Storage().AssignRole(ctx, userID, role.ID, core.Scope{ProjectID: 1}))
}

// TestOwnershipHistory_NoTransfers verifies GET /secrets/{id}/ownership-history
// returns 200 with an empty list when the secret has never changed owners.
func TestOwnershipHistory_NoTransfers(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := seedSecretForOwnershipTest(t, client, srv.URL, token, "no-transfer-secret")

	resp, body := doOwnershipHistoryRequest(t, client, srv.URL, token, secretID)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.Success)
	assert.Equal(t, float64(0), body.Data.Total)
	assert.Empty(t, body.Data.OwnershipHistory)
}

// TestOwnershipHistory_OneTransfer verifies GET /secrets/{id}/ownership-history
// returns 200 with exactly one record after a single ownership transfer.
func TestOwnershipHistory_OneTransfer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	ctx := context.Background()
	secretID := seedSecretForOwnershipTest(t, client, srv.URL, token, "one-transfer-secret")

	// Create a second user and give them project-scoped secrets.write so they are a
	// valid transfer target (the ownership ceiling requires write-tier, not merely
	// read-tier, access).
	user2, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "transferee", Email: "transferee@example.com", Password: "Transfer99!PassValid",
	})
	require.NoError(t, err)
	grantWriterRoleAtProject(t, c, user2.ID)

	// Resolve admin user ID.
	admin, err := c.Storage().GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)

	// Perform a real ownership transfer via the core (seeds the audit event).
	_, err = c.TransferSecretOwnership(ctx, secretID, user2.ID, admin.ID, core.ActorTypeUser)
	require.NoError(t, err)

	// Log in as user2 (the new owner) to view the history: CheckSecretPermission
	// only allows the current owner or share recipients, so we must use the new
	// owner's session to pass the core-layer permission re-check.
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "transferee", Password: "Transfer99!PassValid"})
	require.NoError(t, err)
	user2Token := sess.SessionToken

	resp, body := doOwnershipHistoryRequest(t, client, srv.URL, user2Token, secretID)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.Success)
	assert.Equal(t, float64(1), body.Data.Total)
	require.Len(t, body.Data.OwnershipHistory, 1)

	rec := body.Data.OwnershipHistory[0]
	assert.Equal(t, float64(admin.ID), rec["from_id"])
	assert.Equal(t, float64(user2.ID), rec["to_id"])
	assert.Equal(t, float64(admin.ID), rec["changed_by"])
}

// TestOwnershipHistory_MultipleTransfers verifies that multiple transfers are all
// returned in chronological order (oldest first).
func TestOwnershipHistory_MultipleTransfers(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	ctx := context.Background()
	secretID := seedSecretForOwnershipTest(t, client, srv.URL, token, "multi-transfer-secret")

	// Create two additional users, both with project-scoped write access.
	user2, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "user2mt", Email: "user2mt@example.com", Password: "Multi99!PassValid1",
	})
	require.NoError(t, err)
	grantWriterRoleAtProject(t, c, user2.ID)

	user3, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "user3mt", Email: "user3mt@example.com", Password: "Multi99!PassValid2",
	})
	require.NoError(t, err)
	grantWriterRoleAtProject(t, c, user3.ID)

	admin, err := c.Storage().GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)

	// Transfer 1: admin → user2
	_, err = c.TransferSecretOwnership(ctx, secretID, user2.ID, admin.ID, core.ActorTypeUser)
	require.NoError(t, err)

	// Transfer 2: user2 → user3
	_, err = c.TransferSecretOwnership(ctx, secretID, user3.ID, user2.ID, core.ActorTypeUser)
	require.NoError(t, err)

	// Log in as user3 (the final owner) to view the history.
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "user3mt", Password: "Multi99!PassValid2"})
	require.NoError(t, err)
	user3Token := sess.SessionToken

	resp, body := doOwnershipHistoryRequest(t, client, srv.URL, user3Token, secretID)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.Success)
	assert.Equal(t, float64(2), body.Data.Total)
	require.Len(t, body.Data.OwnershipHistory, 2)

	// First record: admin → user2
	rec0 := body.Data.OwnershipHistory[0]
	assert.Equal(t, float64(admin.ID), rec0["from_id"])
	assert.Equal(t, float64(user2.ID), rec0["to_id"])

	// Second record: user2 → user3
	rec1 := body.Data.OwnershipHistory[1]
	assert.Equal(t, float64(user2.ID), rec1["from_id"])
	assert.Equal(t, float64(user3.ID), rec1["to_id"])
}

// TestOwnershipHistory_NonExistentSecret verifies that requesting ownership
// history for a secret that does not exist returns 404.
func TestOwnershipHistory_NonExistentSecret(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	resp, _ := doOwnershipHistoryRequest(t, client, srv.URL, token, 99999)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestOwnershipHistory_Unauthenticated verifies that an unauthenticated request
// to the ownership-history endpoint returns 401.
func TestOwnershipHistory_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	// Seed a real secret so the ID is valid.
	secretID := seedSecretForOwnershipTest(t, client, srv.URL, token, "unauth-ownership-secret")

	// Make the request WITHOUT an Authorization header.
	resp, _ := doOwnershipHistoryRequest(t, client, srv.URL, "" /*no token*/, secretID)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
