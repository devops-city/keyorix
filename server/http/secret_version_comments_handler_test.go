package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getFirstVersionID fetches the list of versions for a secret and returns the
// ID of the first version (i.e. the version created by CreateSecret).
func getFirstVersionID(t *testing.T, client *http.Client, baseURL, token string, secretID uint) uint {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions", baseURL, secretID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 from GET /versions")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	data, ok := body["data"].(map[string]any)
	require.True(t, ok, "response.data must be an object")

	versions, ok := data["versions"].([]any)
	require.True(t, ok, "response.data.versions must be an array")
	require.NotEmpty(t, versions, "expected at least one version")

	first, ok := versions[0].(map[string]any)
	require.True(t, ok, "first version must be an object")

	id, ok := first["ID"].(float64)
	require.True(t, ok, "version.ID must be a number")
	return uint(id)
}

// TestSecretVersionComments_CreateComment verifies that POST returns 201 and the
// comment body.
func TestSecretVersionComments_CreateComment(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "vc-create-test-secret")
	versionID := getFirstVersionID(t, client, srv.URL, token, secretID)

	body, err := json.Marshal(map[string]string{"comment": "Initial rotation — ticket #42"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/%d/comments", srv.URL, secretID, versionID),
		bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var respBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	data, ok := respBody["data"].(map[string]any)
	require.True(t, ok, "response.data must be an object")

	comment, ok := data["comment"].(map[string]any)
	require.True(t, ok, "response.data.comment must be an object")
	assert.Equal(t, "Initial rotation — ticket #42", comment["comment"])
}

// TestSecretVersionComments_ListComments verifies that GET returns 200 and the
// list includes previously created comments.
func TestSecretVersionComments_ListComments(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "vc-list-test-secret")
	versionID := getFirstVersionID(t, client, srv.URL, token, secretID)

	// Create a comment first.
	body, err := json.Marshal(map[string]string{"comment": "Auditor note"})
	require.NoError(t, err)
	postReq, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/%d/comments", srv.URL, secretID, versionID),
		bytes.NewBuffer(body))
	require.NoError(t, err)
	postReq.Header.Set("Authorization", "Bearer "+token)
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := client.Do(postReq)
	require.NoError(t, err)
	_ = postResp.Body.Close()
	require.Equal(t, http.StatusCreated, postResp.StatusCode)

	// Now list comments.
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/%d/comments", srv.URL, secretID, versionID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var respBody map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&respBody))

	data, ok := respBody["data"].(map[string]any)
	require.True(t, ok, "response.data must be an object")

	total, ok := data["total"].(float64)
	require.True(t, ok, "response.data.total must be a number")
	assert.Equal(t, float64(1), total)

	comments, ok := data["comments"].([]any)
	require.True(t, ok, "response.data.comments must be an array")
	require.Len(t, comments, 1)

	first, ok := comments[0].(map[string]any)
	require.True(t, ok, "first comment must be an object")
	assert.Equal(t, "Auditor note", first["comment"])
}

// TestSecretVersionComments_DeleteComment verifies that DELETE returns 204.
func TestSecretVersionComments_DeleteComment(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "vc-delete-test-secret")
	versionID := getFirstVersionID(t, client, srv.URL, token, secretID)

	// Create a comment.
	body, err := json.Marshal(map[string]string{"comment": "Comment to delete"})
	require.NoError(t, err)
	postReq, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/%d/comments", srv.URL, secretID, versionID),
		bytes.NewBuffer(body))
	require.NoError(t, err)
	postReq.Header.Set("Authorization", "Bearer "+token)
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := client.Do(postReq)
	require.NoError(t, err)
	defer func() { _ = postResp.Body.Close() }()
	require.Equal(t, http.StatusCreated, postResp.StatusCode)

	var postBody map[string]any
	require.NoError(t, json.NewDecoder(postResp.Body).Decode(&postBody))
	postData, ok := postBody["data"].(map[string]any)
	require.True(t, ok)
	commentObj, ok := postData["comment"].(map[string]any)
	require.True(t, ok)
	commentID := uint(commentObj["id"].(float64))

	// Delete the comment.
	delReq, err := http.NewRequest(http.MethodDelete,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/%d/comments/%d", srv.URL, secretID, versionID, commentID), nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+token)

	delResp, err := client.Do(delReq)
	require.NoError(t, err)
	defer func() { _ = delResp.Body.Close() }()

	assert.Equal(t, http.StatusNoContent, delResp.StatusCode)
}

// TestSecretVersionComments_EmptyComment verifies that POST with an empty
// comment returns 400.
func TestSecretVersionComments_EmptyComment(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "vc-empty-comment-secret")
	versionID := getFirstVersionID(t, client, srv.URL, token, secretID)

	body, err := json.Marshal(map[string]string{"comment": ""})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/%d/comments", srv.URL, secretID, versionID),
		bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestSecretVersionComments_Unauthenticated verifies that POST without a token
// returns 401.
func TestSecretVersionComments_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	secretID := createIntegrationTestSecret(t, client, srv.URL, token, "vc-unauth-secret")
	versionID := getFirstVersionID(t, client, srv.URL, token, secretID)

	body, err := json.Marshal(map[string]string{"comment": "should be rejected"})
	require.NoError(t, err)

	// No Authorization header.
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/secrets/%d/versions/%d/comments", srv.URL, secretID, versionID),
		bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
