package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createScheduleTestSecret POSTs to /api/v1/secrets and returns the created secret's ID.
func createScheduleTestSecret(t *testing.T, client *http.Client, baseURL, token string) uint {
	t.Helper()
	secretData := map[string]any{
		"name":           "schedule-test-secret",
		"value":          "secret-value",
		"project_id":     1,
		"environment_id": 1,
		"type":           "password",
	}
	body, err := json.Marshal(secretData)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", baseURL+"/api/v1/secrets", bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "createScheduleTestSecret: POST /api/v1/secrets must return 201")

	var response map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	require.NotNil(t, response["data"], "createScheduleTestSecret: response must contain data")
	data := response["data"].(map[string]any)
	return uint(data["id"].(float64))
}

// scheduleTestSetup spins up a test server backed by its own isolated DB core.
func scheduleTestSetup(t *testing.T) (srv *httptest.Server, client *http.Client, token string) {
	t.Helper()
	c := newTestCore(t)
	token = createTestToken(t, c)
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
		},
	}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	srv = httptest.NewServer(router)
	t.Cleanup(srv.Close)
	client = &http.Client{}
	return srv, client, token
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestSecretSchedule_SetAndGet(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	srv, client, token := scheduleTestSetup(t)
	secretID := createScheduleTestSecret(t, client, srv.URL, token)

	// PUT schedule
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}`
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PUT schedule must return 200")

	// GET schedule — expect the fields back
	req2, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "GET schedule must return 200 after PUT")

	var getResp map[string]any
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&getResp))
	require.NotNil(t, getResp["data"], "GET schedule response must contain data")
	data := getResp["data"].(map[string]any)
	assert.Equal(t, "1,2,3,4,5", data["allowed_days"])
	assert.Equal(t, float64(9), data["start_hour"])
	assert.Equal(t, float64(17), data["end_hour"])
	assert.Equal(t, "UTC", data["timezone"])
}

func TestSecretSchedule_Delete(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	srv, client, token := scheduleTestSetup(t)
	secretID := createScheduleTestSecret(t, client, srv.URL, token)

	// PUT a schedule first
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}`
	putReq, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), strings.NewReader(body))
	require.NoError(t, err)
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := client.Do(putReq)
	require.NoError(t, err)
	_ = putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT schedule must return 200 before DELETE")

	// DELETE the schedule
	delReq, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := client.Do(delReq)
	require.NoError(t, err)
	defer func() { _ = delResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, delResp.StatusCode, "DELETE schedule must return 200")

	// GET after delete — must 404 (no schedule configured)
	getReq, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), nil)
	require.NoError(t, err)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := client.Do(getReq)
	require.NoError(t, err)
	defer func() { _ = getResp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode, "GET schedule after DELETE must return 404")
}

func TestSecretSchedule_InvalidHours(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	srv, client, token := scheduleTestSetup(t)
	secretID := createScheduleTestSecret(t, client, srv.URL, token)

	// end_hour < start_hour must be rejected
	body := `{"allowed_days":"1,2,3,4,5","start_hour":17,"end_hour":9,"timezone":"UTC"}`
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "PUT with end_hour < start_hour must return 400")
}

func TestSecretSchedule_Unauthenticated(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	srv, client, token := scheduleTestSetup(t)
	secretID := createScheduleTestSecret(t, client, srv.URL, token)

	// PUT without Authorization header
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"UTC"}`
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	// no Authorization header
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "PUT schedule without token must return 401")
}

func TestSecretSchedule_InvalidTimezone(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	srv, client, token := scheduleTestSetup(t)
	secretID := createScheduleTestSecret(t, client, srv.URL, token)

	// An invalid IANA timezone name must be rejected
	body := `{"allowed_days":"1,2,3,4,5","start_hour":9,"end_hour":17,"timezone":"Not/AZone"}`
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/secrets/%d/schedule", srv.URL, secretID), strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "PUT with invalid timezone must return 400")
}
