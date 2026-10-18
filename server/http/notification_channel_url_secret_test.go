// notification_channel_url_secret_test.go — #3425: a channel URL is a bearer
// credential (Slack-style tokens live in the path). Before this change
// channelToAPI returned the decrypted URL on create, list and get to every
// alerts.write caller. The contract now: the full URL comes back once, in the
// create response; list/get/update return scheme+host with the path elided
// plus url_set; an update that omits "url" keeps the stored credential and an
// explicit "url" replaces it. Driven through the real router as a user holding
// ONLY alerts.write (the alert_operator role).
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

const (
	ncSecretToken = "SUPERSECRETTOKEN"
	ncSecretURL   = "https://hooks.slack.test/services/T000/B000/" + ncSecretToken
	ncElidedURL   = "https://hooks.slack.test/…"
)

func TestNotificationChannelURL_AlertsWriteOnlyNeverSeesPathTokenAfterCreate(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newFullSchemaTestCore(t)
	testCore.SetWebhookURLValidator(func(string) error { return nil })
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	createTestToken(t, testCore) // bootstraps the system (seeds alert_operator)
	token := createAlertOperatorToken(t, testCore)

	client := &http.Client{Timeout: 10 * time.Second}
	do := func(method, path string, body map[string]any) (int, string, map[string]any) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, merr := json.Marshal(body)
			require.NoError(t, merr)
			rdr = bytes.NewReader(b)
		}
		req, rerr := http.NewRequest(method, server.URL+path, rdr)
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		defer func() { _ = resp.Body.Close() }()
		raw, rerr := io.ReadAll(resp.Body)
		require.NoError(t, rerr)
		var env struct {
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(raw, &env)
		return resp.StatusCode, string(raw), env.Data
	}
	stored := func(id uint) string {
		t.Helper()
		ch, gerr := testCore.GetNotificationChannel(context.Background(), id)
		require.NoError(t, gerr)
		return ch.URL
	}

	// create: the one response that carries the full URL.
	status, raw, data := do(http.MethodPost, "/api/v1/notification-channels", map[string]any{
		"name": "ops-slack", "type": "slack", "url": ncSecretURL,
	})
	require.Equal(t, http.StatusCreated, status, raw)
	assert.Equal(t, ncSecretURL, data["url"], "create must still return the full URL, once")
	assert.Equal(t, true, data["url_set"])
	id := uint(data["id"].(float64))
	path := "/api/v1/notification-channels/" + strconv.FormatUint(uint64(id), 10)

	// list: no path, no token anywhere in the body.
	status, raw, _ = do(http.MethodGet, "/api/v1/notification-channels", nil)
	require.Equal(t, http.StatusOK, status, raw)
	assert.NotContains(t, raw, ncSecretToken, "list leaked the bearer token to an alerts.write caller")
	assert.NotContains(t, raw, "/services/", "list leaked the URL path")
	assert.Contains(t, raw, ncElidedURL)
	assert.Contains(t, raw, `"url_set":true`)

	// get
	status, raw, data = do(http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, status, raw)
	assert.NotContains(t, raw, ncSecretToken, "get leaked the bearer token to an alerts.write caller")
	assert.NotContains(t, raw, "/services/", "get leaked the URL path")
	assert.Equal(t, ncElidedURL, data["url"])
	assert.Equal(t, true, data["url_set"])

	// update that omits url: stored credential untouched, response still elided.
	status, raw, data = do(http.MethodPut, path, map[string]any{"events": "secret.rotated"})
	require.Equal(t, http.StatusOK, status, raw)
	assert.NotContains(t, raw, ncSecretToken, "update response leaked the bearer token")
	assert.Equal(t, ncElidedURL, data["url"])
	assert.Equal(t, ncSecretURL, stored(id), "an update that omits url must keep the stored credential")

	// update with an explicit url replaces it; the new one is not echoed either.
	const replacement = "https://hooks.slack.test/services/T111/B111/REPLACEMENTTOKEN"
	status, raw, _ = do(http.MethodPut, path, map[string]any{"url": replacement})
	require.Equal(t, http.StatusOK, status, raw)
	assert.NotContains(t, raw, "REPLACEMENTTOKEN", "update response echoed the new bearer token")
	assert.Equal(t, replacement, stored(id), "an explicit url must replace the stored one")

	// An email channel has no URL: url_set is false, url empty.
	status, raw, data = do(http.MethodPost, "/api/v1/notification-channels", map[string]any{
		"name": "ops-mail", "type": "email", "email": "ops@example.com",
	})
	require.Equal(t, http.StatusCreated, status, raw)
	assert.Equal(t, false, data["url_set"])
	assert.Equal(t, "", data["url"])
}
