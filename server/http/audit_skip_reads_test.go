package http

// audit_skip_reads_test.go -- ADR-112 Amendment 4
// (storage.database.insecure_audit_skip_reads) against the real router: with
// the setting on, every REST value-read route still returns the value but
// writes no secret.read row and no "read" access-log row, while the secret's
// create, update and delete are still audited. With it off (the
// TestCLISecretDeleteFlow_WritesNoSecretRead world), the same reads are
// audited as before.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInsecureAuditSkipReads_RESTValueReadsUnauditedWritesAudited(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("insecure_audit_skip_reads=%v", skip), func(t *testing.T) {
			runRESTSkipReadsJourney(t, skip)
		})
	}
}

func runRESTSkipReadsJourney(t *testing.T, skip bool) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	c.SetInsecureAuditSkipReads(skip)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{}).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(b)
	}

	ctx := context.Background()
	project, err := c.Storage().GetProject(ctx, 1)
	require.NoError(t, err)
	env, err := c.Storage().GetEnvironment(ctx, 1)
	require.NoError(t, err)

	st, body := do(http.MethodPost, "/api/v1/secrets", `{"name":"skip-reads","value":"v1-value","project_id":1,"environment_id":1,"type":"password"}`)
	require.Equal(t, http.StatusCreated, st, body)
	var created struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &created))
	id := created.Data.ID
	require.NotZero(t, id)

	// Three value-disclosing routes; each must still return the value.
	st, body = do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), "")
	require.Equal(t, http.StatusOK, st, body)
	assert.Contains(t, body, "v1-value")
	ref := url.QueryEscape(project.Name + "/" + env.Name + "/skip-reads")
	st, body = do(http.MethodGet, "/api/v1/secrets/value?ref="+ref, "")
	require.Equal(t, http.StatusOK, st, body)
	assert.Contains(t, body, "v1-value")
	tmpl, _ := json.Marshal(map[string]string{"template": "X=${secret:" + env.Name + "/skip-reads}"})
	st, body = do(http.MethodPost, "/api/v1/projects/1/secrets/render", string(tmpl))
	require.Equal(t, http.StatusOK, st, body)
	assert.Contains(t, body, "X=v1-value")

	st, body = do(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), `{"value":"v2-value"}`)
	require.Equal(t, http.StatusOK, st, body)
	st, body = do(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), "")
	require.Equal(t, http.StatusNoContent, st, body)

	count := func(eventType string) int {
		t.Helper()
		et, sid := eventType, id
		var n int
		// The non-read writes are fire-and-forget; wait for them.
		require.Eventually(t, func() bool {
			events, _, err := c.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Action: &et, SecretID: &sid, PageSize: 100})
			require.NoError(t, err)
			n = len(events)
			return eventType == "secret.read" || n > 0
		}, 2*time.Second, 10*time.Millisecond, "%s never written", eventType)
		return n
	}
	for _, et := range []string{"secret.created", "secret.updated", "secret.deleted"} {
		assert.Positive(t, count(et), "%s must be audited at either setting", et)
	}

	logs, err := c.Storage().ListSecretAccessLogs(ctx, id, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	reads := 0
	for _, l := range logs {
		if l.Action == "read" {
			reads++
		}
	}
	if skip {
		assert.Zero(t, count("secret.read"), "no successful value read may be audited with the setting on")
		assert.Zero(t, reads, "no access-log read row with the setting on")
		return
	}
	assert.Equal(t, 3, count("secret.read"), "setting off: one secret.read per value-disclosing request, as before")
	assert.Equal(t, 3, reads)
}
