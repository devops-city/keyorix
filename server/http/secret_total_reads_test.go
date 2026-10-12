package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// AUDIT-UX-2 item 4 (#2951 item 5): GET /secrets/{id} and GET
// /secrets/{id}/versions report total_reads, the secret's lifetime value-read
// count (secret_access_logs rows with action "read"). read_count keeps its
// #2963 meaning (reads charged against max_reads), so for a secret without
// max_reads it stays 0 while total_reads counts every read.
func TestSecretGetAndVersions_ReportTotalReads(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := newTestCore(t)
	token := createTestToken(t, c)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	do := func(method, path, body string) (int, []byte) {
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
		return resp.StatusCode, b
	}

	st, body := do(http.MethodPost, "/api/v1/secrets", `{"name":"total-reads","value":"v1","project_id":1,"environment_id":1,"type":"password"}`)
	require.Equal(t, http.StatusCreated, st, string(body))
	var created struct {
		Data struct {
			ID uint `json:"ID"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	id := created.Data.ID

	type secretWire struct {
		ReadCount  int    `json:"read_count"`
		TotalReads *int64 `json:"total_reads"`
	}
	getMeta := func() secretWire {
		t.Helper()
		st, body := do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include=total_reads", id), "")
		require.Equal(t, http.StatusOK, st, string(body))
		var out struct {
			Data secretWire `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &out))
		return out.Data
	}

	m := getMeta()
	require.NotNil(t, m.TotalReads, "GET /secrets/{id} must report total_reads: %+v", m)
	assert.Equal(t, int64(0), *m.TotalReads, "no value read yet")

	// Two value reads. The second response's own total includes itself.
	for i := 1; i <= 2; i++ {
		st, body := do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true&include=total_reads", id), "")
		require.Equal(t, http.StatusOK, st, string(body))
		var out struct {
			Data struct {
				Secret secretWire `json:"secret"`
				Value  string     `json:"value"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &out))
		require.NotNil(t, out.Data.Secret.TotalReads, "value read response must report total_reads")
		assert.Equal(t, int64(i), *out.Data.Secret.TotalReads, "a value read's total includes that read")
	}

	m = getMeta()
	assert.Equal(t, int64(2), *m.TotalReads, "metadata GETs are not reads")
	assert.Equal(t, 0, m.ReadCount, "read_count keeps its #2963 meaning: 0 without max_reads")

	// Versions: total_reads beside each version's ReadCount. Exactly the two value
	// reads above: listing versions is secret.versions_listed (#2970), not a read, and
	// nothing else has touched the access log yet (the async by-name audit write
	// below has not been triggered), so the count is deterministic.
	st, body = do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/versions", id), "")
	require.Equal(t, http.StatusOK, st, string(body))
	var vout struct {
		Data struct {
			Versions []struct {
				ReadCount int `json:"ReadCount"`
			} `json:"versions"`
			TotalReads *int64 `json:"total_reads"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &vout))
	require.NotNil(t, vout.Data.TotalReads, "GET /secrets/{id}/versions must report total_reads: %s", body)
	assert.Equal(t, int64(2), *vout.Data.TotalReads, "the two value reads, and not the versions listing")
	for _, v := range vout.Data.Versions {
		assert.Equal(t, 0, v.ReadCount, "per-version ReadCount stays max_reads accounting")
	}

	// Listings stay as they were: no total_reads per row.
	st, body = do(http.MethodGet, "/api/v1/secrets?project_id=1&environment_id=1", "")
	require.Equal(t, http.StatusOK, st, string(body))
	assert.NotContains(t, string(body), "total_reads", "listings do not carry total_reads (one COUNT per row)")

	// LAST, because it starts an asynchronous audit write that would race any count
	// taken after it. GET /secrets/by-name is a metadata lookup that is itself audited
	// (async) as a secret.read, so a count there would be non-deterministic and would
	// include non-value reads. It does not report total_reads.
	st, nameBody := do(http.MethodGet, "/api/v1/secrets/by-name?name=total-reads&project_id=1&environment_id=1", "")
	require.Equal(t, http.StatusOK, st, string(nameBody))
	assert.NotContains(t, string(nameBody), "total_reads", "by-name must not report total_reads")
}
