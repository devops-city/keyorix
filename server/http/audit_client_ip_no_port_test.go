package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// #3141 (from #2977 item 4): secret handlers passed r.RemoteAddr ("172.17.0.1:56508")
// raw into audit_events / secret_access_logs. The stored client IP must be the bare IP
// for a direct request, and forwarding headers must keep their exact existing trust
// rules: ignored from an untrusted peer, honoured only from a configured trusted proxy.
func TestSecretAudit_StoresClientIPWithoutPort(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		xff     string
		wantIP  string
	}{
		{"direct request stores the bare peer IP", nil, "", "127.0.0.1"},
		{"X-Forwarded-For from an untrusted peer is ignored", nil, "203.0.113.42", "127.0.0.1"},
		{"trusted proxy: forwarded client IP is stored, still without a port", []string{"127.0.0.1/32"}, "203.0.113.42", "203.0.113.42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, i18n.InitializeForTesting())
			defer i18n.ResetForTesting()

			c := newTestCore(t)
			token := createTestToken(t, c)
			cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{
				Enabled: true, Port: "8080", TrustedProxies: tc.trusted,
			}}}
			router, err := NewRouter(cfg, c)
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
				if tc.xff != "" {
					req.Header.Set("X-Forwarded-For", tc.xff)
				}
				resp, err := (&http.Client{}).Do(req)
				require.NoError(t, err)
				defer func() { _ = resp.Body.Close() }()
				b, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				return resp.StatusCode, b
			}

			st, body := do(http.MethodPost, "/api/v1/secrets", `{"name":"ip-no-port","value":"v1","project_id":1,"environment_id":1,"type":"password"}`)
			require.Equal(t, http.StatusCreated, st, string(body))
			var created struct {
				Data struct {
					ID uint `json:"ID"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(body, &created))
			id := created.Data.ID
			require.NotZero(t, id)

			st, body = do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), "")
			require.Equal(t, http.StatusOK, st, string(body))

			ctx := context.Background()
			read := "secret.read"
			sid := id
			require.Eventually(t, func() bool {
				ev, _, err := c.Storage().GetAuditLogs(ctx, &storage.AuditFilter{Action: &read, SecretID: &sid, PageSize: 100})
				return err == nil && len(ev) == 1
			}, 5*time.Second, 20*time.Millisecond, "the read must be audited")

			events, _, err := c.Storage().GetAuditLogs(ctx, &storage.AuditFilter{SecretID: &sid, PageSize: 100})
			require.NoError(t, err)
			require.NotEmpty(t, events)
			for _, e := range events {
				assert.Equal(t, tc.wantIP, e.IPAddress, "audit event %s", e.EventType)
				_, _, splitErr := net.SplitHostPort(e.IPAddress)
				assert.Error(t, splitErr, "audit event %s stored a host:port %q", e.EventType, e.IPAddress)
			}

			logs, err := c.Storage().ListSecretAccessLogs(ctx, id, time.Now().Add(-time.Hour))
			require.NoError(t, err)
			require.NotEmpty(t, logs)
			for _, l := range logs {
				assert.Equal(t, tc.wantIP, l.IPAddress, "access log %s", l.Action)
			}
		})
	}
}
