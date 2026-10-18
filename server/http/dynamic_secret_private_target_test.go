// dynamic_secret_private_target_test.go — MIGRATE-VERIFY-1 finding, fixed by CLI-UX-2 item 11:
// registering a dynamic-secret target on a private-network host answered
// "an internal error occurred" (HTTP 400) while the server log had the useful text. The
// client now gets what was refused and which setting allows it, and still nothing else:
// no credentials from the DSN, no address the host resolved to.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func (f *dynSecret403Fixture) createConfig(t *testing.T, adminDSN string) (int, string) {
	t.Helper()
	ctx := context.Background()
	projects, err := f.core.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	body, err := json.Marshal(map[string]any{
		"name": "private-target", "project_id": projects[0].ID, "backend_type": "postgres",
		"admin_dsn": adminDSN, "default_ttl_seconds": 300, "max_ttl_seconds": 3600, "max_active_leases": 5,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, f.serverURL+"/api/v1/dynamic-secrets/configs", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+f.adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func TestDynamicSecretCreate_PrivateTargetSaysWhatWasRefusedAndWhichSettingAllowsIt(t *testing.T) {
	f := newDynSecret403Fixture(t)

	t.Run("private IP literal", func(t *testing.T) {
		status, body := f.createConfig(t, "postgres://admin:S3cretPw@10.0.0.5:5432/app")
		require.Equal(t, http.StatusBadRequest, status, body)
		require.Contains(t, body, "10.0.0.5", "name what was refused")
		require.Contains(t, body, "dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets", "name the setting that allows it")
		require.NotContains(t, body, "internal error", "the generic masking text told the operator nothing")
		require.NotContains(t, body, "S3cretPw", "never echo credentials from the DSN")
	})

	t.Run("hostname that resolves to a private address", func(t *testing.T) {
		// localhost resolves to a loopback address on every host this test runs on.
		status, body := f.createConfig(t, "postgres://admin:S3cretPw@localhost:5432/app")
		require.Equal(t, http.StatusBadRequest, status, body)
		require.Contains(t, body, "localhost")
		require.Contains(t, body, "dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets")
		require.NotContains(t, body, "internal error")
		require.NotContains(t, body, "S3cretPw")
		// The addresses the server's resolver returned are internal knowledge: a caller
		// probing hostnames must not learn them from the error text.
		for _, addr := range []string{"127.0.0.1", "::1"} {
			require.NotContains(t, body, addr, "resolved address leaked: %s", fmt.Sprint(addr))
		}
	})

	t.Run("an unrelated failure does not claim the egress policy refused it", func(t *testing.T) {
		// Only the SSRF refusal gets the specific message: anything else keeps the generic one (a driver or
		// storage error must not reach the client), and never names the egress setting.
		status, body := f.createConfig(t, "")
		require.Equal(t, http.StatusBadRequest, status, body)
		require.NotContains(t, body, "dynamic_secrets.insecure_allow")
	})
}
