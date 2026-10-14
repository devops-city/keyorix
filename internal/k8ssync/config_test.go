package k8ssync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "k8s-sync.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestLoadConfig_Valid(t *testing.T) {
	p := writeConfig(t, `
keyorix_url: https://keyorix.internal
project_id: 42
interval: 2m
mappings:
  - ref: production/db-password
    namespace: app
    name: db-creds
    key: DB_PASSWORD
  - ref: production/api-key
    namespace: app
    name: db-creds
    key: API_KEY
`)
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	assert.Equal(t, "https://keyorix.internal", cfg.KeyorixURL)
	assert.EqualValues(t, 42, cfg.ProjectID)
	assert.Equal(t, 2*time.Minute, cfg.GetInterval())
	require.Len(t, cfg.Mappings, 2)
	assert.Equal(t, "production/db-password", cfg.Mappings[0].Ref)
	assert.Equal(t, "DB_PASSWORD", cfg.Mappings[0].Key)
}

func TestLoadConfig_DefaultInterval(t *testing.T) {
	p := writeConfig(t, `
keyorix_url: https://k
project_id: 1
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`)
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, cfg.GetInterval(), "interval defaults to 5m when unset")
}

func TestLoadConfig_Invalid(t *testing.T) {
	cases := map[string]string{
		"missing url": `
project_id: 1
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`,
		"missing project_id": `
keyorix_url: https://k
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`,
		"no mappings": `
keyorix_url: https://k
project_id: 1
`,
		"bad mapping": `
keyorix_url: https://k
project_id: 1
mappings:
  - {ref: e/n, namespace: ns, name: s}
`,
		"bad interval": `
keyorix_url: https://k
project_id: 1
interval: "soon"
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`,
		"cleartext url": `
keyorix_url: http://keyorix.internal
project_id: 1
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, body))
			assert.Error(t, err)
		})
	}
}

// TestLoadConfig_MissingProjectID verifies the specific error message for a missing
// project_id (#Bug1: without it, secret lookups can't be scoped to one project).
func TestLoadConfig_MissingProjectID(t *testing.T) {
	p := writeConfig(t, `
keyorix_url: https://keyorix.internal
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`)
	_, err := LoadConfig(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id is required")
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	assert.Error(t, err)
}

// #178: a non-https keyorix_url must be rejected, UNLESS the host is loopback (local
// development against a Keyorix instance on the same machine) — matching the
// established #122/#544 convention (internal/mcp.NewKeyorixClient).
func TestLoadConfig_KeyorixURLScheme(t *testing.T) {
	mappings := `
project_id: 1
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`
	cases := map[string]struct {
		url     string
		wantErr bool
	}{
		"https allowed":            {"https://keyorix.internal", false},
		"http non-loopback denied": {"http://keyorix.internal", true},
		"http localhost allowed":   {"http://localhost:8080", false},
		"http 127.0.0.1 rejected":  {"http://127.0.0.1:8080", true},
		"http ::1 rejected":        {"http://[::1]:8080", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfig(t, "keyorix_url: "+tc.url+mappings))
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.url, cfg.KeyorixURL)
			}
		})
	}
}

func TestSync_LogsSummary(t *testing.T) {
	var lines []string
	logf := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	res := Sync(context.Background(), NewEngine(f, s), []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	}, logf)

	assert.Equal(t, 1, res.Created)
	require.NotEmpty(t, lines)
	assert.Contains(t, lines[0], "created=1")
	assert.Contains(t, lines[0], "failed=0")
}
