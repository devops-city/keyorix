// Integration test against a real Vault (or OpenBao) dev server — docs/design-keyorix-migrate.md's
// "Testing (Step 2, Vault)" section. Skips (not fails) when $VAULT_ADDR is unset, matching this
// repo's pg-gated convention (docs/security-closures.tsv's `verification` column) applied to a
// Vault dependency instead of Postgres: the CI job that sets VAULT_ADDR (a
// `hashicorp/vault:1.15 server -dev` service container) is the one that actually proves this.
//
// To run locally: `docker run -d -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root-token
// -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 hashicorp/vault:1.15`, then
// `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root-token go test ./... -run Integration`.
package vaultsource

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func requireVaultEnv(t *testing.T) (addr, token string) {
	t.Helper()
	addr = os.Getenv("VAULT_ADDR")
	if addr == "" {
		t.Skip("VAULT_ADDR not set — skipping Vault integration test (see this file's doc comment to run locally)")
	}
	token = os.Getenv("VAULT_TOKEN")
	if token == "" {
		t.Fatal("VAULT_ADDR is set but VAULT_TOKEN is not")
	}
	return addr, token
}

// vaultAdminDo issues a raw admin request against Vault to seed/inspect fixtures — the test's
// own setup, independent of the Client under test.
func vaultAdminDo(t *testing.T, addr, token, method, path string, body any) {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal admin request body: %v", err)
		}
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(context.Background(), method, addr+path, reader)
	if err != nil {
		t.Fatalf("build admin request: %v", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("admin request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 300 {
		t.Fatalf("admin request %s %s returned HTTP %d", method, path, resp.StatusCode)
	}
}

// TestIntegration_KVv2_RecursiveWalk seeds a nested KV v2 tree (single-field and multi-field
// leaves, one soft-deleted version) and asserts Walk returns exactly the live entries with the
// right names/values, skipping the soft-deleted one entirely — the exact footgun
// resolveKVMountVersion's doc comment and internal/connect/vault.go's GetSecret both document.
func TestIntegration_KVv2_RecursiveWalk(t *testing.T) {
	addr, token := requireVaultEnv(t)
	mount := "migrate-it-kv2"
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount, map[string]any{
		"type": "kv", "options": map[string]string{"version": "2"},
	})

	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/"+mount+"/data/team-a/db-password",
		map[string]any{"data": map[string]any{"value": "canary-db-pw-QX7"}})
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/"+mount+"/data/team-a/api",
		map[string]any{"data": map[string]any{"user": "admin", "pass": "canary-api-pw-ZK4"}})

	// Soft-delete a version: write it, then delete it (not destroy) — Vault answers a
	// subsequent read with {"data": null, "metadata": {...}}, a 200 OK.
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/"+mount+"/data/team-a/deleted-me",
		map[string]any{"data": map[string]any{"value": "should-never-appear"}})
	vaultAdminDo(t, addr, token, http.MethodDelete, "/v1/"+mount+"/data/team-a/deleted-me", nil)

	c, err := New(context.Background(), Config{Addr: addr, Mount: mount, Token: token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, skipped, err := c.Walk(context.Background(), "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	got := map[string]string{}
	for _, e := range entries {
		key := e.Path
		if e.Field != "" {
			key += "#" + e.Field
		}
		got[key] = e.Value
	}

	want := map[string]string{
		"team-a/db-password": "canary-db-pw-QX7",
		"team-a/api#user":    "admin",
		"team-a/api#pass":    "canary-api-pw-ZK4",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("entry %q = %q, want %q (got map: %v)", k, got[k], v, got)
		}
	}
	if _, ok := got["team-a/deleted-me"]; ok {
		t.Errorf("soft-deleted secret team-a/deleted-me was returned by Walk — should have been skipped")
	}
	if len(entries) != len(want) {
		t.Errorf("Walk returned %d entries, want %d: %v", len(entries), len(want), entries)
	}

	// Andrei's 2026-09-25 decision: a soft-deleted/destroyed latest version must be reported
	// as skipped with a reason, not silently dropped.
	if len(skipped) != 1 {
		t.Fatalf("got %d skipped entries, want 1: %+v", len(skipped), skipped)
	}
	if skipped[0].Path != "team-a/deleted-me" {
		t.Errorf("skipped[0].Path = %q, want team-a/deleted-me", skipped[0].Path)
	}
	if !strings.Contains(skipped[0].Reason, "soft-deleted") {
		t.Errorf("skipped[0].Reason = %q, want it to mention soft-deleted", skipped[0].Reason)
	}
}

// TestIntegration_KVv1_Read asserts a KV v1 mount (no /data/ or /metadata/ URL layout) is read
// correctly — the other branch of resolveKVMountVersion's dispatch.
func TestIntegration_KVv1_Read(t *testing.T) {
	addr, token := requireVaultEnv(t)
	mount := "migrate-it-kv1"
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount, map[string]any{
		"type": "kv", "options": map[string]string{"version": "1"},
	})
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/"+mount+"/legacy/token",
		map[string]any{"value": "canary-legacy-QW1"})

	c, err := New(context.Background(), Config{Addr: addr, Mount: mount, Token: token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, skipped, err := c.Walk(context.Background(), "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "legacy/token" || entries[0].Value != "canary-legacy-QW1" {
		t.Fatalf("KV v1 Walk = %+v, want one entry legacy/token=canary-legacy-QW1", entries)
	}
	if len(skipped) != 0 {
		t.Errorf("got %d skipped entries, want 0: %+v", len(skipped), skipped)
	}
}

// TestIntegration_CustomMetadata asserts KV v2 custom_metadata round-trips onto the Entry.
func TestIntegration_CustomMetadata(t *testing.T) {
	addr, token := requireVaultEnv(t)
	mount := "migrate-it-meta"
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount, map[string]any{
		"type": "kv", "options": map[string]string{"version": "2"},
	})
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/"+mount+"/data/tagged",
		map[string]any{"data": map[string]any{"value": "canary-tagged-PL9"}})
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/"+mount+"/metadata/tagged",
		map[string]any{"custom_metadata": map[string]string{"owner": "team-a", "env": "prod"}})

	c, err := New(context.Background(), Config{Addr: addr, Mount: mount, Token: token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, skipped, err := c.Walk(context.Background(), "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Metadata["owner"] != "team-a" || entries[0].Metadata["env"] != "prod" {
		t.Errorf("custom_metadata = %v, want owner=team-a env=prod", entries[0].Metadata)
	}
	if len(skipped) != 0 {
		t.Errorf("got %d skipped entries, want 0: %+v", len(skipped), skipped)
	}
	if entries[0].Version == 0 {
		t.Errorf("entries[0].Version = 0, want a KV v2 version number")
	}
	if entries[0].CreatedAt == "" {
		t.Errorf("entries[0].CreatedAt is empty, want the KV v2 created_time")
	}
}

// TestIntegration_AppRoleAuth exercises AppRole login end-to-end: mints a fresh role-id/
// secret-id pair against the running Vault, then confirms a Client built with only those
// (never a raw token) can still read data.
func TestIntegration_AppRoleAuth(t *testing.T) {
	addr, token := requireVaultEnv(t)
	mount := "migrate-it-approle"
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount, map[string]any{
		"type": "kv", "options": map[string]string{"version": "2"},
	})
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/"+mount+"/data/svc",
		map[string]any{"data": map[string]any{"value": "canary-approle-NM3"}})

	policyName := "migrate-it-approle-policy"
	policy := "path \"" + mount + "/*\" { capabilities = [\"read\",\"list\"] }\n" +
		"path \"sys/internal/ui/mounts/*\" { capabilities = [\"read\"] }"
	vaultAdminDo(t, addr, token, http.MethodPut, "/v1/sys/policies/acl/"+policyName, map[string]any{"policy": policy})

	authEnabled := struct {
		Data map[string]any `json:"data"`
	}{}
	_ = authEnabled // enabling approle auth is idempotent-if-already-enabled; ignore a 400 "already in use"
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, addr+"/v1/sys/auth/approle", strings.NewReader(`{"type":"approle"}`))
	req.Header.Set("X-Vault-Token", token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err == nil {
		resp.Body.Close() //nolint:errcheck
	}

	roleName := "migrate-it-role"
	vaultAdminDo(t, addr, token, http.MethodPost, "/v1/auth/approle/role/"+roleName, map[string]any{"policies": []string{policyName}})

	roleIDResp := struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}{}
	roleIDReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, addr+"/v1/auth/approle/role/"+roleName+"/role-id", nil)
	roleIDReq.Header.Set("X-Vault-Token", token)
	roleIDHTTPResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(roleIDReq)
	if err != nil {
		t.Fatalf("fetch role-id: %v", err)
	}
	defer roleIDHTTPResp.Body.Close() //nolint:errcheck
	if err := json.NewDecoder(roleIDHTTPResp.Body).Decode(&roleIDResp); err != nil {
		t.Fatalf("decode role-id response: %v", err)
	}

	secretIDResp := struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}{}
	secretIDReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, addr+"/v1/auth/approle/role/"+roleName+"/secret-id", nil)
	secretIDReq.Header.Set("X-Vault-Token", token)
	secretIDHTTPResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(secretIDReq)
	if err != nil {
		t.Fatalf("fetch secret-id: %v", err)
	}
	defer secretIDHTTPResp.Body.Close() //nolint:errcheck
	if err := json.NewDecoder(secretIDHTTPResp.Body).Decode(&secretIDResp); err != nil {
		t.Fatalf("decode secret-id response: %v", err)
	}

	c, err := New(context.Background(), Config{
		Addr:     addr,
		Mount:    mount,
		RoleID:   roleIDResp.Data.RoleID,
		SecretID: secretIDResp.Data.SecretID,
	})
	if err != nil {
		t.Fatalf("New (AppRole): %v", err)
	}
	entries, skipped, err := c.Walk(context.Background(), "", false)
	if err != nil {
		t.Fatalf("Walk (AppRole): %v", err)
	}
	if len(entries) != 1 || entries[0].Value != "canary-approle-NM3" {
		t.Fatalf("AppRole Walk = %+v, want one entry value=canary-approle-NM3", entries)
	}
	if len(skipped) != 0 {
		t.Errorf("got %d skipped entries, want 0: %+v", len(skipped), skipped)
	}
}

// TestIntegration_AllVersionsNotSupported asserts the honest failure mode
// (docs/design-keyorix-migrate.md's Open questions #1): --all-versions must error, not
// silently behave like latest-only.
func TestIntegration_AllVersionsNotSupported(t *testing.T) {
	addr, token := requireVaultEnv(t)
	c, err := New(context.Background(), Config{Addr: addr, Mount: "secret", Token: token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := c.Walk(context.Background(), "", true); err == nil {
		t.Fatal("Walk with allVersions=true returned no error, want an explicit unsupported error")
	}
}
