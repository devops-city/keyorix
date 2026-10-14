package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// DEPLOY-2 decision 2 (Andrei, 2026-10-10): the two shipped deployment configs run with
// security.enable_file_permission_check ON -- key material (and, with *_FILE, secret
// files) strict, orchestrator-mounted config/TLS files warn.
//
// How it is expressed: both configs OMIT the key. Since ADR-112 (#2446) an absent key
// resolves to true, and ONLY on that implicit default are the orchestrator-mounted
// config file and TLS files softened to a warning (an explicit `true` audits them
// strictly, and the Helm ConfigMap is root-owned 0644 / the compose bind mount keeps
// the host owner, so an explicit `true` would refuse to start). The guard therefore
// asserts the EFFECTIVE setting, loaded through the server's own config loader, so it
// is right whichever way the key is spelled and fails if someone adds `false`.
//
// What this does not cover: that the server then boots under it. That is proven on
// the bench (compose and kind), see the PR.

func effectivePermissionCheck(t *testing.T, path string) (on, implicit bool) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", path, err)
	}
	return cfg.Security.EnableFilePermissionCheck, cfg.Security.EnableFilePermissionCheckImplicitDefault
}

func TestShippedComposeConfig_FilePermissionCheckIsOn(t *testing.T) {
	on, implicit := effectivePermissionCheck(t, withLocalTokenFile(t, "keyorix.docker.yaml", "/app/tls/metrics_token"))
	if !on {
		t.Error("keyorix.docker.yaml: effective security.enable_file_permission_check is false -- remove the `false`; the key must be omitted (implicit true) so that the bind-mounted config only warns")
	}
	if !implicit {
		t.Error("keyorix.docker.yaml sets security.enable_file_permission_check explicitly: an explicit true audits the host-owned bind-mounted config strictly and the container would refuse to start; omit the key (ADR-112 implicit default)")
	}
}

func TestShippedHelmConfig_FilePermissionCheckIsOn(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart config check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	out, err := exec.Command("helm", "template", "kx", chart, "-s", "templates/server-config.yaml", //nolint:gosec // fixed binary and chart path
		"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(out, &cm); err != nil {
		t.Fatal(err)
	}
	body, ok := cm.Data["keyorix.yaml"]
	if !ok {
		t.Fatalf("server ConfigMap has no keyorix.yaml: %s", out)
	}
	p := filepath.Join(t.TempDir(), "keyorix.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	on, implicit := effectivePermissionCheck(t, p)
	if !on {
		t.Error("Helm server ConfigMap: effective security.enable_file_permission_check is false")
	}
	if !implicit {
		t.Error("Helm server ConfigMap sets security.enable_file_permission_check explicitly: an explicit true audits the root-owned 0644 ConfigMap file strictly and the pod would refuse to start; omit the key (ADR-112 implicit default)")
	}
}
