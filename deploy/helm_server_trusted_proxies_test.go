package deploy

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// COOKIE-SECURE-1: the chart's server.trustedProxies lands in the server config as
// server.http.trusted_proxies (which now also decides the Secure flag of the session
// and CSRF cookies), defaults to nothing trusted, and rejects a non-IP entry.
// Skips when helm is not installed, like the other chart tests; CI's chart jobs have it.
func TestHelmServerTrustedProxies(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart server-config check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	render := func(extra ...string) (string, error) {
		args := append([]string{"template", "kx", chart, "-s", "templates/server-config.yaml",
			"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}, extra...)
		out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary and chart path
		return string(out), err
	}

	t.Run("default trusts nothing", func(t *testing.T) {
		out, err := render()
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		if strings.Contains(out, "trusted_proxies") {
			t.Errorf("default values must not trust any proxy:\n%s", out)
		}
	})
	t.Run("value reaches server.http.trusted_proxies", func(t *testing.T) {
		out, err := render("--set", "server.trustedProxies={10.42.0.0/16,192.0.2.7}")
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, out)
		}
		for _, want := range []string{"trusted_proxies:", `- "10.42.0.0/16"`, `- "192.0.2.7"`} {
			if !strings.Contains(out, want) {
				t.Errorf("rendered server config lacks %q:\n%s", want, out)
			}
		}
		if i, j := strings.Index(out, "      http:"), strings.Index(out, "trusted_proxies:"); i < 0 || j < i {
			t.Errorf("trusted_proxies must sit under server.http:\n%s", out)
		}
		if g := strings.Index(out, "      grpc:"); g >= 0 && strings.Index(out, "trusted_proxies:") > g {
			t.Errorf("trusted_proxies must not land under server.grpc (it would be ignored there):\n%s", out)
		}
	})
	t.Run("a non-IP entry fails the render", func(t *testing.T) {
		out, err := render("--set", "server.trustedProxies={not-an-ip}")
		if err == nil {
			t.Fatalf("a non-IP trusted proxy must fail the render:\n%s", out)
		}
		if !strings.Contains(out, "server.trustedProxies") {
			t.Errorf("failure should name server.trustedProxies:\n%s", out)
		}
	})
}
