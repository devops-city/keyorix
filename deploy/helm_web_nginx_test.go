package deploy

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// DEMO-WALK-3 finding 23, Helm side (compose side: server/middleware
// TestNginxConfSingleLayerHeadersAndNoPlainHTTPHSTS). The chart's web nginx
// listens on plain http; TLS terminates at the Ingress / load balancer, so it
// must not send Strict-Transport-Security, and it must be the only layer that
// emits the security headers on proxied API responses (the backend adds the
// same set itself, so each one is hidden from the upstream response).
//
// Skips when helm is not installed, like TestShippedHelmConfig_*; CI's chart
// jobs have it. It checks the RENDERED ConfigMap, not the template text.
func TestHelmWebNginxSingleLayerHeadersAndNoPlainHTTPHSTS(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart web-config check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	out, err := exec.Command("helm", "template", "kx", chart, "-s", "templates/web-config.yaml", //nolint:gosec // fixed binary and chart path
		"--set", "web.enabled=true", "--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	conf := string(out)

	// #3058: HSTS only via $keyorix_hsts (non-empty only for a trusted proxy that says
	// X-Forwarded-Proto=https); with the default values (no web.trustedProxies) no
	// peer is trusted and no HSTS value is defined. Behaviour: TestWebNginxHSTS_HelmChart.
	stsRe := regexp.MustCompile(`(?m)^\s*add_header\s+Strict-Transport-Security\s+(\S+)\s+always;`)
	if len(stsRe.FindAllString(conf, -1)) == 0 {
		t.Error("the chart's web nginx never adds HSTS; it must for a trusted TLS-terminating proxy (#3058)")
	}
	for _, m := range stsRe.FindAllStringSubmatch(conf, -1) {
		if m[1] != "$keyorix_hsts" {
			t.Errorf("the chart's plain-http web nginx adds HSTS unconditionally (%q)", m[0])
		}
	}
	if regexp.MustCompile(`(?m)^\s*"~`).MatchString(conf) || regexp.MustCompile(`(?m)^\s+[0-9a-fA-F:.]+(/\d+)?\s+1;`).MatchString(conf) {
		t.Error("default values trust a proxy / define an HSTS value; web.trustedProxies must default to empty")
	}

	hidden := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*proxy_hide_header\s+([A-Za-z-]+);`).FindAllStringSubmatch(conf, -1) {
		hidden[m[1]] = true
	}
	added := regexp.MustCompile(`(?m)^\s*add_header\s+([A-Za-z-]+)\s`).FindAllStringSubmatch(conf, -1)
	if len(added) == 0 {
		t.Fatalf("rendered web-config has no add_header at all -- the test is not looking at the nginx config:\n%s", conf)
	}
	for _, m := range added {
		name := m[1]
		switch name {
		case "Cache-Control", "Content-Type", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
			"Access-Control-Allow-Headers", "Access-Control-Allow-Credentials":
			continue // per-response or CORS, not part of the backend's security-header set
		}
		if !hidden[name] {
			t.Errorf("nginx adds %s but does not proxy_hide_header it: proxied API responses would carry it twice", name)
		}
	}
	if !hidden["Strict-Transport-Security"] {
		t.Error("a backend HSTS must not leak through the plain-http proxy")
	}
}
