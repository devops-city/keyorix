//go:build e2e

// CI-FIX-5 regression coverage: RewritePort must set server.http.port in the
// config `admin init` actually writes. portLineRe once anchored on
// "enabled: true\n port:" and silently matched nothing after #2946 inserted
// comment lines between the two keys, so every e2e server kept 8080 while the
// harness polled its random port ("never became healthy" on the first
// merge_group run of every PR).
package harness

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestRewriteHTTPPort_RealTemplate runs the rewrite against the shipped
// template, so a future template edit that moves or reformats the key turns
// this red instead of silently leaving servers on 8080.
func TestRewriteHTTPPort_RealTemplate(t *testing.T) {
	raw, err := os.ReadFile("../../../configs/keyorix.yaml.tpl")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	out, ok := rewriteHTTPPort(string(raw), "45678")
	if !ok {
		t.Fatal("server.http.port not found in configs/keyorix.yaml.tpl")
	}
	httpPort := regexp.MustCompile(`(?m)^  http:\n(?:.*\n)*?    port: "(\d+)"`).FindStringSubmatch(out)
	if httpPort == nil || httpPort[1] != "45678" {
		t.Errorf("server.http.port not rewritten to 45678: %v", httpPort)
	}
	if !strings.Contains(out, `port: "9090"`) {
		t.Error("server.grpc.port (9090) must be left alone")
	}
	if strings.Count(out, `"45678"`) != 1 {
		t.Errorf("expected exactly one rewritten port, got %d", strings.Count(out, `"45678"`))
	}
}

// TestRewriteHTTPPort_SyntheticLayouts covers comment/sibling lines between
// enabled and port, and a Postgres storage block carrying its own port.
func TestRewriteHTTPPort_SyntheticLayouts(t *testing.T) {
	const cfg = `server:
  http:
    enabled: true
    # explanation
    # host: "127.0.0.1"
    port: "8080"
    tls:
      enabled: true
  grpc:
    enabled: false
    port: "9090"
storage:
  database:
    port: "15433"
`
	out, ok := rewriteHTTPPort(cfg, "40000")
	if !ok {
		t.Fatal("no match")
	}
	want := strings.Replace(cfg, `port: "8080"`, `port: "40000"`, 1)
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	if _, ok := rewriteHTTPPort("server:\n  grpc:\n    port: \"9090\"\n", "1"); ok {
		t.Error("must not match when server.http.port is absent")
	}
}
