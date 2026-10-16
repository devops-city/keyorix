package main

// metrics_endpoint_integration_test.go — OBS-1: the operator metrics are really on
// GET /metrics of a real, freshly initialised server (built binary, SQLite), and the
// authenticated-only audit-verification metrics are not.

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMetricsEndpoint_OperatorMetricsOnRealServer(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-obs1-metrics")

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	const port = "8080"
	cmd := exec.Command(bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, env...), "KEYORIX_BOOTSTRAP_TOKEN=test-bootstrap-token-0123456789", "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	logFile, err := os.Create(filepath.Join(dir, "metrics-server.log")) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close() //nolint:errcheck
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := "http://localhost:" + port
	up := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if resp, gerr := http.Get(base + "/health"); gerr == nil { //nolint:noctx // test-local liveness poll
			_ = resp.Body.Close()
			up = true
			break
		}
	}
	if !up {
		raw, _ := os.ReadFile(filepath.Join(dir, "metrics-server.log")) //nolint:gosec // test-generated path
		t.Fatalf("server never became reachable; log:\n%s", raw)
	}

	// Generate audited traffic: bootstrapping the first admin writes audit events.
	bootstrapReq, _ := http.NewRequest(http.MethodPost, base+"/system/init", strings.NewReader(
		`{"username":"obsadmin","email":"obs1@example.com","password":"InitialPassw0rd!","display_name":"Obs Admin"}`))
	bootstrapReq.Header.Set("Content-Type", "application/json")
	bootstrapReq.Header.Set("X-Keyorix-Bootstrap-Token", "test-bootstrap-token-0123456789")
	if resp, derr := http.DefaultClient.Do(bootstrapReq); derr != nil {
		t.Fatalf("bootstrap: %v", derr)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bootstrap returned %d", resp.StatusCode)
		}
	}

	resp, err := http.Get(base + "/metrics") //nolint:noctx // test-local scrape
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	body := string(raw)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics returned %d:\n%s", resp.StatusCode, body)
	}

	for _, want := range []string{
		"keyorix_encryption_state{state=",
		"keyorix_single_writer_enabled 0",
		`keyorix_db_pool_connections{pool="request",state="in_use"}`,
		`keyorix_db_pool_max_connections{pool="request"}`,
		`keyorix_rate_limit_rejections_total{limiter="principal"} 0`,
		"keyorix_audit_write_duration_seconds_count",
		"keyorix_audit_group_commit_wait_seconds_count",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GET /metrics is missing %q", want)
		}
	}

	m := regexp.MustCompile(`(?m)^keyorix_audit_write_duration_seconds_count (\d+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no audit write latency sample count on /metrics")
	}
	if n, _ := strconv.Atoi(m[1]); n == 0 {
		t.Error("audited bootstrap traffic produced no keyorix_audit_write_duration_seconds observations")
	}
	if strings.Contains(body, "keyorix_audit_verify_") {
		t.Error("audit-verification metrics must not be served on the unauthenticated /metrics")
	}

	// The authenticated endpoint refuses an anonymous caller.
	anon, err := http.Get(base + "/api/v1/admin/scheduler-metrics") //nolint:noctx // test-local request
	if err != nil {
		t.Fatal(err)
	}
	_ = anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized && anon.StatusCode != http.StatusForbidden {
		t.Errorf("anonymous GET /api/v1/admin/scheduler-metrics = %d, want 401/403", anon.StatusCode)
	}
}
