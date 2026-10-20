package main

// metrics_endpoint_integration_test.go — OBS-1: the operator metrics are really on
// GET /metrics of a real, freshly initialised server (built binary, SQLite), and the
// authenticated-only audit-verification metrics are not.

import (
	"encoding/json"
	"fmt"
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

// protectedPostureMetrics are the posture/tamper series that live on
// internal/protectedmetrics and are served only at the authenticated
// /api/v1/admin/scheduler-metrics.
var protectedPostureMetrics = []string{
	"keyorix_encryption_state",
	"keyorix_encryption_kek_provider_info",
	"keyorix_encryption_operation_failures_total",
	"keyorix_encryption_kek_provider_downgrades_total",
	"keyorix_audit_write_failures_total",
	"keyorix_auth_budget_rejections_total",
	"keyorix_single_writer_unattributed_bumps_total",
}

// awaitServerHealthy polls base+"/health" for up to 30 s after cmd was started, and
// kills the child when the test ends. On timeout it fails with the child's exit state
// (exited with what, or still running) and the tail of its log, so a bind failure is
// visible in the failure message rather than only "never became reachable".
func awaitServerHealthy(t *testing.T, cmd *exec.Cmd, logPath, base string) {
	t.Helper()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
		}
	})

	var exitState string
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if resp, gerr := http.Get(base + "/health"); gerr == nil { //nolint:noctx // test-local liveness poll
			_ = resp.Body.Close()
			return
		}
		select {
		case werr := <-exited:
			exited <- werr // keep it readable for the cleanup
			exitState = fmt.Sprintf("child exited early: %v (%s)", werr, cmd.ProcessState)
		default:
		}
		if exitState != "" {
			break
		}
	}
	if exitState == "" {
		exitState = "child still running"
	}
	raw, _ := os.ReadFile(logPath) //nolint:gosec // test-generated path
	const tailBytes = 8 << 10
	if len(raw) > tailBytes {
		raw = raw[len(raw)-tailBytes:]
	}
	t.Fatalf("server never became reachable at %s: %s; log tail:\n%s", base, exitState, raw)
}

func TestMetricsEndpoint_OperatorMetricsOnRealServer(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-obs1-metrics")

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	// Same opt-out the web e2e harness uses (scripts/e2e/web-real-smoke.sh): the shared
	// bootstrap admin has no MFA, which security.require_mfa would confine to the
	// enrolment endpoints, and this test calls an ordinary admin endpoint.
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	cfgRaw, err := os.ReadFile(cfgPath) //nolint:gosec // test-generated path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(string(cfgRaw), "\n  require_mfa: true\n", "\n  require_mfa: false\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	// The server refuses a bootstrap token shorter than 32 characters.
	const bootstrapToken = "test-bootstrap-token-0123456789abcdef"
	// A free port, not the product default 8080: the CI runner runs several packages'
	// tests concurrently and anything else holding 8080 made the server fail to bind.
	port := pinFreeHTTPPort(t, dir)
	cmd := exec.Command(bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, env...), "KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken, "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	logPath := filepath.Join(dir, "metrics-server.log")
	logFile, err := os.Create(logPath) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close() //nolint:errcheck
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	base := "http://127.0.0.1:" + port
	awaitServerHealthy(t, cmd, logPath, base)

	// Generate audited traffic: bootstrapping the first admin writes audit events.
	bootstrapReq, _ := http.NewRequest(http.MethodPost, base+"/system/init", strings.NewReader(
		`{"username":"obsadmin","email":"obs1@example.com","password":"InitialPassw0rd!","display_name":"Obs Admin"}`))
	bootstrapReq.Header.Set("Content-Type", "application/json")
	bootstrapReq.Header.Set("X-Keyorix-Bootstrap-Token", bootstrapToken)
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
	// Posture and tamper signals: an anonymous reader must not learn that encryption is
	// off, which KEK source is configured, that decrypts are failing, that the KEK chain
	// downgraded, that audit appends are failing, how hard logins are being refused, or
	// that something else wrote to the fenced tables.
	for _, name := range protectedPostureMetrics {
		if strings.Contains(body, name) {
			t.Errorf("%s must not be served on the unauthenticated /metrics", name)
		}
	}

	// The authenticated endpoint serves the protected metrics to an admin session.
	loginResp, err := http.Post(base+"/auth/login", "application/json", strings.NewReader( //nolint:noctx // test-local request
		`{"username":"obsadmin","password":"InitialPassw0rd!"}`))
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	loginRaw, _ := io.ReadAll(loginResp.Body)
	_ = loginResp.Body.Close()
	if err := json.Unmarshal(loginRaw, &login); err != nil || login.Data.Token == "" {
		t.Fatalf("login failed (%d): %s", loginResp.StatusCode, loginRaw)
	}
	authReq, _ := http.NewRequest(http.MethodGet, base+"/api/v1/admin/scheduler-metrics", nil)
	authReq.Header.Set("Authorization", "Bearer "+login.Data.Token)
	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatal(err)
	}
	protectedRaw, _ := io.ReadAll(authResp.Body)
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated GET scheduler-metrics = %d: %s", authResp.StatusCode, protectedRaw)
	}
	for _, want := range []string{
		"keyorix_audit_verify_failure_recorded 0",
		"keyorix_audit_verify_state_rejected 0",
		"keyorix_encryption_state{state=",
		"keyorix_encryption_kek_provider_info{provider=",
		`keyorix_encryption_operation_failures_total{op="decrypt"} 0`,
		`keyorix_encryption_operation_failures_total{op="encrypt"} 0`,
		"keyorix_encryption_kek_provider_downgrades_total 0",
		"keyorix_audit_write_failures_total 0",
	} {
		if !strings.Contains(string(protectedRaw), want) {
			t.Errorf("authenticated scheduler-metrics is missing %q", want)
		}
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
