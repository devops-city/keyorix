package main

// admin_init_secure_baseline_test.go: SECURE-DEFAULT-1. ADR-112 §4 requires the
// posture command, run against the default configuration, to report zero
// deviations. The default configuration is what `keyorix-server admin init`
// writes, so this drives the documented first-install sequence against the real
// binary (init -> encryption init -> migrate -> validate --posture) and requires
// a clean report, then boots the server on that config and checks the generated
// TLS certificate and metrics token actually take effect.
//
// The --dev config is the deliberate exception: it must say DEV-ONLY in the file
// and must FAIL the posture check, so it can never be mistaken for the default.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const secureBaselinePassphrase = "test-passphrase-secure-baseline"

// initToMigrated runs the documented first-install sequence in dir.
func initToMigrated(t *testing.T, bin, dir string, env []string, initArgs ...string) string {
	t.Helper()
	initOut, err := runAdmin(t, bin, dir, env, append([]string{"init", "--config", "./keyorix.yaml"}, initArgs...)...)
	if err != nil {
		t.Fatalf("admin init %v failed: %v\n%s", initArgs, err, initOut)
	}
	if out, err := runAdmin(t, bin, dir, env, "encryption", "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin encryption init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	return initOut
}

func TestAdminInit_DefaultConfigPassesSecureBaselinePosture(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+secureBaselinePassphrase)

	initOut := initToMigrated(t, bin, dir, env)

	// Generated secret material: owner-only, and never echoed to stdout.
	for _, rel := range []string{"keyorix.yaml", "secrets/metrics_token", "certs/server.key", "certs/server.crt"} {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("admin init did not create %s: %v", rel, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s has mode %04o, want 0600", rel, perm)
		}
	}
	tokenBytes, err := os.ReadFile(filepath.Join(dir, "secrets/metrics_token"))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) < 32 {
		t.Fatalf("metrics token is %d characters, want at least 32", len(token))
	}
	if strings.Contains(initOut, token) {
		t.Fatalf("admin init printed the generated metrics token to stdout:\n%s", initOut)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "certs/server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(initOut, strings.TrimSpace(string(keyPEM))) || strings.Contains(initOut, "PRIVATE KEY") {
		t.Fatalf("admin init printed the TLS private key to stdout:\n%s", initOut)
	}

	// The config references the token file; it never holds the token, and it
	// is not the DEV-ONLY variant.
	cfgBytes, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfgBytes), token) {
		t.Fatal("the generated config contains the metrics token itself; it must only reference the token file")
	}
	if strings.Contains(string(cfgBytes), "DEV-ONLY") {
		t.Fatal("the default (secure) config is labelled DEV-ONLY")
	}
	// The printed trust step names the generated certificate.
	if !strings.Contains(initOut, "keyorix config set ca_file ") || !strings.Contains(initOut, "KEYORIX_CA_FILE=") {
		t.Fatalf("admin init did not print how to trust the generated certificate:\n%s", initOut)
	}

	out, err := runAdmin(t, bin, dir, env, "validate", "--posture", "--config", "./keyorix.yaml")
	if err != nil || !strings.Contains(out, "No deviations found.") {
		t.Fatalf("validate --posture on the config admin init generated must report zero deviations (err=%v):\n%s", err, out)
	}

	// The config must also boot, serve TLS with the generated certificate, and
	// gate /metrics on the generated token.
	port := freeTCPPort(t)
	setConfigPort(t, filepath.Join(dir, "keyorix.yaml"), port)
	startServerInDir(t, bin, dir, env)

	pool := x509.NewCertPool()
	certPEM, err := os.ReadFile(filepath.Join(dir, "certs/server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("certs/server.crt is not a PEM certificate")
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	base := "https://localhost:" + port
	waitForHealth(t, client, base+"/health", dir)

	if code := getStatus(t, client, base+"/metrics", ""); code != http.StatusUnauthorized {
		t.Errorf("/metrics without the token: status %d, want 401", code)
	}
	if code := getStatus(t, client, base+"/metrics", token); code != http.StatusOK {
		t.Errorf("/metrics with the generated token: status %d, want 200", code)
	}
	plain := &http.Client{Timeout: 5 * time.Second}
	if resp, err := plain.Get("http://localhost:" + port + "/health"); err == nil {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "ok") {
			t.Errorf("the generated config served /health over cleartext HTTP")
		}
	}
}

func TestAdminInitDev_IsLabelledAndFailsSecureBaselinePosture(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+secureBaselinePassphrase)

	initToMigrated(t, bin, dir, env, "--dev")

	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "DEV-ONLY") {
		t.Fatalf("admin init --dev wrote a config without the DEV-ONLY label:\n%s", raw)
	}
	for _, rel := range []string{"secrets/metrics_token", "certs/server.key", "certs/server.crt"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			t.Errorf("admin init --dev generated %s; the dev config does not reference it", rel)
		}
	}

	out, err := runAdmin(t, bin, dir, env, "validate", "--posture", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("validate --posture must fail on the --dev config, got exit 0:\n%s", out)
	}
	for _, want := range []string{
		"security.insecure_allow_cleartext_transport",
		"server.insecure_allow_unauthenticated_metrics",
		"server.insecure_disable_api_ratelimit",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate --posture on the --dev config does not report %s:\n%s", want, out)
		}
	}
}

// TestAdminInit_ExistingConfigIsNotChanged: ADR-112 "no silent change" for
// existing installs. Re-running admin init next to an existing config leaves the
// config alone and generates nothing it would reference.
func TestAdminInit_ExistingConfigIsNotChanged(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+secureBaselinePassphrase)

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init --dev failed: %v\n%s", err, out)
	}
	before, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("second admin init failed: %v\n%s", err, out)
	}
	after, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("admin init rewrote an existing config without --overwrite-existing")
	}
	for _, rel := range []string{"secrets/metrics_token", "certs/server.key"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			t.Errorf("admin init generated %s for an existing config it did not write", rel)
		}
	}
}

var configPortLine = regexp.MustCompile(`(?m)^(    port: )"8080"`)

// setConfigPort points the HTTP listener of an admin-init config at port.
func setConfigPort(t *testing.T, path, port string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !configPortLine.Match(raw) {
		t.Fatalf("%s has no `port: \"8080\"` line to rewrite", path)
	}
	if err := os.WriteFile(path, configPortLine.ReplaceAll(raw, []byte(fmt.Sprintf(`${1}"%s"`, port))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func startServerInDir(t *testing.T, bin, dir string, env []string) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(append([]string(nil), env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	})
}

func waitForHealth(t *testing.T, client *http.Client, url, dir string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
	t.Fatalf("server never became healthy at %s (last: %v); server log:\n%s", url, lastErr, logBytes)
}

func getStatus(t *testing.T, client *http.Client, url, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
