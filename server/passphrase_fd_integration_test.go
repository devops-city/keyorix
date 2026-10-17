package main

// passphrase_fd_integration_test.go: `keyorix-server --passphrase-fd=N` reads
// the master passphrase from an inherited file descriptor (ADR-099), the
// documented systemd LoadCredential= recipe. The flag was declared with
// flag.IntVar, which never sets PassphraseSource.FDSet, so the server ignored
// it and reported "no master passphrase available". Driven against the built
// binary: the passphrase is NOT in the environment, only on fd 3.

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServer_PassphraseFD_IsHonoured(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "passphrase-fd-test-passphrase-0123456789"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)
	for _, args := range [][]string{
		{"init", "--dev", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
		{"migrate", "--config", "./keyorix.yaml"},
	} {
		if out, err := runAdmin(t, bin, dir, env, args...); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	port := freeTCPPort(t)
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(raw), `port: "8080"`, `port: "`+port+`"`, 1)
	if text == string(raw) {
		t.Fatal("config template no longer has the 8080 port line this test rewrites")
	}
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}

	credFile := filepath.Join(dir, "credential")
	if err := os.WriteFile(credFile, []byte(passphrase+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	cred, err := os.Open(credFile) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cred.Close() }()

	// No passphrase in the environment: only fd 3 (ExtraFiles[0]).
	serverEnv := append(baseEnv(dir), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	cmd := exec.Command(bin, "--passphrase-fd=3") //nolint:gosec // this suite's own binary
	cmd.Dir, cmd.Env = dir, serverEnv
	cmd.ExtraFiles = []*os.File{cred}
	var logBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &logBuf, &logBuf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() {
		_ = cmd.Process.Kill()
		<-exited
	}()

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("the server exited instead of reading the passphrase from fd 3:\n%s", logBuf.String())
		default:
		}
		if resp, err := http.Get("http://127.0.0.1:" + port + "/health"); err == nil { //nolint:gosec,noctx // loopback test URL
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server never became healthy with --passphrase-fd=3:\n%s", logBuf.String())
}

func TestServer_PassphraseFD_RejectsNonNumeric(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	cmd := exec.Command(bin, "--passphrase-fd=abc") //nolint:gosec // this suite's own binary
	cmd.Dir, cmd.Env = dir, baseEnv(dir)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "invalid file descriptor") {
		t.Fatalf("--passphrase-fd=abc must be refused with a clear error, got err=%v:\n%s", err, out)
	}
}

// TestAdminDiagnose_PassphraseFD_IsHonoured: the admin commands that take the
// passphrase sources had the same IntVar defect (server/admin/passphrase.go).
// No KEYORIX_MASTER_PASSWORD in the environment: only fd 3.
func TestAdminDiagnose_PassphraseFD_IsHonoured(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "passphrase-fd-admin-passphrase-0123456789"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)
	for _, args := range [][]string{
		{"init", "--dev", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
		{"migrate", "--config", "./keyorix.yaml"},
	} {
		if out, err := runAdmin(t, bin, dir, env, args...); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	credFile := filepath.Join(dir, "credential")
	if err := os.WriteFile(credFile, []byte(passphrase+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	cred, err := os.Open(credFile) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cred.Close() }()

	cmd := exec.Command(bin, "admin", "diagnose", "--config", "./keyorix.yaml", "--passphrase-fd=3") //nolint:gosec // this suite's own binary
	cmd.Dir, cmd.Env = dir, baseEnv(dir)                                                             // no passphrase in the environment
	cmd.ExtraFiles = []*os.File{cred}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("admin diagnose --passphrase-fd=3 failed (the fd was ignored?): %v\n%s", err, out)
	}
}
