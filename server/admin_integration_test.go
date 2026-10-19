package main

// admin_integration_test.go exercises `keyorix-server admin <cmd>` as a real
// subprocess against the built binary (ADR-108 §B, PR 11) -- the same
// build-then-exec pattern internal/cli/cli_remote_mode_behavior_test.go uses
// for the CLI binary. Covers: plain `keyorix-server` flag parsing/behavior
// stays unchanged; each admin command against a temp SQLite database; the
// running-server guard refuses without --force; `admin diagnose` names the
// failing check for a broken config, a missing KEK, and an unmigrated
// database. Postgres-backed admin-command coverage lives in
// admin_integration_postgres_test.go (gated on KEYORIX_TEST_PG_DSN).

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
)

var (
	sharedServerBinOnce sync.Once
	sharedServerBinDir  string
	sharedServerBinPath string
	sharedServerBinErr  error
)

// TestMain removes the shared server-binary build directory once every test in
// the package has finished. t.TempDir is per-test, so it cannot own a binary
// built once for the whole run; without this the ~99 MB build dir leaked into
// $TMPDIR on every run of this package (TEST-TMP-LEAK-1).
func TestMain(m *testing.M) {
	code := m.Run()
	if sharedServerBinDir != "" {
		_ = os.RemoveAll(sharedServerBinDir)
	}
	os.Exit(code)
}

// buildServerBinary compiles the real keyorix-server binary once for the
// whole test binary run (not once per test function -- every subprocess
// test in this file exercises the identical build, and `go build ./server`
// alone takes several seconds; paying that N times across a dozen tests
// dominated this suite's wall-clock for no benefit).
func buildServerBinary(t *testing.T) string {
	t.Helper()
	sharedServerBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "keyorix-server-admin-test-bin-*")
		if err != nil {
			sharedServerBinErr = err
			return
		}
		sharedServerBinDir = dir // removed by TestMain, also when the build below fails
		binPath := filepath.Join(dir, "keyorix-server")
		repoRoot := findServerRepoRoot(t)
		cmd := exec.Command("go", "build", "-o", binPath, "./server")
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			sharedServerBinErr = fmt.Errorf("failed to build keyorix-server binary: %w\n%s", err, out)
			return
		}
		sharedServerBinPath = binPath
	})
	if sharedServerBinErr != nil {
		t.Fatalf("%v", sharedServerBinErr)
	}
	return sharedServerBinPath
}

// findServerRepoRoot walks up from the current working directory (server/)
// to the directory containing go.mod, since `go build ./server` must run
// from the module root.
func findServerRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) walking up from server/")
		}
		dir = parent
	}
}

func runAdmin(t *testing.T, binPath, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binPath, append([]string{"admin"}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// adminConfigForProbe loads a config file the same way admin commands do,
// for tests that need to call internal/serverguard.ProbeRunning directly
// in-process (see waitForPresence).
func adminConfigForProbe(path string) (*config.Config, error) {
	return config.Load(path)
}

// waitForPresence polls internal/serverguard.ProbeRunning in-process until
// it reports a live server (or the timeout elapses). See
// TestAdminGuard_RefusesWhileServerRunning_ThenForceOverrides's inline
// comment for why polling must go through ProbeRunning directly rather than
// shelling out to an admin command that could itself race the server's own
// boot-time lock acquisitions.
func waitForPresence(t *testing.T, cfg *config.Config, timeoutSeconds int) bool {
	t.Helper()
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		running, _, err := serverguard.ProbeRunning(cfg)
		if err != nil {
			t.Fatalf("ProbeRunning: %v", err)
		}
		if running {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// waitForLockFree is waitForPresence's mirror image: polls
// internal/serverguard.ProbeRunning until it reports NO live server or admin
// operation holds cfg's lock (or the timeout elapses). Use this after
// releasing a lock holder (a subprocess exiting, a killed/shut-down server)
// and before the test re-acquires the same lock -- a subprocess exiting, or
// cmd.Wait() returning, is not by itself proof the underlying lock is free.
// Product code (internal/serverguard's acquirePostgresExclusive/Presence)
// already calls pg_advisory_unlock explicitly and synchronously before
// closing its connection, but a CI run (36115004629) captured a server
// startup still refused up to the full poll window after the admin
// lock-holder had already exited -- polling the lock's OBSERVED state, not
// trusting process-exit as a release signal, is what actually closes that
// gap regardless of its exact cause.
func waitForLockFree(t *testing.T, cfg *config.Config, timeoutSeconds int) bool {
	t.Helper()
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for {
		running, _, err := serverguard.ProbeRunning(cfg)
		if err != nil {
			t.Fatalf("ProbeRunning: %v", err)
		}
		if !running {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func baseEnv(dir string) []string {
	env := []string{
		"HOME=" + dir,
		"PATH=/usr/bin:/bin",
	}
	// Honour the caller's temp dir: the child (admin restore creates a staging
	// directory under os.TempDir) otherwise falls back to /tmp, which a
	// sandboxed runner may not allow writing. Only forwarded when set, so an
	// environment without TMPDIR (CI) is unchanged.
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	return env
}

// freeTCPPort returns a port number no listener is bound to, by binding to
// 127.0.0.1:0 (kernel-assigned) and immediately releasing it. This repo's
// admin/server integration tests previously hard-coded distinct ports
// (8080/8081/8082) per test to avoid same-suite collisions -- a magic
// number that still collides with anything else already using that exact
// port on the host or CI runner, and silently caps how many such tests can
// coexist. There is an inherent, narrow TOCTOU window between this call and
// the caller's own listener binding that port; acceptable here since this
// is only used to hand out non-colliding default ports for test servers,
// not for anything security-sensitive.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free TCP port: %v", err)
	}
	defer l.Close() //nolint:errcheck
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// --- Plain server flag parsing/behavior stays unchanged ---------------------

func TestPlainServer_PassphraseFlagsStillParse(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()

	// No config file present: the plain server must reach config loading and
	// fail there -- NOT fail on flag parsing (which would mean the admin
	// dispatch broke the existing -passphrase-* flag set).
	cmd := exec.Command(bin, "-passphrase-stdin")
	cmd.Dir = dir
	cmd.Env = baseEnv(dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected the plain server to fail (no config present), got success:\n%s", out)
	}
	if strings.Contains(string(out), "flag provided but not defined") {
		t.Fatalf("admin dispatch broke plain-server flag parsing: %s", out)
	}
	if strings.Contains(string(out), "not defined: -passphrase-stdin") {
		t.Fatalf("passphrase-stdin flag no longer recognized: %s", out)
	}
}

func TestPlainServer_HelpUsageUnchanged(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	cmd := exec.Command(bin, "-h")
	cmd.Dir = dir
	cmd.Env = baseEnv(dir)
	out, _ := cmd.CombinedOutput()
	for _, want := range []string{"-passphrase-fd", "-passphrase-file", "-passphrase-stdin"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("expected plain server -h usage to mention %q, got:\n%s", want, out)
		}
	}
	// The stdlib flag package's usage output has no concept of subcommands at
	// all -- it is exactly the flag list above, nothing else. Checking for
	// "Available Commands:" (cobra's own section heading, used by `admin
	// --help`) is more precise than a bare "admin" substring, which
	// false-positives on the binary's own temp path
	// (buildServerBinary names it .../keyorix-server-admin-test-bin-*/...).
	if strings.Contains(string(out), "Available Commands:") {
		t.Errorf("plain server -h usage should not look like the cobra-based admin command tree:\n%s", out)
	}
}

func TestAdminDispatch_DoesNotStartAListener(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	out, err := runAdmin(t, bin, dir, baseEnv(dir), "--help")
	if err != nil {
		t.Fatalf("admin --help failed: %v\n%s", err, out)
	}
	for _, want := range []string{"init", "validate", "audit", "diagnose", "migrate"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected admin --help to list %q, got:\n%s", want, out)
		}
	}
}

// --- Full admin workflow against a temp SQLite database ---------------------

func TestAdminWorkflow_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-sqlite")

	out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keyorix.yaml")); statErr != nil {
		t.Fatalf("expected config file to be created: %v", statErr)
	}

	// First diagnose creates the DEK (first-boot key derivation) and must
	// report every check passing.
	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"[ OK ] config parse",
		"[ OK ] KEK/passphrase access",
		"[ OK ] database open",
		"[ OK ] migration state",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected diagnose output to contain %q, got:\n%s", want, out)
		}
	}

	out, err = runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "All validations passed") {
		t.Errorf("expected validate to pass after init+diagnose, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin audit failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Audit passed") {
		t.Errorf("expected audit to pass, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "migrated successfully") {
		t.Errorf("expected migrate to report success, got:\n%s", out)
	}

	// migrate must be idempotent -- re-running against an already-migrated DB
	// must still succeed.
	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("second admin migrate (idempotency check) failed: %v\n%s", err, out)
	}
}

// --- diagnose names the failing check ---------------------------------------

func TestAdminDiagnose_BrokenConfig(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte("not: [valid yaml"), 0600); err != nil {
		t.Fatalf("write broken config: %v", err)
	}
	out, err := runAdmin(t, bin, dir, baseEnv(dir), "diagnose", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("expected diagnose to fail against a broken config, got success:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] config parse") {
		t.Errorf("expected diagnose to name 'config parse' as the failing check, got:\n%s", out)
	}
}

func TestAdminDiagnose_MissingKEK(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir) // deliberately no KEYORIX_MASTER_PASSWORD

	out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("expected diagnose to fail with no passphrase available, got success:\n%s", out)
	}
	if !strings.Contains(out, "[ OK ] config parse") {
		t.Errorf("expected config parse to pass before the KEK check, got:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] KEK/passphrase access") {
		t.Errorf("expected diagnose to name 'KEK/passphrase access' as the failing check, got:\n%s", out)
	}
}

func TestAdminDiagnose_UnmigratedDatabase(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-unmigrated")

	out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}

	// Derive the KEK without ever opening storage through the migrating
	// factory: init's own audit-event recording (recordAdminAction) DOES
	// open (and thus migrate) storage as a side effect, so use --config only
	// through diagnose's encryption check in isolation is not enough to
	// avoid it. Delete the database file init created and replace it with an
	// empty, definitely-unmigrated one to force the "no tables yet" state
	// diagnose's migration-state check reports.
	dbPath := filepath.Join(dir, "keyorix.db")
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove db: %v", err)
	}
	if err := os.WriteFile(dbPath, nil, 0600); err != nil {
		t.Fatalf("recreate empty db: %v", err)
	}

	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("expected diagnose to succeed (an unmigrated DB is a WARN, not a FAIL): %v\n%s", err, out)
	}
	if !strings.Contains(out, "[WARN] migration state") {
		t.Errorf("expected diagnose to WARN on an unmigrated database, got:\n%s", out)
	}
	if !strings.Contains(out, "admin migrate") {
		t.Errorf("expected diagnose to point at `admin migrate`, got:\n%s", out)
	}
}

// --- running-server guard ----------------------------------------------------

func TestAdminGuard_RefusesWhileServerRunning_ThenForceOverrides(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-guard")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	pinFreeHTTPPort(t, dir)
	// diagnose performs first-boot KEK derivation (creates keys/kek.salt and
	// keys/dek.key) -- required before the real server below can pass its own
	// startup validation and actually boot far enough to acquire the
	// presence lock this test is probing for.
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	serverEnv := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-guard", "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	serverCmd := exec.Command(bin)
	serverCmd.Dir = dir
	serverCmd.Env = serverEnv
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	defer logFile.Close() //nolint:errcheck
	serverCmd.Stdout = logFile
	serverCmd.Stderr = logFile
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = serverCmd.Process.Kill()
		_, _ = serverCmd.Process.Wait()
	})

	// Poll internal/serverguard.ProbeRunning DIRECTLY (in-process, no
	// subprocess) rather than shelling out to an admin command: any admin
	// command that itself touches the pre-existing migration lock
	// (withMigrationLock, internal/storage/factory.go) or the DEK exclusive
	// lock (internal/encryption/exclusive_lock.go) during the polling window
	// races the SERVER's own boot-time acquisition of those SAME locks --
	// and since both are non-blocking, whichever side loses hard-fails
	// instead of waiting, which can kill the server this test is trying to
	// observe. ProbeRunning touches only the NEW presence lock this task
	// adds, so it cannot collide with either pre-existing lock.
	probeCfg, err := adminConfigForProbe(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatalf("load config for probe: %v", err)
	}
	if !waitForPresence(t, probeCfg, 30) {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected the server to acquire the presence lock within the deadline; server log:\n%s", logBytes)
	}

	out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected admin migrate to refuse while the server is running, got (err=%v):\n%s\nserver log:\n%s", err, out, logBytes)
	}

	// --force must reach past the guard (and then legitimately hit the
	// pre-existing, unrelated DEK exclusive lock the live server also
	// holds -- confirming --force bypasses ONLY this guard, not every
	// safety mechanism in the codebase).
	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml", "--force")
	if err == nil {
		t.Fatalf("expected --force to still fail (DEK lock genuinely held by the live server), got success:\n%s", out)
	}
	if strings.Contains(out, "admin commands must not run concurrently") {
		t.Errorf("--force should have bypassed the server-presence guard entirely, got:\n%s", out)
	}
}

// lockHolderHook wraps the `admin __hold-lock-for-test` hidden hook (see
// server/admin/testhook.go): a subprocess that acquires and HOLDS the
// exclusive database lock until told to stop, so tests can deterministically
// hold it across a concurrent server-startup attempt without racing a real
// command's own (often sub-second) actual work.
type lockHolderHook struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	configPath string
}

// startLockHolderHook starts the hook and blocks until it confirms (via a
// "LOCKED" line on stdout) that it actually holds the lock.
func startLockHolderHook(t *testing.T, bin, dir string, env []string) *lockHolderHook {
	t.Helper()
	cmd := exec.Command(bin, "admin", "__hold-lock-for-test", "--config", "./keyorix.yaml")
	cmd.Dir = dir
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lock-holder hook: %v", err)
	}
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- scanner.Text()
		}
	}()
	select {
	case got := <-line:
		if got != "LOCKED" {
			_ = cmd.Process.Kill()
			t.Fatalf("expected lock-holder hook to print LOCKED, got %q (stderr: %s)", got, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("timed out waiting for lock-holder hook to acquire the lock (stderr: %s)", stderr.String())
	}
	return &lockHolderHook{cmd: cmd, stdin: stdin, configPath: filepath.Join(dir, "keyorix.yaml")}
}

// release tells the hook to stop holding the lock, waits for it to exit, and
// then polls until the underlying lock is OBSERVABLY free (waitForLockFree)
// before returning -- the hook process exiting is not by itself proof the
// lock it held is free; see waitForLockFree's doc comment for why a caller
// that immediately re-acquires the same lock (every current caller does)
// needs this rather than trusting cmd.Wait() alone.
func (h *lockHolderHook) release(t *testing.T) {
	t.Helper()
	_, _ = h.stdin.Write([]byte("\n"))
	_ = h.stdin.Close()
	if err := h.cmd.Wait(); err != nil {
		t.Fatalf("lock-holder hook exited with error: %v", err)
	}
	cfg, err := adminConfigForProbe(h.configPath)
	if err != nil {
		t.Fatalf("load config %q to confirm lock release: %v", h.configPath, err)
	}
	if !waitForLockFree(t, cfg, 10) {
		t.Fatalf("lock-holder hook process exited but its lock (%q) is still observably held 10s later", h.configPath)
	}
}

// TestServerStartup_RefusedWhileAdminHoldsExclusiveLock_SQLite is the
// reverse-direction regression test for the review finding: admin commands
// only PROBED the presence lock and ran unlocked, so a server starting
// after the probe raced the admin command's actual work. The fix makes
// admin commands HOLD the exclusive lock for their whole operation --
// this test confirms a server attempting to start while that lock is held
// fails FAST (non-blocking) with the specific message, and succeeds once
// the admin operation releases it.
func TestServerStartup_RefusedWhileAdminHoldsExclusiveLock_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-reverse-guard")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	pinFreeHTTPPort(t, dir)
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	hook := startLockHolderHook(t, bin, dir, env)

	serverEnv := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-reverse-guard", "KEYORIX_CONFIG_PATH=./keyorix.yaml")

	// Bounded well above what a non-blocking lock check should ever take, so
	// a regression back to blocking behavior fails this assertion instead of
	// hanging the whole test run until `go test`'s own -timeout fires.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverCmd := exec.CommandContext(ctx, bin)
	serverCmd.Dir = dir
	serverCmd.Env = serverEnv
	start := time.Now()
	out, err := serverCmd.CombinedOutput()
	elapsed := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		hook.release(t)
		t.Fatalf("server startup did not fail fast while the admin lock was held -- still running after 8s (blocking regression)")
	}
	if err == nil {
		hook.release(t)
		t.Fatalf("expected server startup to fail while the admin lock is held, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "admin operation is running against this database") {
		hook.release(t)
		t.Fatalf("expected the specific admin-operation-in-progress message, got:\n%s", out)
	}
	if !strings.Contains(string(out), "retry when it finishes") {
		hook.release(t)
		t.Fatalf("expected the message to tell the operator to retry, got:\n%s", out)
	}
	if elapsed > 5*time.Second {
		t.Errorf("server startup took %s to refuse -- expected a fast, non-blocking failure", elapsed)
	}

	hook.release(t)

	// Now that the admin operation released the lock, the server must start
	// successfully.
	serverCmd2 := exec.Command(bin)
	serverCmd2.Dir = dir
	serverCmd2.Env = serverEnv
	logFile, err := os.Create(filepath.Join(dir, "server-after-release.log"))
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	defer logFile.Close() //nolint:errcheck
	serverCmd2.Stdout = logFile
	serverCmd2.Stderr = logFile
	if err := serverCmd2.Start(); err != nil {
		t.Fatalf("start server after hook release: %v", err)
	}
	t.Cleanup(func() {
		_ = serverCmd2.Process.Kill()
		_, _ = serverCmd2.Process.Wait()
	})

	probeCfg, err := adminConfigForProbe(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatalf("load config for probe: %v", err)
	}
	if !waitForPresence(t, probeCfg, 15) {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server-after-release.log"))
		t.Fatalf("expected the server to start successfully after the admin lock released; server log:\n%s", logBytes)
	}
}

// --- backup / restore (ADR-108 §B3) ------------------------------------------

var chainedEventsRE = regexp.MustCompile(`chained events:\s+(\d+)`)

func chainedEventsCount(t *testing.T, verifyAuditOutput string) int {
	t.Helper()
	m := chainedEventsRE.FindStringSubmatch(verifyAuditOutput)
	if m == nil {
		t.Fatalf("could not find 'chained events: N' in verify-audit output:\n%s", verifyAuditOutput)
	}
	var n int
	if _, err := fmt.Sscanf(m[1], "%d", &n); err != nil {
		t.Fatalf("parse chained events count %q: %v", m[1], err)
	}
	return n
}

// TestAdminBackupRestore_SQLite_RoundTrip is the AIRGAP-E2E core assertion at
// the Go-test level (docs/AIRGAP_RUNBOOK.md and scripts/airgap-e2e.sh exercise
// the same flow end-to-end against a running container): init -> migrate ->
// backup -> wipe the data dir entirely (db file AND key files, simulating a
// genuinely fresh host) -> restore -> the audit chain's chained-event count
// is identical and verify-audit still reports VALID.
func TestAdminBackupRestore_SQLite_RoundTrip(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-backup-restore")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	beforeOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("verify-audit before backup failed: %v\n%s", err, beforeOut)
	}
	beforeCount := chainedEventsCount(t, beforeOut)
	if beforeCount == 0 {
		t.Fatalf("expected admin init/migrate to have written at least one audit event, got 0:\n%s", beforeOut)
	}

	backupPath := filepath.Join(dir, "backup.tar.gz")
	out, err := runAdmin(t, bin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", "./backup.tar.gz")
	if err != nil {
		t.Fatalf("admin backup failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Backup written to") {
		t.Errorf("expected backup to report success, got:\n%s", out)
	}
	if _, statErr := os.Stat(backupPath); statErr != nil {
		t.Fatalf("expected backup archive to exist: %v", statErr)
	}

	// Simulate a genuinely fresh host: remove the database AND every
	// key-material file admin init created, not just the database. A backup
	// that only restores the DB and leaves stale keys behind would silently
	// pass this test for the wrong reason (the OLD keys would still decrypt
	// fine) -- wiping both is what actually exercises the restore path.
	if err := os.Remove(filepath.Join(dir, "keyorix.db")); err != nil {
		t.Fatalf("remove db: %v", err)
	}
	keysDir := filepath.Join(dir, "keys")
	if err := os.RemoveAll(keysDir); err != nil {
		t.Fatalf("remove keys dir: %v", err)
	}

	out, err = runAdmin(t, bin, dir, env, "restore", "--config", "./keyorix.yaml", "--input", "./backup.tar.gz")
	if err != nil {
		t.Fatalf("admin restore failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Restored ") || !strings.Contains(out, "table(s)") {
		t.Errorf("expected restore to report success, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose after restore failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"[ OK ] config parse",
		"[ OK ] KEK/passphrase access",
		"[ OK ] database open",
		"[ OK ] migration state",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected post-restore diagnose to contain %q, got:\n%s", want, out)
		}
	}

	afterOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("verify-audit after restore failed (expected VALID/exit 0): %v\n%s", err, afterOut)
	}
	if !strings.Contains(afterOut, "Verdict: VALID") {
		t.Errorf("expected verify-audit to report VALID after restore, got:\n%s", afterOut)
	}
	// restore itself writes one more admin.restore_completed audit event
	// AFTER the pre-backup snapshot was taken, so the post-restore chain is
	// exactly one event longer than what backup captured -- not merely equal.
	afterCount := chainedEventsCount(t, afterOut)
	if afterCount != beforeCount+1 {
		t.Errorf("expected chained events to be beforeCount+1 (%d) after the restored chain recorded its own restore event, got %d", beforeCount+1, afterCount)
	}
}

func TestAdminBackup_OutputAlreadyExists_Refuses(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-backup-exists")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup.tar.gz"), []byte("existing"), 0600); err != nil {
		t.Fatalf("pre-create output file: %v", err)
	}

	out, err := runAdmin(t, bin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", "./backup.tar.gz")
	if err == nil {
		t.Fatalf("expected admin backup to refuse an existing --output, got success:\n%s", out)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("expected the 'already exists' refusal message, got:\n%s", out)
	}
}

func TestAdminRestore_RefusesNonEmptyTargetWithoutOverwrite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-restore-nonempty")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", "./backup.tar.gz"); err != nil {
		t.Fatalf("admin backup failed: %v\n%s", err, out)
	}

	// Deliberately do NOT wipe the data dir this time -- keyorix.db still has
	// the real, non-empty database in it.
	out, err := runAdmin(t, bin, dir, env, "restore", "--config", "./keyorix.yaml", "--input", "./backup.tar.gz")
	if err == nil {
		t.Fatalf("expected admin restore to refuse a non-empty existing database without --overwrite-existing, got success:\n%s", out)
	}
	if !strings.Contains(out, "already exists and is not empty") {
		t.Errorf("expected the non-empty-target refusal message, got:\n%s", out)
	}

	// --overwrite-existing must let it through.
	out, err = runAdmin(t, bin, dir, env, "restore", "--config", "./keyorix.yaml", "--input", "./backup.tar.gz", "--overwrite-existing")
	if err != nil {
		t.Fatalf("admin restore --overwrite-existing failed: %v\n%s", err, out)
	}
	// The replaced database must be kept aside, never deleted or truncated.
	aside, _ := filepath.Glob(filepath.Join(dir, "keyorix.db.pre-restore-*"))
	if len(aside) == 0 {
		t.Errorf("expected the pre-restore database to be moved aside as keyorix.db.pre-restore-*, found none")
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose after --overwrite-existing restore failed: %v\n%s", err, out)
	}
}

func TestAdminRestore_ChecksumMismatchDetected(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-restore-corrupt")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", "./backup.tar.gz"); err != nil {
		t.Fatalf("admin backup failed: %v\n%s", err, out)
	}

	corruptBackupDBEntry(t, filepath.Join(dir, "backup.tar.gz"))

	if err := os.Remove(filepath.Join(dir, "keyorix.db")); err != nil {
		t.Fatalf("remove db: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "keys")); err != nil {
		t.Fatalf("remove keys dir: %v", err)
	}

	out, err := runAdmin(t, bin, dir, env, "restore", "--config", "./keyorix.yaml", "--input", "./backup.tar.gz")
	if err == nil {
		t.Fatalf("expected admin restore to detect the tampered table entry, got success:\n%s", out)
	}
	if !strings.Contains(out, "integrity check") {
		t.Errorf("expected the integrity-check failure message, got:\n%s", out)
	}
}

// corruptBackupDBEntry rewrites the first non-empty table entry
// (tables/<name>.ndjson, backup format v2) of path with one flipped byte,
// leaving every other entry (including MANIFEST.json's recorded checksum)
// untouched -- the minimal change that should make restore's
// checksum verification fail without otherwise breaking archive parsing.
func corruptBackupDBEntry(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read backup archive: %v", err)
	}

	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	corrupted := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar entry: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %q: %v", hdr.Name, err)
		}
		if !corrupted && strings.HasPrefix(hdr.Name, "tables/") && len(data) > 0 {
			data[0] ^= 0xFF
			corrupted = true
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write tar entry: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if !corrupted {
		t.Fatalf("backup archive has no non-empty tables/*.ndjson entry to corrupt")
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("reopen backup archive for corruption: %v", err)
	}
	defer f.Close() //nolint:errcheck
	gzw := gzip.NewWriter(f)
	if _, err := gzw.Write(buf.Bytes()); err != nil {
		t.Fatalf("write corrupted archive: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
}

// Backup format v2 is backend-neutral; with no reachable Postgres server both
// commands must fail closed (non-zero exit, no archive left behind, no
// success message) rather than producing or consuming an empty backup.
func TestAdminBackupRestore_PostgresUnreachable_FailsClosed(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)
	cfg := "storage:\n  type: postgres\n  database:\n    host: 127.0.0.1\n    port: 1\n    name: keyorix\n    user: keyorix\n"
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatalf("write postgres config: %v", err)
	}

	out, err := runAdmin(t, bin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", "./backup.tar.gz")
	if err == nil {
		t.Fatalf("expected admin backup against an unreachable Postgres to fail, got success:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "backup.tar.gz")); statErr == nil {
		t.Errorf("admin backup failed but still left ./backup.tar.gz behind")
	}

	out, err = runAdmin(t, bin, dir, env, "restore", "--config", "./keyorix.yaml", "--input", "./backup.tar.gz")
	if err == nil {
		t.Fatalf("expected admin restore against an unreachable Postgres to fail, got success:\n%s", out)
	}
	if strings.Contains(out, "Restored ") {
		t.Errorf("failed restore must not report success, got:\n%s", out)
	}
}
