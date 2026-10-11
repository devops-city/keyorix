package main

// admin_recover_admin_integration_test.go exercises `keyorix-server admin
// recover-admin` (docs/design-b2-recover-admin.md §3) as a real subprocess
// against the built binary, reusing this package's existing
// buildServerBinary/runAdmin/baseEnv/lockHolderHook harness
// (admin_integration_test.go) plus groupedRecoveryKeyForm
// (admin_recovery_key_integration_test.go).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"time"
)

// bootstrapAdminViaHTTP starts the built binary as a real server (pinned
// KEYORIX_BOOTSTRAP_TOKEN), waits for it to accept connections, claims the
// first admin over POST /system/init (bootstrap token via header, preferred
// path per server/http/handlers/auth.go's InitSystem), and stops the
// server -- leaving behind a real, HTTP-bootstrapped admin account in dir's
// database, the same way an actual operator would create one. Returns that
// account's email.
func bootstrapAdminViaHTTP(t *testing.T, bin, dir string, env []string, port, username, email, password string) {
	t.Helper()
	const bootstrapToken = "test-bootstrap-token-0123456789"

	serverEnv := append(append([]string{}, env...), "KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken, "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = serverEnv
	logFile, err := os.Create(filepath.Join(dir, "bootstrap-server.log"))
	if err != nil {
		t.Fatalf("create bootstrap server log: %v", err)
	}
	defer logFile.Close() //nolint:errcheck
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server for bootstrap: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := "http://localhost:" + port
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/health")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr != nil && time.Now().After(deadline) {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "bootstrap-server.log"))
		t.Fatalf("server never became reachable for bootstrap (%v); log:\n%s", lastErr, logBytes)
	}

	body, err := json.Marshal(map[string]string{
		"username": username, "email": email, "password": password, "display_name": "Test Admin",
	})
	if err != nil {
		t.Fatalf("marshal bootstrap body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, base+"/system/init", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build bootstrap request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", bootstrapToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bootstrap request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "bootstrap-server.log"))
		t.Fatalf("bootstrap returned %d; server log:\n%s", resp.StatusCode, logBytes)
	}

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	// Give the OS a moment to release the SQLite file/lock before the next
	// admin command (run in a separate process) opens it.
	time.Sleep(200 * time.Millisecond)
}

func TestAdminRecoverAdmin_FullFlow_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-recover-admin")

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	bootstrapAdminViaHTTP(t, bin, dir, env, "8080", "recoveryadmin", "recover-admin-e2e@example.com", "InitialPassw0rd!")

	keyOut, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("recovery-key rotate failed: %v\n%s", keyOut, err)
	}
	key := groupedRecoveryKeyForm.FindString(keyOut)
	if key == "" {
		t.Fatalf("expected a grouped recovery key in rotate output, got:\n%s", keyOut)
	}

	cmd := exec.Command(bin, "admin", "recover-admin", "--user", "recover-admin-e2e@example.com", "--recovery-key", "-", "--config", "./keyorix.yaml")
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = strings.NewReader(key + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("recover-admin failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Recovered admin account: recoveryadmin") {
		t.Errorf("expected recover-admin success message, got:\n%s", out)
	}
	if !strings.Contains(string(out), "active session(s)") {
		t.Errorf("expected the reset summary line, got:\n%s", out)
	}

	// Wrong key must be rejected.
	cmd2 := exec.Command(bin, "admin", "recover-admin", "--user", "recover-admin-e2e@example.com", "--recovery-key", "-", "--config", "./keyorix.yaml")
	cmd2.Dir = dir
	cmd2.Env = env
	cmd2.Stdin = strings.NewReader("ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-Z\n")
	out2, err := cmd2.CombinedOutput()
	if err == nil {
		t.Fatalf("expected recover-admin to reject a wrong key, got success:\n%s", out2)
	}
	if !strings.Contains(string(out2), "recovery key does not match") {
		t.Errorf("expected the specific key-mismatch message, got:\n%s", out2)
	}
}

// TestAdminRecoverAdmin_KeylessMode_SQLite exercises design §5's labs/demo
// escape hatch end to end: with security.recover_admin.keyless_mode: true
// in the config, recover-admin succeeds on host access alone with NO
// --recovery-key/stdin at all, and the audit event it writes says so
// explicitly.
func TestAdminRecoverAdmin_KeylessMode_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-recover-admin-keyless")

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	// Enable keyless mode by editing the generated config's existing
	// security: block (see internal/config/keyless_mode_reachability_test.go
	// for why this is the ONLY legitimate way to set this field).
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	edited := strings.Replace(string(raw), "\nsecurity:\n",
		"\nsecurity:\n  recover_admin:\n    keyless_mode: true\n", 1)
	if edited == string(raw) {
		t.Fatalf("failed to inject keyless_mode into the generated config (anchor line not found)")
	}
	if err := os.WriteFile(cfgPath, []byte(edited), 0600); err != nil {
		t.Fatalf("write edited config: %v", err)
	}

	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	bootstrapAdminViaHTTP(t, bin, dir, env, "8080", "keylessadmin", "keyless-e2e@example.com", "InitialPassw0rd!")

	// The startup audit event (design §5) must have been written during
	// that boot -- verified directly against the SQLite file, independent
	// of any CLI reporting.
	verifyDB, err := gorm.Open(sqlite.Open(filepath.Join(dir, "keyorix.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	var startupEvents []models.AuditEvent
	if err := verifyDB.Where("event_type = ?", "admin.keyless_mode_enabled_at_startup").Find(&startupEvents).Error; err != nil {
		t.Fatalf("query startup audit events: %v", err)
	}
	if len(startupEvents) != 1 {
		t.Fatalf("expected exactly 1 admin.keyless_mode_enabled_at_startup audit event after one boot, got %d", len(startupEvents))
	}
	if sqlDB, derr := verifyDB.DB(); derr == nil {
		_ = sqlDB.Close()
	}

	// No recovery key has EVER been generated on this install -- keyless
	// mode must still succeed, with an empty stdin and no --recovery-key.
	cmd := exec.Command(bin, "admin", "recover-admin", "--user", "keyless-e2e@example.com", "--config", "./keyorix.yaml")
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keyless recover-admin failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Recovered admin account: keylessadmin") {
		t.Errorf("expected recover-admin success message, got:\n%s", out)
	}
	if !strings.Contains(string(out), "WARNING: keyless mode is enabled") {
		t.Errorf("expected the keyless-mode stderr warning, got:\n%s", out)
	}
}

func TestAdminRecoverAdmin_RequiresDashRecoveryKeyFlag(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}

	out, err := runAdmin(t, bin, dir, env, "recover-admin", "--user", "someone@example.com", "--recovery-key", "not-a-dash", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("expected recover-admin to refuse a --recovery-key value other than \"-\", got success:\n%s", out)
	}
	if !strings.Contains(out, `must be exactly "-"`) {
		t.Errorf("expected the specific --recovery-key contract message, got:\n%s", out)
	}
}

// TestAdminRecoverAdmin_ConcurrentRunRefusesWhileLockHeld exercises design
// §6's own adversarial-review item, the recover-admin counterpart of
// TestAdminRecoveryKey_ConcurrentRotateRefusesWhileLockHeld
// (admin_recovery_key_integration_test.go): the exclusive admin lock is
// acquired BEFORE any user/key resolution, so this needs no bootstrapped
// admin at all to observe the refusal.
func TestAdminRecoverAdmin_ConcurrentRunRefusesWhileLockHeld(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	holder := startLockHolderHook(t, bin, dir, env)
	defer holder.release(t)

	cmd := exec.Command(bin, "admin", "recover-admin", "--user", "1", "--recovery-key", "-", "--config", "./keyorix.yaml")
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = strings.NewReader("SOME-KEY-VALUE\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected recover-admin to refuse while another admin command holds the exclusive lock, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "admin commands must not run concurrently") {
		t.Errorf("expected the standard concurrent-admin-command refusal message, got:\n%s", out)
	}
}
