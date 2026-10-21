package main

// admin_integration_postgres_test.go covers the same `keyorix-server admin`
// workflow as admin_integration_test.go's TestAdminWorkflow_SQLite, but
// against a real PostgreSQL backend -- gated on KEYORIX_TEST_PG_DSN, per
// this repo's standing convention (see e.g.
// internal/storage/postgres_pk_rebuild_helpers_test.go's pgTestDSN). Skips
// (not fails) when unset.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var adminPGDBCounter int64

func adminPgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres admin-command integration test")
	}
	return dsn
}

// adminPgIsolatedDatabaseDSN creates a fresh, empty database on the real
// Postgres server at base, dropped on test cleanup, and returns a DSN
// pointing at it -- mirrors internal/storage's own
// pgIsolatedDatabaseDSN, so each test's migration/audit-chain state is
// genuinely isolated rather than racing other tests sharing one database.
func adminPgIsolatedDatabaseDSN(t *testing.T, base string) string {
	t.Helper()
	n := atomic.AddInt64(&adminPGDBCounter, 1)
	dbName := fmt.Sprintf("admin_pr11_%d_%d", os.Getpid(), n)

	admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	adminSQL, err := admin.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminSQL.Close() })

	require.NoError(t, admin.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName)).Error)
	t.Cleanup(func() {
		// Terminate any lingering connections (the admin commands under test
		// each open and close their own) before dropping, or DROP DATABASE
		// fails with "database is being accessed by other users".
		_ = admin.Exec(fmt.Sprintf(
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s' AND pid <> pg_backend_pid()", dbName,
		)).Error
		_ = admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName)).Error
	})

	return replaceAdminDBName(base, dbName)
}

// replaceAdminDBName points base at newName for either DSN form
// KEYORIX_TEST_PG_DSN may take (keyword/value or postgres:// URL); see
// pgdsn.PGReplaceDBName.
func replaceAdminDBName(dsn, newName string) string {
	return pgdsn.PGReplaceDBName(dsn, newName)
}

func TestAdminWorkflow_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-postgres")

	configContent := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: %q
  grpc:
    enabled: false
`, dsn, freeTCPPort(t))
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// `admin init` (which normally creates this) also unconditionally treats
	// storage.database.path as a local SQLite file to create -- a
	// pre-existing gap in the ported-near-verbatim CLI logic, out of scope
	// here since storage.type is postgres. Create the key directory directly
	// instead of routing through `admin init` for this Postgres config.
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	// First diagnose derives the KEK (first-boot key derivation) against a
	// not-yet-migrated database -- migration state is expected to WARN here,
	// not pass; see TestAdminDiagnose_UnmigratedDatabase for that behavior
	// covered directly against SQLite.
	out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose (first-boot key derivation) failed: %v\n%s", err, out)
	}
	for _, want := range []string{"[ OK ] config parse", "[ OK ] KEK/passphrase access", "[ OK ] database open"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected diagnose output to contain %q, got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "[WARN] migration state") {
		t.Errorf("expected diagnose to WARN on the not-yet-migrated database, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "migrated successfully") {
		t.Errorf("expected migrate to report success, got:\n%s", out)
	}

	// Idempotency: re-running migrate against an already-migrated Postgres
	// database must still succeed (mirrors the SQLite workflow test).
	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("second admin migrate (idempotency check) failed: %v\n%s", err, out)
	}

	// A fresh diagnose after migrate must now report every check passing.
	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose after migrate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[ OK ] migration state") {
		t.Errorf("expected diagnose to report migration state OK after `admin migrate`, got:\n%s", out)
	}
}

func TestAdminGuard_Postgres_RefusesWhileServerRunning(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-pg-guard")

	configContent := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: %q
  grpc:
    enabled: false
`, dsn, freeTCPPort(t))
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	serverEnv := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-pg-guard", "KEYORIX_CONFIG_PATH=./keyorix.yaml")
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

	cfg, err := adminConfigForProbe(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatalf("load config for probe: %v", err)
	}
	running := waitForPresence(t, cfg, 30)
	if !running {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected the server to acquire the presence lock within the deadline; server log:\n%s", logBytes)
	}

	out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected admin migrate to refuse while the server is running, got (err=%v):\n%s\nserver log:\n%s", err, out, logBytes)
	}
}

// TestServerStartup_RefusedWhileAdminHoldsExclusiveLock_Postgres is the
// Postgres counterpart of the SQLite reverse-direction regression test in
// admin_integration_test.go: a server starting while an admin operation
// holds the exclusive lock must fail fast with the specific message, and
// succeed once the admin operation releases it.
func TestServerStartup_RefusedWhileAdminHoldsExclusiveLock_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-pg-reverse-guard")

	configContent := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: %q
  grpc:
    enabled: false
`, dsn, freeTCPPort(t))
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	hook := startLockHolderHook(t, bin, dir, env)

	serverEnv := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-pg-reverse-guard", "KEYORIX_CONFIG_PATH=./keyorix.yaml")

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

// TestAdminAudit_PermissionIssue_ReleasesLockPromptly_Postgres covers a bug
// found alongside this file's own flake investigation (TRACK ADMIN):
// runAdminAudit's failure path used to call os.Exit(1) directly
// (server/admin/audit.go), which terminates the process WITHOUT unwinding
// the call stack -- skipping that function's own `defer lock.Release()`.
// Fixed by returning an error instead, so Execute() (admin.go) sets the same
// exit code AFTER that defer (and the explicit, synchronous
// pg_advisory_unlock it triggers) has run.
//
// Caveat, stated plainly rather than overclaimed: this test is NOT a
// red/green proof of the historical bug. Manually reverted to the old
// os.Exit(1) form and re-run at -count=15 locally, it stayed GREEN every
// time (~0.6s) -- a healthy, unloaded local Postgres's connection-close
// detection (the fallback path os.Exit forced) is ALSO fast enough here to
// clear waitForLockFree's 2s bound, so this specific assertion doesn't
// discriminate the two code paths by timing alone in this environment. The
// bug itself is proven independent of any test: os.Exit skips deferred
// calls unconditionally, a language-level fact, not something requiring a
// timing reproduction. What this test actually verifies, and is worth
// keeping for: `admin audit`'s failure path (previously untested -- see
// TestAdminWorkflow_Postgres for the only prior coverage, success-only)
// exits non-zero with the expected message and does not leave the lock
// stuck for anywhere near this file's other tests' 10-15s windows.
func TestAdminAudit_PermissionIssue_ReleasesLockPromptly_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-audit-perms")

	configContent := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: %q
  grpc:
    enabled: false
`, dsn, freeTCPPort(t))
	configPath := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}

	// Loosen the config file's permissions below the 0600 audit expects --
	// securefiles.FixFilePerms (audit-only mode) reports this as a failing
	// check, taking runAdminAudit's failure path.
	if err := os.Chmod(configPath, 0644); err != nil {
		t.Fatalf("chmod config file: %v", err)
	}

	out, err := runAdmin(t, bin, dir, env, "audit", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("expected admin audit to report the permission issue as a failure, got success:\n%s", out)
	}
	if !strings.Contains(out, "Audit finished with warnings/errors") {
		t.Errorf("expected the audit-failure message, got:\n%s", out)
	}

	cfg, err := adminConfigForProbe(configPath)
	if err != nil {
		t.Fatalf("load config for probe: %v", err)
	}
	if !waitForLockFree(t, cfg, 2) {
		t.Fatalf("expected admin audit's exclusive lock to be free within 2s of its (failure-path) exit")
	}
}

// TestWaitForPresence_Postgres_NeverRefusesAStartingServer pins the property
// waitForPresence's doc comment rests on: polling for a server must never hold
// the presence lock in a way that makes a starting server's non-blocking shared
// try-lock fail. A goroutine plays a server starting over and over
// (pg_try_advisory_lock_shared on the presence key, then release) for as long
// as waitForPresence keeps polling; not one of its attempts may be refused.
// Then both directions of the detection itself: a session holding the lock
// shared reads as a server, and no holder reads as none. Red against the
// earlier serverguard.ProbeRunning-based poll, which takes the lock
// exclusively on every probe.
func TestWaitForPresence_Postgres_NeverRefusesAStartingServer(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn

	gdb, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := gdb.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	ctx := t.Context()
	server, err := sqlDB.Conn(ctx) // one session, like a server's lock connection
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	var attempts, refused atomic.Int64
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			var ok bool
			if err := server.QueryRowContext(ctx, "SELECT pg_try_advisory_lock_shared($1)", presenceLockKey).Scan(&ok); err != nil {
				done <- err
				return
			}
			attempts.Add(1)
			if !ok {
				refused.Add(1)
				continue
			}
			if _, err := server.ExecContext(ctx, "SELECT pg_advisory_unlock_shared($1)", presenceLockKey); err != nil {
				done <- err
				return
			}
		}
	}()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
		waitForPresence(t, cfg, 1) // returns at once whenever it catches the goroutine mid-hold
	}
	close(stop)
	require.NoError(t, <-done)
	require.Positive(t, attempts.Load(), "the starting-server goroutine never ran")
	require.Zero(t, refused.Load(), "waitForPresence refused %d of %d shared try-locks: polling contends with a starting server", refused.Load(), attempts.Load())

	var ok bool
	require.NoError(t, server.QueryRowContext(ctx, "SELECT pg_try_advisory_lock_shared($1)", presenceLockKey).Scan(&ok))
	require.True(t, ok)
	require.True(t, waitForPresence(t, cfg, 10), "a session holding the presence lock shared must read as a running server")
	_, err = server.ExecContext(ctx, "SELECT pg_advisory_unlock_shared($1)", presenceLockKey)
	require.NoError(t, err)
	require.False(t, waitForPresence(t, cfg, 1), "with no holder, waitForPresence must not report a server")
}
