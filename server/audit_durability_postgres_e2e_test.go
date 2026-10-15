package main

// audit_durability_postgres_e2e_test.go — ADR-112 Amendment 3 on PostgreSQL,
// end to end against the real built binary on a real cluster: a default
// install runs standard and says so in its INFO line and in admin validate;
// switching to strict between two starts is audited by the settings diff
// (old/new); the chain written at both levels verifies.
//
// DSN-gated, so it skips cleanly wherever KEYORIX_TEST_PG_DSN is absent --
// same convention as internal/storage/store's pg-gated tests, and the `core`
// CI leg is what actually runs it.

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// writePostgresAuditDurabilityConfig writes a server config pointed at schema
// on the pg-gated cluster, with dbLines added to storage.database. The schema
// is created and dropped around the test, so a full AutoMigrate cannot collide
// with another test's tables in the same database.
func writePostgresAuditDurabilityConfig(t *testing.T, dir, baseDSN, schema string, dbLines ...string) string {
	t.Helper()

	admin, err := gorm.Open(postgres.Open(baseDSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open pg admin connection: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA IF NOT EXISTS " + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, derr := admin.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	})

	extra := ""
	for _, l := range dbLines {
		extra += "\n    " + l
	}

	cfg := fmt.Sprintf(`environment: production

server:
  http:
    enabled: true
    port: "8099"
  grpc:
    enabled: false

storage:
  type: postgres
  database:
    dsn: %q%s
  encryption:
    enabled: true
    dek_path: "keys/dek.key"
    salt_path: "keys/kek.salt"

security:
  enable_file_permission_check: false
  require_transport_tls: false
`, pgdsn.PGSearchPathDSN(baseDSN, schema), extra)

	// `admin init` would create this for the SQLite flow; this config is
	// hand-written, so the key directory has to be made here or the encryption
	// provider cannot take its DEK lock.
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	path := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestAuditDurability_PostgresEndToEnd boots the real binary on PostgreSQL
// with neither key set (standard, the PostgreSQL default), then again with
// audit_durability: strict, and checks every surface agrees on the level.
func TestAuditDurability_PostgresEndToEnd(t *testing.T) {
	baseDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if baseDSN == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- standard is PostgreSQL-only and needs a real cluster")
	}
	const schema = "audit_durability_pg_e2e"

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir),
		"KEYORIX_MASTER_PASSWORD=test-passphrase-audit-durability-pg-e2e",
		"KEYORIX_CONFIG_PATH=./keyorix.yaml",
	)
	// Clean slate: a leftover schema from an interrupted run would carry a
	// previous settings snapshot.
	dropSchema(t, baseDSN, schema)
	writePostgresAuditDurabilityConfig(t, dir, baseDSN, schema)

	// `diagnose` creates the encryption key files and validates the config.
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed on a default POSTGRES config: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	// Start 1: neither key set.
	serverLog := runServerExpectingItToStayUp(t, bin, dir, env, "8099")
	const wantStandard = "INFO: audit durability: standard (PostgreSQL default; committed before every disclosure; " +
		"up to ~600 ms of entries can be lost to an OS crash or power loss; set audit_durability: strict to wait for the disk sync)"
	if !strings.Contains(serverLog, wantStandard) {
		t.Errorf("a default PostgreSQL boot must log %q. Server log:\n%s", wantStandard, serverLog)
	}
	for _, unwanted := range []string{"insecure_audit_skip_durable_sync", "Durable audit sync is DISABLED", "WARNING: audit durability"} {
		if strings.Contains(serverLog, unwanted) {
			t.Errorf("a default PostgreSQL boot must not log %q: standard is the baseline, not a deviation. Server log:\n%s", unwanted, serverLog)
		}
	}

	validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "Audit durability: standard (committed before every disclosure") {
		t.Errorf("`admin validate` must report the effective level. Output:\n%s", validateOut)
	}

	// Start 2: the operator switches to strict.
	writePostgresAuditDurabilityConfig(t, dir, baseDSN, schema, "audit_durability: strict")
	serverLog = runServerExpectingItToStayUp(t, bin, dir, env, "8099")
	if !strings.Contains(serverLog, "INFO: audit durability: strict (committed and synced to disk before every disclosure") {
		t.Errorf("a strict boot must log the strict INFO line. Server log:\n%s", serverLog)
	}

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(baseDSN, schema)),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	changes := postureChanges(t, db, "storage.database.audit_durability")
	if len(changes) == 0 || changes[len(changes)-1]["old_value"] != "standard" || changes[len(changes)-1]["new_value"] != "strict" {
		t.Errorf("the level change between the two starts must be one settings-diff event standard -> strict; got %v", changes)
	}
	var legacy []models.AuditEvent
	if err := db.Where("event_type = ?", legacyFastAuditStartupEventType).Find(&legacy).Error; err != nil {
		t.Fatalf("query legacy startup events: %v", err)
	}
	if len(legacy) != 0 {
		t.Errorf("found %d %s events; Amendment 3 removed the per-start event", len(legacy), legacyFastAuditStartupEventType)
	}

	// The chain written at both levels verifies.
	verifyOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("`admin verify-audit` failed: %v\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "VALID") {
		t.Errorf("expected a VALID verdict from verify-audit, got:\n%s", verifyOut)
	}
}

// dropSchema drops and recreates schema on the pg-gated cluster.
func dropSchema(t *testing.T, baseDSN, schema string) {
	t.Helper()
	db, err := gorm.Open(postgres.Open(baseDSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open pg admin connection: %v", err)
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	if err := db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if err := db.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
}

// runServerExpectingItToStayUp starts the built binary as a real server,
// waits for it to accept connections, then kills it and returns its log.
//
// The mirror image of runServerExpectingExit in the sibling file, and the
// distinction matters: on the supported backend the server must COME UP, so a
// process that dies here is the failure. Asserting "it stayed up" is what
// stops this test from passing on a boot that crashed immediately after
// printing its start-up lines.
func runServerExpectingItToStayUp(t *testing.T, bin, dir string, env []string, port string) string {
	t.Helper()
	logPath := filepath.Join(dir, "pg-e2e-server.log")
	logFile, err := os.Create(logPath) //nolint:gosec // test-generated path under t.TempDir()
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	defer func() { _ = logFile.Close() }()

	cmd := exec.Command(bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := "http://localhost:" + port
	deadline := time.Now().Add(30 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		resp, gerr := http.Get(base + "/health") //nolint:noctx // test-local liveness poll
		if gerr == nil {
			_ = resp.Body.Close()
			up = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	raw, _ := os.ReadFile(logPath) //nolint:gosec // test-generated path
	if !up {
		t.Fatalf("the server never became reachable on port %s. Both audit durability levels are "+
			"supported on PostgreSQL, so the server must come up -- a refusal here would mean the SQLite guard "+
			"is rejecting Postgres too. Server log:\n%s", port, raw)
	}
	return string(raw)
}
