package main

// admin_encryption_integration_postgres_test.go covers the same `keyorix-server
// admin encryption` workflow as admin_encryption_integration_test.go's
// TestAdminEncryptionWorkflow_SQLite, but against a real PostgreSQL backend --
// gated on KEYORIX_TEST_PG_DSN (see admin_integration_postgres_test.go's own
// header for the convention). Skips (not fails) when unset.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func encryptionPostgresYAML(dir, dsn string) error {
	content := fmt.Sprintf(`storage:
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
    port: "8090"
  grpc:
    enabled: false
`, dsn)
	return os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(content), 0600)
}

func openTestSecretsDBPostgres(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open postgres secrets db directly: %v", err)
	}
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		t.Fatalf("automigrate secret tables: %v", err)
	}
	return db
}

func seedProbeSecretPostgres(t *testing.T, dir, dsn, passphrase, plaintext string) (db *gorm.DB, versionID uint, aad []byte) {
	t.Helper()
	db = openTestSecretsDBPostgres(t, dsn)
	node := &models.SecretNode{ProjectID: 1, Name: "probe-node-pg", IsSecret: true}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := svc.Initialize(passphrase); err != nil {
		t.Fatalf("seed service Initialize: %v", err)
	}
	defer svc.Shutdown()
	aad = encryption.SecretAAD(node.ID, node.ProjectID, 1)
	enc, meta, err := svc.EncryptSecretWithAAD([]byte(plaintext), aad)
	if err != nil {
		t.Fatalf("seed EncryptSecretWithAAD: %v", err)
	}
	v := &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}
	if err := db.Create(v).Error; err != nil {
		t.Fatalf("seed SecretVersion: %v", err)
	}
	return db, v.ID, aad
}

func decryptProbeSecretPostgres(t *testing.T, dir, passphrase string, db *gorm.DB, versionID uint, aad []byte) (string, error) {
	t.Helper()
	var v models.SecretVersion
	if err := db.First(&v, versionID).Error; err != nil {
		t.Fatalf("fetch probe row: %v", err)
	}
	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := svc.Initialize(passphrase); err != nil {
		return "", fmt.Errorf("Initialize: %w", err)
	}
	defer svc.Shutdown()
	pt, err := svc.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// TestAdminEncryptionWorkflow_Postgres mirrors TestAdminEncryptionWorkflow_SQLite's
// happy path (init through auth-encryption rotate) against a real, isolated
// Postgres database, confirming the encryption family's admin commands work
// identically regardless of storage backend.
func TestAdminEncryptionWorkflow_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-postgres"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionPostgresYAML(dir, dsn); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}

	// `encryption init` is the only admin command that creates the keys: since
	// REVIEW-COVERAGE-2, status/validate/fix-perms/rotate/... refuse on missing
	// keys instead of silently generating a brand-new KEK/DEK (see
	// TestAdminEncryptionStatus_Postgres_DoesNotCreateKeys). It used to be
	// bootstrapped through `status`, relying on that side effect; init no longer
	// opens a SQLite file under storage.type: postgres (#2980), so use it directly.
	out, err := runAdmin(t, bin, dir, env, "encryption", "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption init failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keys", "dek.key")); statErr != nil {
		t.Fatalf("expected dek.key to be created by encryption init: %v", statErr)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Encryption setup is valid") {
		t.Errorf("expected validate to pass, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "fix-perms", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption fix-perms failed: %v\n%s", err, out)
	}

	db, versionID, aad := seedProbeSecretPostgres(t, dir, dsn, passphrase, "rotate-me-probe-value-pg")

	out, err = runAdmin(t, bin, dir, env, "encryption", "rotate", "--dry-run", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption rotate --dry-run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no changes were made") {
		t.Errorf("expected dry-run to report no changes, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption rotate --confirm failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "DEK rotated successfully") {
		t.Errorf("expected rotate to report success, got:\n%s", out)
	}
	got, derr := decryptProbeSecretPostgres(t, dir, passphrase, db, versionID, aad)
	if derr != nil {
		t.Fatalf("DATA LOSS: probe secret unreadable after rotate (postgres): %v", derr)
	}
	if got != "rotate-me-probe-value-pg" {
		t.Fatalf("VALUE CORRUPTION: probe secret changed after rotate (postgres): got %q", got)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "upgrade-aad", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption upgrade-aad failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption status failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Authentication Encryption Status") {
		t.Errorf("expected auth-encryption status header, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "enable", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption enable failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption migrate failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "validation checks passed") {
		t.Errorf("expected auth-encryption validate to pass, got:\n%s", out)
	}

	// auth-encryption rotate (S13's fix point) must still preserve the probe
	// secret against the Postgres backend too.
	out, err = runAdmin(t, bin, dir, env, "encryption", "auth-encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("auth-encryption rotate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "rotation completed successfully") {
		t.Errorf("expected auth-encryption rotate to report success, got:\n%s", out)
	}
	got, derr = decryptProbeSecretPostgres(t, dir, passphrase, db, versionID, aad)
	if derr != nil || got != "rotate-me-probe-value-pg" {
		t.Fatalf("probe secret unreadable or changed after auth-encryption rotate (postgres): got=%q err=%v", got, derr)
	}
}

// TestAdminEncryptionStatus_Postgres_DoesNotCreateKeys pins the REVIEW-COVERAGE-2
// behaviour change that broke TestAdminEncryptionWorkflow_Postgres: `encryption
// status` on an install without keys must report "not initialized" and create
// nothing. Generating a new KEK/DEK from a read-only command (run from the wrong
// directory, with a wrong dek_path or an unmounted volume) made every later
// command act on brand-new keys and report success. Only `encryption init`
// creates keys.
func TestAdminEncryptionStatus_Postgres_DoesNotCreateKeys(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-status-nokeys-postgres"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionPostgresYAML(dir, dsn); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}

	// status reports a missing install and exits 0 (its output IS the answer).
	out, err := runAdmin(t, bin, dir, env, "encryption", "status", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("encryption status must exit 0 on a missing install: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no wrapped DEK") {
		t.Errorf("expected status to say there is no wrapped DEK, got:\n%s", out)
	}
	if strings.Contains(out, "Initialized: ✅") {
		t.Errorf("status must not report an install with no keys as initialized:\n%s", out)
	}
	for _, name := range []string{"dek.key", "kek.salt"} {
		if _, statErr := os.Stat(filepath.Join(dir, "keys", name)); !os.IsNotExist(statErr) {
			t.Errorf("encryption status must not create keys/%s (stat err: %v)", name, statErr)
		}
	}

	// A command that does act on keys must fail closed, not create them either.
	if out, err := runAdmin(t, bin, dir, env, "encryption", "validate", "--config", "./keyorix.yaml"); err == nil {
		t.Errorf("encryption validate must fail on missing keys, got success:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keys", "dek.key")); !os.IsNotExist(statErr) {
		t.Errorf("encryption validate must not create keys/dek.key (stat err: %v)", statErr)
	}

	// init is the one command that creates them.
	if out, err := runAdmin(t, bin, dir, env, "encryption", "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("encryption init failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keys", "dek.key")); statErr != nil {
		t.Errorf("expected encryption init to create keys/dek.key: %v", statErr)
	}
}

// TestAdminEncryptionRotate_RefusedWhileExclusiveLockHeld_Postgres is the
// Postgres counterpart of the SQLite lock-guard regression test.
func TestAdminEncryptionRotate_RefusedWhileExclusiveLockHeld_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-enc-lock-postgres"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	if err := encryptionPostgresYAML(dir, dsn); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("mkdir keys: %v", err)
	}
	if out, err := runAdmin(t, bin, dir, env, "encryption", "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("encryption init failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keys", "dek.key")); statErr != nil {
		t.Fatalf("expected dek.key to be created by encryption init: %v", statErr)
	}

	hook := startLockHolderHook(t, bin, dir, env)
	defer hook.release(t)

	out, err := runAdmin(t, bin, dir, env, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		t.Fatalf("expected encryption rotate to refuse while the exclusive lock is held, got (err=%v):\n%s", err, out)
	}
}

// TestAdminInitEncryptionInitMigrate_Postgres_NoStraySQLite is the #2980 proof:
// with storage.type: postgres (and the template's leftover database.path), the
// first-run admin sequence must not create or open a SQLite file.
func TestAdminInitEncryptionInitMigrate_Postgres_NoStraySQLite(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	const passphrase = "test-passphrase-2980-postgres"
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passphrase)

	cfg := fmt.Sprintf(`storage:
  type: postgres
  database:
    path: keyorix.db
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: "8090"
  grpc:
    enabled: false
`, dsn)
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	for _, args := range [][]string{
		{"init", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
		{"migrate", "--config", "./keyorix.yaml"},
	} {
		out, err := runAdmin(t, bin, dir, env, args...)
		if err != nil {
			t.Fatalf("admin %v failed: %v\n%s", args, err, out)
		}
		if strings.Contains(out, "SQLite database") {
			t.Errorf("admin %v opened a SQLite database under storage.type: postgres:\n%s", args, out)
		}
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*.db*"))
	if len(matches) != 0 {
		t.Fatalf("stray SQLite file(s) under storage.type: postgres: %v", matches)
	}
}
