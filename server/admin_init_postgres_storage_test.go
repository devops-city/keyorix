package main

// admin_init_postgres_storage_test.go: FIX-3151B. `admin init` must not leave an
// empty SQLite file (or its lock/WAL sidecars) behind when the deployment's
// storage is PostgreSQL. Driven against the real binary.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sqliteArtifacts lists files under dir that belong to a SQLite database
// (keyorix.db and the .db-wal/.db-shm/.db.*.lock sidecars).
func sqliteArtifacts(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.Contains(d.Name(), ".db") {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// An unreachable DSN keeps the test self-contained: the exclusive lock cannot be
// taken (--force proceeds), which is the path where a SQLite fallback would
// show up if init still touched one.
const unreachablePostgresDSN = "host=127.0.0.1 port=1 user=keyorix dbname=keyorix sslmode=disable connect_timeout=2"

func TestAdminInit_StorageTypePostgres_CreatesNoSQLiteFile(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	out, err := runAdmin(t, bin, dir, env, "init", "--storage-type", "postgres", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init --storage-type postgres failed: %v\n%s", err, out)
	}
	if got := sqliteArtifacts(t, dir); len(got) != 0 {
		t.Fatalf("first init with --storage-type postgres left SQLite files: %v\n%s", got, out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\n  type: postgres") || strings.Contains(string(raw), `path: "keyorix.db"`) {
		t.Fatalf("written config is not a postgres config without a SQLite path:\n%s", raw)
	}

	// Second init, after the operator set the DSN: still no SQLite file.
	cfg := strings.Replace(string(raw), "    # dsn: \"host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require\"", "    dsn: \""+unreachablePostgresDSN+"\"", 1)
	if cfg == string(raw) {
		t.Fatal("config has no commented Option A dsn line to enable")
	}
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runAdmin(t, bin, dir, env, "init", "--force", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("second admin init failed: %v\n%s", err, out)
	}
	if got := sqliteArtifacts(t, dir); len(got) != 0 {
		t.Fatalf("admin init against a postgres config created SQLite files: %v\n%s", got, out)
	}
}

// A hand-written postgres config (the pre-existing flow) must also stay clean.
func TestAdminInit_ExistingPostgresConfig_CreatesNoSQLiteFile(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--storage-type", "postgres", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// Keep a stale SQLite path in the config, as an operator editing the default
	// template by hand typically does.
	cfg := strings.Replace(string(raw), "    # dsn: \"host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require\"",
		"    path: \"keyorix.db\"\n    dsn: \""+unreachablePostgresDSN+"\"", 1)
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runAdmin(t, bin, dir, env, "init", "--force", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if got := sqliteArtifacts(t, dir); len(got) != 0 {
		t.Fatalf("admin init against a postgres config created SQLite files: %v\n%s", got, out)
	}
}

func TestAdminInit_StorageTypeMismatchIsRefused(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	out, err := runAdmin(t, bin, dir, env, "init", "--storage-type", "postgres", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "does not match the existing config") {
		t.Fatalf("--storage-type postgres over an existing sqlite config must be refused; err=%v\n%s", err, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if string(before) != string(after) {
		t.Fatal("config was changed")
	}

	if out, err := runAdmin(t, bin, t.TempDir(), env, "init", "--storage-type", "mysql", "--config", "./keyorix.yaml"); err == nil || !strings.Contains(out, "--storage-type must be") {
		t.Fatalf("invalid --storage-type must be refused; err=%v\n%s", err, out)
	}
}

// The SQLite path is unchanged.
func TestAdminInit_DefaultStillCreatesSQLiteFile(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)
	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "keyorix.db")); err != nil {
		t.Fatalf("default (sqlite) init no longer creates keyorix.db: %v", err)
	}
}
