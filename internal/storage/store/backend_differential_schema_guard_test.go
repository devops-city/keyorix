package store_test

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	storagefactory "github.com/keyorixhq/keyorix/internal/storage"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// schemaGuardSeq is this file's own disposable-target counter — deliberately not shared
// with FuzzStorageBackendDifferential's pgSchemaSeq (backend_differential_fuzz_test.go),
// so this guard test has no compile-time dependency on that file.
var schemaGuardSeq atomic.Int64

// differentialHarnessRequiredIndexes are the production partial unique indexes that
// migrateDatabase's own ensure*Index helpers (internal/storage/factory.go) create for
// every model FuzzStorageBackendDifferential exercises (Project, User, SecretNode).
// None of these are gorm struct tags — models.User's own doc comment explains why
// (case/collation differs between SQLite's ASCII-only LOWER() and Postgres's
// locale-dependent one, so the index has to be on a Go-folded column, not a plain
// uniqueIndex tag) — so a bare db.AutoMigrate() genuinely cannot create them; only the
// real migration path can.
var differentialHarnessRequiredIndexes = []struct {
	table string
	index string
}{
	{"users", "uniq_users_username_folded_active"},
	{"users", "uniq_users_email_folded_active"},
	{"users", "uniq_users_external_id_active"},
	{"projects", "uniq_projects_name_active"},
	{"secret_nodes", "uniq_secret_nodes_project_env_name_active"},
}

// TestBackendDifferentialHarnessSchema_MatchesProduction guards against
// FuzzStorageBackendDifferential's migration step drifting back to a bare
// db.AutoMigrate() (as it did before the 2026-09-25 hardening — see that fuzz target's
// own doc comment) and silently losing every constraint-level divergence it exists to
// find. It runs the EXACT same migration call the fuzz target's setup uses
// (storagefactory.NewStorageFactory().CreateStorage) against fresh, disposable targets on
// both backends, then asserts every index in differentialHarnessRequiredIndexes exists.
// A future edit that reintroduces a bare AutoMigrate (here or in the fuzz target itself)
// makes this go red, on both backends, immediately — it does not depend on the fuzzer
// ever generating the right byte sequence to notice the gap by accident.
func TestBackendDifferentialHarnessSchema_MatchesProduction(t *testing.T) {
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — needs a real Postgres (rig-only)")
	}

	// The factory migrates it and sdb below must reach the SAME database, so only
	// the DSN comes from sqlitetest; sdb caps its own pool to one connection.
	sqliteDSN := sqlitetest.DSN("schemaguard_")
	if _, err := storagefactory.NewStorageFactory().CreateStorage(&config.Config{
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqliteDSN}},
	}); err != nil {
		t.Fatalf("sqlite production migration: %v", err)
	}
	sdb, err := gorm.Open(sqlite.Open(sqliteDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if s, e := sdb.DB(); e == nil {
		s.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = s.Close() })
	}

	schema := fmt.Sprintf("schemaguard_%d_%d", os.Getpid(), schemaGuardSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open pg admin: %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		t.Fatalf("pg drop schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("pg create schema: %v", err)
	}
	t.Cleanup(func() {
		if c, e := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard}); e == nil {
			_ = c.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		}
	})
	pgTargetDSN := pgdsn.PGSearchPathDSN(pgDSN, schema)
	if _, err := storagefactory.NewStorageFactory().CreateStorage(&config.Config{
		Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: pgTargetDSN}},
	}); err != nil {
		t.Fatalf("pg production migration: %v", err)
	}
	pdb, err := gorm.Open(postgres.Open(pgTargetDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}

	for _, req := range differentialHarnessRequiredIndexes {
		if !sdb.Migrator().HasIndex(req.table, req.index) {
			t.Errorf("sqlite: production migration should have created %q on %s, but it's missing — the differential harness's migration step has drifted from the real production path", req.index, req.table)
		}
		if !pdb.Migrator().HasIndex(req.table, req.index) {
			t.Errorf("postgres: production migration should have created %q on %s, but it's missing — the differential harness's migration step has drifted from the real production path", req.index, req.table)
		}
	}
}
