package storage

import (
	"context"
	"errors"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// MigrateExisting runs the production schema bootstrap -- exactly the
// migrateDatabase step CreateStorage runs, under the same in-process
// migration mutex (plus the Postgres advisory lock when db is Postgres) --
// against an already-open *gorm.DB.
//
// For callers that must choose their own connection shape but must still
// end up with every index and constraint production enforces, not just what
// GORM AutoMigrate derives from struct tags: test and fuzz fixtures using an
// in-memory SQLite DSN or a schema-scoped Postgres connection (#1947 --
// AutoMigrate alone never creates uniq_secret_versions_node_version, the
// partial unique indexes on users/projects/memberships/..., the
// account-state CHECK, etc.). Unlike CreateStorage it takes no SQLite
// sidecar flock (it has no path to key one on); on SQLite it still runs the
// migration inside the in-database BEGIN EXCLUSIVE lock
// (withSQLiteInDBMigrationLock, INV-STORAGE-23), which needs no path.
//
// The audit list indexes are built too, synchronously on both dialects (on
// Postgres CONCURRENTLY, after the migration transaction; a fixture's table is
// small), and a build error is returned rather than logged.
func MigrateExisting(db *gorm.DB) error {
	f := &DefaultStorageFactory{}
	if db.Dialector.Name() != "postgres" {
		return withMigrationLock(db, false, "", f.migrateSQLite)
	}
	if err := withMigrationLock(db, true, "", f.migrateDatabase); err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	// Bounded like the server's own synchronous build: an idle transaction on
	// audit_events must not hang a fixture forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err = store.BuildAuditListIndexesPostgres(ctx, sqlDB, false, log.Printf)
	if errors.Is(err, store.ErrAuditIndexBuildLockHeld) {
		return nil // another process is building them
	}
	return err
}
