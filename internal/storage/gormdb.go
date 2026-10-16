package storage

import (
	"fmt"

	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
)

// postgresConnectError is the error for a failed Postgres open: a clear
// config.PostgresAuthError when the failure is an authentication one (the
// original stays wrapped), otherwise the usual wrapped driver error.
func postgresConnectError(err error, cc *pgx.ConnConfig) error {
	classified := config.ClassifyPostgresConnectErrorConfig(err, cc)
	if classified != err {
		return classified
	}
	return fmt.Errorf("failed to connect to postgres: %w", err)
}

// OpenGormDB opens a raw *gorm.DB for the configured local backend, switching on
// cfg.Storage.Type with the same mapping the factory uses (postgres/postgresql →
// Postgres, local/sqlite → SQLite, a blank type or anything else rejected — #463,
// #G-blank-storage-default) and applying the same connection-pool settings via
// applyPoolSettings.
//
// Unlike the factory's CreateStorage, it deliberately does NOT run migrations: it
// exists for the handful of CLI admin commands that need a raw *gorm.DB the
// storage.Storage interface cannot provide — the DEK rotation sweep, which owns
// its own transaction (ADR-010), and the auth-encryption statistics counters.
// Those commands operate on an already-initialized database and must not trigger
// schema changes as a side effect, so migration stays CreateStorage's job. This
// keeps every GORM driver import inside internal/storage rather than in the CLI
// command files (ADR-049).
//
// Remote storage has no local *gorm.DB; these are host-local admin commands and
// require a non-remote backend.
func OpenGormDB(cfg *config.Config) (*gorm.DB, error) {
	switch cfg.Storage.Type {
	case "remote":
		return nil, fmt.Errorf("this command needs direct database access and cannot run against a remote backend; run it on the server host")
	case "postgres", "postgresql":
		db, err := openPostgresGorm(&cfg.Storage.Database, gormConfig())
		if err != nil {
			return nil, err
		}
		if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
			return nil, err
		}
		// #3361: the DEK rotation sweep writes, so the same refusal as the server.
		if err := refuseNonOriginReplicationRole(db); err != nil {
			if sqlDB, dbErr := db.DB(); dbErr == nil {
				_ = sqlDB.Close()
			}
			return nil, err
		}
		return db, nil
	// #1640: "sqlite" is an accepted alias for "local" -- see the matching
	// comment in internal/storage/factory.go's CreateStorage switch. This
	// function's own doc comment already notes these CLI admin commands run
	// without Config.Validate() first, so it must accept the alias
	// independently, not rely on Validate() to have normalized it upstream.
	case "local", "sqlite":
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		// #1647 sibling gap (Part 2 regression audit continuation): this opens the
		// SAME local secrets.db the factory's createLocalStorage path does, for the
		// DEK-rotation/auth-encryption-stats CLI admin commands named in this
		// function's own doc comment -- but until this fix, skipped BOTH
		// permission-hardening steps #1647 added there (explicit-mode pre-creation
		// and retroactive tightening of a pre-existing lax-mode file). A database
		// file that predates #1647 was never corrected when opened through this
		// path, leaving it world/group-readable exactly as #1647 closed for the
		// primary storage path.
		if err := prepareLocalStorageFile(dbPath); err != nil {
			return nil, err
		}
		db, err := openSQLiteGorm(sqliteDSN(dbPath))
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		tightenExistingLocalStorageFiles(dbPath)
		if err := applyPoolSettings(db, &cfg.Storage.Database); err != nil {
			return nil, err
		}
		return db, nil
	case "":
		// #G-blank-storage-default: mirrors internal/storage/factory.go's
		// CreateStorage -- a blank storage.type must never silently open local
		// SQLite here either. These CLI admin commands (DEK rotation,
		// auth-encryption stats) load their config directly via config.Load("")
		// with no CLI-applied default (internal/cli/common.InitializeStorage/
		// InitializeCoreService deliberately don't set one), so a blank type
		// reaching this function means the operator's config genuinely has no
		// storage.type set -- fail loudly instead of guessing local.
		return nil, fmt.Errorf("storage.type is not set: no storage configuration found -- specify \"local\", \"postgres\", \"postgresql\", or \"remote\" explicitly")
	default:
		// #463: defense in depth, mirroring the factory's own hardening — these
		// CLI admin commands run without going through Config.Validate() first,
		// so a typo'd storage.type must not silently open a local SQLite file
		// disconnected from the operator's intended (e.g. shared Postgres) backend.
		return nil, fmt.Errorf("invalid storage.type %q: must be one of \"local\", \"sqlite\", \"postgres\", \"postgresql\", or \"remote\"", cfg.Storage.Type)
	}
}
