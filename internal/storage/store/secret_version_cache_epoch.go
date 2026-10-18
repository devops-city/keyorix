// secret_version_cache_epoch.go — secret_versions.cache_epoch, the term of the
// latest-version cache's generation that the DEK-rotation sweep moves.
//
// The sweep (internal/encryption/sweep.go) rewrites encrypted_value and
// encryption_metadata in place. Every other term of versionsGeneration is
// content-derived from columns the sweep leaves alone (count, max(version_number),
// sum(read_count)), so without this column a warm entry keeps serving the
// pre-sweep ciphertext. The sweep raises cache_epoch in the same UPDATE; the
// generation sums it, so the entry misses on the next hit — on this replica and
// on every other one, since the signal is read from the database.
//
// Deliberately a plain column set by its one writer, not a trigger like
// secret_nodes.cache_epoch: no other code path rewrites a version's ciphertext
// (TestSecretVersionCiphertextWriters_AreOnlyTheSweep fails if one appears), a
// trigger would add a second migration object per dialect, and a column that is
// missing never yields a stale hit: the aggregate errors, GetLatestSecretVersion
// treats that as a miss and caches nothing, and the combined schedule+version
// statement fails the read (the same dependency the node cache has on
// secret_nodes.cache_epoch), so a schema without the column is loud, not stale.
package store

import (
	"fmt"

	"gorm.io/gorm"
)

// SecretVersionCacheEpochColumn is the column's name.
const SecretVersionCacheEpochColumn = "cache_epoch"

// EnsureSecretVersionCacheEpoch adds secret_versions.cache_epoch to a database
// that predates it. A fresh install gets the column from models.SecretVersion
// through AutoMigrate; this is the upgrade call site (and the one a bare test
// schema without the model field would need). Idempotent, and a no-op until
// secret_versions exists. NOT NULL DEFAULT 0 so existing rows read as epoch 0
// with no backfill: the term only has to CHANGE when a row's ciphertext does.
func EnsureSecretVersionCacheEpoch(db *gorm.DB) error {
	if !tableExistsRaw(db, "secret_versions") {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if columnExistsRaw(tx, "secret_versions", SecretVersionCacheEpochColumn) {
			return nil
		}
		if err := tx.Exec("ALTER TABLE secret_versions ADD COLUMN cache_epoch BIGINT NOT NULL DEFAULT 0").Error; err != nil {
			return fmt.Errorf("failed to add secret_versions.cache_epoch: %w", err)
		}
		return nil
	})
}

// tableExistsRaw and columnExistsRaw are catalog lookups for the same reason as
// secretNodesTableExists: the Migrator path panics rather than erroring on an
// unusable handle, and any error is read as "not there", so the caller's next
// step (an idempotent ADD COLUMN) either works or fails loudly.
func tableExistsRaw(db *gorm.DB, table string) bool {
	var count int64
	q := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?"
	if db.Dialector.Name() == "postgres" {
		q = "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ? AND table_schema = CURRENT_SCHEMA()"
	}
	if err := db.Raw(q, table).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}

func columnExistsRaw(db *gorm.DB, table, column string) bool {
	var count int64
	q := "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?"
	if db.Dialector.Name() == "postgres" {
		q = "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = ? AND column_name = ? AND table_schema = CURRENT_SCHEMA()"
	}
	if err := db.Raw(q, table, column).Scan(&count).Error; err != nil {
		return false
	}
	return count > 0
}
