package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// auditHashIndexes are the audit_events indexes on prev_hash and entry_hash
// that releases before DB-TUNE-1 created. Nothing looks an audit row up by
// either hash (the chain is walked by id), so migrateDatabase drops them.
var auditHashIndexes = []string{"idx_audit_events_prev_hash", "idx_audit_events_entry_hash"}

// requireAuditHashIndexesDroppedOnUpgrade boots db fresh, checks the hash
// indexes are not created, recreates them the way an older release did (as
// an install that ran one would have them), boots again and checks they are
// gone, then boots a third time to prove the DROP is idempotent.
func requireAuditHashIndexesDroppedOnUpgrade(t *testing.T, db *gorm.DB) {
	t.Helper()
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	for _, idx := range auditHashIndexes {
		require.False(t, indexExists(db, idx), "a fresh install must not create %s", idx)
	}
	require.NoError(t, db.Exec("CREATE INDEX idx_audit_events_prev_hash ON audit_events (prev_hash)").Error)
	require.NoError(t, db.Exec("CREATE INDEX idx_audit_events_entry_hash ON audit_events (entry_hash)").Error)
	for _, idx := range auditHashIndexes {
		require.True(t, indexExists(db, idx), "%s must exist before the upgrade boot", idx)
	}
	require.NoError(t, f.migrateDatabase(db))
	for _, idx := range auditHashIndexes {
		require.False(t, indexExists(db, idx), "an upgraded install must drop %s", idx)
	}
	require.NoError(t, f.migrateDatabase(db), "re-running the migration must be a no-op")
	ensureAuditListIndexesForTest(t, db)
	for _, ix := range store.AuditListIndexes {
		require.True(t, indexExists(db, ix.Name), "the audit list index %s exists", ix.Name)
	}
}

func TestAuditEventHashIndexes_DroppedOnUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "audit-hash-index.db"))
	require.NoError(t, err)
	requireAuditHashIndexesDroppedOnUpgrade(t, db)
}

// Postgres twin. Skips without KEYORIX_TEST_PG_DSN.
func TestAuditEventHashIndexes_Postgres_DroppedOnUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	requireAuditHashIndexesDroppedOnUpgrade(t, pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t))))
}
