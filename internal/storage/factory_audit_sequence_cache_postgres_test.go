// factory_audit_sequence_cache_postgres_test.go — the pipelined audit commit
// reserves ids with nextval under the audit lock and needs them handed out in
// order, i.e. audit_events' id sequence at CACHE 1. migrateDatabase (every
// boot) must refuse a Postgres database where it is not, with an actionable
// error. Gated on KEYORIX_TEST_PG_DSN.
package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditIDSequenceCache_Postgres_RefusesCacheAboveOne(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	f := &DefaultStorageFactory{}

	// Default (what AutoMigrate creates): boots, and keeps booting.
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, f.migrateDatabase(db))

	require.NoError(t, db.Exec("ALTER SEQUENCE audit_events_id_seq CACHE 20").Error)
	err := f.migrateDatabase(db)
	require.Error(t, err, "a CACHE 20 audit id sequence must stop startup")
	assert.Contains(t, err.Error(), "CACHE 20")
	assert.Contains(t, err.Error(), "ALTER SEQUENCE")

	// The operator's fix, as the error spells it, clears the refusal.
	require.NoError(t, db.Exec("ALTER SEQUENCE audit_events_id_seq CACHE 1").Error)
	require.NoError(t, f.migrateDatabase(db))
}
