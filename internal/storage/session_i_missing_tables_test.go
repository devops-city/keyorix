// session_i_missing_tables_test.go — regression coverage for the six tables
// SESSION-I's fresh-install API smoke driver (scripts/e2e, PR to follow)
// found completely missing from migrateDatabase: secret_version_comments,
// notification_channels, alert_escalation_policies, secret_templates,
// hygiene_trend_snapshots, compliance_posture_snapshots.
//
// Each was registered in models.AllTestModels() (the test-only schema list)
// and has full, live handler/core/CLI support, but was never once passed to
// db.AutoMigrate in this production migration path -- confirmed live against
// a freshly `admin migrate`d SQLite database, every one of the six 500s with
// "SQL logic error: no such table: <name>" on its very first read or write.
// The exact same "was never migrated anywhere" bug class as MFAStepUpGrant
// (store-mfa-002) just above these in factory.go, just never caught for
// these six because no test previously booted a real server against a
// really-empty database and called them.
package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrateDatabase_SessionI_SixMissingTables_FreshInstall verifies that
// migrateDatabase, run once against a completely empty database (the
// genuine fresh-install case -- no projects table, so the "skip full
// AutoMigrate if already initialised" bulk-list gate further down in
// migrateDatabase does NOT apply here either; these six are migrated by
// their own unconditional guarded blocks), creates all six tables AND that
// each is actually usable (a real insert succeeds, not just "table exists
// with zero columns").
func TestMigrateDatabase_SessionI_SixMissingTables_FreshInstall(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "session-i-six-tables-fresh.db"))
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	for _, tc := range []struct {
		table string
		row   any
	}{
		{"secret_version_comments", &models.SecretVersionComment{VersionID: 1, SecretID: 1, UserID: 1, Username: "u", Comment: "c"}},
		{"notification_channels", &models.NotificationChannel{Name: "n", Type: "webhook", CreatedBy: "u"}},
		{"alert_escalation_policies", &models.AlertEscalationPolicy{Name: "p", MinSeverity: "high", CreatedBy: 1}},
		{"secret_templates", &models.SecretTemplate{Name: "t", CreatedBy: 1}},
		{"hygiene_trend_snapshots", &models.HygieneTrendSnapshot{}},
		{"compliance_posture_snapshots", &models.CompliancePostureSnapshot{}},
	} {
		t.Run(tc.table, func(t *testing.T) {
			assert.True(t, tableExists(db, tc.table), "table %s must exist after migrateDatabase", tc.table)
			assert.NoError(t, db.Create(tc.row).Error,
				"table %s must be genuinely usable (a real insert must succeed), not merely present", tc.table)
		})
	}
}

// TestMigrateDatabase_SessionI_SixMissingTables_UpgradedInstall verifies the
// SAME six tables are created when migrateDatabase runs against a database
// that ALREADY HAS a projects table (the "upgraded existing install" case) --
// these six are declared and guarded in the individual-tableExists-check
// section of migrateDatabase, which runs unconditionally on every call, not
// only in the "skip full AutoMigrate if already initialised" bulk list
// further down (which would silently never retrofit an existing install).
func TestMigrateDatabase_SessionI_SixMissingTables_UpgradedInstall(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "session-i-six-tables-upgrade.db"))
	require.NoError(t, err)

	// Simulate an already-migrated install: create just the projects table
	// (the bulk-list gate's own existence check) without any of the six.
	require.NoError(t, db.AutoMigrate(&models.Project{}))

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	for _, table := range []string{
		"secret_version_comments", "notification_channels", "alert_escalation_policies",
		"secret_templates", "hygiene_trend_snapshots", "compliance_posture_snapshots",
	} {
		assert.True(t, tableExists(db, table),
			"table %s must be retrofitted onto an already-migrated install, not only created on a fresh one", table)
	}
}
