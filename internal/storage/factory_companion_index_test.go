package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompanionIndexes_CreatedOnUpgrade pins the gap left behind by the #490/#761
// columnExists/tableExists SQLite fix: several columns models/models.go tags
// `gorm:"index"` are added to an EXISTING table only via a raw `ALTER TABLE ADD
// COLUMN` (gated on columnExists), never through AutoMigrate — migrateDatabase's
// full, struct-driven `db.AutoMigrate(...)` block only ever runs once, on a
// genuinely fresh install (`if projectsExists { return nil }` short-circuits it
// for every upgrade). A fresh install therefore gets the companion index for
// free via AutoMigrate; an upgraded install previously never did, silently
// degrading classification/certificate-expiry/audit-chain queries to full table
// scans as these tables grow.
//
// Simulate an upgraded install by: booting once against a fresh file (which
// creates the full, fully-indexed schema, exactly like any real fresh install),
// dropping just the target companion index to stand in for "this deployment
// predates the fix that added it" (the column, added many releases ago via the
// same raw-ALTER path, is already present either way), then re-running
// migrateDatabase directly against the same *gorm.DB — the exact call a second
// process boot makes — and confirming the companion index re-converges.
func TestCompanionIndexes_CreatedOnUpgrade(t *testing.T) {
	// idxName -> the table it lives on, purely for the DROP INDEX statement
	// (SQLite's DROP INDEX takes only the index name, but this documents intent).
	cases := []struct {
		name    string
		idxName string
	}{
		{"secret_nodes.classification", "idx_secret_nodes_classification"},
		{"secret_nodes.cert_not_after", "idx_secret_nodes_cert_not_after"},
		{"machine_identities.classification", "idx_machine_identities_classification"},
		{"machine_identity_credentials.classification", "idx_machine_identity_credentials_classification"},
		{"dynamic_secret_configs.classification", "idx_dynamic_secret_configs_classification"},
		{"anomaly_alerts.alerted", "idx_anomaly_alerts_alerted"},
		// C-PERF-FIXES: CreateAnomalyAlert's dedup count and the anomaly detector's
		// per-secret / candidate access-log reads.
		{"anomaly_alerts dedup (composite)", "idx_anomaly_alerts_dedup"},
		{"secret_access_logs (secret_node_id, access_time)", "idx_secret_access_logs_secret_time"},
		{"secret_access_logs.access_time", "idx_secret_access_logs_access_time"},
		// total_reads: a secret's lifetime read count, answered from the index alone.
		{"secret_access_logs (secret_node_id, action)", "idx_secret_access_logs_secret_action"},
	}

	dbPath := filepath.Join(t.TempDir(), "companion-index.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}

	// First boot: a genuinely fresh database. projects doesn't exist yet, so the
	// full AutoMigrate block runs and creates every table (including secret_nodes,
	// audit_events, machine_identities, etc.) with all of their `gorm:"index"`
	// companion indexes already in place — the fresh-install baseline.
	require.NoError(t, f.migrateDatabase(db))

	for _, tc := range cases {
		assert.True(t, indexExists(db, tc.idxName), "%s: fresh install must already have this index via AutoMigrate", tc.name)
	}

	// Drop every companion index under test, standing in for an install that
	// upgraded through the raw-ALTER-only path in an older binary that predates
	// this fix (column present, index never created).
	for _, tc := range cases {
		require.NoError(t, db.Exec("DROP INDEX "+tc.idxName).Error, "failed to drop %s to simulate a pre-fix upgraded install", tc.idxName)
		require.False(t, indexExists(db, tc.idxName), "%s: index must actually be gone before re-running the migration", tc.name)
	}

	// Second run: mirrors exactly what a real process boot does on an existing
	// (projects table present) database — migrateDatabase takes the
	// columnExists-gated raw-ALTER path for every column above (the column is
	// already present, so no ALTER runs), and must independently re-create each
	// companion index.
	require.NoError(t, f.migrateDatabase(db))

	for _, tc := range cases {
		assert.True(t, indexExists(db, tc.idxName), "%s: companion index must be re-created on an upgraded install, not just a fresh one", tc.name)
	}
}
