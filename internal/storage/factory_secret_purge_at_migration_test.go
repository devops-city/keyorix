package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// TestSecretNodePurgeAtColumn_AddedOnUpgrade pins the #3021 review blocker: models.SecretNode
// gained PurgeAt, but migrateDatabase exits early (freshInstallComplete) on an existing
// database, so secret_nodes is never re-AutoMigrated there and the column was only ever
// created on fresh installs. Every INSERT/UPDATE GORM generates for SecretNode names
// purge_at, so on an upgraded install secret create and delete failed with "no column
// named purge_at". Same simulate-an-upgrade shape as TestRoleNameFoldedColumn_AddedOnUpgrade:
// boot fresh, drop the column to stand in for an install that predates it, migrate again.
func TestSecretNodePurgeAtColumn_AddedOnUpgrade(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secret-purge-at-upgrade.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}

	require.NoError(t, f.migrateDatabase(db))
	require.True(t, columnExists(db, "secret_nodes", "purge_at"), "fresh install must have purge_at")

	require.NoError(t, db.Exec("ALTER TABLE secret_nodes DROP COLUMN purge_at").Error)
	require.False(t, columnExists(db, "secret_nodes", "purge_at"), "purge_at must actually be gone before re-running the migration")

	require.NoError(t, f.migrateDatabase(db))
	assert.True(t, columnExists(db, "secret_nodes", "purge_at"), "purge_at must be re-added on an upgraded install, not just a fresh one")

	// The user-visible symptom: creating (and stamping) a secret on the upgraded schema.
	require.NoError(t, db.Exec(`INSERT INTO projects (id, name, created_at, updated_at) VALUES (1, 'p', datetime('now'), datetime('now'))`).Error)
	require.NoError(t, db.Exec(`INSERT INTO environments (id, project_id, name, created_at, updated_at) VALUES (1, 1, 'e', datetime('now'), datetime('now'))`).Error)
	at := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	node := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "s", Type: "static", PurgeAt: &at}
	require.NoError(t, db.Create(node).Error, "Create(SecretNode) must work on an upgraded install")

	var got models.SecretNode
	require.NoError(t, db.Unscoped().First(&got, node.ID).Error)
	require.NotNil(t, got.PurgeAt)
	assert.True(t, got.PurgeAt.Equal(at), "purge_at must round-trip: got %v want %v", got.PurgeAt, at)
}

// TestSecretNodePurgeAtColumn_AddedOnUpgrade_Postgres is the same upgrade check on
// Postgres, where the ALTER takes TIMESTAMP WITH TIME ZONE rather than SQLite's DATETIME.
//
// pg-gated: skipped without KEYORIX_TEST_PG_DSN.
func TestSecretNodePurgeAtColumn_AddedOnUpgrade_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — the Postgres purge_at upgrade path is unverified in this run")
	}
	schema := fmt.Sprintf("purge_at_%d", os.Getpid())
	admin, err := gorm.Open(postgres.Open(dsn), gormConfig())
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), gormConfig())
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	require.NoError(t, f.migrateDatabase(db))
	require.True(t, columnExists(db, "secret_nodes", "purge_at"), "fresh install must have purge_at")

	require.NoError(t, db.Exec("ALTER TABLE secret_nodes DROP COLUMN purge_at").Error)
	require.False(t, columnExists(db, "secret_nodes", "purge_at"))

	require.NoError(t, f.migrateDatabase(db))
	assert.True(t, columnExists(db, "secret_nodes", "purge_at"), "purge_at must be re-added on an upgraded Postgres install")

	at := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	node := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "pg-purge-at", Status: "active", PurgeAt: &at}
	require.NoError(t, db.Create(node).Error, "Create(SecretNode) must work on an upgraded install")
	var got models.SecretNode
	require.NoError(t, db.Unscoped().First(&got, node.ID).Error)
	require.NotNil(t, got.PurgeAt)
	assert.True(t, got.PurgeAt.Equal(at), "purge_at must round-trip: got %v want %v", got.PurgeAt, at)
}
