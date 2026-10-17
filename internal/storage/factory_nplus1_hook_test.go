//go:build nplus1

package storage

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"gorm.io/gorm"
)

// The nplus1 run proves nothing if the hook never fires. This is its vacuity check:
// after the factory's migration every table must carry the extra column.
func TestNPlusOneHook_AddsTheExtraColumnToEveryTable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := openSQLiteGorm(sqlitetest.DSN("nplus1hook"))
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, (&DefaultStorageFactory{}).migrateSQLite(db))

	for _, m := range models.AllTestModels() {
		stmt := &gorm.Statement{DB: db}
		require.NoError(t, stmt.Parse(m))
		require.True(t, columnExists(db, stmt.Schema.Table, NPlusOneExtraColumn), "%s has no %s", stmt.Schema.Table, NPlusOneExtraColumn)
	}
}
