// explicit_columns_postgres_test.go: the Postgres half of the QUERYFIELDS-1 guard
// (INV-STORE-explicit-column-reads). Gated on KEYORIX_TEST_PG_DSN.
package storage

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestQueryFields_PlansSurviveAColumnAddedByTheNextRelease_Postgres reproduces the
// rolling-upgrade failure on one connection. A release N-1 replica has run a
// query, so its pooled connection holds the prepared plan. Release N then adds a
// column. Re-running the same statement must still work.
//
// A `SELECT *` fails here with SQLSTATE 0A000 ("cached plan must not change
// result type"); that is the control subtest, which proves the setup can see the
// failure at all. Every model read through the production gorm.Config must pass.
func TestQueryFields_PlansSurviveAColumnAddedByTheNextRelease_Postgres(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	db, err := gorm.Open(postgres.Open(dsn), gormConfig()) // the production config is the thing under test
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	sqlDB.SetMaxOpenConns(1) // one connection, so the second run reuses the first run's cached plan

	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))

	readAll := func(m any) error {
		slice := reflect.New(reflect.SliceOf(reflect.TypeOf(m).Elem())).Interface()
		return db.Limit(1).Find(slice).Error
	}
	control := func() error { return db.Raw("SELECT * FROM projects LIMIT 1").Scan(&[]models.Project{}).Error }

	all := models.AllTestModels()
	for _, m := range all {
		require.NoError(t, readAll(m), "%T before the schema change", m)
	}
	require.NoError(t, control(), "control, before the schema change")

	for _, m := range all {
		stmt := &gorm.Statement{DB: db}
		require.NoError(t, stmt.Parse(m))
		require.NoError(t, db.Exec("ALTER TABLE "+stmt.Quote(stmt.Schema.Table)+" ADD COLUMN IF NOT EXISTS zz_n1_extra TEXT NOT NULL DEFAULT ''").Error)
	}

	t.Run("control: SELECT * hits the cached plan", func(t *testing.T) {
		err := control()
		require.Error(t, err, "the setup cannot reproduce the rolling-upgrade failure; this guard would prove nothing")
		require.Contains(t, err.Error(), "cached plan must not change result type")
	})
	for _, m := range all {
		require.NoError(t, readAll(m), "%T after a column was added: a read still selects by star or position", m)
	}
}
