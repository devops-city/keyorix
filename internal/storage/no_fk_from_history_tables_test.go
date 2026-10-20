package storage

// no_fk_from_history_tables_test.go -- INV-STORAGE-no-fk-from-history-tables.
//
// The audit and history tables must never hold a foreign key to a live table.
// DB-TUNE-1 (Analysis 1) measured the cost of one (+10% per audit flight, a
// FOR KEY SHARE lock on the hot secret's row) and, more to the point, showed that
// every purge semantics an FK allows breaks something: RESTRICT makes soft-delete
// retention impossible, CASCADE deletes chained audit rows, SET NULL rewrites them
// and fails chain verification. These rows are kept after what they reference is
// purged on purpose (internal/storage/store/local_purge_secret_refs.go,
// backupfmt.HistoricalReferences).
//
// Nothing stops a future change adding one by accident: production GORM leaves
// foreign-key creation on, so a model that gains an association field (or a
// `gorm:"constraint:..."` tag) gets a real FK from AutoMigrate with nobody having
// decided anything. This guard inspects the schema the real migration produces, on
// SQLite and (KEYORIX_TEST_PG_DSN) Postgres, and fails on any FK whose source is one
// of historyTables.
//
// What it does not cover: a FK on a table not named below. A new audit/history table
// has to be added to historyTables (and to backupfmt.HistoricalReferences if it
// references a secret) -- the first test keeps the two lists from drifting, but a
// brand-new history table that is in neither is invisible. FKs between live tables
// are out of scope and allowed.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
)

// historyTables are the audit/history tables DB-TUNE-1's recommendation names:
// audit_events, secret_access_logs (the access log), anomaly_alerts and
// access_review_items.
var historyTables = []string{"audit_events", "secret_access_logs", "anomaly_alerts", "access_review_items"}

// fkEdge is one foreign key of the migrated schema: table From references table To.
type fkEdge struct {
	From string `gorm:"column:fk_from"`
	To   string `gorm:"column:fk_to"`
}

func sqliteForeignKeys(t *testing.T, db *gorm.DB) []fkEdge {
	t.Helper()
	var edges []fkEdge
	require.NoError(t, db.Raw(`SELECT m.name AS fk_from, f."table" AS fk_to
		FROM sqlite_master m JOIN pragma_foreign_key_list(m.name) f
		WHERE m.type = 'table'`).Scan(&edges).Error)
	return edges
}

func postgresForeignKeys(t *testing.T, db *gorm.DB) []fkEdge {
	t.Helper()
	var edges []fkEdge
	require.NoError(t, db.Raw(`SELECT c.relname AS fk_from, r.relname AS fk_to
		FROM pg_constraint k
		JOIN pg_class c ON c.oid = k.conrelid
		JOIN pg_class r ON r.oid = k.confrelid
		WHERE k.contype = 'f' AND k.connamespace = current_schema()::regnamespace`).Scan(&edges).Error)
	return edges
}

// historyForeignKeys returns one line per FK whose source is a history table.
func historyForeignKeys(edges []fkEdge) []string {
	var bad []string
	for _, e := range edges {
		if slices.Contains(historyTables, e.From) {
			bad = append(bad, e.From+" -> "+e.To)
		}
	}
	sort.Strings(bad)
	return bad
}

func requireNoHistoryForeignKeys(t *testing.T, db *gorm.DB, edges []fkEdge) {
	t.Helper()
	// Not vacuous: every listed table must exist in the migrated schema, so a rename
	// cannot leave this guard looking at nothing.
	for _, tbl := range historyTables {
		require.Truef(t, db.Migrator().HasTable(tbl), "%s is in historyTables but the migrated schema has no such table: "+
			"update historyTables in no_fk_from_history_tables_test.go", tbl)
	}
	if bad := historyForeignKeys(edges); len(bad) > 0 {
		t.Fatalf("foreign key(s) from audit/history tables to other tables: %v\n"+
			"INV-STORAGE-no-fk-from-history-tables: these rows outlive what they reference, so no FK is allowed "+
			"(RESTRICT blocks purge, CASCADE deletes chained audit rows, SET NULL breaks the hash chain). "+
			"Find the model association or constraint tag that makes AutoMigrate create it and remove it.", bad)
	}
}

func TestNoForeignKeysFromHistoryTables_SQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "no-fk-history.db"))
	require.NoError(t, err)
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
	requireNoHistoryForeignKeys(t, db, sqliteForeignKeys(t, db))
}

func TestNoForeignKeysFromHistoryTables_Postgres(t *testing.T) {
	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	cfg.Storage.Database.MaxOpenConns = 5
	cfg.Storage.Database.MaxIdleConns = 2
	cfg.Storage.Database.ConnMaxLifetimeMinutes = 10
	// The real production migration path, same call as TestMigrateDatabase_EveryModelGetsATable_Postgres_Fresh.
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	require.NotNil(t, st)

	db := pgRawOpen(t, dsn)
	requireNoHistoryForeignKeys(t, db, postgresForeignKeys(t, db))
}

// The two tests below watch the detector itself fail: a planted FK from a history
// table must be reported, and an FK between two live tables must not be.

func TestNoForeignKeysFromHistoryTables_DetectsPlantedFK_SQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "planted-fk.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_nodes (id INTEGER PRIMARY KEY)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE audit_events (id INTEGER PRIMARY KEY,
		secret_node_id INTEGER REFERENCES secret_nodes(id))`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE live_child (id INTEGER PRIMARY KEY,
		secret_node_id INTEGER REFERENCES secret_nodes(id))`).Error)

	edges := sqliteForeignKeys(t, db)
	require.Equal(t, []string{"audit_events -> secret_nodes"}, historyForeignKeys(edges),
		"the planted audit_events FK must be reported, and the live_child FK must not")
}

func TestNoForeignKeysFromHistoryTables_DetectsPlantedFK_Postgres(t *testing.T) {
	dsn := pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	db := pgRawOpen(t, dsn)
	require.NoError(t, db.Exec(`CREATE TABLE secret_nodes (id BIGINT PRIMARY KEY)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE audit_events (id BIGINT PRIMARY KEY,
		secret_node_id BIGINT REFERENCES secret_nodes(id))`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE live_child (id BIGINT PRIMARY KEY,
		secret_node_id BIGINT REFERENCES secret_nodes(id))`).Error)

	edges := postgresForeignKeys(t, db)
	require.Equal(t, []string{"audit_events -> secret_nodes"}, historyForeignKeys(edges),
		"the planted audit_events FK must be reported, and the live_child FK must not")
}

var historicalRefTableRe = regexp.MustCompile(`Table:\s+"([a-z_]+)"`)

// TestNoForeignKeysFromHistoryTables_CoversBackupfmtHistoricalReferences keeps
// historyTables from drifting away from backupfmt.HistoricalReferences, the code's
// own list of history columns that outlive a purge. backupfmt imports this package,
// so the list is read from its source rather than called.
func TestNoForeignKeysFromHistoryTables_CoversBackupfmtHistoricalReferences(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRootU1(), "internal", "backupfmt", "historical_refs.go"))
	require.NoError(t, err)
	matches := historicalRefTableRe.FindAllStringSubmatch(string(src), -1)
	require.NotEmpty(t, matches, "no Table: \"...\" entries found in backupfmt/historical_refs.go: its layout changed, "+
		"so this check is blind -- update historicalRefTableRe")
	for _, m := range matches {
		if !slices.Contains(historyTables, m[1]) {
			t.Errorf("backupfmt.HistoricalReferences names table %q, which is not in historyTables: add it to "+
				"no_fk_from_history_tables_test.go so no FK can be added from it", m[1])
		}
	}
}
