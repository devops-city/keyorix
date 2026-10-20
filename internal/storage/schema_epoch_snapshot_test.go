// schema_epoch_snapshot_test.go — a schema change cannot land without a
// schema-epoch decision (ADR-097, ADR-101; REVIEW-COVERAGE-2).
//
// TestCurrentSchemaEpoch_Is5_SeeADR101 only fires when someone changes the
// epoch constant. It is silent when the schema changes and the constant does
// not, which is exactly how the class happened: #3215 added
// secret_nodes.suspend_clear_synced_copies at epoch 2 (9b8fd490a) and the N-1
// resume bug it made (#3362) was only closed later by HA-READY-1's floor-3 bump;
// #3041 added sessions.setup_only (an N-1 binary would read a setup-only
// session as a full one) and 13424cbf3 added the users/groups/roles *_folded
// columns, all without a bump.
//
// These tests migrate a fresh database and compare its schema (tables, every
// column with type, nullability and default, indexes, triggers) with the
// snapshot recorded for currentSchemaEpoch in testdata/schema_epoch/. A
// difference means: bump currentSchemaEpoch, decide minCompatibleSchemaEpoch
// (factory.go explains both), then record the new snapshot with
//
//	KEYORIX_UPDATE_SCHEMA_SNAPSHOT=1 go test ./internal/storage -run TestSchemaSnapshot
//
// (with KEYORIX_TEST_PG_DSN set for the PostgreSQL one). A change that really
// needs no bump (none so far) may re-record the current epoch's file, and the
// PR must say why; that edit is the reviewer's signal.
//
// What it does NOT see: a change in what a column MEANS without a schema
// change (#3021's purge_at semantics would have needed a bump with no DDL at
// all), data backfills, and objects created outside migrateDatabase.
package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

const updateSchemaSnapshotEnv = "KEYORIX_UPDATE_SCHEMA_SNAPSHOT"

func schemaSnapshotPath(dialect string) string {
	return filepath.Join("testdata", "schema_epoch", fmt.Sprintf("epoch-%d.%s.txt", currentSchemaEpoch, dialect))
}

// compareSchemaSnapshot compares got with the recorded snapshot, or records it.
func compareSchemaSnapshot(t *testing.T, dialect string, got []string) {
	t.Helper()
	slices.Sort(got)
	text := "# schema of a fresh " + dialect + " install at currentSchemaEpoch " + strconv.Itoa(currentSchemaEpoch) +
		"; see schema_epoch_snapshot_test.go\n" + strings.Join(got, "\n") + "\n"
	path := schemaSnapshotPath(dialect)
	if os.Getenv(updateSchemaSnapshotEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded %s (%d lines)", path, len(got))
		return
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed testdata path
	if err != nil {
		t.Fatalf("no schema snapshot for currentSchemaEpoch %d (%v): a new epoch needs its snapshot recorded with %s=1",
			currentSchemaEpoch, err, updateSchemaSnapshotEnv)
	}
	var want []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			want = append(want, line)
		}
	}
	var added, removed []string
	for _, l := range got {
		if !slices.Contains(want, l) {
			added = append(added, l)
		}
	}
	for _, l := range want {
		if !slices.Contains(got, l) {
			removed = append(removed, l)
		}
	}
	if len(added)+len(removed) > 0 {
		t.Fatalf("the %s schema changed but currentSchemaEpoch is still %d.\n"+
			"Bump currentSchemaEpoch and decide minCompatibleSchemaEpoch (internal/storage/factory.go, ADR-097/ADR-101): "+
			"can a replica still running the previous binary read and write this schema safely during a rolling upgrade? "+
			"Then record the new snapshot with %s=1.\nadded:\n  %s\nremoved:\n  %s",
			dialect, currentSchemaEpoch, updateSchemaSnapshotEnv,
			strings.Join(added, "\n  "), strings.Join(removed, "\n  "))
	}
}

func sqliteSchemaLines(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	type obj struct{ Type, Name, TblName, SQL string }
	var objs []obj
	if err := db.Raw(`SELECT type, name, tbl_name AS tbl_name, COALESCE(sql, '') AS sql FROM sqlite_master
WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`).Scan(&objs).Error; err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range objs {
		switch o.Type {
		case "table":
			out = append(out, "table "+o.Name)
			type col struct {
				Name      string
				Type      string
				NotNull   int     `gorm:"column:notnull"`
				DfltValue *string `gorm:"column:dflt_value"`
				PK        int     `gorm:"column:pk"`
			}
			var cols []col
			if err := db.Raw("SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info(?)", o.Name).Scan(&cols).Error; err != nil {
				t.Fatal(err)
			}
			for _, c := range cols {
				d := "<none>"
				if c.DfltValue != nil {
					d = *c.DfltValue
				}
				out = append(out, fmt.Sprintf("column %s.%s %s notnull=%d default=%s pk=%d", o.Name, c.Name, strings.ToUpper(c.Type), c.NotNull, d, c.PK))
			}
		case "index", "trigger":
			out = append(out, fmt.Sprintf("%s %s on %s: %s", o.Type, o.Name, o.TblName, strings.Join(strings.Fields(o.SQL), " ")))
		}
	}
	return out
}

func postgresSchemaLines(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var out []string
	type col struct{ TableName, ColumnName, DataType, IsNullable, ColumnDefault string }
	var cols []col
	if err := db.Raw(`SELECT table_name, column_name, data_type, is_nullable, COALESCE(column_default, '<none>') AS column_default
FROM information_schema.columns WHERE table_schema = current_schema()`).Scan(&cols).Error; err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{}
	for _, c := range cols {
		tables[c.TableName] = true
		out = append(out, fmt.Sprintf("column %s.%s %s nullable=%s default=%s", c.TableName, c.ColumnName, c.DataType, c.IsNullable, c.ColumnDefault))
	}
	for tbl := range tables {
		out = append(out, "table "+tbl)
	}
	type idx struct{ Tablename, Indexname, Indexdef string }
	var idxs []idx
	if err := db.Raw(`SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema()`).Scan(&idxs).Error; err != nil {
		t.Fatal(err)
	}
	for _, i := range idxs {
		def := strings.ReplaceAll(i.Indexdef, " "+currentSchemaName(t, db)+".", " ")
		out = append(out, fmt.Sprintf("index %s on %s: %s", i.Indexname, i.Tablename, def))
	}
	type trg struct{ Relname, Tgname, Tgenabled, Def string }
	var trgs []trg
	if err := db.Raw(`SELECT c.relname, t.tgname, t.tgenabled::text AS tgenabled, pg_get_triggerdef(t.oid) AS def
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE NOT t.tgisinternal AND n.nspname = current_schema()`).Scan(&trgs).Error; err != nil {
		t.Fatal(err)
	}
	for _, tr := range trgs {
		def := strings.ReplaceAll(tr.Def, " "+currentSchemaName(t, db)+".", " ")
		out = append(out, fmt.Sprintf("trigger %s on %s enabled=%s: %s", tr.Tgname, tr.Relname, tr.Tgenabled, def))
	}
	return out
}

func currentSchemaName(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var s string
	if err := db.Raw("SELECT current_schema()").Scan(&s).Error; err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSchemaSnapshot_SQLite_MatchesEpoch runs in default CI.
func TestSchemaSnapshot_SQLite_MatchesEpoch(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatal(err)
	}
	defer i18n.ResetForTesting()
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "snapshot.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := (&DefaultStorageFactory{}).migrateDatabase(db); err != nil {
		t.Fatal(err)
	}
	compareSchemaSnapshot(t, "sqlite", sqliteSchemaLines(t, db))
}

// TestSchemaSnapshot_Postgres_MatchesEpoch is pg-gated: PostgreSQL-only DDL
// (the rolling-upgrade triggers, partial indexes' exact form, column types)
// shows only here.
func TestSchemaSnapshot_Postgres_MatchesEpoch(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatal(err)
	}
	defer i18n.ResetForTesting()
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	if err := (&DefaultStorageFactory{}).migrateDatabase(db); err != nil {
		t.Fatal(err)
	}
	compareSchemaSnapshot(t, "postgres", postgresSchemaLines(t, db))
}
