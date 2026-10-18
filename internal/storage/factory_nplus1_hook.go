//go:build nplus1

package storage

import (
	"fmt"

	"gorm.io/gorm"
)

// NPlusOneExtraColumn is the column the nplus1 build adds to every table.
const NPlusOneExtraColumn = "zz_n1_extra"

// Built only with -tags nplus1. It simulates the schema of the NEXT release: after
// every migration, each table gains one column this binary has never heard of,
// NOT NULL with a default (the shape a real migration uses, and the one that makes
// an insert that omits it still succeed). Run the storage and core suites with the
// tag; every failure is a query that depended on the table having exactly the
// columns this release knows (a SELECT *, a positional scan).
//
//	go test -tags nplus1 ./internal/storage/... ./internal/core/...
func init() {
	afterMigrateHook = addExtraColumnToEveryTable
}

func addExtraColumnToEveryTable(db *gorm.DB) error {
	var tables []string
	var listSQL, hasSQL string
	switch db.Dialector.Name() {
	case "postgres":
		listSQL = "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'"
		hasSQL = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?"
	default:
		listSQL = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
		hasSQL = "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?"
	}
	if err := db.Raw(listSQL).Scan(&tables).Error; err != nil {
		return fmt.Errorf("nplus1: list tables: %w", err)
	}
	for _, t := range tables {
		var n int64
		if err := db.Raw(hasSQL, t, NPlusOneExtraColumn).Scan(&n).Error; err != nil {
			return fmt.Errorf("nplus1: inspect %s: %w", t, err)
		}
		if n > 0 {
			continue
		}
		ddl := fmt.Sprintf(`ALTER TABLE "%s" ADD COLUMN %s TEXT NOT NULL DEFAULT ''`, t, NPlusOneExtraColumn)
		if err := db.Exec(ddl).Error; err != nil {
			return fmt.Errorf("nplus1: add column to %s: %w", t, err)
		}
	}
	return nil
}
