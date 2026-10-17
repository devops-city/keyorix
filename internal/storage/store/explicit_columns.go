package store

import (
	"strings"

	"gorm.io/gorm"
)

// modelColumns returns the comma-separated, quoted, alias-qualified column list
// of model's table ("s"."id", "s"."name", ...), for hand-written SQL and Select
// strings that would otherwise say `alias.*`.
//
// gorm.Config.QueryFields only rewrites the SELECT list gorm generates itself.
// A literal `s.*` or `SELECT *` is expanded by the database, so a column a newer
// release added makes an older replica's cached plan fail (Postgres SQLSTATE
// 0A000) during a rolling upgrade. Deriving the list from the model keeps it in
// step with the struct that scans it (INV-STORE-explicit-column-reads).
//
// It panics if model cannot be parsed: that is a programming error, and a query
// that silently selected nothing would be worse.
func modelColumns(db *gorm.DB, model any, alias string) string {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		panic("store: modelColumns: " + err.Error())
	}
	cols := make([]string, 0, len(stmt.Schema.DBNames))
	for _, name := range stmt.Schema.DBNames {
		cols = append(cols, quoteColumn(db, alias, name))
	}
	return strings.Join(cols, ", ")
}

func quoteColumn(db *gorm.DB, table, name string) string {
	var sb strings.Builder
	db.Dialector.QuoteTo(&sb, table)
	sb.WriteByte('.')
	db.Dialector.QuoteTo(&sb, name)
	return sb.String()
}
