package backupfmt

import (
	"fmt"

	"gorm.io/gorm"
)

// filterEdgesToModels keeps only the edges whose child AND parent table are
// both present in models -- table names, resolved via parseSchema, so this
// works regardless of which arbitrary subset of the registry the caller
// passed.
func filterEdgesToModels(edges []referenceEdge, models []any) []referenceEdge {
	tables := make(map[string]bool, len(models))
	for _, m := range models {
		s, err := parseSchema(m)
		if err != nil {
			continue // unparseable model can't be in scope either way
		}
		tables[s.Table] = true
	}
	var out []referenceEdge
	for _, e := range edges {
		if tables[e.ChildTable] && tables[e.ParentTable] {
			out = append(out, e)
		}
	}
	return out
}

// CheckDanglingReferences walks every cross-table reference edge
// referenceEdges() derives (design-b3-backup-v2.md §3.4), SCOPED to edges
// whose child AND parent are both in models (both are always
// storage.AllModels()'s full registry in production; a caller exercising
// this against a smaller table set -- e.g. a test -- gets edges scoped to
// only what it actually has, rather than failing on a table that was never
// created). For each in-scope edge, finds every row in the child table
// whose reference column is non-zero but has no matching row in the parent
// table -- run read-only, for EVERY edge, not a sample. Callers decide what
// to do with a non-empty result: admin backup records it as a manifest
// warning (never a refusal); admin restore refuses the whole restore (no
// skip flag) when this finds anything against the just-loaded target, per
// §3.4's corrected text.
func CheckDanglingReferences(db *gorm.DB, models []any) ([]DanglingReference, error) {
	edges, err := referenceEdges()
	if err != nil {
		return nil, fmt.Errorf("derive reference edges: %w", err)
	}
	edges = filterEdgesToModels(edges, models)

	isPostgres := db.Dialector.Name() == "postgres"

	var out []DanglingReference
	for _, e := range edges {
		if isHistoricalReference(e.ChildTable, e.ChildColumn) {
			continue // named allow list, historical_refs.go (#3085)
		}
		// #nosec G201 -- table/column names come from referenceEdges(), which
		// resolves them via gorm schema.Parse against storage.AllModels()'s
		// compiled-in Go structs, never from archive or request content.
		//
		// child.id when the child table has one -- every real entity table
		// does, and it's the same column name on both backends. The small
		// set of composite-primary-key join tables with no "id" column at
		// all (RolePermission, UserRole, GroupRole, UserGroup) need a
		// backend-specific fallback: SQLite's implicit rowid exists on every
		// ordinary table regardless of declared PK shape; Postgres has no
		// equally-simple equivalent usable in a plain SELECT here (ctid is
		// not a stable identifier to report back to an operator, and isn't
		// needed to be -- the table/column/missing-id combo already
		// pinpoints the violation), so those rows report row_id=0 rather
		// than a fabricated identifier. parent.id is always fine as-is:
		// every table these edges ever point AT (the "one" side of a
		// reference) is a real entity table with a genuine "id" column --
		// confirmed by construction, since a composite-key join table is
		// never itself the target of a reference in this schema. Found live
		// via TestAdminBackupRestore_RoundTrip (SQLite, "no such column:
		// child.id" on group_roles) and TestAdminBackupRestore_Postgres_
		// RoundTrip (Postgres, "column child.rowid does not exist" once the
		// SQLite-only rowid fix landed) -- the same class of bug walkTable's
		// own primary-key assumption had, on each backend in turn.
		rowIDExpr := "0"
		if e.ChildHasIDColumn {
			rowIDExpr = "child.id"
		} else if !isPostgres {
			rowIDExpr = "child.rowid"
		}
		query := fmt.Sprintf(
			`SELECT %s AS row_id, child.%s AS missing_id FROM %s child `+
				`LEFT JOIN %s parent ON child.%s = parent.id `+
				`WHERE child.%s != 0 AND parent.id IS NULL`,
			rowIDExpr, e.ChildColumn, e.ChildTable, e.ParentTable, e.ChildColumn, e.ChildColumn,
		)
		rows, err := db.Raw(query).Rows()
		if err != nil {
			return nil, fmt.Errorf("check %s.%s -> %s: %w", e.ChildTable, e.ChildColumn, e.ParentTable, err)
		}
		for rows.Next() {
			var d DanglingReference
			if err := rows.Scan(&d.RowID, &d.MissingID); err != nil {
				rows.Close() //nolint:errcheck
				return nil, fmt.Errorf("scan dangling reference in %s.%s: %w", e.ChildTable, e.ChildColumn, err)
			}
			d.Table = e.ChildTable
			d.Column = e.ChildColumn
			d.RefTable = e.ParentTable
			out = append(out, d)
		}
		rerr := rows.Err()
		rows.Close() //nolint:errcheck
		if rerr != nil {
			return nil, fmt.Errorf("iterate dangling references in %s.%s: %w", e.ChildTable, e.ChildColumn, rerr)
		}
	}
	return out, nil
}
