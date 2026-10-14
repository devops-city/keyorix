// fresh_install_complete_covers_bulk_models_test.go — #2440.
//
// migrateDatabase decides whether a database is already fully initialised with
// `freshInstallComplete`, a hand-written conjunction of ~23 tableExists flags.
// The fresh-install tail it gates has its OWN hand-written model list (the bulk
// `for _, m := range []interface{}{...}` AutoMigrate loop). The two lists are
// supposed to describe the same set of tables — freshInstallComplete's own doc
// comment says so outright: "true only when EVERY model the transactional block
// below migrates already has its table."
//
// Nothing enforced that. Add a model to the loop and forget the flag, and a
// database missing exactly that new table satisfies freshInstallComplete,
// returns early, and is never repaired — reintroducing, for the new table, the
// half-migrated bug #2389 fixed. Nothing errors; the install just quietly lacks
// a table forever, which is the same silent shape #2258/#2264 kept producing
// (see all_models_migration_guard_test.go's header).
//
// This guard derives BOTH lists from internal/storage/factory.go's own AST, so
// there is no third hand-written list to go stale in turn:
//
//   - every `x := tableExists(db, "t")` assignment gives an identifier → table
//     name mapping;
//   - `freshInstallComplete := a && b && ...` gives the identifiers the gate
//     actually requires, which map to table names through the above;
//   - the bulk loop's composite literal gives `models.X{}` type names, which map
//     to table names through gorm's own NamingStrategy (not a hand-written
//     pluralisation), reusing models.AllTestModels() — itself AST-guarded by
//     TestAllTestModels_MatchesModelsGoStructSet — to turn a name back into a
//     typed value.
//
// Then it asserts SET EQUALITY, both directions. A model migrated by the loop
// but absent from the gate is #2440 itself. A table required by the gate but no
// longer migrated by the loop is the opposite drift: the gate can never be
// satisfied by a database the loop actually produces, so every boot re-runs the
// fresh-install tail forever.
//
// What this does NOT cover, stated rather than left implicit:
//   - models migrated by one of the DEDICATED existence-gated blocks above the
//     bulk loop (AuditCheckpoint, SecretAccessLog, Setting, …). Those run
//     unconditionally, before the gate, so they are intentionally NOT part of
//     freshInstallComplete; "every model gets a table" for them is
//     all_models_migration_guard_test.go's job, not this file's.
//   - whether the gate's SEMANTICS are right (that an early return is safe at
//     all). That is factory_half_migrated_db_test.go and
//     factory_schema_epoch_upgrade_path_test.go.
//   - a model added to the loop via anything other than a literal
//     `&models.X{}` element — a variable, a helper call, a spread. The
//     extractor reports such an element loudly (a failed test naming the
//     unparsed expression) rather than skipping it silently, which is the only
//     honest option for a structural check over source text.
package storage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// factoryASTFor2440 parses internal/storage/factory.go.
func factoryASTFor2440(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	path := filepath.Join(repoRootU1(), "internal", "storage", "factory.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	require.NoError(t, err, "parsing factory.go")
	return fset, file
}

// tableExistsIdentsFor2440 maps each local identifier assigned from
// `tableExists(db, "<table>")` to that table name.
func tableExistsIdentsFor2440(t *testing.T, file *ast.File) map[string]string {
	t.Helper()
	out := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		lhs, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := call.Fun.(*ast.Ident)
		if !ok || fn.Name != "tableExists" || len(call.Args) != 2 {
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		out[lhs.Name] = lit.Value[1 : len(lit.Value)-1] // strip quotes
		return true
	})
	require.NotEmpty(t, out, "found no `x := tableExists(db, \"...\")` assignments in factory.go — "+
		"the extractor no longer matches the code it reads; fix this test, do not delete it")
	return out
}

// freshInstallCompleteTablesFor2440 returns the table names
// `freshInstallComplete := a && b && ...` requires, resolved through the
// tableExists identifier map.
func freshInstallCompleteTablesFor2440(t *testing.T, file *ast.File, idents map[string]string) map[string]bool {
	t.Helper()
	var rhs ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if lhs, ok := as.Lhs[0].(*ast.Ident); ok && lhs.Name == "freshInstallComplete" {
			rhs = as.Rhs[0]
			return false
		}
		return true
	})
	require.NotNil(t, rhs, "no `freshInstallComplete := ...` assignment found in factory.go — "+
		"if the gate was renamed or restructured, update this test deliberately")

	tables := map[string]bool{}
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.BinaryExpr:
			require.Equal(t, token.LAND, v.Op,
				"freshInstallComplete is expected to be a pure && conjunction; found operator %q, "+
					"which this extractor cannot interpret -- update it rather than trusting a partial read", v.Op)
			walk(v.X)
			walk(v.Y)
		case *ast.ParenExpr:
			walk(v.X)
		case *ast.Ident:
			tbl, ok := idents[v.Name]
			require.Truef(t, ok, "freshInstallComplete references %q, which is not assigned from "+
				"tableExists(db, \"...\") anywhere in factory.go -- this test cannot tell which table it means", v.Name)
			tables[tbl] = true
		default:
			require.Failf(t, "unparsable freshInstallComplete operand",
				"operand of type %T is neither an identifier nor a && chain", e)
		}
	}
	walk(rhs)
	return tables
}

// bulkFreshInstallModelsFor2440 returns the `models.X` type names in the
// fresh-install tail's bulk AutoMigrate loop: the `for _, m := range
// []interface{}{...}` range statement whose body calls tx.AutoMigrate(m).
func bulkFreshInstallModelsFor2440(t *testing.T, file *ast.File) []string {
	t.Helper()
	var names []string
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		rs, ok := n.(*ast.RangeStmt)
		if !ok || found {
			return true
		}
		comp, ok := rs.X.(*ast.CompositeLit)
		if !ok {
			return true
		}
		arr, ok := comp.Type.(*ast.ArrayType)
		if !ok {
			return true
		}
		// The element type is the empty interface, spelled `interface{}` or `any`.
		switch elt := arr.Elt.(type) {
		case *ast.InterfaceType:
			if len(elt.Methods.List) != 0 {
				return true
			}
		case *ast.Ident:
			if elt.Name != "any" {
				return true
			}
		default:
			return true
		}
		// Confirm this is the AutoMigrate loop, not some other []interface{}
		// range: its body must call .AutoMigrate.
		migrates := false
		ast.Inspect(rs.Body, func(b ast.Node) bool {
			if sel, ok := b.(*ast.SelectorExpr); ok && sel.Sel.Name == "AutoMigrate" {
				migrates = true
			}
			return true
		})
		if !migrates {
			return true
		}
		found = true
		for _, el := range comp.Elts {
			unary, ok := el.(*ast.UnaryExpr)
			require.Truef(t, ok && unary.Op == token.AND, "bulk AutoMigrate list element %T is not `&models.X{}`", el)
			lit, ok := unary.X.(*ast.CompositeLit)
			require.Truef(t, ok, "bulk AutoMigrate list element %T is not a composite literal", unary.X)
			sel, ok := lit.Type.(*ast.SelectorExpr)
			require.Truef(t, ok, "bulk AutoMigrate list element type %T is not models.X", lit.Type)
			pkg, ok := sel.X.(*ast.Ident)
			require.Truef(t, ok && pkg.Name == "models", "bulk AutoMigrate list element is not from the models package")
			names = append(names, sel.Sel.Name)
		}
		return false
	})
	require.True(t, found, "no fresh-install bulk `for _, m := range []interface{}{...}` AutoMigrate loop found in "+
		"factory.go (`[]any{...}` is accepted too) -- if it was restructured, update this test deliberately")
	require.NotEmpty(t, names, "the bulk AutoMigrate loop's model list came back empty")
	return names
}

// modelTableNameFor2440 resolves a models.X type NAME to the table name gorm
// itself would use, via models.AllTestModels() (AST-guarded against drift by
// TestAllTestModels_MatchesModelsGoStructSet) plus gorm's own NamingStrategy —
// never a hand-written pluralisation.
func modelTableNameFor2440(t *testing.T, typeName string) string {
	t.Helper()
	for _, m := range models.AllTestModels() {
		if reflect.TypeOf(m).Elem().Name() != typeName {
			continue
		}
		sch, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		require.NoErrorf(t, err, "schema.Parse(%s)", typeName)
		return sch.Table
	}
	require.FailNowf(t, "model not found",
		"models.%s appears in migrateDatabase's bulk AutoMigrate loop but not in models.AllTestModels()", typeName)
	return ""
}

func TestFreshInstallComplete_CoversEveryBulkMigratedModel(t *testing.T) {
	_, file := factoryASTFor2440(t)
	idents := tableExistsIdentsFor2440(t, file)
	gateTables := freshInstallCompleteTablesFor2440(t, file, idents)

	loopTables := map[string]bool{}
	for _, name := range bulkFreshInstallModelsFor2440(t, file) {
		loopTables[modelTableNameFor2440(t, name)] = true
	}

	var missingFromGate, missingFromLoop []string
	for tbl := range loopTables {
		if !gateTables[tbl] {
			missingFromGate = append(missingFromGate, tbl)
		}
	}
	for tbl := range gateTables {
		if !loopTables[tbl] {
			missingFromLoop = append(missingFromLoop, tbl)
		}
	}
	sort.Strings(missingFromGate)
	sort.Strings(missingFromLoop)

	assert.Emptyf(t, missingFromGate,
		"#2440: migrateDatabase's fresh-install bulk AutoMigrate loop creates %v, but freshInstallComplete "+
			"does not require them. A database missing exactly those tables satisfies the gate, returns early, "+
			"and is never repaired -- the half-migrated bug #2389 fixed, reintroduced for the new table. "+
			"Fix: add `xExists := tableExists(db, \"<table>\")` to the up-front snapshot block "+
			"(internal/storage/factory.go, alongside environmentExists et al. -- it MUST be snapshotted before "+
			"any AutoMigrate runs, see that block's own pgx note) and AND it into freshInstallComplete",
		missingFromGate)

	assert.Emptyf(t, missingFromLoop,
		"freshInstallComplete requires %v, but migrateDatabase's bulk AutoMigrate loop no longer creates them. "+
			"The gate can then never be satisfied by a database this code produces, so every boot re-runs the "+
			"whole fresh-install tail forever. Fix: drop those flags from freshInstallComplete, or (if the model "+
			"moved to one of the dedicated existence-gated blocks above the loop) confirm that move was intended "+
			"-- those blocks run unconditionally, before the gate, so they are deliberately not part of it",
		missingFromLoop)
}
