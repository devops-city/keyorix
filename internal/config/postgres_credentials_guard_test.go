package config

// postgres_credentials_guard_test.go — the CLASS guard for REVIEW-3162B: the
// connection checks read one string while the driver is handed another,
// because some code rebuilt a DSN with the password in it.
//
// The rule: storage.database's DSN and password reach the driver only through
// ResolvePostgresConnConfig, which parses the DSN with pgx and sets the
// password on the parsed config. So no package outside internal/config reads
// DatabaseConfig.DSN, DatabaseConfig.Password or DatabaseConfig.GetPassword().
//
// # What the guard recognises, and what it does not
//
//   - RECOGNISED: any selector, anywhere in the module's non-test Go code
//     outside internal/config, whose receiver's static type is
//     config.DatabaseConfig (value or pointer) and whose name is DSN, Password
//     or GetPassword. Type information, not names: it sees through
//     `d := &cfg.Storage.Database; d.DSN` and through helper returns.
//   - ALLOWED: comparing DSN with the empty string literal (`d.DSN == ""`,
//     `"" != d.DSN`): a presence check reads no credential and cannot rebuild
//     a connection string (server/admin/init.go uses it). Any other use of the
//     value, including a comparison with a non-empty literal, is a hit.
//   - NOT RECOGNISED: reflection, or copying the struct into another type
//     field by field (neither exists today).
//   - NOT RECOGNISED: test files (they build DSNs on purpose), and other DSNs
//     that do not come from storage.database (dynamic-secrets engines, the
//     explicit `admin verify-audit --pg-dsn` flag).

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/token"
	"go/types"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestPostgresCredentialsReachTheDriverOnlyAsParsedConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks the whole module")
	}
	const cfgPkg = "github.com/keyorixhq/keyorix/internal/config"
	// #3354: the loader is asked for syntax and export-file paths only, and the
	// packages are type-checked HERE, one at a time. With NeedTypes, x/tools
	// type-checks packages concurrently, and under -race (Go 1.27.2) the race
	// detector reports a DATA RACE inside go/types itself, ~1 run in 15:
	// Checker.isComplete reads Named.fromRHS with no lock while Named.unpack
	// (called by another checker on the same lazily-loaded, export-data Named)
	// writes it under Named.mu. That is a go/types bug, not keyorix code, and the
	// loader's concurrency is not configurable from packages.Config. Checking
	// serially never has two checkers touching one imported Named, so the whole
	// guard keeps running, race detector on, with no skip.
	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedImports | packages.NeedExportFile,
		Dir: "../..",
	}, "./...")
	if err != nil {
		t.Fatal(err)
	}
	exportFiles := map[string]string{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.ExportFile != "" {
			exportFiles[p.PkgPath] = p.ExportFile
		}
	})
	if len(pkgs) == 0 {
		t.Fatal("packages.Load returned no packages; the guard is not looking")
	}
	fset := pkgs[0].Fset
	// One importer for the whole run: it caches by path and is not safe for
	// concurrent use, which is fine because nothing below runs concurrently.
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := exportFiles[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %q", path)
		}
		return os.Open(file)
	})
	forbidden := map[string]bool{"DSN": true, "Password": true, "GetPassword": true}
	var hits, importFailures []string
	checked := 0
	for _, p := range pkgs {
		if p.PkgPath == cfgPkg || p.Imports[cfgPkg] == nil {
			continue
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
		tc := &types.Config{
			Importer: imp,
			Sizes:    types.SizesFor("gc", runtime.GOARCH),
			// Type errors are tolerated, as before (a selector whose receiver did not
			// type-check is skipped below), but a failed IMPORT would silently shrink
			// what the guard sees, so it is collected and fails the test.
			Error: func(err error) {
				if strings.Contains(err.Error(), "could not import") {
					importFailures = append(importFailures, p.PkgPath+": "+err.Error())
				}
			},
		}
		_, _ = tc.Check(p.PkgPath, fset, p.Syntax, info)
		checked++
		for _, f := range p.Syntax {
			name := fset.File(f.Pos()).Name()
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			presenceChecks := map[ast.Expr]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				if be, ok := n.(*ast.BinaryExpr); ok && (be.Op == token.EQL || be.Op == token.NEQ) {
					if isEmptyStringLit(be.Y) {
						presenceChecks[ast.Unparen(be.X)] = true
					}
					if isEmptyStringLit(be.X) {
						presenceChecks[ast.Unparen(be.Y)] = true
					}
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !forbidden[sel.Sel.Name] || (sel.Sel.Name == "DSN" && presenceChecks[sel]) {
					return true
				}
				tv, ok := info.Types[sel.X]
				if !ok {
					return true
				}
				typ := tv.Type
				if ptr, ok := typ.(*types.Pointer); ok {
					typ = ptr.Elem()
				}
				named, ok := typ.(*types.Named)
				if ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == cfgPkg && named.Obj().Name() == "DatabaseConfig" {
					hits = append(hits, fset.Position(sel.Pos()).String()+": DatabaseConfig."+sel.Sel.Name)
				}
				return true
			})
		}
	}
	if checked < 5 {
		t.Fatalf("only %d packages importing internal/config were type-checked; the guard is not looking", checked)
	}
	for _, f := range importFailures {
		t.Errorf("an import failed to resolve, so the guard saw less than the whole module: %s", f)
	}
	sort.Strings(hits)
	for _, h := range hits {
		t.Errorf("%s is read outside internal/config; open PostgreSQL with config.ResolvePostgresConnConfig "+
			"(the password is set on pgx's parse of the DSN, never spliced into a string)", h)
	}
}

func isEmptyStringLit(e ast.Expr) bool {
	lit, ok := ast.Unparen(e).(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
}
