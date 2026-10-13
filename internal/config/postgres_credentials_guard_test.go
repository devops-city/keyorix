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
	"go/ast"
	"go/token"
	"go/types"
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
	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedImports | packages.NeedCompiledGoFiles,
		Dir: "../..",
	}, "./...")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"DSN": true, "Password": true, "GetPassword": true}
	var hits []string
	checked := 0
	for _, p := range pkgs {
		if p.PkgPath == cfgPkg || len(p.Errors) > 0 && p.TypesInfo == nil {
			continue
		}
		imports := false
		for path := range p.Imports {
			if path == cfgPkg {
				imports = true
			}
		}
		if !imports {
			continue
		}
		checked++
		for i, f := range p.Syntax {
			name := p.CompiledGoFiles[i]
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
				tv, ok := p.TypesInfo.Types[sel.X]
				if !ok {
					return true
				}
				typ := tv.Type
				if ptr, ok := typ.(*types.Pointer); ok {
					typ = ptr.Elem()
				}
				named, ok := typ.(*types.Named)
				if ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == cfgPkg && named.Obj().Name() == "DatabaseConfig" {
					hits = append(hits, p.Fset.Position(sel.Pos()).String()+": DatabaseConfig."+sel.Sel.Name)
				}
				return true
			})
		}
	}
	if checked < 5 {
		t.Fatalf("only %d packages importing internal/config were type-checked; the guard is not looking", checked)
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
