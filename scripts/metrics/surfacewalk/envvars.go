package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// envReaders are the call forms recognised as "this code reads environment
// variable <first argument>". The list is the enumeration: a read through any
// other helper is not counted, and that is a known, stated limit. secretenv
// reads NAME and NAME_FILE; only NAME is listed.
var envReaders = map[string]map[string]bool{
	"os":        {"Getenv": true, "LookupEnv": true},
	"secretenv": {"Lookup": true, "LookupChecked": true},
}

// projectEnvName matches a string literal that is exactly a Keyorix environment
// variable name. A trailing underscore (a prefix such as "KEYORIX_SSO_") is
// not a variable.
var projectEnvName = regexp.MustCompile(`^KEYORIX_[A-Z0-9_]*[A-Z0-9]$`)

// envVars returns the sorted unique variable names in non-test Go code under
// root/<dirs>, by two rules: (1) the first argument of a recognised read call
// (envReaders), whatever the variable; (2) any whole-string literal that is a
// KEYORIX_* name. It also returns the number of rule-1 reads whose name could
// not be resolved (a computed string, or a constant from another package that
// is not unique). Names starting KEYORIX_TEST_ / KEYORIX_E2E_ are test knobs
// and are dropped.
func envVars(root string, dirs []string) (names []string, unresolved int, err error) {
	fset := token.NewFileSet()
	type pkgFiles struct{ files []*ast.File }
	byDir := map[string]*pkgFiles{}
	for _, d := range dirs {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		base := filepath.Join(root, d)
		if _, serr := os.Stat(base); serr != nil {
			continue // a directory that does not exist at this ref
		}
		werr := filepath.WalkDir(base, func(p string, e os.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if e.IsDir() {
				switch e.Name() {
				case "vendor", "node_modules", "testdata", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				return nil // a file that does not parse is not a product file; build catches real ones
			}
			dir := filepath.Dir(p)
			if byDir[dir] == nil {
				byDir[dir] = &pkgFiles{}
			}
			byDir[dir].files = append(byDir[dir].files, f)
			return nil
		})
		if werr != nil {
			return nil, 0, werr
		}
	}

	// String constants: per directory (same package), and globally by "pkg.Name"
	// when that key is unique.
	local := map[string]map[string]string{}
	global := map[string]string{}
	ambiguous := map[string]bool{}
	for dir, pf := range byDir {
		local[dir] = map[string]string{}
		for _, f := range pf.files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i >= len(vs.Values) {
							break
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						s, uerr := strconv.Unquote(lit.Value)
						if uerr != nil {
							continue
						}
						local[dir][n.Name] = s
						key := f.Name.Name + "." + n.Name
						if prev, seen := global[key]; seen && prev != s {
							ambiguous[key] = true
						}
						global[key] = s
					}
				}
			}
		}
	}

	set := map[string]bool{}
	for dir, pf := range byDir {
		for _, f := range pf.files {
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, isLit := n.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
					// Whole-string literal naming a project variable: catches reads
					// through project helpers (resolveSecret("KEYORIX_X", ...)) and
					// name tables, which the call forms above cannot enumerate.
					if s, uerr := strconv.Unquote(lit.Value); uerr == nil && projectEnvName.MatchString(s) {
						set[s] = true
					}
					return true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || !envReaders[pkg.Name][sel.Sel.Name] {
					return true
				}
				switch a := call.Args[0].(type) {
				case *ast.BasicLit:
					if s, uerr := strconv.Unquote(a.Value); uerr == nil {
						set[s] = true
						return true
					}
				case *ast.Ident:
					if s, found := local[dir][a.Name]; found {
						set[s] = true
						return true
					}
				case *ast.SelectorExpr:
					if x, isIdent := a.X.(*ast.Ident); isIdent {
						key := x.Name + "." + a.Sel.Name
						if s, found := global[key]; found && !ambiguous[key] {
							set[s] = true
							return true
						}
					}
				}
				unresolved++
				return true
			})
		}
	}
	for s := range set {
		if strings.HasPrefix(s, "KEYORIX_TEST_") || strings.HasPrefix(s, "KEYORIX_E2E_") {
			continue // test-harness knobs that live in non-test helper packages
		}
		names = append(names, s)
	}
	sort.Strings(names)
	return names, unresolved, nil
}
