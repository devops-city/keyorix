// named_lock_order_static_test.go — the static half of C-GUARD-3 guard 3: every
// WithNamedLock call site's key comes from a constructor whose key family is
// declared in storage.NamedLockOrder. The dynamic half (the panic in
// LocalStorage.WithNamedLock, enabled by named_lock_order_enable_test.go)
// checks nesting order, but only on paths a test drives; this one checks the
// declaration is complete for every call site, driven or not.
//
// Recognised key shapes (anything else fails, so a new shape is noticed): a
// call to a function or const whose name ends in "LockKey" — local, or
// qualified as storage.X — defined in internal/core or internal/core/storage
// as `return fmt.Sprintf("<prefix>%d...", ...)` (a %s verb counts as fixed
// text when the call site passes a string literal for it) or as a string const.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestNamedLockOrder_EveryCallSiteKeyHasAFamily(t *testing.T) {
	fset := token.NewFileSet()
	var files []*ast.File
	for _, dir := range []string{"..", "../storage", "../../storage/store"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
	}

	// Constructor name -> the key's fixed text (Sprintf prefix before the
	// first verb, or the whole const value).
	ctor := map[string]string{}
	exact := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			switch v := d.(type) {
			case *ast.FuncDecl:
				if !strings.HasSuffix(v.Name.Name, "LockKey") || v.Body == nil || len(v.Body.List) != 1 {
					continue
				}
				ret, ok := v.Body.List[0].(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					continue
				}
				ce, ok := ret.Results[0].(*ast.CallExpr)
				if !ok || len(ce.Args) == 0 {
					continue
				}
				if sel, ok := ce.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Sprintf" {
					continue
				}
				if bl, ok := ce.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
					s, _ := strconv.Unquote(bl.Value)
					ctor[v.Name.Name] = s
				}
			case *ast.GenDecl:
				for _, sp := range v.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, n := range vs.Names {
						if strings.HasSuffix(n.Name, "LockKey") && i < len(vs.Values) {
							if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
								s, _ := strconv.Unquote(bl.Value)
								ctor[n.Name] = s
								exact[n.Name] = true
							}
						}
					}
				}
			}
		}
	}

	// keyText renders a call site's key up to its first verb not filled by a
	// string-literal argument: sodGrantLockKey("user", id) -> "sod-grant:user:".
	keyText := func(name string, args []ast.Expr) (string, bool) {
		format, ok := ctor[name]
		if !ok {
			return "", false
		}
		if exact[name] {
			return format, true
		}
		var b strings.Builder
		argi := 0
		for i := 0; i < len(format); i++ {
			if format[i] != '%' {
				b.WriteByte(format[i])
				continue
			}
			if i+1 < len(format) && format[i+1] == 's' && argi < len(args) {
				if bl, ok := args[argi].(*ast.BasicLit); ok && bl.Kind == token.STRING {
					v, _ := strconv.Unquote(bl.Value)
					b.WriteString(v)
					argi++
					i++
					continue
				}
			}
			break
		}
		return b.String(), true
	}
	usedFamilies := map[string]bool{}
	familyFor := func(name string, args []ast.Expr) bool {
		text, ok := keyText(name, args)
		if !ok {
			return false
		}
		for _, fam := range storage.NamedLockOrder {
			if fam.Exact == exact[name] && fam.Prefix == text {
				usedFamilies[fam.Prefix] = true
				return true
			}
		}
		return false
	}

	sites := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "WithNamedLock" || len(ce.Args) != 3 {
				return true
			}
			sites++
			pos := fset.Position(ce.Pos())
			var name string
			var args []ast.Expr
			switch k := ce.Args[1].(type) {
			case *ast.Ident:
				name = k.Name
			case *ast.CallExpr:
				args = k.Args
				switch fn := k.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
			}
			if name == "" || !familyFor(name, args) {
				t.Errorf("%s: WithNamedLock key %q has no family in storage.NamedLockOrder (or is built in a shape this guard does not recognise) — declare it there, in its place in the order", pos, name)
			}
			return true
		})
	}
	if sites < 20 {
		t.Fatalf("found only %d WithNamedLock call sites — the scan stopped seeing them", sites)
	}
	today := time.Now().UTC().Format("2006-01-02")
	for _, fam := range storage.NamedLockOrder {
		if fam.PendingPR != "" {
			if today > storage.NamedLockPendingExpires {
				t.Errorf("storage.NamedLockOrder family %q still carries PendingPR %s after %s — delete the field (or the family, if that PR was abandoned)", fam.Prefix, fam.PendingPR, storage.NamedLockPendingExpires)
			}
			continue // declared ahead of the PR that adds its constructor
		}
		if !usedFamilies[fam.Prefix] {
			t.Errorf("storage.NamedLockOrder declares family %q but no WithNamedLock call site uses it — delete the stale entry", fam.Prefix)
		}
	}
}
