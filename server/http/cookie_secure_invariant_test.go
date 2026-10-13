package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// INV-MW-secure-cookie-follows-effective-https: every cookie the server sets takes
// its Secure attribute from the one per-request decision middleware.RequestIsHTTPS,
// the same decision that gates HSTS. This is a static scan, the counterpart of the
// behavioural TestSessionCookies_SecureBehindTrustedProxy: that test proves the
// cookies we know about, this one fails when a new cookie-setting path appears that
// the behavioural test does not know about.
//
// What it recognises (and so what it does NOT): a cookie is set through
// http.SetCookie or an http.Cookie composite literal (anywhere under server/,
// internal/, cmd/, non-test files), or a Set-Cookie header written by name via
// Header().Set/Add("Set-Cookie", ...). Cookies written through some other library
// would not be seen.

func parseNonTestGo(t *testing.T, roots ...string) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			require.NoError(t, perr, path)
			files[filepath.ToSlash(path)] = f
			return nil
		})
		require.NoError(t, err)
	}
	return files
}

func isSel(e ast.Expr, pkg, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := s.X.(*ast.Ident)
	return ok && x.Name == pkg && s.Sel.Name == name
}

func TestCookieSecureInvariant_OnlySessionCookieFileBuildsCookies(t *testing.T) {
	const home = "../../server/middleware/session_cookie.go"
	files := parseNonTestGo(t, "../../server", "../../internal", "../../cmd")
	require.Contains(t, files, filepath.ToSlash(home))

	var cookieNames []string
	for path, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CallExpr:
				if isSel(v.Fun, "http", "SetCookie") && path != filepath.ToSlash(home) {
					t.Errorf("%s: http.SetCookie outside session_cookie.go; add the cookie there so it takes the shared Secure decision", path)
				}
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Set" || sel.Sel.Name == "Add") && len(v.Args) > 0 {
					if lit, ok := v.Args[0].(*ast.BasicLit); ok && strings.EqualFold(strings.Trim(lit.Value, `"`), "Set-Cookie") {
						t.Errorf("%s: raw Set-Cookie header write; use middleware cookie helpers so Secure follows RequestIsHTTPS", path)
					}
				}
			case *ast.CompositeLit:
				if !isSel(v.Type, "http", "Cookie") {
					return true
				}
				if path != filepath.ToSlash(home) {
					t.Errorf("%s: http.Cookie literal outside session_cookie.go", path)
					return true
				}
				var name string
				secureFromParam := false
				for _, el := range v.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					switch kv.Key.(*ast.Ident).Name {
					case "Name":
						if id, ok := kv.Value.(*ast.Ident); ok {
							name = id.Name
						}
					case "Secure":
						id, ok := kv.Value.(*ast.Ident)
						secureFromParam = ok && id.Name == "secure"
					}
				}
				assert.True(t, secureFromParam, "session_cookie.go: cookie %q must set Secure from the `secure` parameter, never a constant", name)
				cookieNames = append(cookieNames, name)
			}
			return true
		})
	}

	// The set of cookies the server can set is exactly the set the behavioural test
	// (TestSessionCookies_SecureBehindTrustedProxy) drives. A new cookie name here
	// fails until it is added to both.
	sort.Strings(cookieNames)
	var uniq []string
	for i, n := range cookieNames {
		if i == 0 || n != cookieNames[i-1] {
			uniq = append(uniq, n)
		}
	}
	assert.Equal(t, []string{"AdminSessionCookieName", "CSRFCookieName", "SessionCookieName"}, uniq,
		"cookie set changed: add the new cookie to TestSessionCookies_SecureBehindTrustedProxy's flows, then update this list")
	assert.Equal(t, "kx_session", middleware.SessionCookieName)
}

var cookieHelper = regexp.MustCompile(`^(Set|Clear)\w*Cookie$`)

func TestCookieSecureInvariant_HandlersUseSharedDecisionOncePerRequest(t *testing.T) {
	files := parseNonTestGo(t, "handlers")
	require.NotEmpty(t, files)

	helperCalls := 0
	for path, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			decisions := 0
			allowed := map[ast.Node]bool{} // tlsEnabled selectors consumed by RequestIsHTTPS
			var cookieCalls []*ast.CallExpr
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isSel(call.Fun, "middleware", "RequestIsHTTPS") {
					decisions++
					for _, a := range call.Args {
						allowed[a] = true
					}
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "middleware" && cookieHelper.MatchString(sel.Sel.Name) {
						cookieCalls = append(cookieCalls, call)
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == "tlsEnabled" && !allowed[s] {
					t.Errorf("%s: %s reads tlsEnabled directly; pass it through middleware.RequestIsHTTPS", path, fn.Name.Name)
				}
				return true
			})
			assert.LessOrEqual(t, decisions, 1, "%s: %s computes the https decision more than once", path, fn.Name.Name)
			for _, c := range cookieCalls {
				helperCalls++
				last := c.Args[len(c.Args)-1]
				id, ok := last.(*ast.Ident)
				assert.True(t, ok && id.Name == "secure", "%s: %s passes a non-shared Secure value to a cookie helper", path, fn.Name.Name)
				assert.Equal(t, 1, decisions, "%s: %s sets cookies without computing middleware.RequestIsHTTPS once", path, fn.Name.Name)
			}
		}
	}
	// The scan must actually have seen the call sites, or it proves nothing.
	assert.GreaterOrEqual(t, helperCalls, 14, "scan saw fewer cookie helper calls than exist today")
}
