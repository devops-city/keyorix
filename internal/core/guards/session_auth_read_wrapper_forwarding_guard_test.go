package guards

// session_auth_read_wrapper_forwarding_guard_test.go — PERF-FIX-7.
//
// The HTTP session cache hit reads the account and the session row through ONE
// storage method (GetSessionAuthLiveness). A Storage wrapper that embeds a
// Storage and overrides GetUser or GetSessionByID (the usual way a test injects
// a fault) would be bypassed silently on that path: the embedded store's
// combined method never calls the override. Same class as PERF-FIX-6's role
// reads (role_read_wrapper_forwarding_guard_test.go).
//
// The guard: every type that EMBEDS a store (an unnamed field whose type name
// ends in "Storage": storage.Storage, *store.LocalStorage, *MockStorage, ...,
// pointer or not) and declares GetUser or
// GetSessionByID must also declare GetSessionAuthLiveness (forwarding to
// storage.ComposeSessionAuthLiveness over itself). Unlike the role-read guard
// it is limited to embedding types, because GetUser is also a method name of
// handlers, gRPC services and core itself, which are not Storage wrappers. A
// complete Storage implementation that does not embed (LocalStorage,
// faultstorage.FaultyStorage, MockStorage) is already forced by the compiler
// to declare GetSessionAuthLiveness. What it does not see: an embedding
// declared through a type alias or a named non-"Storage" interface, and a
// fault injected below the Storage interface (those reach the combined
// statement directly).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var sessionAuthReadFeeds = []string{"GetUser", "GetSessionByID"}

const sessionAuthCombinedRead = "GetSessionAuthLiveness"

// sessionAuthForwardingViolations returns "dir: Type overrides M but not
// GetSessionAuthLiveness" for every Storage-embedding type in files.
func sessionAuthForwardingViolations(t *testing.T, files map[string][]byte) []string {
	t.Helper()
	embeds := map[string]bool{}             // "dir\x00Type" -> embeds a Storage
	methods := map[string]map[string]bool{} // "dir\x00Type" -> method set
	fset := token.NewFileSet()
	for path, src := range files {
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		require.NoError(t, err, path)
		dir := filepath.Dir(path)
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range st.Fields.List {
						if len(field.Names) == 0 && isStorageTypeExpr(field.Type) {
							embeds[dir+"\x00"+ts.Name.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) != 1 {
					continue
				}
				typ := d.Recv.List[0].Type
				if star, ok := typ.(*ast.StarExpr); ok {
					typ = star.X
				}
				ident, ok := typ.(*ast.Ident)
				if !ok {
					continue
				}
				key := dir + "\x00" + ident.Name
				if methods[key] == nil {
					methods[key] = map[string]bool{}
				}
				methods[key][d.Name.Name] = true
			}
		}
	}
	var out []string
	for key, set := range methods {
		if !embeds[key] || set[sessionAuthCombinedRead] {
			continue
		}
		for _, m := range sessionAuthReadFeeds {
			if set[m] {
				dir, typ, _ := strings.Cut(key, "\x00")
				out = append(out, dir+": "+typ+" overrides "+m+" but not "+sessionAuthCombinedRead)
			}
		}
	}
	sort.Strings(out)
	return out
}

func isStorageTypeExpr(e ast.Expr) bool {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	switch x := e.(type) {
	case *ast.Ident:
		return strings.HasSuffix(x.Name, "Storage")
	case *ast.SelectorExpr:
		return strings.HasSuffix(x.Sel.Name, "Storage")
	}
	return false
}

func TestSessionAuthReadWrappersForwardTheCombinedRead(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "vendor", "testdata", ".scratch":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, rerr := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path from filepath.WalkDir, not external input
		if rerr != nil {
			return rerr
		}
		// Every file that declares a type embedding a Storage, or one of the methods.
		if strings.Contains(string(src), "Storage") || strings.Contains(string(src), "GetUser") ||
			strings.Contains(string(src), "GetSessionByID") {
			files[path] = src
		}
		return nil
	})
	require.NoError(t, err)

	// It must see the known wrappers: this package's test stubs that embed a
	// store and override GetUser.
	seen := map[string]bool{}
	for path := range files {
		switch filepath.Base(path) {
		case "pre_verdict_storage_error_labelling_test.go", "share_recipients_test.go",
			"secret_ownership_test.go", "session_cache_hit_liveness_test.go":
			seen[filepath.Base(path)] = true
		}
	}
	require.Len(t, seen, 4, "the scan must cover the known Storage wrappers that override GetUser (found %v)", seen)

	require.Empty(t, sessionAuthForwardingViolations(t, files),
		"a Storage wrapper that overrides GetUser or GetSessionByID must also override GetSessionAuthLiveness "+
			"(forward it to storage.ComposeSessionAuthLiveness over itself), or the session cache hit never meets the override")
}

// Calibration: flags an embedding wrapper overriding either read without the
// combined one; accepts it with the forward (declared in another file of the
// same package); ignores a non-embedding type with a GetUser method.
func TestSessionAuthReadWrappersForwardTheCombinedRead_Calibration(t *testing.T) {
	bad := []byte(`package x
type w struct{ storage.Storage }
func (s *w) GetUser() {}
type v struct{ *store.LocalStorage; n int }
func (s v) GetSessionByID() {}
type handler struct{ store storage.Storage }
func (h *handler) GetUser() {}
`)
	require.Equal(t, []string{
		"a: v overrides GetSessionByID but not GetSessionAuthLiveness",
		"a: w overrides GetUser but not GetSessionAuthLiveness",
	}, sessionAuthForwardingViolations(t, map[string][]byte{"a/x.go": bad}))

	fwd := []byte(`package x
func (s *w) GetSessionAuthLiveness() {}
func (s v) GetSessionAuthLiveness() {}
`)
	require.Empty(t, sessionAuthForwardingViolations(t, map[string][]byte{"a/x.go": bad, "a/y.go": fwd}))
	require.NotEmpty(t, sessionAuthForwardingViolations(t, map[string][]byte{"a/x.go": bad, "b/y.go": fwd}),
		"a same-named type in another package does not count")
}
