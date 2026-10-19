package core

// hook_storage_selftest_test.go — CORE-MOCKS-SLIM-1.
//
// Pins the behaviour hookStore promises (hook_storage_test.go) and keeps the
// [internal/core.test] archive from growing back: a second type embedding the whole
// storage.Storage interface costs ~2.6 MB of wrapper code each, which is how 123 of
// them made the archive 326-434 MB.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var _ storage.Storage = (*hookStore)(nil)

func TestHookStore_UnhookedMethodDelegatesToTheInnerStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	hookedCalls := 0
	inner := hooked(nil, &storeHooks{
		GetUser: func(storage.Storage, context.Context, uint) (*models.User, error) {
			return &models.User{ID: 42}, nil
		},
	})
	outer := hooked(inner, &storeHooks{
		GetRole: func(storage.Storage, context.Context, uint) (*models.Role, error) {
			hookedCalls++
			return nil, errors.New("hooked")
		},
	})

	_, err := outer.GetRole(ctx, 1)
	require.EqualError(t, err, "hooked")
	assert.Equal(t, 1, hookedCalls, "a hooked method runs its hook")

	u, err := outer.GetUser(ctx, 7)
	require.NoError(t, err)
	assert.Equal(t, uint(42), u.ID, "an un-hooked method must reach the inner store, as a promoted method did")
}

func TestHookStore_UnhookedMethodOnANilInnerStoreFailsLoudly(t *testing.T) {
	t.Parallel()
	spy := hooked(nil, &storeHooks{
		GetRole: func(storage.Storage, context.Context, uint) (*models.Role, error) { return nil, nil },
	})
	assert.Panics(t, func() { _, _ = spy.GetUser(context.Background(), 1) },
		"a pure spy must never silently answer a method nobody faked")
}

func TestHookStore_WithTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage) // WithTransaction hands fn the store itself

	var rawTx storage.Storage
	raw := hooked(ms, &storeHooks{})
	require.NoError(t, raw.WithTransaction(ctx, func(tx storage.Storage) error { rawTx = tx; return nil }))
	assert.Same(t, ms, rawTx, "without WrapTx the callback gets the inner store's own handle: a hook does not fire inside the transaction")

	fired := 0
	wrapped := hooked(ms, &storeHooks{
		WrapTx: true,
		GetRole: func(storage.Storage, context.Context, uint) (*models.Role, error) {
			fired++
			return nil, errors.New("injected")
		},
	})
	require.NoError(t, wrapped.WithTransaction(ctx, func(tx storage.Storage) error {
		_, err := tx.GetRole(ctx, 1)
		assert.EqualError(t, err, "injected", "with WrapTx the hook also fires on the transaction handle")
		return nil
	}))
	assert.Equal(t, 1, fired)

	var overridden bool
	custom := hooked(ms, &storeHooks{WithTransaction: func(storage.Storage, context.Context, func(storage.Storage) error) error {
		overridden = true
		return nil
	}})
	require.NoError(t, custom.WithTransaction(ctx, func(storage.Storage) error { return errors.New("must not run") }))
	assert.True(t, overridden)
}

// The combined reads are served by the store in one statement that never calls the
// per-statement reads a test overrides; hookStore must compose them over itself when a
// feeding read is hooked (the PERF-FIX-6/7 rule), and otherwise delegate untouched.
func TestHookStore_CombinedReadsMeetTheHooksThatFeedThem(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	innerAnswered := map[string]bool{}
	inner := hooked(nil, &storeHooks{
		GetSessionAuthLiveness: func(storage.Storage, context.Context, uint, uint) (*storage.SessionAuthLiveness, error) {
			innerAnswered["session"] = true
			return &storage.SessionAuthLiveness{}, nil
		},
		ResolveUserPermissionAt: func(storage.Storage, context.Context, uint, storage.Scope, string) (*storage.PrincipalPermission, error) {
			innerAnswered["user"] = true
			return &storage.PrincipalPermission{}, nil
		},
		ResolveMachinePermissionAt: func(storage.Storage, context.Context, uint, storage.Scope, string) (*storage.PrincipalPermission, error) {
			innerAnswered["machine"] = true
			return &storage.PrincipalPermission{}, nil
		},
	})

	// Nothing hooked: delegate to the inner store's own combined read.
	plain := hooked(inner, &storeHooks{})
	_, _ = plain.GetSessionAuthLiveness(ctx, 1, 1)
	_, _ = plain.ResolveUserPermissionAt(ctx, 1, storage.Scope{}, "p")
	_, _ = plain.ResolveMachinePermissionAt(ctx, 1, storage.Scope{}, "p")
	assert.Equal(t, map[string]bool{"session": true, "user": true, "machine": true}, innerAnswered)

	// A feeding read hooked: the combined read is composed over the hookStore, so the
	// hook is met and the inner combined read is NOT used.
	innerAnswered = map[string]bool{}
	boom := errors.New("injected read fault")
	faulted := hooked(inner, &storeHooks{
		GetUserRoleIDsAt: func(storage.Storage, context.Context, uint, storage.Scope) ([]uint, error) { return nil, boom },
		GetMachineRoleIDsAt: func(storage.Storage, context.Context, uint, storage.Scope) ([]uint, error) {
			return nil, boom
		},
		GetUser: func(storage.Storage, context.Context, uint) (*models.User, error) { return nil, boom },
		GetSessionByID: func(storage.Storage, context.Context, uint) (*models.Session, error) {
			return nil, boom
		},
	})
	_, err := faulted.ResolveUserPermissionAt(ctx, 1, storage.Scope{}, "p")
	assert.ErrorIs(t, err, boom, "a hooked GetUserRoleIDsAt must reach Authorize through ResolveUserPermissionAt")
	_, err = faulted.ResolveMachinePermissionAt(ctx, 1, storage.Scope{}, "p")
	assert.ErrorIs(t, err, boom, "a hooked GetMachineRoleIDsAt must reach AuthorizePrincipal through ResolveMachinePermissionAt")
	live, err := faulted.GetSessionAuthLiveness(ctx, 1, 1)
	require.NoError(t, err)
	require.NotNil(t, live)
	assert.Empty(t, innerAnswered, "the inner combined reads must be bypassed when a feeding read is hooked")

	// A hook on the combined read itself wins over composition.
	direct := hooked(inner, &storeHooks{
		GetUser: func(storage.Storage, context.Context, uint) (*models.User, error) { return nil, boom },
		GetSessionAuthLiveness: func(storage.Storage, context.Context, uint, uint) (*storage.SessionAuthLiveness, error) {
			return nil, errors.New("combined hook")
		},
	})
	_, err = direct.GetSessionAuthLiveness(ctx, 1, 1)
	assert.EqualError(t, err, "combined hook")
}

// ---- guard: no second whole-Storage embedding in the in-package tests ----

// storageEmbedNames are the type names whose embedding drags the whole 1,087-method
// Storage method set into the embedding type's wrapper set.
var storageEmbedNames = map[string]bool{
	"Storage":      true, // storage.Storage / corestorage.Storage / coreStorage.Storage
	"LocalStorage": true, // *store.LocalStorage
	"MockStorage":  true, // testify mock with ~480 methods
	"hookStore":    true,
}

// wholeStorageEmbeddingViolations returns "file: Type embeds X" for every struct type
// declared in a `package core` file of files (path -> source) that anonymously embeds a
// whole-Storage type, directly or through another such struct. hookStore itself is the
// one allowed embedding.
func wholeStorageEmbeddingViolations(t *testing.T, files map[string][]byte) []string {
	t.Helper()
	type decl struct {
		file   string
		embeds []string
	}
	structs := map[string]decl{}
	fset := token.NewFileSet()
	for path, src := range files {
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		require.NoError(t, err, path)
		if f.Name.Name != "core" {
			continue // internal/core_test is a separate archive
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				dd := decl{file: filepath.Base(path)}
				for _, field := range st.Fields.List {
					if len(field.Names) != 0 {
						continue
					}
					e := field.Type
					if star, ok := e.(*ast.StarExpr); ok {
						e = star.X
					}
					switch x := e.(type) {
					case *ast.Ident:
						dd.embeds = append(dd.embeds, x.Name)
					case *ast.SelectorExpr:
						dd.embeds = append(dd.embeds, x.Sel.Name)
					}
				}
				structs[ts.Name.Name] = dd
			}
		}
	}
	// A struct is "heavy" if it embeds a storage name or another heavy struct.
	heavy := map[string]string{}
	for changed := true; changed; {
		changed = false
		for name, d := range structs {
			if _, done := heavy[name]; done {
				continue
			}
			for _, e := range d.embeds {
				if storageEmbedNames[e] {
					heavy[name], changed = e, true
					break
				}
				if _, ok := heavy[e]; ok {
					heavy[name], changed = e, true
					break
				}
			}
		}
	}
	var out []string
	for name, via := range heavy {
		if name == "hookStore" {
			continue
		}
		out = append(out, structs[name].file+": "+name+" embeds "+via)
	}
	sort.Strings(out)
	return out
}

func TestNoWholeStorageEmbeddingInCoreTests(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	files := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(e.Name()) // #nosec G304 -- directory listing of this package's own test files
		require.NoError(t, rerr)
		files[e.Name()] = src
	}
	require.Contains(t, files, "hook_storage_test.go", "the scan must cover hookStore itself")
	assert.Empty(t, wholeStorageEmbeddingViolations(t, files),
		"a test double must not embed the whole storage.Storage (or *store.LocalStorage, MockStorage, hookStore): "+
			"each embedding costs ~2.6 MB of wrapper code in the [internal/core.test] archive. "+
			"Build it with hooked(inner, &storeHooks{...}) instead (hook_storage_test.go)")
}

// Calibration: the guard flags a direct embedding in each of its spellings and a
// chained one, ignores hookStore itself, other packages and non-embedding fields.
func TestNoWholeStorageEmbeddingInCoreTests_Calibration(t *testing.T) {
	t.Parallel()
	bad := []byte(`package core
type a struct{ storage.Storage }
type b struct {
	*store.LocalStorage
	n int
}
type c struct{ *MockStorage }
type d struct{ *hookStore }
type e struct{ a }
type hookStore struct{ storage.Storage }
type fine struct{ inner storage.Storage }
type alsoFine struct{ *captureStore }
`)
	assert.Equal(t, []string{
		"x_test.go: a embeds Storage",
		"x_test.go: b embeds LocalStorage",
		"x_test.go: c embeds MockStorage",
		"x_test.go: d embeds hookStore",
		"x_test.go: e embeds a",
	}, wholeStorageEmbeddingViolations(t, map[string][]byte{"x_test.go": bad}))
	assert.Empty(t, wholeStorageEmbeddingViolations(t, map[string][]byte{"y_test.go": []byte("package core_test\ntype z struct{ storage.Storage }\n")}),
		"the external test package has its own archive")
}
