// cache_enabled_guard_test.go — LocalStorage.cacheEnabled is the whole of the
// fix for the rolled-back-transaction defect (coordinator review of
// #2764/#2767), and both of its failure directions are INVISIBLE:
//
//   - silently false on the root store → every read-path cache is off, in
//     production, with no symptom but a latency number nobody is watching.
//     PERF-3's entire win would evaporate silently.
//   - silently true on a derived/transaction-scoped store → the blocker is
//     back: an uncommitted answer gets published into a cache that outlives
//     the transaction.
//
// Neither shows up in a correctness test, so the flag gets its own guard. The
// positive direction matters as much as the negative one here: a flag that is
// never true is as useless as one that is always true.
package store

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
	"gorm.io/gorm"
)

// TestCacheEnabled_OnForTheRootStoreOffForDerivedOnes pins both directions on
// the real constructors.
func TestCacheEnabled_OnForTheRootStoreOffForDerivedOnes(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	root := NewLocalStorage(db)
	require.True(t, root.cacheEnabled,
		"NewLocalStorage must enable caching — this is the ONLY place it is set, so a refactor that drops it turns every read-path cache off in production with no other symptom")

	sentinel := errors.New("done")
	require.ErrorIs(t, root.WithTransaction(context.Background(), func(tx storage.Storage) error {
		inner, ok := tx.(*LocalStorage)
		require.True(t, ok)
		require.False(t, inner.cacheEnabled,
			"a transaction-scoped LocalStorage must NOT have caching enabled: it reads through the transaction handle, so everything it resolves is uncommitted, and the shared cache outlives the transaction")
		return sentinel
	}), sentinel)
}

// TestCacheEnabled_IsNeverSetOnADerivedLocalStorageLiteral is the structural
// half. Every `&LocalStorage{…}` composite literal in this package other than
// NewLocalStorage's own is a derived store (WithTransaction's clone, and the
// ad-hoc `&LocalStorage{db: tx}` literals in local_rbac.go and the tests), and
// each must leave cacheEnabled at its zero value. Setting it in one of them
// would re-open the blocker for that path alone — the kind of one-site opt-in
// that no behavioural test covers because the path looks identical.
//
// Recognised: a composite literal of type LocalStorage (with or without `&`)
// anywhere in this package, including _test.go files. The one allowed to set
// the field is identified by being inside the function named
// cacheEnabledOwner below, not by file, so moving NewLocalStorage to another
// file does not silently widen the exemption.
//
// NOT recognised by THIS test, and covered by its sibling instead: a store
// built by copying a struct value (`cp := *ls`), which inherits cacheEnabled
// without any literal mentioning the field —
// TestCacheEnabled_IsNeverInheritedByAStructCopy owns that shape. Still not
// claimed by either: construction by reflection, or outside package store.
func TestCacheEnabled_IsNeverSetOnADerivedLocalStorageLiteral(t *testing.T) {
	t.Parallel()
	const cacheEnabledOwner = "NewLocalStorage"

	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()

	var violations []string
	owners := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		require.NoError(t, perr)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inOwner := fn.Name.Name == cacheEnabledOwner
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isLocalStorageLiteral(lit) {
					return true
				}
				if !literalSetsField(lit, "cacheEnabled") {
					return true
				}
				if inOwner {
					owners++
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s:%d: %s builds a LocalStorage literal that sets cacheEnabled. Only %s may; every other LocalStorage in this package is DERIVED from another (a transaction-scoped clone or an ad-hoc tx handle) and must leave the field false, because it reads uncommitted state through a transaction handle while sharing the parent's cache. See cacheEnabled's doc comment.",
					name, fset.Position(lit.Pos()).Line, fn.Name.Name, cacheEnabledOwner))
				return true
			})
		}
	}

	sort.Strings(violations)
	require.Empty(t, violations, "cacheEnabled set on a derived LocalStorage:\n%s", strings.Join(violations, "\n"))
	require.Equal(t, 1, owners,
		"expected exactly one LocalStorage literal to set cacheEnabled (%s's); got %d. Zero means the flag was dropped and caching is off everywhere; more than one means a second construction path claims to own it.",
		cacheEnabledOwner, owners)
}

func isLocalStorageLiteral(lit *ast.CompositeLit) bool {
	id, ok := lit.Type.(*ast.Ident)
	return ok && id.Name == "LocalStorage"
}

func literalSetsField(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
			return true
		}
	}
	return false
}

// TestCacheEnabled_IsNeverInheritedByAStructCopy closes the hole the literal
// guard above explicitly disclaims (coordinator review of #2764, item 3).
//
// The literal guard asks "does any composite literal SET cacheEnabled". A
// dereference copy never mentions the field and inherits it anyway:
//
//	derived := *ls      // cacheEnabled: true, carried over silently
//	derived.db = tx     // now a transaction-scoped store that caches
//
// That is the blocker exactly, reachable without tripping a single check — the
// literal guard sees no literal, and no behavioural test distinguishes the
// path. So the rule here is structural and absolute: **no value copy of a
// LocalStorage anywhere in this package.** A derived store must be constructed
// explicitly, which is what makes "this one is derived, so it must not cache" a
// thing the code states rather than a property it happens to have.
//
// Uses real type information (go/types via x/tools), not names: it flags any
// dereference whose operand's static type is *LocalStorage, and any assignment
// whose right-hand side has static type LocalStorage (the value, not the
// pointer), however the expression got there.
//
// Recognised: `*ls`, `*someField`, `*f()` — any StarExpr in a value position
// over a *LocalStorage. NOT recognised, and deliberately: reflection
// (reflect.New/Indirect), unsafe pointer casts, and copies made outside package
// store. Nothing in this repo constructs a LocalStorage by any of those; if one
// ever does, this guard does not see it.
func TestCacheEnabled_IsNeverInheritedByAStructCopy(t *testing.T) {
	t.Parallel()
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		Dir:   ".",
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, ".")
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	var violations []string
	seenFiles := map[string]bool{}
	pointerExprs := 0

	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			fname := pkg.Fset.Position(file.Pos()).Filename
			if seenFiles[fname] {
				continue // Tests:true returns the same files under several packages
			}
			seenFiles[fname] = true
			ast.Inspect(file, func(n ast.Node) bool {
				star, ok := n.(*ast.StarExpr)
				if !ok {
					return true
				}
				// A StarExpr is also how a pointer TYPE is written (*LocalStorage in
				// a signature). Only a dereference has a type recorded for its
				// operand as a value, so TypeOf on the operand distinguishes them.
				operandType := pkg.TypesInfo.TypeOf(star.X)
				if operandType == nil {
					return true
				}
				ptr, ok := operandType.(*types.Pointer)
				if !ok {
					return true
				}
				pointerExprs++
				named, ok := ptr.Elem().(*types.Named)
				if !ok || named.Obj() == nil || named.Obj().Name() != "LocalStorage" {
					return true
				}
				if named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != localStoragePkgPath {
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s:%d: dereference copy of a *LocalStorage. A value copy INHERITS cacheEnabled=true without any literal setting it, so a store derived this way caches uncommitted reads into the shared cache that outlives its transaction — the #2764 blocker, reachable without tripping the literal guard. Construct the derived store explicitly instead.",
					filepath.Base(fname), pkg.Fset.Position(star.Pos()).Line))
				return true
			})
		}
	}

	// Vacuity: if the type information stopped resolving (a packages.Load mode
	// change, a build failure swallowed into an empty TypesInfo), the loop above
	// finds nothing and looks green. This package dereferences plenty of
	// pointers, so zero pointer dereferences seen means the guard is blind.
	require.Greater(t, pointerExprs, 0,
		"no pointer dereference was type-resolved anywhere in package store — this guard is not looking at anything")

	sort.Strings(violations)
	require.Empty(t, violations, "LocalStorage copied by value:\n%s", strings.Join(violations, "\n"))
}

const localStoragePkgPath = "github.com/keyorixhq/keyorix/internal/storage/store"
