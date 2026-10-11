// advisory_lock_key_uniqueness_guard_test.go — coordinator round-5 finding on
// #2764: postgresCacheEpochLockKey (secret_node_cache_epoch.go) was picked as
// 872342, checked only against postgresMigrationLockKey (872341) — and
// collided with internal/serverguard's serverPresenceLockKey, ALSO 872342, a
// completely unrelated lock. In `admin restore`'s real Postgres path,
// serverguard's connection holds 872342 for the whole operation while this
// migration's own xact-scoped acquire of the SAME key, on a different
// connection, waits on it forever — a self-inflicted deadlock, reproduced
// locally with pg_locks/pg_stat_activity, not caught by any test before this
// one, and invisible to internal/storage/store's own tests because
// serverguard lives in a different package entirely.
//
// "Distinct from the one key I checked" is not "distinct from every key in
// the codebase" — nothing enumerated them centrally. This does: every
// top-level Go constant named *LockKey across the three packages that define
// Postgres advisory-lock keys today must evaluate to a value no other one
// does, derived from the actual constant value (so a hex literal and a
// decimal literal that happen to collide are still caught), not from a
// hand-written list of "the keys I know about".
package store

import (
	"go/ast"
	"go/constant"
	"go/token"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// advisoryLockKeyGuardPackages are every package this repo defines a
// top-level *LockKey constant in today. A new package introducing one owes
// this list an entry — the same obligation #2764 missed, now explicit and
// checkable rather than implicit.
var advisoryLockKeyGuardPackages = []string{
	"github.com/keyorixhq/keyorix/internal/storage",
	"github.com/keyorixhq/keyorix/internal/storage/store",
	"github.com/keyorixhq/keyorix/internal/serverguard",
}

type advisoryLockKeyConst struct {
	name  string
	pkg   string
	file  string
	value int64
}

func findAdvisoryLockKeyConsts(t *testing.T) []advisoryLockKeyConst {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedFiles,
	}
	pkgs, err := packages.Load(cfg, advisoryLockKeyGuardPackages...)
	require.NoError(t, err)
	require.Len(t, pkgs, len(advisoryLockKeyGuardPackages),
		"expected one loaded package per entry in advisoryLockKeyGuardPackages — a typo'd import path loads silently fewer")

	var found []advisoryLockKeyConst
	for _, pkg := range pkgs {
		for _, err := range pkg.Errors {
			t.Fatalf("package %s failed to load: %v", pkg.PkgPath, err)
		}
		for _, file := range pkg.Syntax {
			fileName := pkg.Fset.Position(file.Pos()).Filename
			for _, decl := range file.Decls {
				genDecl, ok := decl.(*ast.GenDecl)
				if !ok || genDecl.Tok != token.CONST {
					continue
				}
				for _, spec := range genDecl.Specs {
					valueSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, nameIdent := range valueSpec.Names {
						if !strings.HasSuffix(nameIdent.Name, "LockKey") {
							continue
						}
						if i >= len(valueSpec.Values) {
							continue
						}
						tv, ok := pkg.TypesInfo.Types[valueSpec.Values[i]]
						if !ok || tv.Value == nil {
							t.Fatalf("%s: %s is named like an advisory lock key but has no resolved constant value — this guard cannot check it", fileName, nameIdent.Name)
						}
						iv, exact := constant.Int64Val(tv.Value)
						if !exact {
							t.Fatalf("%s: %s's value does not fit in an int64 — pg_advisory_lock takes a bigint, so this constant cannot be a real lock key", fileName, nameIdent.Name)
						}
						found = append(found, advisoryLockKeyConst{
							name: nameIdent.Name, pkg: pkg.PkgPath, file: fileName, value: iv,
						})
					}
				}
			}
		}
	}
	return found
}

// TestEveryAdvisoryLockKeyConstantIsUnique is the structural half of the
// round-5 fix: it does not merely pin postgresCacheEpochLockKey's new value,
// it makes the NEXT key anyone adds — in any of the three packages above —
// get checked against every key that already exists, the check #2764 skipped.
func TestEveryAdvisoryLockKeyConstantIsUnique(t *testing.T) {
	found := findAdvisoryLockKeyConsts(t)

	// Vacuity: known count today is 6 (postgresMigrationLockKey,
	// serverPresenceLockKey, postgresCacheEpochLockKey, auditAdvisoryLockKey,
	// auditCheckpointAdvisoryLockKey, bootstrapAdvisoryLockKey). Fewer than
	// that means the scan found nothing to check, which is the same failure
	// mode as the bug itself: a guard that silently has no population.
	require.GreaterOrEqual(t, len(found), 6,
		"expected at least 6 *LockKey constants across internal/storage, internal/storage/store and internal/serverguard — found fewer, which means this guard is not actually seeing the real constants (wrong import paths, wrong AST shape) rather than that the collision risk went away")

	byValue := map[int64][]advisoryLockKeyConst{}
	for _, c := range found {
		byValue[c.value] = append(byValue[c.value], c)
	}

	var names []string
	for _, c := range found {
		names = append(names, c.name)
	}
	sort.Strings(names)
	t.Logf("checked %d advisory-lock key constants: %v", len(found), names)

	for value, consts := range byValue {
		if len(consts) < 2 {
			continue
		}
		var detail []string
		for _, c := range consts {
			detail = append(detail, c.name+" ("+c.pkg+")")
		}
		t.Errorf("advisory-lock key value %d is used by more than one constant: %v — two unrelated Postgres advisory locks sharing a key means whichever one acquires it first blocks the other forever (this is exactly how postgresCacheEpochLockKey collided with serverguard's serverPresenceLockKey on #2764)", value, detail)
	}
}
