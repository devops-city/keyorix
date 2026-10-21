package main

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// auditChainAdvisoryLockKey is internal/storage/store's auditAdvisoryLockKey
// ("KEYAUDIT"), which no scheduler key may reuse.
const auditChainAdvisoryLockKey int64 = 0x4B455941_55444954

// TestSchedulerLockKeysAreDistinct keeps the background jobs' advisory-lock keys
// (ADR-039) distinct now that each job declares its own schedLock* constant in its
// scheduler_<job>.go file instead of one shared const block. Two jobs on one key
// would make the second one skip every tick its sibling holds the lock.
//
// What it recognises: package-level `const schedLock<Name> int64 = <integer literal>`
// in this package's non-test files. A key spelled any other way (an expression, an
// untyped constant) is not seen; the count floor below fails if that leaves fewer
// keys than jobs.
func TestSchedulerLockKeysAreDistinct(t *testing.T) {
	fset, files := parseServerPackage(t)
	byValue := map[int64]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "schedLock") {
						continue
					}
					if i >= len(vs.Values) {
						t.Fatalf("%s: %s has no literal value", fset.Position(name.Pos()), name.Name)
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.INT {
						t.Fatalf("%s: %s is not an integer literal", fset.Position(name.Pos()), name.Name)
					}
					v, err := strconv.ParseInt(lit.Value, 0, 64)
					if err != nil {
						t.Fatalf("%s: %s: %v", fset.Position(name.Pos()), name.Name, err)
					}
					if v == auditChainAdvisoryLockKey {
						t.Errorf("%s reuses the audit-chain advisory-lock key", name.Name)
					}
					if other, dup := byValue[v]; dup {
						t.Errorf("%s and %s share the advisory-lock key %#x", other, name.Name, v)
					}
					byValue[v] = name.Name
				}
			}
		}
	}
	if len(byValue) < len(schedulerStarts) {
		t.Fatalf("found %d schedLock* keys for %d scheduled jobs: a key is declared in a shape this guard does not recognise",
			len(byValue), len(schedulerStarts))
	}
}
