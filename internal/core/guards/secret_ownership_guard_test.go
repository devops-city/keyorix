// secret_ownership_guard_test.go — structural guard against a third, divergent
// ownership-transfer implementation (the "variant B" mistake called out in this fix's
// history: G10/#1413 added actor authorization to the bulk reassign path but left the
// shared transferOwnership primitive itself unpatched — a partial fix at ONE call site
// instead of the shared check both call sites route through). This test takes the
// opposite structural approach: rather than trusting every future call site to
// remember to re-derive transferOwnership's authorization rules, it parses this
// package's own source and fails the build the moment ANY function other than
// transferOwnership assigns directly to a SecretNode's OwnerID field.
//
// Modeled on internal/storage/store/g81_guard_test.go's AST-freshness sweep: parse
// every non-test .go file in this package, walk each function body, and flag a bare
// `<expr>.OwnerID = ...` assignment whose enclosing function isn't in the allowlist
// below. A fully unexported-boundary refactor (making the field unreachable except
// through one function, a compile-time guarantee) was considered and rejected: GORM
// requires OwnerID to stay exported for column mapping, and dozens of legitimate
// read-only call sites across this package compare secret.OwnerID directly (ownership
// checks, filters, audit payloads) — hiding the field would require touching all of
// them for no safety gain, since reads aren't the risk. An AST sweep on writes alone
// is the smaller, equally load-bearing guard.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ownerIDMutationAllowlist maps "file.go:FuncName" to why that function is allowed to
// assign SecretNode.OwnerID directly. transferOwnership (secret_ownership.go) is the
// ONE shared, authorization-checked primitive both TransferSecretOwnership (single) and
// ReassignOwnedSecrets (bulk, secret_reassign_owner.go) route through — see that
// function's doc comment for the two checks it enforces (new-owner write-tier ceiling,
// actor roles.assign on the recovery path). A new function assigning OwnerID directly
// anywhere else reimplements ownership transfer outside those checks; add it here only
// with a reasoned justification for why it independently satisfies the same
// authorization invariants — a bare grep would find a new one too, but a red CI run is
// a much stronger backstop than "somebody remembers to grep."
var ownerIDMutationAllowlist = map[string]string{
	"secret_ownership.go:transferOwnership": "the one shared, authorization-checked " +
		"ownership-transfer primitive; TransferSecretOwnership and ReassignOwnedSecrets " +
		"both call it rather than mutating OwnerID themselves",
}

// TestNoUntrackedOwnerIDMutations is the AST freshness check described above.
func TestNoUntrackedOwnerIDMutations(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatalf("failed to list package directory: %v", err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join("..", name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", path, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := name + ":" + fn.Name.Name
			_, allowed := ownerIDMutationAllowlist[key]

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range assign.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "OwnerID" {
						continue
					}
					// storage.SecretFilter.OwnerID is a *uint (pointer) query filter field,
					// not models.SecretNode's uint OwnerID column — a structurally distinct
					// shape (assigned via &localVar, never a bare value) that AST alone can't
					// tell apart from the real target by field name alone. Excluding an
					// address-of RHS filters out that one legitimate, unrelated call shape
					// (secret_listing_query.go's filter construction) without an allowlist
					// entry that would otherwise read as "this function may transfer
					// ownership," which it does not.
					if i < len(assign.Rhs) {
						if u, ok := assign.Rhs[i].(*ast.UnaryExpr); ok && u.Op == token.AND {
							continue
						}
					}
					if !allowed {
						pos := fset.Position(sel.Pos())
						t.Errorf("%s:%d: %s assigns SecretNode.OwnerID directly, outside the "+
							"shared transferOwnership primitive (secret_ownership.go) — route "+
							"ownership changes through core.transferOwnership instead of "+
							"reimplementing the authorization checks, or add a justified entry "+
							"to ownerIDMutationAllowlist in secret_ownership_guard_test.go if "+
							"this genuinely is a new, equally-guarded primitive", pos.Filename, pos.Line, key)
					}
				}
				return true
			})
		}
	}
}

// TestOwnerIDMutationAllowlist_NoStaleEntries is the inverse check: every allowlist
// entry must name a function that still exists and still assigns OwnerID, so a rename
// or refactor doesn't leave a stale, misleadingly-permissive entry behind.
func TestOwnerIDMutationAllowlist_NoStaleEntries(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	found := make(map[string]bool, len(ownerIDMutationAllowlist))

	for key := range ownerIDMutationAllowlist {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed allowlist key %q: expected \"file.go:FuncName\"", key)
		}
		fileName, funcName := parts[0], parts[1]

		src, err := os.ReadFile(filepath.Join("..", fileName))
		if err != nil {
			t.Errorf("allowlist entry %q: %v", key, err)
			continue
		}
		file, err := parser.ParseFile(fset, fileName, src, parser.ParseComments)
		if err != nil {
			t.Errorf("allowlist entry %q: failed to parse %s: %v", key, fileName, err)
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != funcName || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "OwnerID" {
						found[key] = true
					}
				}
				return true
			})
		}
	}

	for key := range ownerIDMutationAllowlist {
		if !found[key] {
			t.Errorf("allowlist entry %q no longer assigns SecretNode.OwnerID (or no longer exists) — remove the stale entry", key)
		}
	}
}
