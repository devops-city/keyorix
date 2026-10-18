// audit_write_context_completeness_test.go — #1650 repo-wide structural guard.
//
// The fix for #1650 (a committed mutation can end up with zero audit record if the
// triggering client disconnects between the mutation and the audit write, because the
// audit write shares the request's cancellable context) lives at the lowest common
// layer: every concrete LogAuditEvent implementation must detach from its caller's
// context via auditWriteContext before doing any I/O, rather than relying on each of
// the ~190 call sites that eventually reach one of them to remember to do so.
//
// This test verifies that invariant PROGRAMMATICALLY via go/ast, across the whole
// repository — not just the two files known to implement LogAuditEvent today — so a
// future third implementation (a new storage backend) that omits the fix is caught
// automatically, and so a regression that strips the call out of an existing one is
// caught too. It is deliberately NOT a hand-maintained list of "the two files we fixed".
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// auditWriteContextAllowlist names LogAuditEvent implementations that are
// deliberately exempt from calling auditWriteContext, keyed
// "<file basename>:<enclosing type name>", with the reason as the value.
var auditWriteContextAllowlist = map[string]string{
	// FaultyStorage.LogAuditEvent (internal/faultstorage/faulty_storage_generated.go,
	// produced by internal/faultstorage/gen from the storage.Storage interface source —
	// see that package's own doc comment) never does I/O itself: every branch either
	// returns/panics with the injected fault WITHOUT calling the real storage at all,
	// or forwards ctx unmodified to w.real.LogAuditEvent(ctx, event) — the wrapped
	// real storage.Storage, always a genuine LocalStorage/RemoteStorage in this
	// package's test harness (server/faultops), whose OWN LogAuditEvent already calls
	// auditWriteContext as its first statement and is independently covered by this
	// same walk. Detachment from caller cancellation is therefore still enforced, one
	// layer down, at the implementation that actually performs the write. Adding a
	// redundant auditWriteContext(ctx) call here would mean hand-patching one method
	// inside an otherwise fully machine-generated file, which the package's own doc
	// comment says should fail to build (not silently drift) if the interface changes
	// out from under it — a hand-edit defeats that. FaultyStorage has zero production
	// callers (verified by grep: only server/faultops's *_test.go files construct it).
	"faulty_storage_generated.go:FaultyStorage": "test-only fault-injection wrapper; forwards ctx unmodified to the wrapped real storage.Storage, which already detaches (and is independently covered by this test) — see internal/faultstorage's package doc comment",
	// LocalStorage.LogAuditEvent (local_audit_chain.go, SESSION-PERF #2403 follow-up,
	// item 3): now a thin dispatcher — LogAuditEvent(ctx, event) error { return
	// ls.logAuditEvent(ctx, event, nil) } — that forwards ctx unmodified to
	// logAuditEvent, which routes to EITHER logAuditEventDirect or
	// logAuditEventBatched depending on whether this LocalStorage is transaction-
	// scoped. Both of those (not "LogAuditEvent" by name, so invisible to this AST
	// walk, which matches on method name) call auditWriteContext(ctx) as their own
	// first real step before any I/O — logAuditEventDirect literally inline;
	// logAuditEventBatched via auditWriteContext inside itself before handing the
	// detached+bounded context to the batch item it submits. Exactly the same
	// "wrapper forwards unmodified, the real implementation one layer down
	// detaches" shape as the FaultyStorage exemption above — see
	// TestLogAuditEventImplementations_DetachFromCallerCancellation's own
	// companion runtime test (TestLogAuditEvent_SucceedsWithAlreadyCanceledCallerContext)
	// for behavioral (not just structural) proof this still holds.
	"local_audit_chain.go:LocalStorage": "thin dispatcher forwarding ctx unmodified to logAuditEventDirect/logAuditEventBatched, both of which call auditWriteContext themselves before any I/O — same shape as the FaultyStorage exemption above, verified behaviorally by TestLogAuditEvent_SucceedsWithAlreadyCanceledCallerContext",
}

func TestLogAuditEventImplementations_DetachFromCallerCancellation(t *testing.T) {
	thisFile := filepath.Join(srcpath.PkgDir(), "audit_write_context_completeness_test.go")
	// internal/storage/store -> repo root.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")

	fset := token.NewFileSet()
	implementations := discoverLogAuditEventImplementations(t, fset, repoRoot)

	if len(implementations) == 0 {
		t.Fatal("discovered zero LogAuditEvent implementations across the repo — the AST walk is almost certainly broken (LocalStorage.LogAuditEvent and RemoteStorage.LogAuditEvent alone should match), not that both were removed")
	}
	if len(implementations) < 2 {
		t.Fatalf("discovered only %d LogAuditEvent implementation(s); expected at least 2 (LocalStorage, RemoteStorage) — the AST walk may be skipping a file it shouldn't", len(implementations))
	}

	var violations []string
	for _, impl := range implementations {
		if impl.CallsAuditWriteContext {
			continue
		}
		key := impl.key()
		if reason, ok := auditWriteContextAllowlist[key]; ok {
			t.Logf("allowlisted LogAuditEvent implementation %s (does not call auditWriteContext): %s", key, reason)
			continue
		}
		violations = append(violations, impl.String()+
			": does not call auditWriteContext(ctx) before doing I/O -- a canceled caller context (e.g. an HTTP client disconnecting) can silently turn a committed mutation into one with zero audit record (#1650)")
	}
	sort.Strings(violations)

	if len(violations) > 0 {
		t.Errorf("found %d LogAuditEvent implementation(s) not detached from caller cancellation, and not in auditWriteContextAllowlist:\n%s\n"+
			"Fix: add `ctx, cancel := auditWriteContext(ctx); defer cancel()` as the first thing the method does (see LocalStorage.LogAuditEvent / RemoteStorage.LogAuditEvent for the pattern), or, if this really is a deliberate exception, add it to auditWriteContextAllowlist with a comment explaining why.",
			len(violations), strings.Join(violations, "\n"))
	}
}

type logAuditEventImpl struct {
	File                   string // basename
	TypeName               string // receiver type, e.g. "LocalStorage"
	CallsAuditWriteContext bool
}

func (i logAuditEventImpl) key() string    { return i.File + ":" + i.TypeName }
func (i logAuditEventImpl) String() string { return i.File + ":" + i.TypeName + ".LogAuditEvent" }

// skipDir reports whether a directory should be excluded from the walk: VCS metadata,
// dependency/build output, and the operator module (a separate Go module per its own
// go.mod, kept out of this repo's go.work — see operator/README or go.work itself).
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "dist", ".scratch", "vendor", "operator", "web":
		return true
	}
	return false
}

// discoverLogAuditEventImplementations walks root for every non-test .go file,
// parses it, and finds every method literally named LogAuditEvent — recording, for
// each, whether its body contains a call to auditWriteContext anywhere (a shallow
// syntactic check, not a full call-graph analysis: it would not catch a method that
// calls a wrapper which itself calls auditWriteContext, but every implementation found
// to date calls it directly, matching the pattern this test asks every implementation
// to follow).
func discoverLogAuditEventImplementations(t *testing.T, fset *token.FileSet, root string) []logAuditEventImpl {
	t.Helper()
	var out []logAuditEventImpl

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("failed to parse %s: %v", path, perr)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "LogAuditEvent" || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			typeName := receiverTypeName(fn.Recv.List[0].Type)
			if typeName == "" {
				continue
			}
			out = append(out, logAuditEventImpl{
				File:                   filepath.Base(path),
				TypeName:               typeName,
				CallsAuditWriteContext: bodyCallsFunction(fn.Body, "auditWriteContext"),
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	return out
}

// receiverTypeName extracts the bare type name from a method receiver expression,
// unwrapping a single leading pointer star (e.g. "*LocalStorage" -> "LocalStorage").
func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// bodyCallsFunction reports whether body contains a call expression whose function
// name is exactly name, anywhere in its statement tree (including inside nested
// blocks, closures, etc.).
func bodyCallsFunction(body *ast.BlockStmt, name string) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}
