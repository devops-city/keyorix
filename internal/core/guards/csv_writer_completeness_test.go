// csv_writer_completeness_test.go — FIX-8 (adversarial review run 2) repo-wide
// structural guard.
//
// CSV formula injection (CWE-1236) was found and fixed at least 5 separate
// times across this codebase's history (G49, #1682 web frontend,
// secret_access_log_export.go's ActorType/IPAddress, internal/cli/audit's
// ActorType) because each CSV-writing function carried its own local
// encoding responsibility with nothing enforcing it repo-wide. This test
// verifies, via go/ast across the whole repository -- not a hand-maintained
// list of "the writers we already fixed" -- that every Go function
// constructing an encoding/csv.Writer also calls a CSV-safety encoder
// (csvSafe or CSVSafe) somewhere in its body, so a future CSV writer that
// omits it is caught automatically rather than silently shipping bare.
package guards

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

// csvWriterCompletenessAllowlist names CSV-writing functions deliberately
// exempt from calling a csvSafe/CSVSafe encoder, keyed
// "<file basename>:<function name>", with the reason as the value. Empty on
// purpose: every real CSV writer found so far needs the fix.
var csvWriterCompletenessAllowlist = map[string]string{}

func TestCSVWriters_EncodeAgainstFormulaInjection(t *testing.T) {
	t.Parallel()
	thisFile := filepath.Join(srcpath.PkgDir(), "csv_writer_completeness_test.go")
	// internal/core -> repo root.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")

	fset := token.NewFileSet()
	writers := discoverCSVWriterFunctions(t, fset, repoRoot)

	if len(writers) == 0 {
		t.Fatal("discovered zero CSV-writing functions across the repo — the AST walk is almost certainly broken, not that every CSV export was removed")
	}
	// #1682/this campaign's own audit found 12 Go CSV writers; a sharp drop
	// below that most likely means the walk is skipping files it shouldn't,
	// not that exports were legitimately deleted.
	if len(writers) < 8 {
		t.Fatalf("discovered only %d CSV-writing function(s); expected at least 8 — the AST walk may be skipping a directory it shouldn't", len(writers))
	}

	var violations []string
	for _, w := range writers {
		if w.CallsSafetyEncoder {
			continue
		}
		key := w.key()
		if reason, ok := csvWriterCompletenessAllowlist[key]; ok {
			t.Logf("allowlisted CSV writer %s (does not call csvSafe/CSVSafe): %s", key, reason)
			continue
		}
		violations = append(violations, w.String()+
			": constructs an encoding/csv.Writer but never calls csvSafe/CSVSafe anywhere in its body -- any user-controlled field written to this CSV (name, description, actor, IP, etc.) is vulnerable to spreadsheet formula injection (CWE-1236) when a victim opens the export in Excel/Sheets/LibreOffice")
	}
	sort.Strings(violations)

	if len(violations) > 0 {
		t.Errorf("found %d CSV-writing function(s) not encoding against formula injection, and not in csvWriterCompletenessAllowlist:\n%s\n"+
			"Fix: wrap every user-controlled string field with csvSafe(...) (server/http/handlers, internal/core) or CSVSafe(...) (internal/cli/common) before writing it, or, if every field this function writes is a controlled constant/number (never any of this), add it to csvWriterCompletenessAllowlist with a comment explaining why.",
			len(violations), strings.Join(violations, "\n"))
	}
}

type csvWriterFunc struct {
	File               string // basename
	FuncName           string // function or method name
	CallsSafetyEncoder bool
}

func (f csvWriterFunc) key() string    { return f.File + ":" + f.FuncName }
func (f csvWriterFunc) String() string { return f.File + ":" + f.FuncName }

// csvWriterSkipDir mirrors internal/storage/store's skipDir (VCS metadata,
// build output, the operator module's separate go.mod, and the web frontend
// -- which has its own, separately-fixed #1682 CSV writer in TypeScript, out
// of scope for a go/ast walk).
//
// Any dot-prefixed directory is skipped: besides .git and .scratch, a developer
// checkout can carry nested git WORKTREES (e.g. .claude/worktrees/<branch>,
// .claire/worktrees/<branch>) that each hold a full, STALE copy of the repo.
// Walking those pollutes the scan with duplicate CSV writers and, worse, files
// mid-rebase that don't parse ("expected 'package', found placeholder") -- a
// spurious local-only failure. CI checks out a single clean tree with no such
// dirs, so this only affects local `go test`; skipping all dot-dirs (tool/VCS
// metadata by convention -- none hold first-party Go CSV writers) makes the walk
// deterministic regardless of a developer's stray worktrees.
func csvWriterSkipDir(name string) bool {
	if strings.HasPrefix(name, ".") { // .git, .scratch, .claude/.claire worktrees, .github, ...
		return true
	}
	switch name {
	case "node_modules", "dist", "vendor", "operator", "web":
		return true
	}
	return false
}

// discoverCSVWriterFunctions walks root for every non-test .go file, parses
// it, and finds every function/method whose body calls csv.NewWriter --
// recording, for each, whether its body (OR a same-file helper function it
// calls by name, one hop deep -- e.g. a writer that builds each CSV row via
// a separate rowToCSV(r) helper rather than encoding inline) contains a call
// to csvSafe or CSVSafe anywhere. This is a shallow syntactic check, not a
// full call-graph analysis or per-field verification: it would not catch a
// writer that calls csvSafe on some fields but not others, or a helper
// defined in a DIFFERENT file/package, but every writer found to date either
// encodes every field it writes (inline or via one same-file helper) or
// none.
func discoverCSVWriterFunctions(t *testing.T, fset *token.FileSet, root string) []csvWriterFunc {
	t.Helper()
	var out []csvWriterFunc

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if csvWriterSkipDir(d.Name()) {
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

		funcsByName := map[string]*ast.FuncDecl{}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				funcsByName[fn.Name.Name] = fn
			}
		}

		for _, fn := range funcsByName {
			if !bodyCallsSelectorFunction(fn.Body, "csv", "NewWriter") {
				continue
			}
			out = append(out, csvWriterFunc{
				File:               filepath.Base(path),
				FuncName:           fn.Name.Name,
				CallsSafetyEncoder: bodyOrCalleesCallSafetyEncoder(fn.Body, funcsByName),
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	return out
}

// bodyOrCalleesCallSafetyEncoder reports whether body itself calls
// csvSafe/CSVSafe, or calls (by plain identifier, one hop) a same-file
// helper function that does.
func bodyOrCalleesCallSafetyEncoder(body *ast.BlockStmt, funcsByName map[string]*ast.FuncDecl) bool {
	if bodyCallsFunctionNamed(body, "csvSafe") || bodyCallsFunctionNamed(body, "CSVSafe") {
		return true
	}
	for _, callee := range calledLocalFunctions(body, funcsByName) {
		if bodyCallsFunctionNamed(callee.Body, "csvSafe") || bodyCallsFunctionNamed(callee.Body, "CSVSafe") {
			return true
		}
	}
	return false
}

// calledLocalFunctions returns every same-file function (from funcsByName)
// that body calls by plain identifier anywhere in its statement tree.
func calledLocalFunctions(body *ast.BlockStmt, funcsByName map[string]*ast.FuncDecl) []*ast.FuncDecl {
	var callees []*ast.FuncDecl
	seen := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if fn, ok := funcsByName[ident.Name]; ok && !seen[ident.Name] {
			seen[ident.Name] = true
			callees = append(callees, fn)
		}
		return true
	})
	return callees
}

// bodyCallsSelectorFunction reports whether body contains a call expression
// of the shape pkg.Fn(...) anywhere in its statement tree.
func bodyCallsSelectorFunction(body *ast.BlockStmt, pkg, fn string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != fn {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == pkg {
			found = true
			return false
		}
		return true
	})
	return found
}

// TestCSVWriterScannerDetectsSafetyEncoding is this guard's red-proof.
//
// TestCSVWriters_EncodeAgainstFormulaInjection asserts today's CSV writers are
// clean. That is a claim about the repo, not the scanner: bodyOrCalleesCallSafetyEncoder
// combines two independent AST walks (bodyCallsFunctionNamed, and the one-hop
// calledLocalFunctions indirection), and either one going quietly wrong reads
// as "no violation" — indistinguishable from a genuinely safe writer. The
// property that matters most is the transitive one: a writer that encodes via
// a same-file helper (rowToCSV, per this file's own doc comment) must still
// be recognized as safe, or the one-hop indirection this helper exists for is
// dead code that happens to return the right answer today by coincidence.
func TestCSVWriterScannerDetectsSafetyEncoding(t *testing.T) {
	// Parsed, never compiled: undefined identifiers (Row, x, w, etc.) are
	// fine and deliberate.
	const src = `package fixture

// writesDirect calls csvSafe inline — the simple case.
func writesDirect() {
	_ = csvSafe(x)
}

// writesViaHelper never calls csvSafe/CSVSafe itself; it delegates row
// encoding to a same-file helper, exactly the shape this file's own doc
// comment describes as needing the one-hop check.
func writesViaHelper() {
	_ = rowToCSV(row)
}

func rowToCSV(row Row) string {
	return CSVSafe(row.Name)
}

// writesNothing is the planted violation: a CSV writer whose body, and whose
// callees, never touch csvSafe/CSVSafe at all.
func writesNothing() {
	fmt.Fprintln(w, row.Name)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "csv_fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the synthetic fixture: %v", err)
	}

	funcsByName := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcsByName[fn.Name.Name] = fn
		}
	}

	if got := bodyOrCalleesCallSafetyEncoder(funcsByName["writesDirect"].Body, funcsByName); !got {
		t.Error("bodyOrCalleesCallSafetyEncoder must report true for a function that calls csvSafe inline")
	}

	if got := bodyOrCalleesCallSafetyEncoder(funcsByName["writesViaHelper"].Body, funcsByName); !got {
		t.Error("bodyOrCalleesCallSafetyEncoder must report true for a function that delegates encoding to a " +
			"same-file helper one hop away — if this regresses, TestCSVWriters_EncodeAgainstFormulaInjection " +
			"would flag every writer that uses the one-hop helper pattern this file's own doc comment describes, " +
			"or (if the false-negative direction breaks instead) silently stop catching the ones that don't")
	}

	// The planted violation: a writer whose body and callees never reach a
	// safety encoder must be reported false, or the scanner cannot ever find
	// a real unencoded CSV writer — it would report every writer as safe
	// regardless of what it actually does.
	if got := bodyOrCalleesCallSafetyEncoder(funcsByName["writesNothing"].Body, funcsByName); got {
		t.Error("bodyOrCalleesCallSafetyEncoder reported true for a function that never calls csvSafe/CSVSafe, " +
			"directly or via a callee — the scanner would no longer be able to find a real formula-injection gap")
	}
}

// bodyCallsFunctionNamed reports whether body contains a call expression
// whose function is exactly name -- either a bare identifier (csvSafe(...))
// or a selector whose final name matches (common.CSVSafe(...)) -- anywhere
// in its statement tree.
func bodyCallsFunctionNamed(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == name {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == name {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
