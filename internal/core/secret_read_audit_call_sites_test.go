// secret_read_audit_call_sites_test.go — coordinator review item 6 on #2420.
//
// Audit-before-disclosure (SESSION-PERF #2403 follow-up, item 3) only holds
// at a call site if that call site both (a) checks LogSecretReadWithProject's
// returned error, and (b) does not call it from inside goSafe (a detached,
// fire-and-forget goroutine — see server/http/handlers/helpers.go's and this
// package's own goSafe) — a checked error that only a background goroutine
// ever sees can't stop the response that already went out. This test finds
// EVERY call site of LogSecretReadWithProject across the repository via
// go/ast (not a hand-maintained list of "the files we remembered to fix"),
// classifies each against those two rules, and fails on any violation not
// explicitly allowlisted below.
//
// One call site is a deliberate, documented exception today:
// GetSecretByName (server/http/handlers/secrets_crud.go) never discloses a
// value — it returns secret metadata only (newSecretNodeWire, no value
// field) — so there is no value for audit-before-disclosure to gate, and it
// correctly stays fire-and-forget inside goSafe, same as every OTHER
// audit call that doesn't gate a disclosure (LogSecretCreated,
// LogSecretUpdated, etc.). See secretReadAuditCallSiteAllowlist.
package core

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

// secretReadAuditCallSiteAllowlist names LogSecretReadWithProject call sites
// deliberately exempt from "checked, not in goSafe", keyed
// "<file basename>:<enclosing function name>", with the reason as the value.
//
// Empty since AUDIT-UX-3: GET /secrets/by-name (the former only entry) is a
// metadata-only lookup and now writes secret.metadata_read via
// LogSecretMetadataRead, so every remaining LogSecretReadWithProject call site
// is a value disclosure and must be checked and synchronous.
var secretReadAuditCallSiteAllowlist = map[string]string{}

func TestSecretReadAuditCallSites_CheckedAndNotInGoSafe(t *testing.T) {
	thisFile := filepath.Join(srcpath.PkgDir(), "secret_read_audit_call_sites_test.go")
	// internal/core -> repo root.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	fset := token.NewFileSet()
	sites := discoverSecretReadAuditCallSites(t, fset, repoRoot)

	if len(sites) == 0 {
		t.Fatal("discovered zero LogSecretReadWithProject call sites across the repo — the AST walk is almost certainly broken (GetSecret, GetSecretValueByRef, and CopySecret alone should match), not that every value-disclosing path stopped auditing")
	}
	// A floor, not an exact count: new value-disclosing endpoints are expected to
	// add call sites over time. 5 is the count of value-disclosing sites today
	// (GetSecret, GetSecretValueByRef, GetSecretValue gRPC, CopySecret, bulk-render);
	// GetSecretVersions (#2970) and GetSecretByName (AUDIT-UX-3) moved to their own
	// metadata events and are no longer call sites.
	if len(sites) < 5 {
		t.Fatalf("discovered only %d LogSecretReadWithProject call site(s); expected at least 5 — the AST walk may be skipping a directory it shouldn't", len(sites))
	}

	var violations []string
	for _, site := range sites {
		key := site.key()
		reason, allowlisted := secretReadAuditCallSiteAllowlist[key]
		if allowlisted {
			t.Logf("allowlisted call site %s (ignored error / goSafe permitted): %s", key, reason)
			continue
		}
		if site.ResultIgnored {
			violations = append(violations, site.String()+
				": LogSecretReadWithProject's returned error is discarded -- a failed audit write would let a value-disclosing response go out with no durable record of the read")
		}
		if site.InsideGoSafe {
			violations = append(violations, site.String()+
				": LogSecretReadWithProject is called from inside goSafe (a detached goroutine) -- the caller's response can't wait for, or fail on, an error only a background goroutine ever sees, defeating audit-before-disclosure")
		}
	}
	sort.Strings(violations)

	if len(violations) > 0 {
		t.Errorf("found %d LogSecretReadWithProject call site(s) violating audit-before-disclosure, and not in secretReadAuditCallSiteAllowlist:\n%s\n"+
			"Fix: check the returned error and fail the response closed before any value is included (see secrets_crud.go's GetSecret for the pattern), or, if this call site genuinely never discloses a value, add it to secretReadAuditCallSiteAllowlist with a comment explaining why.",
			len(violations), strings.Join(violations, "\n"))
	}
}

type secretReadAuditCallSite struct {
	File          string // basename
	FuncName      string // enclosing named function/method
	ResultIgnored bool   // bare statement or assigned to _
	InsideGoSafe  bool   // lexically inside a goSafe(func(){...}) literal
}

func (s secretReadAuditCallSite) key() string { return s.File + ":" + s.FuncName }
func (s secretReadAuditCallSite) String() string {
	return s.File + ":" + s.FuncName + " (LogSecretReadWithProject call site)"
}

// skipDir reports whether a directory should be excluded from the walk: VCS
// metadata, dependency/build output, and the operator module (a separate Go
// module, kept out of this repo's go.work).
func skipSecretReadAuditDir(name string) bool {
	switch name {
	case ".git", "node_modules", "dist", ".scratch", "vendor", "operator", "web":
		return true
	}
	return false
}

// discoverSecretReadAuditCallSites walks root for every non-test .go file,
// parses it, and finds every call expression ending in
// ".LogSecretReadWithProject(...)" or named "LogSecretReadWithProject(...)",
// classifying each per secretReadAuditCallSite's fields.
func discoverSecretReadAuditCallSites(t *testing.T, fset *token.FileSet, root string) []secretReadAuditCallSite {
	t.Helper()
	var out []secretReadAuditCallSite

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipSecretReadAuditDir(d.Name()) {
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

		goSafeRanges := collectGoSafeFuncLitRanges(file)
		funcDecls := collectFuncDeclRanges(file)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isLogSecretReadWithProjectCall(call) {
				return true
			}
			out = append(out, secretReadAuditCallSite{
				File:          filepath.Base(path),
				FuncName:      enclosingFuncName(funcDecls, call.Pos()),
				ResultIgnored: isIgnoredResultStatement(file, call),
				InsideGoSafe:  posInAnyRange(call.Pos(), goSafeRanges),
			})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	return out
}

// isLogSecretReadWithProjectCall reports whether call's function is named
// (or, for a method call, selects a method named) LogSecretReadWithProject.
func isLogSecretReadWithProjectCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "LogSecretReadWithProject"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "LogSecretReadWithProject"
	}
	return false
}

// posRange is a half-open [Start, End) byte-offset range within one file's
// token.Pos space.
type posRange struct {
	Start, End token.Pos
}

func posInAnyRange(p token.Pos, ranges []posRange) bool {
	for _, r := range ranges {
		if p >= r.Start && p < r.End {
			return true
		}
	}
	return false
}

// collectGoSafeFuncLitRanges finds every call `goSafe(func() { ... })` (any
// number of other arguments before/after the literal would still be caught,
// but every real call site in this repo passes exactly one func literal) and
// records that literal's byte range, so a later call found lexically inside
// it can be recognized as running in a detached goroutine.
func collectGoSafeFuncLitRanges(file *ast.File) []posRange {
	var ranges []posRange
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "goSafe" {
			return true
		}
		for _, arg := range call.Args {
			if lit, ok := arg.(*ast.FuncLit); ok {
				ranges = append(ranges, posRange{Start: lit.Pos(), End: lit.End()})
			}
		}
		return true
	})
	return ranges
}

// funcDeclRange pairs a named top-level function/method's name with its body
// range, for mapping an arbitrary call site back to its enclosing function.
type funcDeclRange struct {
	Name       string
	Start, End token.Pos
}

func collectFuncDeclRanges(file *ast.File) []funcDeclRange {
	var out []funcDeclRange
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		out = append(out, funcDeclRange{Name: fn.Name.Name, Start: fn.Pos(), End: fn.End()})
	}
	return out
}

// enclosingFuncName returns the name of the smallest funcDeclRange containing
// pos, or "<package-level>" if none does (e.g. a call in an init or a
// package-level var initializer, neither of which occurs for this call today
// but kept total rather than panicking on a future one).
func enclosingFuncName(decls []funcDeclRange, pos token.Pos) string {
	best := ""
	bestSpan := token.Pos(0)
	for _, d := range decls {
		if pos < d.Start || pos >= d.End {
			continue
		}
		span := d.End - d.Start
		if best == "" || span < bestSpan {
			best = d.Name
			bestSpan = span
		}
	}
	if best == "" {
		return "<package-level>"
	}
	return best
}

// isIgnoredResultStatement reports whether call's single error return value
// is discarded: either call appears as a bare expression statement (no
// assignment at all), or it is assigned to the blank identifier `_`. Any
// other form (err := call(...), if err := call(...); err != nil, return
// call(...), etc.) is treated as checked -- this is a shallow syntactic
// check, not a full data-flow analysis (it would not catch `err := call();
// _ = err` three lines later), matching every real call site in this repo
// today, all of which use one of the two ignored shapes or a direct
// if-err-check.
func isIgnoredResultStatement(file *ast.File, call *ast.CallExpr) bool {
	ignored := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.ExprStmt:
			if stmt.X == call {
				ignored = true
				return false
			}
		case *ast.AssignStmt:
			for i, rhs := range stmt.Rhs {
				if rhs != call {
					continue
				}
				if i < len(stmt.Lhs) {
					if ident, ok := stmt.Lhs[i].(*ast.Ident); ok && ident.Name == "_" {
						ignored = true
						return false
					}
				}
			}
		}
		return true
	})
	return ignored
}
