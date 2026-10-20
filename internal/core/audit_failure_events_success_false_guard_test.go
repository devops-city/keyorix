// audit_failure_events_success_false_guard_test.go — #3363 (AUTH-2 item 5):
// an audit event whose NAME says it records a failure must be stored with
// Success=false. mfa.failed and webauthn.failed were written through
// writeAuditEventFull, which always stores Success=true, so a wrong TOTP code or
// a failed passkey assertion was invisible to every success=false query (SIEM
// rules, exports, the dashboard counters).
//
// The guard parses this package's non-test sources and finds every call that
// writes through a SUCCESS writer: writeAuditEvent, writeAuditEventFull(On),
// writeAuditEventDiff(On), plus any function that forwards one of its own
// parameters as such a writer's event type (found to a fixpoint, so a wrapper
// like auditProjectScoped counts). For each call whose event type is a string
// literal or a package-level string constant, a name ending in one of
// failureEventSuffixes fails the test unless the call site is listed in
// failureNamedSuccessEvents with a reason.
//
// What it does NOT see, by construction: an event type built at run time (a
// variable or a fmt call — reported in the log with a count, so a drop to zero
// matches is visible), an AuditEvent literal handed straight to emitAudit, and
// writers outside internal/core.
package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// failureEventName: the last segment of an event name (after the final '.'
// or '_') that means "this records a failure".
var failureEventName = regexp.MustCompile(`[._](failed|error|denied|refused|rejected|panicked|unresolved)$`)

// failureNamedSuccessEvents: "<enclosing func>:<event type>" written with
// Success=true on purpose. Keep the reason honest.
var failureNamedSuccessEvents = map[string]string{
	"RejectAccessRequest:access_request.rejected": "records an approver's successful decision to reject a request; the action itself succeeded",
}

// successAuditWriters maps a success writer to the index of its event-type
// argument.
var successAuditWriters = map[string]int{
	"writeAuditEvent":       1,
	"writeAuditEventFull":   1,
	"writeAuditEventFullOn": 2,
	"writeAuditEventDiff":   1,
	"writeAuditEventDiffOn": 2,
}

func TestFailureNamedAuditEvents_AreWrittenWithSuccessFalse(t *testing.T) {
	t.Parallel()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	consts := map[string]string{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path) // #nosec G304 -- a glob of this package's own sources
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v, err := strconv.Unquote(lit.Value); err == nil {
								consts[name.Name] = v
							}
						}
					}
				}
			}
		}
	}
	if len(files) < 50 {
		t.Fatalf("parsed only %d source files: the glob no longer finds this package", len(files))
	}

	calleeName := func(call *ast.CallExpr) string {
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			return fun.Sel.Name
		case *ast.Ident:
			return fun.Name
		}
		return ""
	}

	// Wrappers: a function that passes one of its own parameters as a success
	// writer's event type is itself a success writer, at that parameter's index.
	writers := maps.Clone(successAuditWriters)
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if _, known := writers[fd.Name.Name]; known {
					continue
				}
				params := map[string]int{}
				idx := 0
				for _, field := range fd.Type.Params.List {
					for _, n := range field.Names {
						params[n.Name] = idx
						idx++
					}
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					argIdx, ok := writers[calleeName(call)]
					if !ok || argIdx >= len(call.Args) {
						return true
					}
					if id, ok := call.Args[argIdx].(*ast.Ident); ok {
						if pi, isParam := params[id.Name]; isParam {
							writers[fd.Name.Name] = pi
							changed = true
							return false
						}
					}
					return true
				})
			}
		}
	}

	var violations []string
	matched, unresolved := 0, 0
	seen := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				argIdx, ok := writers[calleeName(call)]
				if !ok || argIdx >= len(call.Args) {
					return true
				}
				var event string
				switch a := call.Args[argIdx].(type) {
				case *ast.BasicLit:
					if a.Kind == token.STRING {
						event, _ = strconv.Unquote(a.Value)
					}
				case *ast.Ident:
					event = consts[a.Name]
				}
				if event == "" {
					unresolved++
					return true
				}
				matched++
				if !failureEventName.MatchString(event) {
					return true
				}
				key := fd.Name.Name + ":" + event
				if _, ok := failureNamedSuccessEvents[key]; ok {
					seen[key] = true
					return true
				}
				violations = append(violations, fset.Position(call.Pos()).String()+" "+key+" (via "+calleeName(call)+")")
				return true
			})
		}
	}
	t.Logf("success-writer calls: %d with a resolvable event type, %d built at run time (not checked); %d writers incl. wrappers", matched, unresolved, len(writers))
	if matched < 100 {
		t.Fatalf("resolved only %d success-writer calls: the scan no longer matches how audit events are written, so it would pass vacuously", matched)
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Errorf("failure-named audit event written with Success=true: %s -- use writeAuditEventFailed (Success=false), or list the site in failureNamedSuccessEvents with a reason", v)
	}
	for key := range failureNamedSuccessEvents {
		if !seen[key] {
			t.Errorf("stale failureNamedSuccessEvents entry %s: no such call site any more", key)
		}
	}
}
