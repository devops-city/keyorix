// Package statemap generates the AT0 state map (SESSION-AT, docs/state-map/):
// every state store Keyorix has, every entry point that can start a state
// transition, and a best-effort CLASS for each entry point (does it reach
// 2+ distinct write targets, and if so has that been reviewed).
//
// Design choice, stated up front: this is a pragmatic AST extractor over
// known, single-location registration sites (one router file, one proto
// file, one scheduler-startup function, cobra command literals, one MCP
// tool-dispatch switch), not a whole-program go/ssa call graph. Enumeration
// (which entry points/stores exist) is fully mechanical and CI-guarded
// (completeness_test.go). Classification (AT0(d)) is a BOUNDED 1-hop scan:
// for each entry point, resolve its handler/RunE/closure body (a single
// function, found by an exact, sometimes ambiguous, method-name search —
// see findMethodBody) and count DISTINCT write-verb-shaped calls in it,
// reusing the exact verb list and WithTransaction-escape logic
// internal/core/atomicity_guard_test.go already uses and already has CI
// history for. This is Session O's own "handlerscan" technique (its O1
// report: "10 hits, all D (false positives)... flagging this as the
// shallowest-verified part of the sweep") generalized from a hand-picked
// subset to every entry point this package enumerates, not a new technique.
//
// Named blind spots:
//   - REST route paths ARE now the fully-composed mounted path (nested
//     r.Route prefixes, and named path constants, are both resolved) —
//     fixed from an earlier draft that only had the local literal.
//   - CLI command IDs ARE now the full CommandPath (root down to leaf,
//     space-joined Use tokens), built from an AddCommand parent/child graph
//     — fixed from an earlier draft that only had the leaf Use token.
//   - Classification is 1-hop: a handler that calls an unexported helper in
//     the same file which itself makes the writes is invisible to the write
//     count (the helper call itself doesn't match the write-verb regex
//     unless its name happens to start with one). This under-counts, never
//     over-counts, so it cannot wrongly clear a multi-write operation as
//     safe without a human seeing SOME hit list it — worst case, a
//     genuinely multi-write handler is missed by this scan the same way
//     Session O found handlerscan_tool.go's own shallow verification was
//     the weakest part of its sweep. Stated, not fixed, given session scope.
//   - gRPC RPC and REST route handler resolution is a GLOBAL method-name
//     search across server/grpc/services and server/http/handlers
//     respectively: if two distinct handler structs define a method with
//     the same name, resolution is ambiguous and the entry point is left
//     unclassified-with-reason "ambiguous handler resolution" rather than
//     guessed at.
package statemap

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Entry describes one entry point: a way a state transition can start.
type Entry struct {
	Kind    string // rest | grpc | cli | job | mcp
	ID      string // stable identifier used for diffing: "METHOD /full/mounted/path" | "Service.Method" | full CommandPath | job name | mcp tool name
	File    string // relative to repo root
	Line    int
	Handler string // resolved handler/RunE/closure identity, best-effort, informational
	Class   string // A|S|B|C|D|F|R|X|L|none — see docs/state-map/CLASSES in the generated header
	Reason  string
}

// DBTable is one row of internal/storage/all_models.go's AllModels() --
// the codebase's own canonical, already-CI-guarded table list
// (TestAllModels_MatchesLiveMigratedTables). Reused here rather than
// re-deriving table existence from struct scanning, per this repo's
// "derive it, don't re-derive it" preference.
type DBTable struct {
	Model string
}

// FileWriteSite is a non-test call site that writes a file outside the
// securefiles atomic-write helpers (an AT4 guard candidate) or through them
// (informational -- these ARE going through the intended chokepoint).
type FileWriteSite struct {
	Func string // os.WriteFile | os.Create | securefiles.SecureWriteFile | ...
	File string
	Line int
}

// ---------------------------------------------------------------------
// REST routes: full AST parse of server/http/router.go, resolving named
// path constants and composing nested r.Route(...)/r.Group(...) prefixes
// via position-interval containment (robust to arbitrary if/for wrapping,
// unlike a statement-shape walker that would need to special-case every
// control-flow construct router.go might use around a route registration).
// ---------------------------------------------------------------------

type routeInterval struct {
	prefix     string
	start, end token.Pos
}

// RESTRoutes extracts every chi route registration in server/http/router.go,
// with fully composed mounted paths.
func RESTRoutes(repoRoot string) ([]Entry, error) {
	path := filepath.Join(repoRoot, "server", "http", "router.go")
	relPath, _ := filepath.Rel(repoRoot, path)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	return restRoutesFromAST(f, fset, relPath), nil
}

// restRoutesFromAST is RESTRoutes' actual extraction logic, split out from
// file I/O so a test can exercise the position-interval nested-Route
// composition (and its duplicate-detection consequence) against a small,
// FIXED fixture source instead of depending on router.go's current
// contents — see rest_composition_test.go.
func restRoutesFromAST(f *ast.File, fset *token.FileSet, relPath string) []Entry {
	consts := collectStringConsts(f)

	var intervals []routeInterval
	var routeCalls []*ast.CallExpr

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if baseIdentName(sel.X) != "r" {
			return true
		}
		switch sel.Sel.Name {
		case "Route":
			if len(call.Args) < 2 {
				return true
			}
			p := resolveStringExpr(call.Args[0], consts)
			if fn, ok := call.Args[1].(*ast.FuncLit); ok && fn.Body != nil {
				intervals = append(intervals, routeInterval{prefix: p, start: fn.Body.Lbrace, end: fn.Body.Rbrace})
			}
		case "Get", "Post", "Put", "Patch", "Delete", "Head", "Options":
			routeCalls = append(routeCalls, call)
		}
		return true
	})

	// Sort intervals widest-first is not required; containment check below
	// just accumulates every enclosing interval's prefix, outermost to
	// innermost, by interval SIZE (a nested Route's interval is always a
	// strict subset of its parent's).
	sort.Slice(intervals, func(i, j int) bool {
		return (intervals[i].end - intervals[i].start) > (intervals[j].end - intervals[j].start)
	})

	var entries []Entry
	for _, call := range routeCalls {
		sel := call.Fun.(*ast.SelectorExpr) // #nosec G601 -- guaranteed by the collection pass above
		if len(call.Args) < 1 {
			continue
		}
		p := resolveStringExpr(call.Args[0], consts)
		pos := call.Pos()
		prefix := ""
		for _, iv := range intervals {
			if pos > iv.start && pos < iv.end {
				prefix += iv.prefix
			}
		}
		handler := ""
		if len(call.Args) >= 2 {
			handler = atomicityExprStr(call.Args[1])
		}
		entries = append(entries, Entry{
			Kind:    "rest",
			ID:      strings.ToUpper(sel.Sel.Name) + " " + prefix + p,
			File:    relPath,
			Line:    fset.Position(call.Pos()).Line,
			Handler: handler,
		})
	}
	return dedupSortEntries(entries)
}

// collectStringConsts returns every top-level `const Name = "literal"`
// binding in f (router.go's path* constants).
func collectStringConsts(f *ast.File) map[string]string {
	consts := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := unquote(lit.Value); err == nil {
						consts[name.Name] = v
					}
				}
			}
		}
	}
	return consts
}

// resolveStringExpr resolves a string literal or a reference to a known
// const; anything else (string concatenation, a computed value) resolves to
// a bracketed placeholder rather than silently guessing.
func resolveStringExpr(e ast.Expr, consts map[string]string) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			if s, err := unquote(v.Value); err == nil {
				return s
			}
		}
	case *ast.Ident:
		if s, ok := consts[v.Name]; ok {
			return s
		}
		return "<" + v.Name + ">"
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			return resolveStringExpr(v.X, consts) + resolveStringExpr(v.Y, consts)
		}
	}
	return "<dynamic>"
}

func unquote(lit string) (string, error) {
	if len(lit) >= 2 && lit[0] == '"' && lit[len(lit)-1] == '"' {
		return lit[1 : len(lit)-1], nil
	}
	if len(lit) >= 2 && lit[0] == '`' && lit[len(lit)-1] == '`' {
		return lit[1 : len(lit)-1], nil
	}
	return "", fmt.Errorf("not a string literal: %s", lit)
}

func baseIdentName(e ast.Expr) string {
	for {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			e = v.X
		case *ast.CallExpr:
			e = v.Fun
		default:
			return ""
		}
	}
}

// atomicityExprStr renders a simple selector/ident expression as text (e.g.
// "authHandler.Login"), mirroring internal/core/atomicity_guard_test.go's
// own atomicityExprStr so entry-point handler identities read the same way
// that guard's function identities do.
func atomicityExprStr(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return atomicityExprStr(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + atomicityExprStr(v.X)
	default:
		return "<expr>"
	}
}

// ---------------------------------------------------------------------
// gRPC methods
// ---------------------------------------------------------------------

var protoRPCRe = regexp.MustCompile(`^\s*rpc\s+(\w+)\s*\(`)
var protoServiceRe = regexp.MustCompile(`^\s*service\s+(\w+)\s*\{`)

// GRPCMethods extracts every "rpc Name(...)" line grouped under its
// enclosing "service X {" block in server/proto/keyorix.proto.
func GRPCMethods(repoRoot string) ([]Entry, error) {
	path := filepath.Join(repoRoot, "server", "proto", "keyorix.proto")
	data, err := os.ReadFile(path) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
	if err != nil {
		return nil, err
	}
	relPath, _ := filepath.Rel(repoRoot, path)
	var entries []Entry
	currentService := ""
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if m := protoServiceRe.FindStringSubmatch(line); m != nil {
			currentService = m[1]
			continue
		}
		if m := protoRPCRe.FindStringSubmatch(line); m != nil {
			entries = append(entries, Entry{
				Kind:    "grpc",
				ID:      currentService + "." + m[1],
				File:    relPath,
				Line:    i + 1,
				Handler: m[1], // method name only; resolved against server/grpc/services during classification
			})
		}
	}
	return dedupSortEntries(entries), nil
}

// ---------------------------------------------------------------------
// Scheduled jobs
// ---------------------------------------------------------------------

// ScheduledJobs extracts every runScheduler / runSchedulerAfter(ctx, "name", ...) call in
// server/main.go's startSchedulers, capturing the tick closure's own body
// position range for classification (no separate resolution step needed --
// the closure is right there).
func ScheduledJobs(repoRoot string) ([]Entry, error) {
	path := filepath.Join(repoRoot, "server", "main.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	relPath, _ := filepath.Rel(repoRoot, path)

	var entries []Entry
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.Ident)
		// runSchedulerAfter (a deferred first tick) registers a job the same way.
		if !ok || (sel.Name != "runScheduler" && sel.Name != "runSchedulerAfter") || len(call.Args) < 3 {
			return true
		}
		name, ok := call.Args[1].(*ast.BasicLit)
		if !ok || name.Kind != token.STRING {
			return true
		}
		label, _ := unquote(name.Value)
		entries = append(entries, Entry{
			Kind: "job",
			ID:   label,
			File: relPath,
			Line: fset.Position(call.Pos()).Line,
		})
		return true
	})
	return dedupSortEntries(entries), nil
}

// ---------------------------------------------------------------------
// CLI commands: cobra.Command literals + AddCommand parent/child graph,
// composed into a full CommandPath (root down to leaf).
// ---------------------------------------------------------------------

var cliDirs = []string{"server/admin", "cmd", "cli"}

type cobraCmdInfo struct {
	varName string // "" if not bound to a simple identifier (blind spot: inline literal args to AddCommand)
	use     string
	runE    string // identifier of the RunE/Run func, "" if inline or absent
	file    string
	line    int
}

// CLICommands walks cliDirs, finds every &cobra.Command{...} literal bound
// to a simple identifier, finds every X.AddCommand(Y1, Y2, ...) call to
// build the parent/child graph, and returns each command's full
// space-joined CommandPath from its root down to itself -- mirroring
// cobra's own Command.CommandPath(). A command that never appears as an
// AddCommand child (a root, or one this scan's blind spots left
// unconnected -- see the package doc) uses its own bare Use token.
func CLICommands(repoRoot string) ([]Entry, error) {
	fset := token.NewFileSet()
	var cmds []cobraCmdInfo
	isChild := map[string]bool{} // varName -> is a child of some AddCommand call
	edges := map[string][]string{}
	missingDir := false

	for _, dir := range cliDirs {
		root := filepath.Join(repoRoot, dir)
		if _, err := os.Stat(root); err != nil {
			missingDir = true
			continue
		}
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				return fmt.Errorf("%s: %w", p, perr)
			}
			rel, rerr := filepath.Rel(repoRoot, p)
			if rerr != nil {
				rel = p
			}
			collectCobraLiterals(f, fset, rel, &cmds)
			collectAddCommandEdges(f, edges, isChild)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if missingDir {
		return nil, fmt.Errorf("one or more CLI directories (%v) do not exist under %s -- cannot enumerate CLI commands", cliDirs, repoRoot)
	}

	byVar := map[string]cobraCmdInfo{}
	for _, c := range cmds {
		if c.varName != "" {
			byVar[c.varName] = c
		}
	}

	var pathOf func(varName string, seen map[string]bool) string
	pathOf = func(varName string, seen map[string]bool) string {
		c, ok := byVar[varName]
		if !ok || seen[varName] {
			return ""
		}
		seen[varName] = true
		if !isChild[varName] {
			return c.use
		}
		// Find a parent whose edges include varName. Multiple parents (a command
		// added under two trees) are possible but rare; the first found wins --
		// blind spot, noted in the package doc.
		for parent, kids := range edges {
			for _, k := range kids {
				if k == varName {
					if pp := pathOf(parent, seen); pp != "" {
						return pp + " " + c.use
					}
					return c.use
				}
			}
		}
		return c.use
	}

	var entries []Entry
	for _, c := range cmds {
		id := c.use
		if c.varName != "" {
			if p := pathOf(c.varName, map[string]bool{}); p != "" {
				id = p
			}
		}
		entries = append(entries, Entry{
			Kind:    "cli",
			ID:      id,
			File:    c.file,
			Line:    c.line,
			Handler: c.runE,
		})
	}
	return dedupSortEntries(entries), nil
}

func collectCobraLiterals(f *ast.File, fset *token.FileSet, relPath string, out *[]cobraCmdInfo) {
	// Map of composite-literal position -> enclosing assignment's LHS identifier,
	// covering both `var X = &cobra.Command{...}` (GenDecl/ValueSpec) and
	// `X := &cobra.Command{...}` / `X = &cobra.Command{...}` (AssignStmt).
	litVar := map[token.Pos]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			for i, name := range v.Names {
				if i < len(v.Values) {
					if ue, ok := v.Values[i].(*ast.UnaryExpr); ok {
						litVar[ue.X.Pos()] = name.Name
					}
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range v.Lhs {
				if i >= len(v.Rhs) {
					continue
				}
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				if ue, ok := v.Rhs[i].(*ast.UnaryExpr); ok {
					litVar[ue.X.Pos()] = id.Name
				}
			}
		}
		return true
	})

	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := cl.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Command" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "cobra" {
			return true
		}
		info := cobraCmdInfo{file: relPath, line: fset.Position(cl.Pos()).Line, varName: litVar[cl.Pos()]}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Use":
				if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := unquote(lit.Value); err == nil && strings.TrimSpace(s) != "" {
						info.use = strings.Fields(s)[0]
					}
				}
			case "RunE", "Run":
				info.runE = atomicityExprStr(kv.Value)
			}
		}
		if info.use == "" {
			return true // a Command literal with no (or empty/whitespace-only) Use is not an invocable command
		}
		*out = append(*out, info)
		return true
	})
}

func collectAddCommandEdges(f *ast.File, edges map[string][]string, children map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "AddCommand" {
			return true
		}
		parent := baseIdentName(sel.X)
		if parent == "" {
			return true
		}
		for _, a := range call.Args {
			if id, ok := a.(*ast.Ident); ok {
				edges[parent] = append(edges[parent], id.Name)
				children[id.Name] = true
			}
		}
		return true
	})
}

func dedupSortEntries(in []Entry) []Entry {
	seen := map[string]bool{}
	var out []Entry
	for _, e := range in {
		key := e.Kind + "|" + e.ID + "|" + e.File + "|" + fmt.Sprint(e.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// ---------------------------------------------------------------------
// MCP tools -- internal/mcp/tools.go's callTool dispatch switch. Read-only
// by design (ADR-061: "no write/rotate/delete tools"), so every row here
// classifies as "none" with that reason rather than needing a per-tool scan.
// ---------------------------------------------------------------------

var mcpToolCaseRe = regexp.MustCompile(`^\s*case\s+"([^"]+)":`)

func MCPTools(repoRoot string) ([]Entry, error) {
	path := filepath.Join(repoRoot, "internal", "mcp", "tools.go")
	data, err := os.ReadFile(path) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no MCP server in this checkout -- not an error
		}
		return nil, err
	}
	relPath, _ := filepath.Rel(repoRoot, path)
	var entries []Entry
	for i, line := range strings.Split(string(data), "\n") {
		if m := mcpToolCaseRe.FindStringSubmatch(line); m != nil {
			entries = append(entries, Entry{
				Kind:   "mcp",
				ID:     m[1],
				File:   relPath,
				Line:   i + 1,
				Class:  "none",
				Reason: "read-only by design (ADR-061: internal/mcp has no write/rotate/delete tool) -- toolDefinitions()'s own doc comment states this explicitly",
			})
		}
	}
	return dedupSortEntries(entries), nil
}

// KnownGapRows are entry-point CATEGORIES this generator does NOT enumerate
// at all (as opposed to individual entries within an enumerated category
// that couldn't be classified, which get class "REVIEW"). Each is a
// considered decision, not an oversight -- reasons state why, per the
// coordinator's B3 review comment on PR #2336 ("Either enumerate them or
// list each as an explicit known-gap row"). Exported (not local to
// cmd/statemapgen) so completeness_test.go can assert these exact rows are
// still present in the checked-in TSV -- deleting a gap row must fail the
// guard the same way deleting a real entry point does.
func KnownGapRows() []Entry {
	return []Entry{
		{
			Kind: "gap", ID: "operator/ reconcile loops", File: "operator/", Line: 0,
			Class: "gap", Reason: "operator/ is a separate Go module (its own go.mod, controller-runtime reconcile-loop entry points, not REST/gRPC/CLI/job in this codebase's sense) and is on SESSION-AT's MUST-NOT-EDIT list. Not enumerated here; recommend a follow-up session scoped to operator/ specifically, using its own entry-point shape (Reconcile methods on each controller).",
		},
		{
			Kind: "gap", ID: "server startup/shutdown sequence", File: "server/main.go", Line: 0,
			Class: "gap", Reason: "main()'s own linear startup (config load, storage init, migration check, startSchedulers, listener start) and shutdown (signal handling, graceful drain) is a single run-once sequence per process, not a repeatable/lookupable entry point the way a route or CLI command is -- there is no clean registration point to enumerate \"hooks\" from (unlike runScheduler's own named-call pattern, which IS enumerated under kind=job). Scheduled jobs themselves (the repeatable part of startup) ARE enumerated (kind=job). Recommend a manual, one-time trace of main()'s own sequence rather than a generator, if this needs auditing.",
		},
		{
			Kind: "gap", ID: "SSO/SAML callbacks", File: "server/http/router.go", Line: 0,
			Class: "gap", Reason: "NOT actually a gap -- checked explicitly per the coordinator's review: /auth/sso/{provider}/callback, /auth/saml/{provider}/acs, and similar IdP-callback routes are plain chi routes already captured by the kind=rest extractor (confirmed: grep -n callback server/http/router.go shows them registered exactly like any other route, inside the same unauthenticated r.Group). Listed here only so this decision is visible in the TSV itself, not just in a PR body someone has to go find.",
		},
		{
			Kind: "gap", ID: "outbound webhook delivery (notification channels)", File: "internal/core", Line: 0,
			Class: "gap", Reason: "distinct from SSO/SAML callbacks above -- this is Keyorix CALLING OUT to an operator-configured webhook URL as a notification channel (internal/core notification dispatch, internal/evidencesink/webhook.go), not an inbound entry point at all. No REST/gRPC/CLI/job registration exists to enumerate; it is reachable only as a side effect of other already-enumerated entries (e.g. an access-request approval triggering a notification send). Listed as a curated external-system row in stores.tsv (\"notification channel delivery target\"), not here as an entry point, since it never STARTS a transition on its own.",
		},
	}
}

// AllEntries runs every extractor and returns the union.
func AllEntries(repoRoot string) ([]Entry, error) {
	var all []Entry
	rest, err := RESTRoutes(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("REST routes: %w", err)
	}
	all = append(all, rest...)
	grpc, err := GRPCMethods(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("gRPC methods: %w", err)
	}
	all = append(all, grpc...)
	jobs, err := ScheduledJobs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("scheduled jobs: %w", err)
	}
	all = append(all, jobs...)
	cli, err := CLICommands(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("CLI commands: %w", err)
	}
	all = append(all, cli...)
	mcp, err := MCPTools(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("MCP tools: %w", err)
	}
	all = append(all, mcp...)
	return dedupSortEntries(all), nil
}

var allModelsRe = regexp.MustCompile(`&models\.(\w+)\{\}`)

// DBTables parses internal/storage/all_models.go's AllModels() function body
// for &models.X{} entries -- the codebase's own canonical table list,
// already drift-guarded by TestAllModels_MatchesLiveMigratedTables
// (internal/storage/all_models_test.go). Reused here, not re-derived.
func DBTables(repoRoot string) ([]DBTable, error) {
	path := filepath.Join(repoRoot, "internal", "storage", "all_models.go")
	data, err := os.ReadFile(path) // #nosec G304 -- repoRoot is a caller-controlled local checkout path, not network input
	if err != nil {
		return nil, err
	}
	var tables []DBTable
	for _, m := range allModelsRe.FindAllStringSubmatch(string(data), -1) {
		tables = append(tables, DBTable{Model: m[1]})
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Model < tables[j].Model })
	return tables, nil
}

var fileWriteRe = regexp.MustCompile(`\b(os\.WriteFile|os\.Create|os\.OpenFile|securefiles\.SecureWriteFile|securefiles\.SecureWriteFileSync|securefiles\.SecureCreateFile|securefiles\.SecureCreateFileSync|securefiles\.SecureCreateFileHandle)\(`)

// FileWriteSites walks the whole repo (excluding vendored/generated/test
// paths) for calls to a file-creating primitive, to support the AT4 guard
// "no direct os.WriteFile / os.Create outside the atomic-write helper". Uses
// a repo-relative path PREFIX match for excluded directories (not a
// basename match at any depth), so a legitimate source path merely
// containing a directory named e.g. "web" as a path component elsewhere
// isn't silently skipped.
func FileWriteSites(repoRoot string) ([]FileWriteSite, error) {
	var sites []FileWriteSite
	skipPrefixes := []string{
		".git/", "node_modules/", "operator/", "web/", "deploy/", "vendor/", "integrations/",
	}
	err := filepath.Walk(repoRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(repoRoot, p)
		if rerr != nil {
			return rerr
		}
		if info.IsDir() {
			relSlash := rel + "/"
			for _, sp := range skipPrefixes {
				if relSlash == sp || strings.HasPrefix(relSlash, sp) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		data, rerr2 := os.ReadFile(p) // #nosec G304 G122 -- repoRoot is a caller-controlled local checkout path, not network input; symlink TOCTOU acceptable for a local developer tool
		if rerr2 != nil {
			return rerr2
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if m := fileWriteRe.FindStringSubmatch(line); m != nil {
				sites = append(sites, FileWriteSite{Func: m[1], File: rel, Line: i + 1})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, nil
}

// AggregateFileWriteSites counts occurrences per (File,Func) pair, DROPPING
// line numbers from the key. A line-numbered key would make stores.tsv churn
// (and conflict across unrelated PRs) on every edit above one of these
// call sites that merely shifts later lines -- a file+func COUNT is exactly
// as capable of catching a genuinely new/removed call site (the count
// changes) without that false-churn cost.
func AggregateFileWriteSites(sites []FileWriteSite) map[string]int {
	out := map[string]int{}
	for _, s := range sites {
		out[s.File+"\t"+s.Func]++
	}
	return out
}
