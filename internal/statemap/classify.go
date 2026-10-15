// classify.go — AT0(d)/B2: a bounded, 1-hop write-multiplicity classifier
// for every entry point statemap.go enumerates.
//
// Technique: resolve each entry's handler/RunE identity to a single Go
// function body (an exact method/func NAME search across a small set of
// implementation directories — server/http/handlers for REST,
// server/grpc/services for gRPC, server/admin+cmd+cli for CLI), then count
// write-verb-shaped calls in that one function using the EXACT SAME verb
// regex and WithTransaction-escape logic internal/core/atomicity_guard_test.go
// already uses (generalized from "c.storage.X / c.X" to any selector call,
// since a handler's write path isn't always through a field literally named
// "storage" or a receiver literally named "c"). This is Session O's own
// "handlerscan_tool.go" technique (see its O1 report) applied to every
// entry point this package enumerates, not a new one.
//
// A handler resolving to 0 or 2+ candidate functions (ambiguous — two
// distinct types define a same-named method) is left unresolved with an
// explicit reason rather than guessed at. A resolved handler with 2+
// write-shaped calls gets class "REVIEW" (needs a human, same as an
// unexempted atomicity_guard_test.go hit needs a docs/atomicity-exempt.tsv
// row) rather than a real class asserted by this scan — this tool counts
// candidates, it does not adjudicate mutually-exclusive branches the way a
// human triage pass (Session O's O1) did for internal/core.
package statemap

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// writeVerbRe mirrors internal/core/atomicity_guard_test.go's
// atomicityWriteVerbRe exactly, so a "2+ writes" verdict means the same
// thing in both places.
var writeVerbRe = regexp.MustCompile(`^(Create|Update|Delete|Assign|Unassign|Set|Remove|Add|Revoke|Insert|Upsert|Save|Mark|Record|Increment|Rotate|Restore|Purge|Archive|Grant|Link|Unlink|Replace|Put|Store|Clear|Reset|Enable|Disable|Lock|Unlock|Consume|Approve|Reject|Expire|Touch|Bump|Append|Move|Rename|Transfer|Finalize|Complete|Cancel|Provision|Deprovision|Patch|Activate|Deactivate|Issue|Open|Close|Withdraw)`)

var implDirsByKind = map[string][]string{
	"rest": {"server/http/handlers"},
	"grpc": {"server/grpc/services"},
	"cli":  {"server/admin", "cmd", "cli"},
}

type funcInfo struct {
	body *ast.BlockStmt
	fset *token.FileSet
	file string
}

// Classify assigns Class/Reason to every entry that doesn't already have one
// (MCPTools already sets Class for its rows). Returns a new slice.
func Classify(repoRoot string, entries []Entry) ([]Entry, error) {
	restIdx, err := buildFuncIndex(repoRoot, implDirsByKind["rest"])
	if err != nil {
		return nil, fmt.Errorf("indexing REST handler impls: %w", err)
	}
	grpcIdx, err := buildFuncIndex(repoRoot, implDirsByKind["grpc"])
	if err != nil {
		return nil, fmt.Errorf("indexing gRPC service impls: %w", err)
	}
	cliIdx, err := buildFuncIndex(repoRoot, implDirsByKind["cli"])
	if err != nil {
		return nil, fmt.Errorf("indexing CLI command impls: %w", err)
	}
	jobBodies, err := jobClosureBodies(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("indexing scheduled-job closures: %w", err)
	}

	out := make([]Entry, len(entries))
	copy(out, entries)
	for i := range out {
		if out[i].Class != "" {
			continue // e.g. MCP rows, already classified at extraction time
		}
		switch out[i].Kind {
		case "rest":
			classifyByName(&out[i], restIdx, lastSegment(out[i].Handler))
		case "grpc":
			classifyByName(&out[i], grpcIdx, out[i].Handler)
		case "cli":
			if out[i].Handler == "" {
				out[i].Class = "none"
				out[i].Reason = "no RunE/Run set on this cobra.Command (a parent/grouping command with no direct action)"
				continue
			}
			classifyByName(&out[i], cliIdx, lastSegment(out[i].Handler))
		case "job":
			body, ok := jobBodies[out[i].ID]
			if !ok {
				out[i].Class = "REVIEW"
				out[i].Reason = "could not re-locate this job's tick closure for classification"
				continue
			}
			applyWriteScan(&out[i], countWriteTargets(body))
		default:
			if out[i].Class == "" {
				out[i].Class = "REVIEW"
				out[i].Reason = "no classifier registered for this entry kind"
			}
		}
	}
	return out, nil
}

func lastSegment(handler string) string {
	if _, after, ok := strings.CutLast(handler, "."); ok {
		return after
	}
	return handler
}

func classifyByName(e *Entry, idx map[string][]funcInfo, name string) {
	if name == "" {
		e.Class = "REVIEW"
		e.Reason = "no resolvable handler identity found by the extractor"
		return
	}
	matches := idx[name]
	switch len(matches) {
	case 0:
		e.Class = "REVIEW"
		e.Reason = fmt.Sprintf("handler %q not found by name in the scanned implementation directories -- resolution blind spot, see classify.go's package doc", name)
	case 1:
		applyWriteScan(e, countWriteTargets(matches[0].body))
	default:
		files := make([]string, 0, len(matches))
		for _, m := range matches {
			files = append(files, m.file)
		}
		e.Class = "REVIEW"
		e.Reason = fmt.Sprintf("ambiguous: %d functions named %q found (%s) -- resolved by exact name only, ambiguity not broken by receiver type", len(matches), name, strings.Join(files, ", "))
	}
}

func applyWriteScan(e *Entry, writes []string) {
	if len(writes) >= 2 {
		e.Class = "REVIEW"
		e.Reason = fmt.Sprintf("%d write-shaped call(s) found by a 1-hop scan of the handler body: %s", len(writes), strings.Join(writes, ", "))
		return
	}
	e.Class = "none"
	e.Reason = "single/no write-shaped call found by a 1-hop scan of the handler body"
}

// countWriteTargets mirrors internal/core/atomicity_guard_test.go's own
// write-counting walk (WithTransaction escapes the count for its closure's
// body; any other call whose selector name matches writeVerbRe counts),
// generalized from "c.storage.X / c.X" to ANY selector call — a handler's
// write path is not always through a field literally named "storage" or a
// receiver literally named "c".
func countWriteTargets(body *ast.BlockStmt) []string {
	var writes []string
	var walk func(n ast.Node, inTx bool)
	walk = func(n ast.Node, inTx bool) {
		ast.Inspect(n, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "WithTransaction" || sel.Sel.Name == "WithNamedLock" {
				walk(sel.X, inTx)
				for _, a := range call.Args {
					walk(a, true)
				}
				return false
			}
			if inTx {
				return true
			}
			if writeVerbRe.MatchString(sel.Sel.Name) {
				writes = append(writes, atomicityExprStr(sel))
			}
			return true
		})
	}
	walk(body, false)
	return writes
}

// buildFuncIndex parses every non-test .go file under dirs and indexes each
// top-level func/method declaration by its bare name (receiver type is
// deliberately NOT part of the key — see classify.go's package doc on
// ambiguous resolution).
func buildFuncIndex(repoRoot string, dirs []string) (map[string][]funcInfo, error) {
	idx := map[string][]funcInfo{}
	for _, dir := range dirs {
		root := filepath.Join(repoRoot, dir)
		if _, err := os.Stat(root); err != nil {
			continue // an implementation dir may legitimately not exist (e.g. no gRPC services yet); enumeration completeness is guarded elsewhere, not here
		}
		fset := token.NewFileSet()
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
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				idx[fd.Name.Name] = append(idx[fd.Name.Name], funcInfo{body: fd.Body, fset: fset, file: rel})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// jobClosureBodies re-parses server/main.go's runScheduler calls (the same
// ones ScheduledJobs finds) and returns each job's tick-closure body,
// keyed by job name -- kept as a separate pass from ScheduledJobs so that
// function's return type doesn't have to carry an AST node.
func jobClosureBodies(repoRoot string) (map[string]*ast.BlockStmt, error) {
	path := filepath.Join(repoRoot, "server", "main.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]*ast.BlockStmt{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		// runScheduler(ctx, name string, interval time.Duration, tick func() ...) --
		// 4 args; the tick closure is Args[3], NOT Args[2] (a real bug this
		// session's own coordinator review caught: the interval argument was
		// missed, so this matched nothing for any of the 18 real call sites and
		// every job silently fell through to the "could not re-locate" REVIEW
		// path in Classify).
		// runSchedulerAfter(ctx, name, interval, firstDelay, tick) carries the
		// closure one argument later.
		tickArg := 3
		switch {
		case !ok:
			return true
		case id.Name == "runScheduler" && len(call.Args) >= 4:
		case id.Name == "runSchedulerAfter" && len(call.Args) >= 5:
			tickArg = 4
		default:
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		label, uerr := unquote(lit.Value)
		if uerr != nil {
			return true
		}
		if fn, ok := call.Args[tickArg].(*ast.FuncLit); ok && fn.Body != nil {
			out[label] = fn.Body
		}
		return true
	})
	return out, nil
}
