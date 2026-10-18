// actor_kind_literal_completeness_test.go — the class guard for #2495
// (INV-CORE-14).
//
// A whole family of internal/core entry points carries the acting principal as
// TWO values, because one is not enough: `actorID uint` plus either
// `actorIsMachine bool` or a `…MachineID uint` companion. The split exists
// because a machine identity has no UserID (ADR-030), so every machine caller
// arrives with actorID==0 — the same value as the genuinely-unauthenticated
// local-CLI/system pseudo-actor that requireGranterHoldsRolePermissions and the
// #169 self-permission-bundling check deliberately EXEMPT from their per-actor
// ceilings. Passing a hardcoded `false`/`0` for the companion therefore does not
// mean "no machine involved"; on a request-reachable path it means "report
// whatever machine is calling as the trusted system", which skips the ceiling.
//
// That has now happened at least four times — #1524 (b)/(c), #1542, #1545, and
// #2495's bulk access-request approval — each found separately, each patched at
// its own site. CLAUDE.md's standing lesson applies verbatim: "an enumeration is
// only as complete as the idioms it knows about", and "if the root cause has
// sibling call sites, the fix is an invariant test, not a site patch."
//
// So: every call site in internal/core and server/ that passes a LITERAL for one
// of those companion parameters needs a reviewed row below. New ones fail this
// test; rows whose call site disappeared fail it too.
//
// What this does NOT verify, stated explicitly:
//
//   - It cannot tell a correct literal from an incorrect one. A row is a human
//     claim that this particular call site has no reachable machine actor (or is
//     the system path by construction). The mechanism forces the claim to be
//     made and reviewed; it does not check it.
//   - It only sees LITERALS. A call site passing a variable that happens to be
//     constant-false is invisible. That is deliberate: a named variable is where
//     the derivation lives, and reviewing derivations is what code review is
//     for. The failure mode this guards is the hardcoded one, which is the one
//     that has actually recurred.
//   - It resolves the callee by NAME, not by type. Two different types with a
//     same-named method collapse into one key. All the names in this family are
//     distinctive KeyorixCore methods, so this has no false matches today; a
//     future collision would over-report (demand a row that is not needed),
//     never under-report.
//   - Test files are not scanned. A test deliberately exercising the human path
//     passes 0/false constantly and that is correct.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// actorKindLiteralScanRoots are the trees scanned, relative to internal/core.
// server/ is included because that is where the request-reachable call sites
// live — a guard that only looked at internal/core would have missed every one
// of #1545's HTTP handlers.
var actorKindLiteralScanRoots = []string{"..", "../../../server"}

type actorKindLiteralVerdict int

const (
	// verdictSystemPath: the call site is not reachable by any authenticated
	// request — startup reconciliation, bootstrap seeding, a scheduler. actorID
	// is 0 because there genuinely is no actor, and `false`/`0` is the true
	// value, not a default.
	verdictSystemPath actorKindLiteralVerdict = iota
	// verdictHumanOnlyByConstruction: the call site IS request-reachable, but
	// the acting principal cannot be a machine identity there — the row must say
	// what makes that true (a route gate, a credential type, an earlier guard),
	// not merely assert it.
	verdictHumanOnlyByConstruction
)

type actorKindLiteralUse struct {
	verdict actorKindLiteralVerdict
	reason  string
}

// actorKindLiteralAllowlist is the reviewed inventory, keyed
// "<path>:<enclosing func>:<callee>".
var actorKindLiteralAllowlist = map[string]actorKindLiteralUse{
	"rbac_reconcile.go:ReconcileRBACPermissions:AssignPermissionToRole": {
		verdictSystemPath,
		"ADR-044 startup permission reconciliation. Runs from BootstrapSystem/server start, " +
			"never from a request; there is no acting principal of any kind, which is why " +
			"actorID is 0 too. Guard on the premise: ReconcileRBACPermissions has no HTTP/gRPC " +
			"caller (it is called only from the startup path).",
	},
	"alerts_write_role_reconcile.go:ReconcileAlertsWriteRole:AssignPermissionToRole": {
		verdictSystemPath,
		"Same startup reconciliation path as ReconcileRBACPermissions above, for the " +
			"alerts.write permission specifically.",
	},
	"recertification.go:RunScheduledRecertification:OpenAccessReviewCampaign": {
		verdictSystemPath,
		"The scheduled recertification sweep, which states its own actor explicitly: the " +
			"ctx it passes is WithActorType(ctx, ActorTypeSystem) and BOTH actorID and " +
			"actorMachineID are 0 because no principal initiated it. A scheduler run has no " +
			"actor to derive, and the ActorTypeSystem tag on the same line is the readable " +
			"assertion of that.",
	},
	"rbac.go:AssignUserRoleScoped:AssignUserRole": {
		verdictHumanOnlyByConstruction,
		"AssignUserRoleScoped/AssignRoleToUser resolve a user by EMAIL and have zero callers " +
			"outside this package and its tests — no HTTP route, no gRPC RPC, no CLI command " +
			"reaches them (the CLI's own rbac.go mentions the name only in a comment about " +
			"the actor parameter they never took). There is no transport by which a machine " +
			"credential could drive this, so actorIsMachine=false is the system-path value. " +
			"If a transport is ever wired to it, this row must be replaced by a real derivation.",
	},
}

// actorKindCompanionParams matches the parameter NAMES that carry the acting
// principal's kind alongside an actorID. Derived from the convention, not from a
// hand-listed set of functions, so a NEW function adopting the convention is
// covered the moment it lands.
func isActorKindCompanionParam(name, typeName string) bool {
	switch {
	case name == "actorIsMachine" && typeName == "bool":
		return true
	case typeName == "uint" && strings.HasSuffix(name, "MachineID"):
		// approverMachineID, invitedByMachineID, actorMachineID, …
		return true
	case typeName == "uint" && strings.HasSuffix(name, "MachineIdentityID"):
		return true
	}
	return false
}

// actorKindParamIndex maps a core function name to the argument position of its
// actor-kind companion parameter, by parsing internal/core's non-test source.
// Only exported-or-not KeyorixCore methods and package functions are considered;
// the position is what the call-site scan needs to know which argument to look at.
func actorKindParamIndex(t *testing.T) map[string]int {
	t.Helper()
	idx := map[string]int{}
	fset := token.NewFileSet()
	entries, err := filepath.Glob("../*.go")
	if err != nil {
		t.Fatalf("globbing internal/core: %v", err)
	}
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", path, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Type.Params == nil {
				continue
			}
			pos := 0
			for _, field := range fn.Type.Params.List {
				typeName := exprName(field.Type)
				names := field.Names
				if len(names) == 0 { // unnamed parameter
					pos++
					continue
				}
				for _, n := range names {
					if isActorKindCompanionParam(n.Name, typeName) {
						idx[fn.Name.Name] = pos
					}
					pos++
				}
			}
		}
	}
	return idx
}

// exprName renders the simple name of a type expression ("bool", "uint"), or ""
// for anything more complex — which is all this guard needs, since every
// companion parameter is a plain bool or uint.
func exprName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// actualActorKindLiteralSites scans the configured roots for calls to a
// known actor-kind-carrying function that pass a LITERAL false/0 in that
// parameter's position, and returns "<path>:<enclosing func>:<callee>" keys.
func actualActorKindLiteralSites(t *testing.T, paramIndex map[string]int) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	for _, root := range actorKindLiteralScanRoots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// Generated clients/stubs re-declare similarly-named methods with
			// unrelated signatures; they never call core.
			if strings.HasSuffix(path, ".gen.go") || strings.Contains(path, "_generated.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parsing %s: %v", path, perr)
			}
			collectActorKindLiteralCalls(f, relKey(root, path), paramIndex, found)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	return found
}

// relKey renders a stable, repo-relative-ish key for a scanned file: bare
// filename for internal/core itself, "server/..." for the server tree.
func relKey(root, path string) string {
	if root == ".." {
		return filepath.Base(path)
	}
	return strings.TrimPrefix(filepath.ToSlash(path), "../../../")
}

func collectActorKindLiteralCalls(f *ast.File, fileKey string, paramIndex map[string]int, found map[string]bool) {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		enclosing := fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			callee := calleeName(call.Fun)
			pos, known := paramIndex[callee]
			if !known || pos >= len(call.Args) {
				return true
			}
			if isFalseOrZeroLiteral(call.Args[pos]) {
				found[fileKey+":"+enclosing+":"+callee] = true
			}
			return true
		})
	}
}

// calleeName extracts the called function's bare name from `f(...)`,
// `x.f(...)` or `pkg.x.f(...)`.
func calleeName(fun ast.Expr) string {
	switch e := fun.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// isFalseOrZeroLiteral reports whether an argument expression is the literal
// `false` or the literal `0` — the two hardcoded "no machine actor" values.
func isFalseOrZeroLiteral(arg ast.Expr) bool {
	switch e := arg.(type) {
	case *ast.Ident:
		return e.Name == "false"
	case *ast.BasicLit:
		return e.Kind == token.INT && e.Value == "0"
	}
	return false
}

// TestActorKindLiteralsAreAllowlisted is the completeness guard.
func TestActorKindLiteralsAreAllowlisted(t *testing.T) {
	t.Parallel()
	paramIndex := actorKindParamIndex(t)
	actual := actualActorKindLiteralSites(t, paramIndex)

	var unreviewed []string
	for key := range actual {
		if _, ok := actorKindLiteralAllowlist[key]; !ok {
			unreviewed = append(unreviewed, key)
		}
	}
	sort.Strings(unreviewed)

	var stale []string
	for key := range actorKindLiteralAllowlist {
		if !actual[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	if len(unreviewed) > 0 {
		t.Errorf("found %d call site(s) passing a HARDCODED actor-kind companion value with no reviewed "+
			"row in actorKindLiteralAllowlist "+
			"(internal/core/guards/actor_kind_literal_completeness_test.go): %v\n\n"+
			"A literal false/0 here does not mean \"no machine actor\". Every machine caller arrives with "+
			"actorID==0 (ADR-030), the same value as the unauthenticated system pseudo-actor that the "+
			"per-actor ceilings deliberately exempt — so on a request-reachable path a hardcoded companion "+
			"reports the calling machine AS the trusted system and the ceiling is skipped. That has now "+
			"happened four times (#1524, #1542, #1545, #2495).\n\n"+
			"Derive the value from the real actor (userCtx.ActorKind() == core.ActorTypeMachine, or "+
			"machineID(r) for a *MachineID companion) unless you can state why this site has no reachable "+
			"machine actor — and if you can, add a row saying so.", len(unreviewed), unreviewed)
	}
	if len(stale) > 0 {
		t.Errorf("found %d actorKindLiteralAllowlist row(s) whose call site no longer exists: %v\n"+
			"Remove them — a stale row makes the reviewed set look larger than what it reviews.",
			len(stale), stale)
	}
}

// TestActorKindLiteralScannerIsCalibrated is the both-directions calibration: a
// guard nobody has watched fail is not a guard, and a scanner that quietly
// matched nothing would make the test above pass forever.
func TestActorKindLiteralScannerIsCalibrated(t *testing.T) {
	t.Parallel()
	paramIndex := actorKindParamIndex(t)

	// The parameter-index derivation must actually find the convention's
	// members, including both spellings of the companion.
	for fn, wantParam := range map[string]string{
		"AssignUserRole":                     "actorIsMachine",
		"requireGranterHoldsRolePermissions": "actorIsMachine",
		"BulkApproveAccessRequests":          "approverMachineID",
		"ApproveAccessRequestWithExpiry":     "approverMachineID",
		"AddUserToGroup":                     "actorIsMachine",
	} {
		if _, ok := paramIndex[fn]; !ok {
			t.Errorf("%s carries an actor-kind companion parameter (%s) but the scanner did not index it — "+
				"the call-site scan below cannot see any of its call sites, so the guard is vacuous for them",
				fn, wantParam)
		}
	}
	if len(paramIndex) < 15 {
		t.Errorf("indexed only %d actor-kind-carrying function(s); the convention has well over that in "+
			"internal/core. The scan is almost certainly not reading the package.", len(paramIndex))
	}

	// Position must be RESOLVED, not assumed to be last — the convention puts
	// the companion wherever it reads best. A receiver is not a parameter, so
	// ctx is index 0.
	// AddUserToGroup(ctx, actorID, actorIsMachine, userID, groupID, projectID).
	if got := paramIndex["AddUserToGroup"]; got != 2 {
		t.Errorf("AddUserToGroup's actorIsMachine is parameter 2 (ctx, actorID, actorIsMachine, userID, groupID, "+
			"projectID); scanner says %d — a wrong index makes the scan inspect an unrelated argument", got)
	}
	// AssignUserRole(ctx, actorID, userID, roleID, scope, actorIsMachine).
	if got := paramIndex["AssignUserRole"]; got != 5 {
		t.Errorf("AssignUserRole's actorIsMachine is parameter 5 (ctx, actorID, userID, roleID, scope, "+
			"actorIsMachine); scanner says %d", got)
	}

	// The literal detector must recognise both hardcoded shapes and reject a
	// derived one.
	for _, src := range []string{"false", "0"} {
		if !isFalseOrZeroLiteral(mustParseExpr(t, src)) {
			t.Errorf("literal %q not recognised as a hardcoded actor-kind value", src)
		}
	}
	for _, src := range []string{
		"userCtx.ActorKind() == core.ActorTypeMachine",
		"machineID(r)",
		"actorIsMachine",
		"approverMachineID",
		"true",
	} {
		if isFalseOrZeroLiteral(mustParseExpr(t, src)) {
			t.Errorf("derived expression %q was flagged as a hardcoded literal — the guard would demand "+
				"rows for correct call sites and get routed around", src)
		}
	}
}

func mustParseExpr(t *testing.T, src string) ast.Expr {
	t.Helper()
	e, err := parser.ParseExpr(src)
	if err != nil {
		t.Fatalf("parsing %q: %v", src, err)
	}
	return e
}
