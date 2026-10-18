// project_membership_definition_guard_test.go — #2781's structural guard: the
// repo must have exactly ONE definition of "is a member of project P".
//
// Two non-equivalent definitions existed and two admin screens disagreed about the
// same user (#2781): `GET /projects/{id}/members` answered from the project-scoped
// role grants, while `GET /users/{id}/memberships` and the admin Users list's
// project-count column answered from the ADR-022 onboarding journal — which nothing
// the web UI writes, so they reported "no projects" for every user on an install
// whose members were all real. The fix picked the role grant (ADR-021,
// project_membership_definition.go's header says why) and left the journal as an
// annotation.
//
// A fix is not a guard. These two tests fail the build when a SECOND definition
// reappears:
//
//	TestProjectMembership_OneDefinition_StorageIsProjectMemberHasOneCaller
//	  storage.IsProjectMember — the primitive that answers the membership question —
//	  has exactly one non-test call site repo-wide, core.IsProjectMember. Anything
//	  else asking storage directly is a second definition by construction, because
//	  it bypasses the one place the semantics are documented.
//
//	TestProjectMembership_OneDefinition_JournalReadsAreAllowlisted
//	  the ADR-022 journal's per-user reads (ListUserProjectMemberships,
//	  GetActiveProjectMembership, CountProjectMembershipsByUsers) are called only
//	  from an explicit allowlist. A new call site anywhere else is a new screen
//	  answering "which projects is this user in" from the journal again.
//
// # Recognized call forms, and why this list is complete
//
// Stating this explicitly because an exclusion-by-pattern is only as complete as
// the idioms it knows about, and this repo has been bitten five times by a guard
// that recognized one call shape and missed another (CLAUDE.md's enumeration rule;
// `raw_storage_bypass_guard_test.go`'s `exportedCoreStorageWrappers` was invisible
// to 9 real wrappers for exactly this reason). The walk below matches an
// `*ast.CallExpr` whose callee is:
//
//  1. `*ast.SelectorExpr` with `.Sel.Name == <method>` — covers EVERY receiver
//     spelling without caring what the receiver is: `c.storage.X(...)`,
//     `tx.X(...)` inside a `WithTransaction` closure (the shape that defeated the
//     raw-storage guard), `w.real.X(...)`, `h.coreService.X(...)`,
//     `s.core.X(...)`, `ls.X(...)`, a package-qualified `pkg.X(...)`, and a
//     chained `a.b.c.X(...)`.
//  2. `*ast.Ident` with `Name == <method>` — a bare in-package call, including a
//     method value assigned to a local (`f := c.storage.X; f(...)` still shows up
//     as the selector at the assignment, which form 1 catches).
//
// The one form NEITHER catches is a call through an interface value whose method
// is reached by reflection or a dynamically-built name. Nothing in this repo does
// that to a storage method, and such a call could not type-check against
// storage.Storage without naming the method somewhere these forms would see.
//
// Having found a call, the IsProjectMember guard then has to tell a CORRECT use
// (`c.IsProjectMember(...)` — the single definition, used as intended) from a
// bypass (`c.storage.IsProjectMember(...)`, `tx.IsProjectMember(...)`, ...). It
// does that on the receiver, not on a list of storage-handle names: a call counts
// as correct only when the receiver expression is the single identifier naming the
// enclosing method's receiver AND that receiver's type is KeyorixCore. Every other
// receiver spelling — including ones nobody has thought of yet — is flagged and
// needs an allowlist entry, so the guard's completeness does not depend on
// enumerating the bypass idioms, only on recognizing the one correct one.
// renderReceiver returns "?" for any receiver shape it cannot render, which can
// never equal a receiver identifier, so an unanticipated shape fails closed.
//
// Both tests assert a FLOOR on the number of call sites found before judging any of
// them, so a broken AST walk (wrong root, a directory skipped that shouldn't be)
// fails loudly instead of reporting a vacuous green — the failure mode CLAUDE.md
// calls "a check that always passes".
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

// membershipDefinitionRepoRoot resolves the repo root from this test file's own
// location, so the walk cannot silently run against the wrong tree.
func membershipDefinitionRepoRoot(t *testing.T) string {
	t.Helper()
	thisFile := filepath.Join(srcpath.PkgDir(), "project_membership_definition_guard_test.go")
	return filepath.Join(filepath.Dir(thisFile), "..", "..") // internal/core -> root
}

// skipMembershipDefinitionDir excludes VCS metadata, dependency/build output, the
// web tree (TypeScript), and the operator module (a separate Go module kept out of
// this repo's go.work), matching skipSecretReadAuditDir's scope.
func skipMembershipDefinitionDir(name string) bool {
	switch name {
	case ".git", "node_modules", "dist", ".scratch", "vendor", "operator", "web":
		return true
	}
	return false
}

// membershipCallSite is one call of a watched method: the file path relative to the
// repo root, the enclosing function's name, and whether the call went through the
// enclosing *KeyorixCore method's OWN receiver (`c.IsProjectMember(...)`) rather
// than through some other handle (`c.storage.X(...)`, `tx.X(...)`,
// `w.real.X(...)`, `ls.X(...)`, a package-qualified call, ...).
//
// SelfOnCore is the whole discrimination the IsProjectMember guard needs: a call on
// the core's own receiver IS the single definition being used correctly, and a call
// on anything else reaches past it. It requires BOTH that the receiver expression is
// the single identifier naming the enclosing method's receiver AND that the receiver's
// type is KeyorixCore — without the type half, a struct that embedded
// storage.Storage and happened to name its receiver the same thing would slip
// through.
type membershipCallSite struct {
	Method     string
	RelPath    string
	Func       string
	Receiver   string // rendered receiver expression, "" for a bare in-package call
	SelfOnCore bool
}

func (s membershipCallSite) String() string {
	recv := s.Receiver
	if recv == "" {
		recv = "(bare)"
	}
	return s.RelPath + ":" + s.Func + " calls " + recv + "." + s.Method
}

// renderReceiver renders a call's receiver expression back to source-ish text,
// handling exactly the expression shapes a receiver can take in this repo:
// an identifier (`c`, `ls`, `tx`), a selector chain (`c.storage`, `w.real`,
// `a.b.c`), and a pointer deref/paren wrapper. Anything else renders as "?" and is
// therefore never mistaken for the core's own receiver — the guard fails closed.
func renderReceiver(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return renderReceiver(x.X) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + renderReceiver(x.X)
	case *ast.ParenExpr:
		return renderReceiver(x.X)
	}
	return "?"
}

// coreMethodReceiverNames returns the receiver identifier of every method declared
// on KeyorixCore in file, so a call can be tested against "is this the enclosing
// core method's own receiver".
func coreMethodReceiverNames(file *ast.File) []struct {
	Name  string
	Range posRange
} {
	var out []struct {
		Name  string
		Range posRange
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
			continue
		}
		field := fn.Recv.List[0]
		if len(field.Names) != 1 {
			continue // an unnamed receiver cannot be the callee of c.X(...)
		}
		if strings.TrimPrefix(renderReceiver(field.Type), "*") != "KeyorixCore" {
			continue
		}
		out = append(out, struct {
			Name  string
			Range posRange
		}{Name: field.Names[0].Name, Range: posRange{Start: fn.Body.Lbrace, End: fn.Body.Rbrace}})
	}
	return out
}

// findMembershipCallSites walks root for every non-test .go file and records every
// call of any method in watched, using the two call forms documented in this file's
// header. testFiles controls whether _test.go files are included (they never are
// for the guard itself — a test may legitimately drive the journal directly).
func findMembershipCallSites(t *testing.T, root string, watched map[string]bool) []membershipCallSite {
	t.Helper()
	var out []membershipCallSite
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if skipMembershipDefinitionDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("failed to parse %s: %v", path, perr)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		decls := collectFuncDeclRanges(file)
		coreRecvs := coreMethodReceiverNames(file)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, recv := "", ""
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr: // form 1 — any receiver spelling
				name, recv = fn.Sel.Name, renderReceiver(fn.X)
			case *ast.Ident: // form 2 — bare in-package call
				name = fn.Name
			}
			if name == "" || !watched[name] {
				return true
			}
			selfOnCore := false
			for _, r := range coreRecvs {
				if recv == r.Name && call.Pos() >= r.Range.Start && call.Pos() < r.Range.End {
					selfOnCore = true
					break
				}
			}
			out = append(out, membershipCallSite{
				Method:     name,
				RelPath:    filepath.ToSlash(rel),
				Func:       enclosingFuncName(decls, call.Pos()),
				Receiver:   recv,
				SelfOnCore: selfOnCore,
			})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// isProjectMemberNonSelfCallers names every non-test call site of IsProjectMember
// that reaches the method through something OTHER than the enclosing core method's
// own receiver, keyed "<rel path>:<enclosing func>".
//
// There is deliberately exactly one real entry — the definition, which is the only
// place allowed to touch the storage primitive. The generated fault-injection
// wrapper is listed too because it mechanically mirrors every storage method and is
// not a semantic call site; regenerating it must not break this guard.
//
// Every OTHER caller in the repo reaches it as `c.IsProjectMember(...)` on its own
// *KeyorixCore receiver, which this guard accepts without an entry — that is the
// single definition being used, and listing each would make the allowlist grow with
// correct code instead of with exceptions.
var isProjectMemberNonSelfCallers = map[string]string{
	"internal/core/project_membership_definition.go:IsProjectMember": "THE definition — the one place that may call the storage primitive. " +
		"Every other caller asks c.IsProjectMember, which is this.",
	"internal/faultstorage/faulty_storage_generated.go:IsProjectMember": "generated fault-injection passthrough (go generate ./internal/faultstorage/...), " +
		"mechanically mirrors every storage method; not a semantic call site.",
}

func TestProjectMembership_OneDefinition_StorageIsProjectMemberHasOneCaller(t *testing.T) {
	t.Parallel()
	root := membershipDefinitionRepoRoot(t)
	sites := findMembershipCallSites(t, root, map[string]bool{"IsProjectMember": true})

	// Violations first, floors second: a planted bypass must report ITSELF, not a
	// side effect of the floor arithmetic. (A bypass necessarily lowers the
	// self-on-core count by one, so a floor checked first would hijack the message
	// and tell a developer "only 4 self callers" instead of naming the file that
	// reached past the definition.)
	var violations []string
	seen := map[string]bool{}
	selfCallers := 0
	for _, s := range sites {
		if s.SelfOnCore {
			selfCallers++
			continue // the single definition, used correctly
		}
		key := s.RelPath + ":" + s.Func
		seen[key] = true
		if reason, ok := isProjectMemberNonSelfCallers[key]; ok {
			t.Logf("allowed non-self call %s (%s)", key, reason)
			continue
		}
		violations = append(violations, s.String()+
			" — storage.IsProjectMember must have exactly one caller, core.IsProjectMember "+
			"(internal/core/project_membership_definition.go). Calling the storage primitive directly creates a "+
			"second definition of project membership: it bypasses the one place the semantics "+
			"(project-scoped grants only, global grants excluded, group grants included, expired grants excluded) are documented. "+
			"Call c.IsProjectMember instead.")
	}
	for key, reason := range isProjectMemberNonSelfCallers {
		if !seen[key] {
			violations = append(violations, "stale allowlist entry "+key+
				" no longer makes a non-self IsProjectMember call — remove it (reason recorded: "+reason+")")
		}
	}
	if len(violations) > 0 {
		t.Fatalf("project-membership definition guard failed (%d):\n  %s", len(violations), strings.Join(violations, "\n  "))
	}

	// Floors, so a broken walk cannot report a vacuous green. 7 = five real core
	// callers (ShareSecret, GrantSecretACL, aclGrantsPermission,
	// requireLiveOwnerAuthority, ActivateBreakGlass) + the definition + the generated
	// passthrough.
	if len(sites) < 7 {
		t.Fatalf("found only %d IsProjectMember call site(s); expected at least 7 "+
			"(5 core access decisions + core.IsProjectMember + the generated faultstorage passthrough) — "+
			"the AST walk is broken, not the code. Sites: %v", len(sites), sites)
	}
	// The floor that matters most: the guard must be watching real self-on-core
	// callers, not only the two allowlisted non-self ones. Without this, deleting
	// every c.IsProjectMember caller — or breaking the receiver classification so
	// nothing is ever classified self — would leave the test green.
	if selfCallers < 5 {
		t.Fatalf("found only %d caller(s) of c.IsProjectMember on a *KeyorixCore receiver; expected at least 5 "+
			"(ShareSecret, GrantSecretACL, aclGrantsPermission, requireLiveOwnerAuthority, ActivateBreakGlass) — "+
			"either the receiver classification is broken or those access decisions stopped checking membership. Sites: %v", selfCallers, sites)
	}
}

// journalPerUserReads are the ADR-022 onboarding-journal storage reads that answer,
// or could be mistaken for answering, "which projects is this user in". The
// per-PROJECT reads (ListProjectMemberships, ListStaleInvitedMemberships) are
// deliberately NOT watched: GET /projects/{id}/memberships is the lifecycle
// endpoint, which is the journal's legitimate reader.
var journalPerUserReads = map[string]bool{
	"ListUserProjectMemberships":          true,
	"ListUserProjectMembershipsByUserIDs": true,
	"GetActiveProjectMembership":          true,
	"CountProjectMembershipsByUsers":      true,
}

// journalReadAllowedCallers names every non-test call site of a journalPerUserReads
// method that may exist, keyed "<rel path>:<enclosing func>".
var journalReadAllowedCallers = map[string]string{
	"internal/core/project_membership_definition.go:journalStateByProject": "the ONE journal read in the membership path, and it is an annotation " +
		"(lifecycle state on a row whose membership was already decided by the grant), never the membership answer.",
	"internal/core/project_membership_definition.go:journalStatesForUsers": "journalStateByProject for a page of users (LIST-ENDPOINTS-1): the same " +
		"annotation read, batched; never the membership answer.",
	"internal/core/membership_lifecycle.go:inviteMemberWithMode": "ADR-022's own duplicate-invite guard — asks whether a journal row already " +
		"exists before creating one. A question about the journal, not about membership.",
	"internal/faultstorage/faulty_storage_generated.go:ListUserProjectMemberships":          "generated fault-injection passthrough; not a semantic call site.",
	"internal/faultstorage/faulty_storage_generated.go:ListUserProjectMembershipsByUserIDs": "generated fault-injection passthrough; not a semantic call site.",
	"internal/faultstorage/faulty_storage_generated.go:GetActiveProjectMembership":          "generated fault-injection passthrough; not a semantic call site.",
	"internal/faultstorage/faulty_storage_generated.go:CountProjectMembershipsByUsers":      "generated fault-injection passthrough; not a semantic call site.",
}

func TestProjectMembership_OneDefinition_JournalReadsAreAllowlisted(t *testing.T) {
	t.Parallel()
	root := membershipDefinitionRepoRoot(t)
	sites := findMembershipCallSites(t, root, journalPerUserReads)

	// Floor: the three generated passthroughs plus the two real readers.
	if len(sites) < 5 {
		t.Fatalf("found only %d journal per-user read call site(s); expected at least 5 — the AST walk is broken. Sites: %v", len(sites), sites)
	}

	var violations []string
	seen := map[string]bool{}
	for _, s := range sites {
		key := s.RelPath + ":" + s.Func
		seen[key] = true
		if reason, ok := journalReadAllowedCallers[key]; ok {
			t.Logf("allowed: %s (%s)", key, reason)
			continue
		}
		violations = append(violations, s.String()+
			" — the ADR-022 project_memberships table is an ONBOARDING JOURNAL, not the answer to "+
			"\"which projects is this user a member of\" (#2781: it is empty on any install whose members were added "+
			"through POST /projects/{id}/members, which is what the web UI calls). Ask "+
			"core.ListProjectMembershipsForUser or core.IsProjectMember instead. If this really is a question ABOUT the "+
			"journal (an invite's lifecycle state), add an allowlist entry here saying so.")
	}
	for key, reason := range journalReadAllowedCallers {
		if !seen[key] {
			violations = append(violations, "stale allowlist entry "+key+
				" no longer reads the journal — remove it (reason recorded: "+reason+")")
		}
	}
	if len(violations) > 0 {
		t.Fatalf("project-membership journal-read guard failed (%d):\n  %s", len(violations), strings.Join(violations, "\n  "))
	}
}

// TestProjectMembership_OneDefinition_NoCoreWrapperForJournalPerUserRead pins the
// PRECONDITION the two guards above rest on, rather than a proxy for it: there is no
// exported KeyorixCore method that hands a caller the journal's per-user rows, so a
// handler cannot reach a second definition without tripping the allowlists.
//
// (CLAUDE.md: "when a verdict depends on a condition, guard the condition, not the
// conclusion." The condition here is the absence of the entry point — asserting that
// no handler calls it would be vacuous precisely because the method is gone.)
func TestProjectMembership_OneDefinition_NoCoreWrapperForJournalPerUserRead(t *testing.T) {
	t.Parallel()
	root := membershipDefinitionRepoRoot(t)
	coreDir := filepath.Join(root, "internal", "core")

	banned := map[string]string{
		"ListUserProjectMemberships": "removed in #2781 — it was the second definition's entry point. " +
			"Use ListProjectMembershipsForUser (project_membership_definition.go).",
	}

	entries, err := os.ReadDir(coreDir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", coreDir, err)
	}
	fset := token.NewFileSet()
	checked := 0
	var violations []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		checked++
		file, perr := parser.ParseFile(fset, filepath.Join(coreDir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("failed to parse %s: %v", e.Name(), perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name == nil {
				continue
			}
			if reason, bad := banned[fn.Name.Name]; bad {
				violations = append(violations, e.Name()+": method "+fn.Name.Name+" must not exist — "+reason)
			}
		}
	}
	if checked < 50 {
		t.Fatalf("only parsed %d non-test files in internal/core; expected well over 50 — the directory scan is broken, not the code", checked)
	}
	if len(violations) > 0 {
		t.Fatalf("banned core method(s) reintroduced (%d):\n  %s", len(violations), strings.Join(violations, "\n  "))
	}
}
