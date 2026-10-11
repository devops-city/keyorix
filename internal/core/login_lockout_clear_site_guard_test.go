// login_lockout_clear_site_guard_test.go — the structural half of
// INV-CORE-login-lockout-clear-only-after-delivery (#2894).
//
// The bug this guards against is an ORDERING, not a value: clearing a login's
// failed-attempt counter before some later step of that same login can still
// fail. No value assertion catches it, because the counter ends up correct on
// the happy path either way; it only diverges when a fault is injected into the
// window between the clear and the response. And the window is easy to reopen
// by accident — a new login path, or one new fallible write appended after an
// existing clear, is enough.
//
// So instead of trying to detect the ordering, this test pins the CALL SITES.
// Every place in internal/core that touches the clear, or that re-checks the
// lock without clearing, is listed below with the reason it is safe. Adding a
// call site (or moving one to a different function) fails this test until the
// new site is added to the list with its own justification — which is the point
// at which somebody has to think about what can still fail after it.
//
// It is deliberately a source scan rather than a behavioural test: the
// behavioural half lives in server/http/handlers/login_lockout_no_oracle_test.go,
// where a fault can actually be injected into each window, and it can only ever
// cover the paths someone remembered to write a case for.
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
)

// clearSite is one allowlisted call to a lockout-accounting primitive:
// the enclosing function, and why calling it there is safe.
type clearSite struct {
	fn     string // enclosing function or method name
	callee string
	why    string
}

// allowedLockoutAccountingSites is the allowlist. Keep the `why` honest: it is
// the only thing a reviewer of a new entry has to go on.
var allowedLockoutAccountingSites = []clearSite{
	// --- the clear ---
	{fn: "Succeeded", callee: "clearLoginFailures",
		why: "LoginCompletion.Succeeded IS the delivery point: the transport calls it after the identity payload is built and the cookies are set, so nothing fallible remains."},
	{fn: "requireReauth", callee: "clearLoginFailures",
		why: "last statement before audit writes only; no fallible step follows (the grant consume already happened above)."},
	{fn: "VerifyMFAStepUp", callee: "clearLoginFailures",
		why: "placed AFTER CreateMFAStepUpGrant, whose failure branch counts the attempt instead (#2894)."},
	{fn: "FinishWebAuthnReauth", callee: "clearLoginFailures",
		why: "placed AFTER CreateMFAStepUpGrant, whose failure branch counts the attempt instead (#2894)."},
	{fn: "CompleteSSO", callee: "clearLoginFailures",
		why: "placed AFTER mintSession. SSO never feeds this counter (an IdP-rejected assertion never reaches here), so a later fault leaving it untouched matches every other SSO failure."},
	{fn: "CompleteSAML", callee: "clearLoginFailures",
		why: "same as CompleteSSO."},

	// --- the no-clear TOCTOU re-check ---
	{fn: "authenticatePasswordLogin", callee: "recheckLockAfterCredentialMatched",
		why: "re-check only (shared by LoginPending and LoginWithIdentityPending); the clear is deferred to the LoginCompletion mintPasswordLogin returns, and the identity read in between counts its failure via denyAfterCredentialMatched."},
	{fn: "VerifyMFACredentials", callee: "recheckLockAfterCredentialMatched",
		why: "re-check only; VerifyMFALoginPending's LoginCompletion owns the clear."},
	{fn: "FinishWebAuthnLoginPending", callee: "recheckLockAfterCredentialMatched",
		why: "re-check only; its own LoginCompletion owns the clear."},
	{fn: "checkPasswordlessAccountState", callee: "recheckLockAfterCredentialMatched",
		why: "re-check only; FinishWebAuthnPasswordlessLoginPending's LoginCompletion owns the clear."},
	{fn: "FinishWebAuthnReauth", callee: "recheckLockAfterCredentialMatched",
		why: "re-check only; the clear is after CreateMFAStepUpGrant."},
	{fn: "VerifyMFAStepUp", callee: "recheckLockAfterCredentialMatched",
		why: "re-check only; the clear is after CreateMFAStepUpGrant."},
	{fn: "recheckLockAfterCredentialMatched", callee: "recheckLoginLockFailClosed",
		why: "the wrapper every credential-verifying login path uses (#2894 review): it adds no clear, and on the recheck's storage-fault branch it counts the attempt (when the path counts wrong credentials) and wraps ErrLoginPostVerdict."},
	{fn: "CompleteSSO", callee: "recheckLoginLockFailClosed",
		why: "re-check only; the clear is after mintSession."},
	{fn: "CompleteSAML", callee: "recheckLoginLockFailClosed",
		why: "re-check only; the clear is after mintSession."},
	// Deliberately NOT listed: UnlockUser. It is an audited admin action, not a
	// login, and it writes UpdateLoginLockoutState directly rather than going
	// through either primitive — so it is out of this guard's scope by
	// construction, not by exemption.
}

// trackedLockoutCallees are the primitives whose call sites are pinned.
var trackedLockoutCallees = map[string]bool{
	"clearLoginFailures":                true,
	"recheckLoginLockFailClosed":        true,
	"recheckLockAfterCredentialMatched": true,
	"checkLockAndClearLoginFailures":    true, // the removed combined form: must never come back
}

// TestClearLoginFailures_HasNoCallerBeforeAFallibleStep is the guard described
// in this file's comment.
func TestClearLoginFailures_HasNoCallerBeforeAFallibleStep(t *testing.T) {
	t.Parallel()

	allowed := map[string]string{}
	for _, s := range allowedLockoutAccountingSites {
		if s.why == "" {
			t.Fatalf("allowlist entry %s -> %s has no justification", s.fn, s.callee)
		}
		allowed[s.fn+"->"+s.callee] = s.why
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var found []string
	seen := map[string]bool{}
	scanned := 0
	for _, path := range files {
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
		scanned++
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			enclosing := fd.Name.Name
			ast.Inspect(fd, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				case *ast.Ident:
					callee = fun.Name
				}
				if !trackedLockoutCallees[callee] {
					return true
				}
				key := enclosing + "->" + callee
				if !seen[key] {
					seen[key] = true
					found = append(found, key)
				}
				return true
			})
		}
	}

	// Floor: an empty or near-empty scan would be green for the wrong reason.
	if scanned < 20 {
		t.Fatalf("expected to scan >=20 non-test files in internal/core, scanned %d", scanned)
	}
	if len(found) < len(allowedLockoutAccountingSites) {
		t.Errorf("found only %d lockout-accounting call sites, allowlist has %d — did a login path lose its re-check?\nfound: %v",
			len(found), len(allowedLockoutAccountingSites), found)
	}

	sort.Strings(found)
	for _, key := range found {
		if strings.HasSuffix(key, "->checkLockAndClearLoginFailures") {
			t.Errorf("%s calls checkLockAndClearLoginFailures, the combined check-and-clear removed by #2894: it clears the counter BEFORE the caller's remaining fallible steps. Use recheckLoginLockFailClosed plus a LoginCompletion (or an explicit clearLoginFailures after the last fallible step).", key)
			continue
		}
		if _, ok := allowed[key]; !ok {
			t.Errorf("unallowlisted lockout-accounting call site %s.\nEvery site must be listed in allowedLockoutAccountingSites with a justification saying what can still fail after it — see INV-CORE-login-lockout-clear-only-after-delivery. If nothing fallible follows, say so; if something does, the failure branch must count the attempt (LoginCompletion.Failed / denyAfterCredentialMatched).", key)
		}
	}

	// And the reverse direction: a stale allowlist entry hides a path that no
	// longer re-checks the lock at all.
	for key := range allowed {
		if !seen[key] {
			t.Errorf("allowlist entry %s matches no call site — remove it, or restore the call it was justifying (a login path that stopped re-checking the lock is a TOCTOU regression, not a cleanup)", key)
		}
	}
}
