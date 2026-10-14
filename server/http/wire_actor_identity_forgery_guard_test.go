// wire_actor_identity_forgery_guard_test.go — a guard for the bug class named
// and swept in the G80 documented-exception re-verification sweep
// (2026-08-25): a /system handler that reads an actor-shaped field straight
// off the wire body (invited_by, resolved_by, created_by, decided_by,
// approver_id, revoked_by) for an authorization decision or a persisted
// actor-identity field, instead of deriving it from the AUTHENTICATED caller
// (actorID(r) / requestActorKindAndID(r)). Two confirmed instances
// (CreateInvitationProxy's invited_by, UpdateAccessRequestProxy's
// resolved_by) were recorded FIXED under earlier PRs without ever touching
// this axis — this guard exists so a THIRD instance of the same shape can't
// land silently again.
//
// Modeled directly on raw_storage_bypass_guard_test.go's
// rawStorageBypassAllowlist / knownUnfixedRawStorageBypasses shape: flag
// every occurrence, require a reasoned entry in one of two lists, and fail on
// staleness (a listed handler that no longer reproduces, or no longer exists
// under /system).
//
// KNOWN BLIND SPOT, disclosed rather than hidden (matching this guard's own
// precedent's own documented gaps): this scan only catches `body.<Field>`
// where `body` is the DIRECT wire-decode variable. It does NOT see through an
// intermediate `.toModel()`/nested-struct hop — e.g.
// TransitionMachineIdentityStateProxy's actor field lives at
// `body.MachineIdentity.CreatedBy`, reached only via `body.MachineIdentity.
// toModel()`, never as a literal `body.CreatedBy` token. Those cases were
// found and fixed by hand during the sweep (see machine_identities_proxy.go's
// own doc comments); this guard cannot re-detect a regression in them and
// makes no claim to.
//
// TestNoUnjustifiedActorIdentityForgery (the actual /system-scoped guard) was
// removed with the ADR-108 Phase 6 /system proxy tier deletion -- its entire
// target population (every /system handler) no longer exists. The scanner
// infrastructure below (handlerBodyText, actorFieldReads,
// actorFieldReadsAgainst) and its self-test
// (TestActorFieldReadsScannerDetectsWireForgery) are generic and handler-name-
// agnostic, so they're kept: retargeting this guard at a live handler
// population, if this bug class recurs elsewhere, is a scope decision for
// that future work, not something Phase 6 deletion should do silently.
package http

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// actorShapedFieldNames are wire-struct field names that name WHO performed
// an action, as opposed to WHAT the action targets. `user_id`/`group_id`-as-
// target (e.g. "invite this user") are deliberately excluded — only fields
// that have been found, in this campaign, to actually feed an authorization
// decision or a persisted actor-identity column are listed. A new field name
// discovered later should be added here, not worked around.
var actorShapedFieldNames = []string{
	"InvitedBy", "ResolvedBy", "CreatedBy", "DecidedBy", "ApproverID", "RevokedBy",
}

// actorFieldReadRe matches `body.<ActorField>` for each name above, used to
// scan a handler's raw source text (comments included, filtered separately —
// see actorFieldReads).
var actorFieldReadRes = func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(actorShapedFieldNames))
	for i, name := range actorShapedFieldNames {
		res[i] = regexp.MustCompile(`\bbody\.` + name + `\b`)
	}
	return res
}()

// handlerBodyText returns the raw source text of the named handler method's
// body (opening brace to matching close), searched across every non-test
// *.go file in server/http/handlers — mirrors
// raw_storage_bypass_guard_test.go's handlerStorageCalls exactly, except it
// returns the joined text instead of extracted call names, since this guard
// needs to inspect the surrounding characters around each match (is it a
// read or a write?), not just detect a call name.
func handlerBodyText(t *testing.T, dir, handlerName string) string {
	t.Helper()
	funcRe := regexp.MustCompile(`^func \([a-zA-Z]+ \*[A-Za-z]+\) ` + regexp.QuoteMeta(handlerName) + `\(`)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading server/http/handlers: %v", err)
	}
	var out strings.Builder
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		inFunc := false
		depth := 0
		sawOpenBrace := false
		for line := range strings.SplitSeq(string(b), "\n") {
			if !inFunc && funcRe.MatchString(line) {
				inFunc = true
				sawOpenBrace = false
			}
			if inFunc {
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				if strings.Contains(line, "{") {
					sawOpenBrace = true
				}
				out.WriteString(line)
				out.WriteByte('\n')
				// Require having actually seen the body's opening brace before
				// depth<=0 can close capture -- a signature that wraps onto
				// multiple lines (the parameter list, not the "func (recv
				// *Type) Name(" prefix, which gofmt always keeps on the
				// funcRe-matched line) nets zero braces on that first matched
				// line, and closing on THAT would stop capture before the
				// body -- and any actor-field read in it -- was ever seen.
				if sawOpenBrace && depth <= 0 {
					inFunc = false
				}
			}
		}
	}
	return out.String()
}

// TestActorFieldReadsScannerDetectsWireForgery is this guard's red-proof.
//
// TestNoUnjustifiedActorIdentityForgery has no total-collapse tripwire at
// all — if actorFieldReadRes stopped matching, or the "=" overwrite check or
// the "//"-comment skip became too permissive, actorFieldReads would just
// come back empty or noisy for every handler, and the allowlist comparison
// would report either universal silence (a false "all safe") or unrelated
// staleness.
//
// This is a regexp/line-scanner, not an AST walk (the file header says so
// directly), and a regexp scanner fails differently than an AST one:
// reformatting alone can defeat it. Proven, not assumed, against a real
// defect this test found while being written: a handler whose signature
// spans multiple lines (the parameter list wrapped onto its own lines,
// rather than "func (recv *Type) Name(args) {" all on one line) used to
// vanish from handlerBodyText's capture entirely. depth tracking started on
// the funcRe-matched line and closed the moment that line's own brace count
// netted to zero — true for a split signature, since the opening "{" lands
// on a later line — stopping capture before the body, and any actor-field
// read in it, was ever seen. Confirmed red before the fix (this test failed
// exactly this way on first write); handlerBodyText now also requires having
// actually seen the opening brace before depth<=0 can close capture, closing
// the gap in the same change that found it rather than leaving it as a
// documented-but-open blind spot.
func TestActorFieldReadsScannerDetectsWireForgery(t *testing.T) {
	dir := t.TempDir()
	// Parsed as plain text (this guard is regexp-based, not go/ast — see the
	// file header), so this fixture is never compiled either way —
	// undefined identifiers are fine and deliberate.
	const src = `package handlers

func (h *Handler) NormalProxy(w http.ResponseWriter, r *http.Request) {
	_ = body.ResolvedBy
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture_handlers.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing the synthetic fixture: %v", err)
	}

	if got := actorFieldReadsAgainst(t, dir, "NormalProxy"); len(got) != 1 || got[0] != "ResolvedBy" {
		t.Errorf("actorFieldReads must find ResolvedBy in a normally-formatted single-line-signature "+
			"handler; got %v — if this regresses, the guard cannot ever fire, on any handler shape", got)
	}

	// The two-line-signature probe: does the scanner survive a signature
	// whose opening "{" is not on the same line funcRe matched? Before the
	// sawOpenBrace fix above, this returned empty — the exact silent-miss
	// this red-proof exists to catch.
	const splitSrc = `package handlers

func (h *Handler) SplitSignatureProxy(
	w http.ResponseWriter, r *http.Request,
) {
	_ = body.ResolvedBy
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture_split_handlers.go"), []byte(splitSrc), 0o600); err != nil {
		t.Fatalf("writing the synthetic split-signature fixture: %v", err)
	}
	if got := actorFieldReadsAgainst(t, dir, "SplitSignatureProxy"); len(got) != 1 || got[0] != "ResolvedBy" {
		t.Errorf("actorFieldReads must find ResolvedBy in a handler whose signature spans multiple lines, "+
			"same as the single-line case above; got %v — a regression here silently exempts every "+
			"multi-line-signature handler from this guard entirely", got)
	}
}

// actorFieldReadsAgainst is actorFieldReads with an injectable handlers
// directory, for the red-proof above — actorFieldReads itself always scans
// handlersDir (the real one), so this fixture needs its own copy of just the
// text-extraction step to point at a temp dir instead.
func actorFieldReadsAgainst(t *testing.T, dir, handlerName string) []string {
	t.Helper()
	text := handlerBodyText(t, dir, handlerName)
	var found []string
	seen := map[string]bool{}
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for i, re := range actorFieldReadRes {
			name := actorShapedFieldNames[i]
			for _, loc := range re.FindAllStringIndex(line, -1) {
				rest := strings.TrimLeft(line[loc[1]:], " \t")
				if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
					continue
				}
				if !seen[name] {
					seen[name] = true
					found = append(found, name)
				}
			}
		}
	}
	sort.Strings(found)
	return found
}
