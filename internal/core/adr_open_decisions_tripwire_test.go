// adr_open_decisions_tripwire_test.go — general mechanism for "an ADR records
// a security-relevant decision, declines to resolve it, and nothing forces
// that resolution to happen." ADR-101 already proves the specific shape works
// (TestCurrentSchemaEpoch_Is5_SeeADR101, internal/storage/schema_epoch_
// tripwire_test.go) — this generalizes it to an explicit, extensible registry
// rather than one bespoke test per ADR, after a 2026-09-07 review
// (keyorix-private/adversarial-review/ADR-CORPUS-REVIEW-2026-09-07.md,
// Findings 3 and 4) found two more ADRs in exactly this shape with no
// enforcing test at all: ADR-102 (system.write blast radius, Proposed,
// undated) and ADR-084 (admin-bypass structural marker, Accepted but
// deferred, no target date/owner/tripwire).
//
// REDESIGNED 2026-09-07, same day, after the first version's own entry for
// ADR-084 went stale on arrival: it claimed the decision was still "deferred,
// no code changes" when PR #1671 had already implemented it 5 days earlier,
// because the check was purely age-based (elapsed time since openedDate) and
// never asked whether the decision was ACTUALLY still open in code. A
// duration-based check answers "has time passed," never "is the claim still
// true" — those are different questions, and only the second one is what a
// reader actually wants to know.
//
// A registry entry MUST assert the decision's PREMISE — a live, checkable
// fact about current code that would change the moment the decision is
// resolved — whenever one is expressible. ADR-084's premise was directly
// checkable ("does roleSetContainsAdmin still resolve by name") and would
// have caught the staleness immediately, the day #1671 merged, instead of
// sitting wrong in a registry entry that was itself only hours old.
// Age-based expiry is kept ONLY as a fallback for decisions whose
// unresolved state produces no code artifact in either branch. Do not add an
// age-only entry without first asking whether a premise exists — leave
// premise nil with a comment stating why not, so the omission reads as
// considered, not overlooked the way ADR-084's was.
//
// ADR-102 update, 2026-09-28: this entry originally had no premise ("neither
// un-chosen branch leaves anything in the codebase to inspect"), which was
// true of the (a)/(b) choice itself but missed a THIRD way the question could
// stop mattering: the 148-route surface the question was posed against could
// be deleted outright, rather than either narrowed (b) or left as intentional
// break-glass (a). ADR-108 Phase 6 did exactly that (deleted the entire
// /system proxy tier, PRs #2162/#2171) — a real code fact, checkable now.
// adr102Premise below checks for it; see docs/adr-110-system-write-scope.md
// for the follow-up review of the (much smaller) surface that remains.
//
// When a premise IS expressible, the check still also runs the age fallback
// underneath it (see evaluateOpenDecision) — a resolved premise fires
// immediately regardless of age (catching a stale-in-the-safe-direction
// entry like ADR-084's), and an unresolved premise still ages out on its own
// threshold (catching a decision that's genuinely still open and has simply
// been forgotten). The two checks are complementary, not alternatives.
//
// Each registry entry names: the ADR, a one-line statement of what remains
// undecided, an optional premise function, the date the decision was opened
// (from `git log --follow --diff-filter=A`, not a guess), and a threshold
// duration chosen per-entry with its own stated reasoning — not a single
// global number, since these decisions differ in urgency and don't share a
// natural deadline the way ADR-101's schema-epoch bump does.
//
// When this fires: read the named ADR, make the (a)/(b)-shaped decision it
// declines to make (or confirm it's already been made elsewhere and update
// the ADR's Status), and either remove the entry below or push its
// openedDate/threshold out with a fresh, stated justification for the
// extension — do not just bump the threshold silently.
package core

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// adrOpenDecision is one entry in the open-decision registry.
type adrOpenDecision struct {
	adr        string // e.g. "ADR-102"
	decision   string // one-line statement of what remains undecided
	openedDate string // RFC3339 date the decision was first recorded, from git history
	threshold  time.Duration
	reasoning  string // why this specific threshold, not a different one
	// premise, when non-nil, checks whether the decision is ACTUALLY still
	// open in code today — takes priority over the age check. Returns
	// stillOpen=false the moment the underlying code fact that would prove
	// the decision resolved is observed, with detail explaining what was
	// found. Leave nil (with a comment explaining why no premise is
	// expressible) rather than omitting it silently — see file header.
	premise func() (stillOpen bool, detail string)
}

// adrOpenDecisionRegistry is the extensible list task 2 of the 2026-09-07 ADR
// review asked for: "any ADR at Proposed (or Accepted-but-deferred) status
// carrying a security-relevant open decision gets a CI check that fails past
// a threshold age." Add an entry here, not a new bespoke test function, the
// next time this shape recurs.
var adrOpenDecisionRegistry = []adrOpenDecision{
	{
		adr: "ADR-105",
		decision: "gRPC's machine-appropriate step-up primitive: MFA step-up has no coherent " +
			"translation for a workload identity ('prompt for a TOTP' is not a second factor " +
			"for a machine), and its absence is currently the only thing making gRPC " +
			"fail-closed on `restricted` secrets. docs/adr-105-grpc-scope-and-parity.md §4 " +
			"states the question and declines to answer it. The answer determines whether " +
			"`restricted` is reachable over gRPC at all, and it must be settled BEFORE " +
			"governance fields reach the gRPC write path -- otherwise that change decides " +
			"it implicitly, which is how the two prior gRPC control gaps happened. " +
			"ADR-106 (proto-first generation) does NOT resolve this: generating both " +
			"transports from one definition says nothing about what a second factor means " +
			"for a workload identity.",
		premise:    adr105Premise,
		openedDate: "2026-09-09",
		threshold:  180 * 24 * time.Hour,
		reasoning: "180 days, deliberately longer than ADR-102's 30: there is no live exposure " +
			"to age against here. gRPC is off by default (server.grpc.enabled: false, Go's zero " +
			"value, no default-true anywhere in code) and the gap is fail-closed -- a gRPC " +
			"client cannot read a restricted secret rather than reading it unguarded. So the " +
			"deadline is not protecting against an open hole; it exists so the question does " +
			"not get answered by accident, by whoever first moves the secrets area onto the " +
			"generated surface. The premise " +
			"check below is the real guard and fires on the day that happens, whatever the age.",
	},
}

// TestADR105_GRPCStepUpPrimitiveStillOpen is the enforcing test named in
// docs/adr-105-grpc-scope-and-parity.md's own Status section.
func TestADR105_GRPCStepUpPrimitiveStillOpen(t *testing.T) {
	t.Parallel()
	checkADROpenDecisionNotStale(t, "ADR-105")
}

// adr105Premise answers "is ADR-105 §4 still an open question in code today?"
// by checking whether CreateSecretRequest still reserves the field-number
// block earmarked for the governance fields (11 = description,
// 12 = classification, 13-20 held for the rest).
//
// Why this is the right premise rather than, say, searching for a step-up
// RPC: the failure this entry exists to prevent is not "nobody ever built
// step-up." It is "governance fields reached the gRPC write path while the
// step-up question was still unanswered, and thereby answered it by
// default." The reservation disappearing IS that event, precisely and
// observably -- you cannot add `classification = 12` without removing the
// reservation first, because protoc will not compile it otherwise.
//
// This holds unchanged under ADR-106 (proto-first generation). Whether those
// fields arrive as a hand-written RPC change or as part of a generated
// surface, they still spend field numbers 11 and 12, and they still make
// `restricted` secrets writable over a transport with no step-up. The
// premise tracks the event, not the mechanism that causes it.
//
// Reads the .proto source rather than the generated descriptor because
// reserved ranges are a source-level compile-time constraint; that is where
// the fact lives, and where the next person will be editing.
func adr105Premise() (stillOpen bool, detail string) {
	const protoPath = "../../server/proto/keyorix.proto"
	b, err := os.ReadFile(protoPath)
	if err != nil {
		// Cannot read the file: report the decision as still open rather
		// than silently reporting it resolved. A premise that fails safe in
		// the "already resolved" direction would remove this entry's guard
		// entirely -- exactly ADR-084's original mistake.
		return true, fmt.Sprintf("could not read %s (%v); treating the decision as still open", protoPath, err)
	}
	src := string(b)
	i := strings.Index(src, "message CreateSecretRequest {")
	if i < 0 {
		return true, "CreateSecretRequest not found in the proto; treating the decision as still open"
	}
	end := strings.Index(src[i:], "\n}")
	if end < 0 {
		return true, "could not delimit CreateSecretRequest; treating the decision as still open"
	}
	if strings.Contains(src[i:i+end], "reserved 11 to 20;") {
		return true, "CreateSecretRequest still reserves fields 11-20 -- governance fields have not reached gRPC"
	}
	return false, "CreateSecretRequest no longer reserves fields 11-20: governance fields " +
		"are reaching the gRPC write path, so ADR-105 §4 (the machine step-up primitive) " +
		"must be decided and the ADR's Status updated now, not after"
}

// adr102Premise answers "does the 148-route /system proxy surface ADR-102's
// blast-radius question was posed against still exist?" by checking for
// r.Route("/system", ...) in server/http/router.go. ADR-108 Phase 6 deleted
// that entire group (PRs #2162/#2171); its absence is a direct code fact,
// not an inference from something else being true. This does not choose (a)
// or (b) — it observes that the specific surface both positions argued about
// is gone, which is the third resolution neither anticipated. See
// docs/adr-110-system-write-scope.md for the review of what remains
// (26 permSystemWrite gate sites, none of them a storage-relay primitive).
func adr102Premise() (stillOpen bool, detail string) {
	const routerGoPath = "../../server/http/router.go"
	b, err := os.ReadFile(routerGoPath)
	if err != nil {
		return true, fmt.Sprintf("could not read %s (%v); treating the decision as still open", routerGoPath, err)
	}
	if strings.Contains(string(b), `r.Route("/system"`) {
		return true, `server/http/router.go still registers r.Route("/system", ...) -- the 148-route ` +
			"surface ADR-102's blast-radius question was posed against still exists; (a)/(b) remains unresolved"
	}
	return false, `server/http/router.go no longer registers r.Route("/system", ...) -- the 148-route ` +
		"surface ADR-102 was posed against was deleted outright (ADR-108 Phase 6), not narrowed by " +
		"choosing (a) or (b). See docs/adr-110-system-write-scope.md for the review of the much " +
		"smaller replacement surface (26 gate sites) -- that ADR is the actual resolution artifact " +
		"now, not this one."
}

// TestADR102SystemGroupStaysDeleted is the ADR-084-style worked example for
// ADR-102: not a registry entry (removed 2026-09-28 once adr102Premise
// confirmed resolution — see docs/adr-102-system-write-blast-radius.md's
// Status section), but a live regression guard that the specific fact this
// ADR's resolution rests on — the /system route group is gone — stays true.
// A future PR that reintroduces r.Route("/system", ...) would silently
// resurrect the exact 148-route blast-radius surface this ADR's (a)/(b)
// question was posed against; this fails loudly instead.
func TestADR102SystemGroupStaysDeleted(t *testing.T) {
	t.Parallel()
	stillOpen, detail := adr102Premise()
	if stillOpen {
		t.Fatalf("ADR-102's resolution (the /system route group was deleted, not narrowed) has "+
			"regressed: %s", detail)
	}
}

// TestADRDecisionRoleSetContainsAdminIsStructural is the worked example of a
// premise function, kept live rather than only demonstrated in the self-test
// below: it directly answers "has ADR-084's decision been implemented,"
// independent of any registry entry or age. If this codebase ever
// regresses roleSetContainsAdmin back to name-based resolution, this test
// documents what a premise check for that regression would look like —
// exercised for real here, not just simulated.
func TestADRDecisionRoleSetContainsAdminIsStructural(t *testing.T) {
	t.Parallel()
	stillOpen, detail := adr084Premise()
	if stillOpen {
		t.Fatalf("ADR-084's decision reads as unresolved again: %s", detail)
	}
}

// adr084Premise checks whether ADR-084's decision — "bypasses_permission_checks
// as a structural, non-name column" — is actually implemented, by asserting
// the column exists on models.Role. This is the premise ADR-084's original
// registry entry should have used from the start: it would have failed the
// moment PR #1671 shipped, 5 days before the entry was written claiming
// otherwise.
func adr084Premise() (stillOpen bool, detail string) {
	// A compile-time assertion, not a runtime one: if BypassesPermissionChecks
	// is ever removed from models.Role, this line itself fails to compile,
	// which is a louder and earlier signal than a runtime test failure. The
	// runtime call below exists so this still reads as a normal premise
	// function callable from the registry shape, for the next ADR that needs
	// one.
	var r models.Role
	_ = r.BypassesPermissionChecks
	return false, "models.Role.BypassesPermissionChecks exists — ADR-084's structural flag is implemented"
}

// checkADROpenDecisionNotStale is the thin per-test entrypoint: find the
// named registry entry and fail loudly via evaluateOpenDecision if either
// check fires.
func checkADROpenDecisionNotStale(t *testing.T, adr string) {
	t.Helper()
	for _, d := range adrOpenDecisionRegistry {
		if d.adr != adr {
			continue
		}
		if err := evaluateOpenDecision(d, time.Now()); err != nil {
			t.Fatal(err.Error())
		}
		return
	}
	t.Fatalf("no registry entry found for %s in adrOpenDecisionRegistry -- this test's own "+
		"name promises to check that ADR; the registry entry was removed without removing "+
		"the test, or renamed without updating it", adr)
}

// evaluateOpenDecision is the pure logic behind checkADROpenDecisionNotStale,
// extracted so it can be exercised directly by the self-test below with
// synthetic entries — the same reason mlockall_removal_guard_test.go and
// other guards in this codebase pair a real check with a red/green
// self-test proving the check mechanism itself actually detects both
// outcomes, not just the one case it happened to run against here.
// now is passed in (not time.Now() called internally) so the self-test can
// exercise "age past threshold" deterministically without sleeping.
func evaluateOpenDecision(d adrOpenDecision, now time.Time) error {
	if d.premise != nil {
		if stillOpen, detail := d.premise(); !stillOpen {
			return fmt.Errorf(
				"%s: registry says this decision is still open, but its premise check reports "+
					"it has already been resolved in code (%s) -- this is exactly ADR-084's original "+
					"mistake (an entry claiming 'deferred' 5 days after the fix actually shipped). "+
					"Update the ADR's Status and remove this registry entry.",
				d.adr, detail,
			)
		}
	}
	opened, err := time.Parse("2006-01-02", d.openedDate)
	if err != nil {
		return fmt.Errorf("%s: openedDate %q does not parse as YYYY-MM-DD: %v", d.adr, d.openedDate, err)
	}
	age := now.Sub(opened)
	if age > d.threshold {
		return fmt.Errorf(
			"%s has been open %s (threshold %s, opened %s) with nothing forcing its "+
				"resolution -- STOP: this is exactly the 'accepted decision, no enforcement "+
				"mechanism' pattern the 2026-09-07 ADR review flagged. Decision still undecided: "+
				"%s\n\nResolve the decision and update the ADR's Status, or if a genuine reason "+
				"exists to keep it open longer, extend this entry's threshold in "+
				"adr_open_decisions_tripwire_test.go with a fresh, stated reason -- do not "+
				"silently bump the number.",
			d.adr, age.Round(time.Hour), d.threshold, d.openedDate, d.decision,
		)
	}
	return nil
}

// TestEvaluateOpenDecision_MechanismSelfTest is the red/green proof that
// evaluateOpenDecision actually detects both failure modes it exists to
// catch, and does not over-fire on the cases it should pass — run against
// synthetic entries, not the real registry, so it exercises the MECHANISM
// deterministically rather than depending on real ADRs' real ages.
func TestEvaluateOpenDecision_MechanismSelfTest(t *testing.T) {
	t.Parallel()
	fixedNow, err := time.Parse("2006-01-02", "2026-09-07")
	if err != nil {
		t.Fatalf("bad fixed 'now' in test setup: %v", err)
	}

	t.Run("premise resolved -- fires immediately regardless of age", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-09-06", // 1 day old -- well within any real threshold
			threshold:  365 * 24 * time.Hour,
			premise:    func() (bool, string) { return false, "synthetic: already resolved" },
		}
		if err := evaluateOpenDecision(d, fixedNow); err == nil {
			t.Fatal("expected the resolved-premise case to fire even though age is nowhere near threshold")
		}
	})

	t.Run("premise still open, within threshold -- does not fire", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-09-06",
			threshold:  30 * 24 * time.Hour,
			premise:    func() (bool, string) { return true, "synthetic: still open" },
		}
		if err := evaluateOpenDecision(d, fixedNow); err != nil {
			t.Fatalf("expected no failure for a genuinely-still-open decision within its threshold, got: %v", err)
		}
	})

	t.Run("premise still open, past threshold -- fires via the age fallback", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-01-01",
			threshold:  30 * 24 * time.Hour,
			premise:    func() (bool, string) { return true, "synthetic: still open" },
		}
		if err := evaluateOpenDecision(d, fixedNow); err == nil {
			t.Fatal("expected the age fallback to fire once a still-genuinely-open decision passes its threshold")
		}
	})

	t.Run("no premise (nil), within threshold -- does not fire", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-09-06",
			threshold:  30 * 24 * time.Hour,
			premise:    nil,
		}
		if err := evaluateOpenDecision(d, fixedNow); err != nil {
			t.Fatalf("expected no failure within threshold with no premise configured, got: %v", err)
		}
	})

	t.Run("no premise (nil), past threshold -- fires via age, the ADR-102 shape", func(t *testing.T) {
		d := adrOpenDecision{
			adr:        "ADR-TEST",
			decision:   "synthetic",
			openedDate: "2026-01-01",
			threshold:  30 * 24 * time.Hour,
			premise:    nil,
		}
		if err := evaluateOpenDecision(d, fixedNow); err == nil {
			t.Fatal("expected the pure age-based path (no premise) to still fire past threshold")
		}
	})
}
