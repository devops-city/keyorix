// g80_1530_machine_actor_attribution_guard_test.go — #1530's guard: every
// audit-emitting path funnels through emitAudit (service.go), the single
// choke point that stamps MachineIdentityID from context when an event is
// actor-typed "machine_identity", and (#1626/#1628) unconditionally clears
// UserID for the same events. A call site that bypasses emitAudit and writes
// storage.LogAuditEvent directly skips BOTH corrections -- if such a site
// ever sets ActorType to "machine_identity" (or leaves it derivable from a
// machine-authenticated context) without also setting MachineIdentityID
// itself and leaving UserID unset, it silently reintroduces #1530's and
// #1626's gaps at once.
//
// Repo-wide, not internal/core-only (#1626 verification pass, 2026-08-30):
// this guard used to scan only internal/core's own directory, and its own
// doc comment claimed "there is exactly one direct storage.LogAuditEvent
// caller outside emitAudit" -- true for that one package, false for the
// repo. server/main.go's auditConnectorProjectBindingCreate is one such
// direct caller outside internal/core entirely, safe on inspection but
// invisible to the old package-scoped scan -- an enumeration is only as
// complete as the directories it looks in. (A second one,
// server/http/handlers/audit_ingest_proxy.go's IngestAuditEventProxy, was
// removed in ADR-108 Phase 6 step 14c along with the rest of the /system
// proxy tier.) Still
// allowlist-shaped, not a full AST walk (a `.LogAuditEvent(` substring match
// per function, not real parsing), but now walks every non-test *.go file
// in the repository.
package core

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// auditAttributionAllowlist is the exhaustive, reasoned inventory of every
// direct storage.LogAuditEvent caller (bypassing emitAudit) reviewed as safe
// -- either it never sets ActorType to "machine_identity" at all (a genuine
// system/no-actor event), or it sets MachineIdentityID itself and leaves
// UserID unset. Each entry needs a reason; TestDirectLogAuditEventCallersAreSafe
// fails if a new direct caller appears unlisted, or if a listed entry no
// longer matches what it claims. Keys are repo-root-relative "path:func".
var auditAttributionAllowlist = map[string]string{
	"internal/core/audit_target.go:emitAuditOn": "#2676: emitAuditOn is emitAudit against an explicit " +
		"storage handle (the transaction-scoped one the access-review revoke path needs so its evidence " +
		"row commits or rolls back with the removal it describes). It is NOT a bypass of the attribution " +
		"stamp this guard protects: it calls the SAME prepareAuditEventForEmit(ctx, event) immediately " +
		"before the write, which is the function that stamps MachineIdentityID and clears UserID for a " +
		"machine-typed event -- the correction emitAudit applies is applied here, by the same code, not " +
		"re-implemented. The only differences are which storage handle receives the row and that the " +
		"off-box side effects are deferred into an auditForwardSink until the transaction commits. It also " +
		"delegates to emitAudit outright when no sink is set, so the non-transactional path is literally " +
		"unchanged. Verified by TestEmitAuditOn_StampsMachineAttributionLikeEmitAudit " +
		"(audit_target_attribution_test.go), which asserts the stamp on a row written through this path.",
	"internal/faultstorage/faulty_storage_generated.go:LogAuditEvent": "generated, mechanical pass-through " +
		"(w.real.LogAuditEvent(ctx, event)) inside a test/fuzz-harness-only storage.Storage wrapper " +
		"(server/faultops's FuzzStorageFaultOperations) -- it forwards whatever *models.AuditEvent the real " +
		"caller already constructed, unmodified, and never builds or mutates one itself, so it cannot be the " +
		"site of an attribution bug: whatever emitAudit correction should have applied already happened " +
		"upstream, before this call. Every one of the other 417 generated methods has the identical pass-" +
		"through shape; this is the one storage.Storage method this guard's AST walk happens to care about.",
	"internal/core/anomaly.go:auditBusinessHoursConfig": "hardcodes ActorType: \"system\" -- a " +
		"scheduler/config-change event with no human or machine actor, correctly using the system-actor marker " +
		"rather than a null. Never machine-identity-typed, so emitAudit's corrections would never apply to it " +
		"anyway.",
	"server/main.go:auditConnectorProjectBindingCreate": "hardcodes ActorType: core.ActorTypeSystem and never " +
		"sets UserID (absent from the struct literal, so it's the zero value nil) -- an unattended boot-time " +
		"binding-creation event with no actor, same shape as the anomaly.go entry above.",
	"server/main.go:auditKeylessModeStartup": "hardcodes ActorType: core.ActorTypeSystem and never sets " +
		"UserID (absent from the struct literal) -- the boot-time keyless-mode warning event " +
		"(docs/design-b2-recover-admin.md §5), emitted before any request context exists, same " +
		"no-actor shape as auditConnectorProjectBindingCreate above.",
	"server/main.go:auditDurableSyncSkippedStartup": "hardcodes ActorType: core.ActorTypeSystem and never sets " +
		"UserID (absent from the struct literal) -- the boot-time fast-audit-mode warning event (ADR-112 " +
		"Amendment 1, docs/specs/fast-audit-mode.md), emitted before any request context exists, same " +
		"no-actor shape as auditKeylessModeStartup above and for the same reason.",
	"server/admin/admin.go:recordAdminAction": "hardcodes ActorType: adminActorType (\"admin_cli\", " +
		"server/admin/admin.go) and never sets UserID (absent from the struct literal, so it's the zero value " +
		"nil) -- a host-side `keyorix-server admin` CLI action with no HTTP/gRPC request context to derive a " +
		"machine identity from in the first place (ADR-108 §B: no admin command starts a network listener), " +
		"same never-machine-identity-typed shape as the anomaly.go and server/main.go entries above.",
	"server/admin/recover_admin_logic.go:recordRecoveryAuditEvent": "hardcodes ActorType: adminActorType " +
		"(\"admin_cli\"), same never-machine-identity-typed, no-network-listener shape as the recordAdminAction " +
		"entry above (ADR-108 §B). UNLIKE recordAdminAction, this one DOES set UserID -- to the RECOVERED " +
		"account's id (docs/design-b2-recover-admin.md §4: \"target user\" is part of the required audit " +
		"content), not the acting identity emitAudit's UserID-clearing rule protects against, since the actor " +
		"here is the host OS user (no Keyorix identity to attribute to, by definition -- design §4) and is never " +
		"conflated with the target. ActorType never being \"machine_identity\" is what makes emitAudit's " +
		"corrections inapplicable here, independent of what UserID holds.",
	"server/admin/login_lockout.go:performClearLoginLockout": "hardcodes ActorType: adminActorType " +
		"(\"admin_cli\") for `keyorix-server admin clear-login-lockout` (#2936) -- same host-side, " +
		"no-network-listener shape as recordRecoveryAuditEvent above (ADR-108 §B). Like it, UserID is set only " +
		"to the TARGET account whose login lockout was cleared (when --user is given), never to an acting " +
		"identity: the actor is the host OS user, and ActorType is never \"machine_identity\".",
}

var logAuditEventFuncRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\(`)

// repoRootG1626 locates the repository root relative to this file's own
// location on disk (internal/core), so the guard works regardless of the
// test runner's working directory.
func repoRootG1626() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// findDirectLogAuditEventCallers scans every non-test *.go file in the
// repository for a `.LogAuditEvent(` call NOT inside emitAudit itself
// (service.go's own funnel implementation is the one legitimate direct
// caller of the storage interface method), returning "path:func" keys
// relative to the repo root.
func findDirectLogAuditEventCallers(t *testing.T, root string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", ".scratch", ".task", ".semgrep":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		currentFunc := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := logAuditEventFuncRe.FindStringSubmatch(line); m != nil {
				currentFunc = m[1]
			}
			if currentFunc == "emitAudit" {
				continue // the funnel itself, not a bypass
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, ".LogAuditEvent(") && currentFunc != "" {
				found[rel+":"+currentFunc] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking repo for direct LogAuditEvent callers: %v", err)
	}
	return found
}

// TestDirectLogAuditEventCallersScannerDetectsBypass is this guard's
// red-proof.
//
// TestDirectLogAuditEventCallersAreSafe has no total-collapse tripwire at
// all (unlike several sibling guards in this campaign) -- if
// logAuditEventFuncRe stopped matching, or the emitAudit exclusion or the
// "//"-comment skip became too permissive, actual would just come back
// smaller or noisier, and the allowlist comparison would report either
// nothing (a false "all safe") or unrelated staleness, never "the scanner
// broke."
func TestDirectLogAuditEventCallersScannerDetectsBypass(t *testing.T) {
	root := t.TempDir()
	// Line-scanned as plain text (findDirectLogAuditEventCallers is a
	// substring scanner, not go/ast), so this fixture is never compiled
	// either way -- undefined identifiers (storage, ev, ctx's type) are fine
	// and deliberate.
	const src = `package fixture

// emitAudit is the funnel itself -- its own LogAuditEvent call must never
// be reported as a bypass.
func emitAudit(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}

// directBypass is the planted violation: a direct call outside emitAudit.
func directBypass(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}

// commentedOut's call is text inside a comment and must not be reported.
func commentedOut(ctx context.Context) {
	// storage.LogAuditEvent(ctx, ev)
}
`
	if err := os.WriteFile(filepath.Join(root, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing the synthetic fixture: %v", err)
	}
	// A _test.go file with an otherwise-matching bypass must be excluded —
	// the scanner only walks non-test files, matching every real caller site.
	const testSrc = `package fixture

func shouldNotAppear(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}
`
	if err := os.WriteFile(filepath.Join(root, "fixture_test.go"), []byte(testSrc), 0o600); err != nil {
		t.Fatalf("writing the synthetic test-file fixture: %v", err)
	}

	found := findDirectLogAuditEventCallers(t, root)

	if !found["fixture.go:directBypass"] {
		t.Errorf("findDirectLogAuditEventCallers must find fixture.go:directBypass; got %v", found)
	}
	if found["fixture.go:emitAudit"] {
		t.Errorf("findDirectLogAuditEventCallers reported emitAudit's own call as a bypass — the funnel "+
			"exclusion has stopped working, got %v", found)
	}
	if found["fixture.go:commentedOut"] {
		t.Errorf("findDirectLogAuditEventCallers reported a commented-out call — the \"//\" skip has "+
			"stopped working, got %v", found)
	}
	if len(found) != 1 {
		t.Errorf("expected exactly 1 direct caller (fixture_test.go's shouldNotAppear must be excluded), "+
			"got %d: %v", len(found), found)
	}
}

// TestDirectLogAuditEventCallersAreSafe is #1530's guard: every direct
// storage.LogAuditEvent caller (bypassing emitAudit's MachineIdentityID
// stamp) must be in auditAttributionAllowlist with a reason, or the test
// fails -- a new bypass site is exactly how this gap would reappear.
func TestDirectLogAuditEventCallersAreSafe(t *testing.T) {
	t.Parallel()
	actual := findDirectLogAuditEventCallers(t, repoRootG1626())

	var unjustified []string
	for key := range actual {
		if _, ok := auditAttributionAllowlist[key]; !ok {
			unjustified = append(unjustified, key)
		}
	}
	if len(unjustified) > 0 {
		t.Errorf("%d direct storage.LogAuditEvent caller(s) bypass emitAudit's MachineIdentityID stamp with no "+
			"reasoned allowlist entry: %v\nEither route through emitAudit instead, or add a reasoned entry to "+
			"auditAttributionAllowlist explaining why this site can never emit a machine-identity-typed event "+
			"without attribution.", len(unjustified), unjustified)
	}

	var stale []string
	for key := range auditAttributionAllowlist {
		if !actual[key] {
			stale = append(stale, key+" (no longer calls LogAuditEvent directly)")
		}
	}
	if len(stale) > 0 {
		t.Errorf("auditAttributionAllowlist entr(y/ies) no longer reproduce: %v\nRemove the entry -- it's either "+
			"been fixed to route through emitAudit, or the direct call was removed.", stale)
	}
}
