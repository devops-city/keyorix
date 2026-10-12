// actor_sentinel_completeness_test.go — P3's chosen fix for the actorID==0
// sentinel ambiguity (#1524, #1532): NOT a Principal type migration (rejected
// as defence in depth behind an existing control, at 20-100x the cost -- P2's
// node-credential route classification already closes this class at the
// boundary where it actually bites: a machine actor can only reach a
// per-actor ceiling through a machine-credential-authenticated route, and
// server/http/node_credential_route_classification_test.go now classifies
// and enforces every one of those). Instead: a frozen, exhaustive inventory
// of every `actorID == 0` / `actorID != 0` comparison in this package,
// classified as classPerActorCeiling (an authorization decision) or
// classAuditOnly (attribution metadata, no authorization implication), with
// a completeness test that fails the moment a FIFTH such comparison appears
// anywhere in this package outside this list -- forcing the same
// enforced/open-gap classification this file already did for the first
// four, at authoring time, not at the next audit round. Same shape as
// remote_unsupported_completeness_test.go's allowlist (C5's pattern).
//
// Keyed by "<file>:<enclosing func>", not file:line -- a line-numbered key
// would need updating on every unrelated edit above the comparison; a
// (file, func) key survives that churn. The trade-off: a SECOND actorID==0
// comparison added to an ALREADY-listed function collapses into the same
// key and isn't separately flagged. Accepted -- the dangerous case this
// guards against is a new function introducing the pattern, not a second
// comparison inside a function a reviewer is already touching (and which
// this table's note already flags).
package core

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type actorSentinelClass int

const (
	// classAuditOnly: the branch decides only whether to attach a non-nil
	// actor pointer to an audit/attribution record. actorID==0 there means
	// "don't record an actor," never "skip a check" -- no authorization
	// implication, so a machine actor producing actorID==0 is harmless here.
	classAuditOnly actorSentinelClass = iota
	// classPerActorCeiling: the branch gates (or should gate) a per-actor
	// authorization ceiling -- self-approval, escalation-by-proxy,
	// self-permission-bundling, ACL/ownership re-authorization. Exactly the
	// site shape #1524 (b)/(c) showed can silently exempt a machine actor
	// when the branch treats actorID==0 as "trusted local caller" instead of
	// "caller identity unknown, deny."
	classPerActorCeiling
)

type actorSentinelStatus int

const (
	// statusEnforced: a machine actor (actorID==0, actorIsMachine==true or
	// no such distinction needed) is already denied here -- either the
	// branch rejects actorID==0 outright as invalid input, or the ceiling
	// was fixed to deny (P1's actorIsMachine parameter).
	statusEnforced actorSentinelStatus = iota
	// statusOpenGap: a machine actor can reach this branch with actorID==0
	// today and the per-actor ceiling is skipped -- a confirmed, live,
	// tracked gap, not fixed by this table. See note for the issue.
	statusOpenGap
	// statusReasonedSafe: a machine actor can reach this branch with
	// actorID==0 and the per-actor ceiling IS skipped, same mechanism as
	// statusOpenGap -- but tracing what the skipped check would have added
	// shows it is fully subsumed by an earlier, coarser gate the caller
	// already had to clear to reach this code at all, so skipping it confers
	// no extra reach. Not the same claim as statusEnforced (nothing here
	// denies the machine actor); the note must show the escalation-delta
	// derivation, not just assert safety.
	statusReasonedSafe
)

type actorSentinelEntry struct {
	class  actorSentinelClass
	status actorSentinelStatus
	note   string
}

// actorSentinelAllowlist is the exhaustive, reasoned inventory of every
// `actorID == 0` / `actorID != 0` comparison in internal/core's non-test
// source. TestActorSentinelComparisonsAreAllowlisted asserts this is an
// EXACT match against the real source.
var actorSentinelAllowlist = map[string]actorSentinelEntry{
	"access_review_campaign.go:requireHumanReviewer": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright: 'a machine identity ... is not an attributable, independent human reviewer.'",
	},
	"access_review_revoke.go:logAccessReviewDecisionOn": {
		class: classAuditOnly,
		note: "attribution-only: whether to attach a non-nil actor pointer to the audit record. Renamed " +
			"from logAccessReviewDecision in #2676, which gave it an explicit audit target so the campaign " +
			"revoke path can write this event inside the same transaction as the removal it describes; the " +
			"comparison itself is unchanged, and logAccessReviewDecision is now a one-line delegate with no " +
			"comparison of its own.",
	},
	"anomaly_alerting.go:AcknowledgeAnomalyAlert": {
		class: classAuditOnly,
		note:  "attribution-only audit pointer; the write-permission gate at the transport already authorized the call.",
	},
	"audit.go:writeRBACAuditOn": {
		class: classAuditOnly,
		note: "attribution-only audit pointer, shared writer for RBAC audit events. Renamed from " +
			"writeRBACAudit in #2676 for the same reason as logAccessReviewDecisionOn above (an explicit " +
			"audit target); writeRBACAudit is now a one-line delegate with no comparison of its own.",
	},
	"share_owned_list.go:ListOwnedShareViews": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "SHARE-3: refuses actorID==0 outright, together with any actorType other than ActorTypeUser, so a machine actor (or an unknown caller) gets the owner-scoped share list's fixed refusal, never another user's or everyone's shares. The HTTP handler passes ActorKind()/PrincipalID(); TestOwnedShares_MachineIsRefusedWithReason drives a real machine token.",
	},
	"authz.go:requireGranterHoldsRolePermissions": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "#1542: actorIsMachine parameter added, denies a machine actor instead of exempting it. AssignRoleWithExpiryProxy's non-node-relay path now passes isMachineActor(r); a genuine node relay skips this function entirely (still calls raw storage, by design -- see rbac_role_grants_proxy.go). #2495 (2026-10-05) audited the sibling gap this note used to describe as open: AssignUserRole's own callers -- AddProjectMember/SetProjectMemberRole, the AssignRole gRPC and HTTP endpoints, SetUserRoles, AddUserToGroup -- all derive the real actor kind today (closed by #1542/#1545 and follow-ups), so that half of the note was stale. Access-request approval was genuinely still open, on the BULK path only, and is now closed; see INV-CORE-14 and actor_kind_literal_completeness_test.go, which is the standing enumeration so this does not have to be re-derived from prose again.",
	},
	"authz.go:requireGranterHoldsRolePermissionsNoBaseline": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "F6 sweep (2026-09-22): identical actorID==0/!actorIsMachine local-CLI/system exemption as requireGranterHoldsRolePermissions above (this function is its per-permission-loop body, factored out so CreateUserWithAssignments' mandatory system_viewer default can skip only the NEW roles.assign baseline, not this pre-existing exemption). Same reasoning applies verbatim: actorID==0 is the local-CLI/system-initiated-write sentinel, not attacker-reachable over any transport.",
	},
	"bulk_delete.go:bulkDeleteOneSecret": {
		class: classPerActorCeiling, status: statusReasonedSafe,
		note: "#1545 escalation-delta analysis: actorID==0 skips GetSecretWithPermissionCheck/DeleteSecretWithPermissionCheck's per-secret ACL/ownership check (2 occurrences, same function), but the route (POST /projects/{id}/secrets/bulk-delete) is gated by RequireScopedPermission(secrets.delete, projectScope) -- Scope{ProjectID, EnvironmentID:0}. GetUserRoleIDsAt/GetMachineRoleIDsAt only match a stored grant whose environment_id is 0 (global) or the scope's environment_id against a project-level (env=0) query, so ONLY a project-wide secrets.delete grant clears that gate; an environment-scoped-only grant is refused before the handler ever runs. Every skipped per-secret check (isLiveOwner, share, ACL-for-humans, RBAC fallback) is purely additive -- it can only grant MORE access, never less -- and the RBAC fallback resolves to the identical AuthorizePrincipal(secrets.delete, {ProjectID, EnvironmentID: secret's env}) call, which a project-wide grant always satisfies (broader scope covers narrower). So the exemption confers no reach a project-wide secrets.delete holder didn't already have by clearing the router gate. Not a vulnerability; issue closed on this reasoning, not fixed.",
	},
	"config_change_audit.go:writeConfigChangeAuditEvent": {
		class: classAuditOnly,
		note: "attribution-only: whether to attach a non-nil actor pointer to the audit record for an admin " +
			"config mutation (notification channel CRUD, anomaly config update). The write-permission gate " +
			"(system.write) already authorized the call before reaching this shared writer; actorID==0 here " +
			"just means the caller didn't have a numeric actor ID to attribute (e.g. a local CLI invocation), " +
			"never a bypassed check.",
	},
	"groups.go:AddUserToGroup": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "P1 (#1524 b): actorIsMachine parameter added; a machine actor is now denied instead of exempted alongside the trusted local-CLI case.",
	},
	"rate_limit.go:PruneLoginAttempts": {
		class: classAuditOnly,
		note:  "attribution-only: whether to attach a non-nil actor pointer to the prune audit record.",
	},
	"rbac_management.go:AssignPermissionToRole": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "#1545: actorIsMachine parameter added (matching P1's AddUserToGroup/ApproveRiskException shape); a machine actor is now denied instead of exempted from the #169 self-permission-bundling check. Only server/http/handlers/rbac.go's direct AssignPermissionToRole handler needed the real isMachineActor(r) value threaded in -- CreateRole/UpdateRole already pre-authorize every permission via Authorize(ctx, userCtx.UserID, ...) before ever reaching this function, which already denied a machine actor (userID 0 has no roles), so those two callers keep actorIsMachine=false unchanged.",
	},
	"secret_acl.go:GrantSecretACL": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input -- denies every actorID==0 caller, human local-CLI included, so a machine actor is denied too.",
	},
	"secret_bulk_rename.go:BulkRenameSecrets": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input.",
	},
	"secret_extend_expiring.go:ExtendExpiringSecrets": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input.",
	},
	"secret_move.go:MoveSecret": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input.",
	},
	"secret_ownership.go:transferOwnership": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input.",
	},
	"secret_reassign_owner.go:ReassignOwnedSecrets": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input.",
	},
	"secret_suspend.go:SuspendProjectSecrets": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input.",
	},
	"secret_suspend.go:ResumeProjectSecrets": {
		class: classPerActorCeiling, status: statusEnforced,
		note: "rejects actorID==0 outright as invalid input.",
	},
}

// actorSentinelFuncRe matches a top-level function declaration and captures
// its name, with or without a method receiver.
var actorSentinelFuncRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\(`)

// actorSentinelCompareRe matches a real actorID==0/actorID!=0 comparison.
var actorSentinelCompareRe = regexp.MustCompile(`actorID\s*(==|!=)\s*0`)

// actualActorSentinelSites scans every non-test *.go file directly in
// internal/core (this package) and returns the set of "file:func" keys where
// a real (non-comment) actorID==0/actorID!=0 comparison appears.
func actualActorSentinelSites(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading internal/core: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		currentFunc := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := actorSentinelFuncRe.FindStringSubmatch(line); m != nil {
				currentFunc = m[1]
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // doc/inline comment mentioning the pattern, not a real branch
			}
			if actorSentinelCompareRe.MatchString(line) && currentFunc != "" {
				found[name+":"+currentFunc] = true
			}
		}
	}
	return found
}

// TestActorSentinelComparisonsAreAllowlisted is the completeness guard: every
// actorID==0/actorID!=0 comparison in internal/core's non-test source must be
// an EXACT match against actorSentinelAllowlist above -- no more, no less.
//
//   - A NEW comparison in a function not already listed fails this test
//     immediately, forcing the same real-reachability classification
//     (classPerActorCeiling + statusEnforced/statusOpenGap, or
//     classAuditOnly) this table was built from before it can be merged --
//     this is the "fifth instance" #1524's investigation warned would keep
//     recurring if each one is just patched in isolation.
//   - An allowlisted entry whose comparison no longer exists (the function
//     was fixed, removed, or rewritten to avoid the sentinel) also fails,
//     keeping the table from accumulating stale entries.
func TestActorSentinelComparisonsAreAllowlisted(t *testing.T) {
	t.Parallel()
	actual := actualActorSentinelSites(t)

	var missing []string
	for key := range actual {
		if _, ok := actorSentinelAllowlist[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)

	var stale []string
	for key := range actorSentinelAllowlist {
		if !actual[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	if len(missing) > 0 {
		t.Errorf("found %d actorID==0/actorID!=0 comparison(s) with NO entry in actorSentinelAllowlist "+
			"(internal/core/actor_sentinel_completeness_test.go): %v\n"+
			"Classify each as classAuditOnly (attribution metadata only) or classPerActorCeiling "+
			"(an authorization decision -- trace whether a machine actor, which also produces actorID==0, "+
			"can reach this branch, and if so whether the ceiling is actually enforced or silently skipped) "+
			"before merging.", len(missing), missing)
	}
	if len(stale) > 0 {
		t.Errorf("found %d actorSentinelAllowlist entr(y/ies) whose comparison no longer exists in source: %v\n"+
			"Remove these entries -- if this closed a statusOpenGap finding, confirm the tracking issue is "+
			"also resolved.", len(stale), stale)
	}
}

// TestActorSentinelOpenGapsAreTracked lists every classPerActorCeiling entry
// still at statusOpenGap, so the open count is visible in test output rather
// than buried in a table -- not a failure condition (open gaps are tracked
// via #1545, not blocked on this table), just a standing visibility check
// that fails if the open count silently grows without anyone noticing.
func TestActorSentinelOpenGapsAreTracked(t *testing.T) {
	t.Parallel()
	var open []string
	for key, e := range actorSentinelAllowlist {
		if e.class == classPerActorCeiling && e.status == statusOpenGap {
			open = append(open, key)
		}
	}
	sort.Strings(open)
	const knownOpen = 0 // #1545's two entries are resolved: AssignPermissionToRole fixed (statusEnforced),
	// BulkDeleteSecrets reasoned safe (statusReasonedSafe) -- see their notes above.
	if len(open) != knownOpen {
		t.Errorf("expected exactly %d statusOpenGap classPerActorCeiling entries (tracked via #1545), found %d: %v\n"+
			"A new open gap needs its own issue filed (see #1545's shape) before this count changes; a closed "+
			"gap needs its status flipped to statusEnforced in the same PR that fixes it.", knownOpen, len(open), open)
	}
}
