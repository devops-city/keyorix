# FINDING: vacuous-empty-collection and branch-restricted authority ceilings (F6 follow-on sweep)

**Date:** 2026-09-22 (branch `fix/system-proxy-sweep-g3`, based on `origin/main`
after #1968/#1969/#1970).
**Component:** `internal/core/authz.go` (`requireGranterHoldsRolePermissions`),
`internal/core/users.go` (`ValidateRoleGrantAuthority`),
`internal/core/membership_lifecycle.go` (`TransitionMembership`), 9
`server/http/handlers/*_proxy.go` call sites (machine-tagging fix),
`server/http/handlers/groups_proxy.go` (`AddGroupMemberProxy`/
`RemoveGroupMemberProxy`), `server/http/handlers/invitations_proxy.go`
(`CreateInvitationProxy`'s own baseline), and
`server/http/system_write_ceiling_walk_test.go` (the F6 allowlist).
**Status:** source-level fix landed; **8 of 8** probe-confirmed route gaps
closed (6 by the source fix alone; `AddGroupMemberProxy` and
`RemoveGroupMemberProxy` needed their own handler-level fix, landed here). 3
stale/false walk-allowlist entries corrected, plus a 4th reclassification
(`RemoveGroupMemberProxy` moved out of the allowlist into
`systemCeilingDenyChecked` now that it requires more than blanket
`system.write`). Full repo test suite green (`go build ./...`,
`go test ./internal/... ./server/... ./cmd/...`).

**Severity correction (2026-09-23), falsified against a live probe:** an
earlier pass of this PR claimed `AddGroupMemberProxy` was **Critical** — a
direct escalation to full `secrets.read`/`write`/`delete` via joining a
group already holding `editor`/`project_developer`. That claim is **false**,
confirmed by actually running the exact request (as both a human caller and
a machine relay) against unmodified `origin/main`, before any of this PR's
fixes, in an isolated worktree:
`validateGroupJoinRoles`'s per-grant loop already called
`requireGranterHoldsRolePermissions` for every grant a group holds, and that
function's pre-fix per-permission loop — run against `editor`'s real,
non-empty permission bundle — already refused a caller holding none of
those permissions. Both probes were refused pre-fix with the exact core
error `"cannot grant this role: you do not hold permission \"secrets.read\"
yourself"`; no membership was created; no secrets access resolved
afterward. The only real pre-fix defect in that exact scenario was a status
code: `AddGroupMemberProxy`'s error handling returned 500 `STORAGE_ERROR`
for a correctly-refused permission denial instead of 403, a minor,
unrelated API-contract issue. **Re-graded to Medium.** See the corrected
finding below and `server/http/group_editor_escalation_falsification_test.go`
for the committed regression test (proves the scenario stays refused
post-fix too, as defense in depth on top of the new unconditional check).
The fix itself is unchanged and still correct — it closes a real, narrower
gap (see below) — only the severity claim was wrong.

## Summary

The 13-route reconciliation against `origin/main` (this branch's earlier
message) found 8 routes where a caller-authority ceiling was reachable but
either absent or structurally skippable. Investigating the root cause instead
of patching each route individually found this is a **bug class**, not 8
unrelated bugs: two distinct shapes where a `Require*`/`Validate*` authority
check is written correctly for the common case but silently never runs for an
edge-case input, and a caller inherits whatever ceiling *should* have applied
by default instead of being refused.

**Shape (a) — empty-collection loop returns nil.** A check that walks a
collection (a role's own bundled permissions, a set of grants) and returns
`nil`/`true` only from inside the loop body never gets a chance to refuse
anything when the collection is empty — an attacker who can make the
collection empty (grant a permission-less role; supply a role-less request)
gets the same "nothing to check, so allowed" outcome a genuinely-safe empty
input would get, except here the caller's OWN authority was never verified at
all.

**Shape (b) — authority check nested in one branch of a state/kind switch.**
A function handling several legal transitions/kinds runs its authority check
only inside the branch someone thought to add it to (e.g. "activating a
membership is the dangerous case"), while sibling branches reach the exact
same underlying write with zero caller-authority check — gated only by
whatever *legality* check (is this transition allowed at all) happens to run
unconditionally. Legality is not authority; a reviewer skimming "the
state-machine check runs for every transition" can read that as blanket
safety when it isn't.

## Source-level fix

Per the explicit instruction to fix the vacuity at the source rather than
patch every call site: `requireGranterHoldsRolePermissions` (`authz.go`) now
requires a `roles.assign` baseline **before** the per-permission loop, via a
new `checkGranterHoldsPermission` helper shared with the loop body itself. The
per-permission loop was split into `requireGranterHoldsRolePermissionsNoBaseline`,
reserved for exactly one documented, principled exception:
`CreateUserWithAssignments`/`InviteGlobal`'s mandatory, non-discretionary
`system_viewer` default when no system role was explicitly requested (mirrors
plain `CreateUser`'s own unconditional auto-assign, gated by `users.write`
alone — not a second instance of the bug, a deliberate carve-out with its own
existing test coverage). `ValidateRoleGrantAuthority` (`users.go`) got the
identical `users.write`-baseline treatment for the analogous grant-set shape.
`TransitionMembership` (`membership_lifecycle.go`) had its `roles.assign`
check moved from inside the `to==MembershipActive` branch to run
unconditionally before the transition switch, with the role-specific ceiling
for activation layered on top as before.

### Sweep table

Repo-wide sweep of every `Require*/Validate*/Authorize*` on `KeyorixCore` for
both shapes (`internal/core/*.go`, non-test):

| Function | Shape | Hit? | Verdict |
|---|---|---|---|
| `requireGranterHoldsRolePermissions`/`NoBaseline` | (a) | Yes | **Fixed** — baseline added |
| `ValidateRoleGrantAuthority` | (a) | Yes | **Fixed** — baseline added |
| `TransitionMembership` | (b) | Yes | **Fixed** — baseline moved outside `to==Active` |
| `validateGroupJoinRoles` | (a)-shaped | No — correct by design | Empty grants means the group confers nothing; the per-grant loop calling the now-fixed baseline closes the "group HAS grants" case. The gap here is a different one — see Still Open below. |
| `requireNoSoDViolation` + 4 siblings (`sod.go`) | (a)-shaped | No — different semantics | These detect forbidden PERMISSION PAIRS; empty input genuinely contains no pairs. Not an authority baseline being skipped. |
| `resolveAndAuthorizePermissions` (role-bundling, `handlers/rbac.go`) | (a)-shaped | No | Router-level `RequirePermission(roles.write)` gates both callers (`CreateRole`/`UpdateRole`) before this runs; no `/system` proxy bypasses it. |
| `requireGlobalAdminToReinstateAdminRoles` | (a)-shaped | No | Correctly no-ops only when the role SET contains no admin-tier role, not "empty means safe." |
| `TransitionMachineIdentity` | (b)-shaped | No core-level ceiling at all | Structurally different from `TransitionMembership`: relies entirely on router-level `RequireScopedPermission(roles.assign)` on its one caller route; the `/system` machine-transition proxy uses a separately-reviewed conditional-write path (`storage.TransitionMachineIdentityState` directly, not this function). Single point of trust, not a branch gap. |
| `InviteGlobal`/`CreateUserWithAssignments`'s `systemRole==""` branch | (b)-shaped | No | Both branches call an authority check (`NoBaseline` for the mandatory default, full baseline otherwise) — the principled exception above, not an unguarded sibling. |

## 8 probe-confirmed route gaps — re-run after the source fix

Each probe sends the request as a `system.write`-only caller (no
`roles.assign` anywhere) and asserts refusal + no state change.

| Route | Closed by source fix alone? | Status | Impact | Severity |
|---|---|---|---|---|
| `CreateInvitationProxy` | No — needed its own unconditional `roles.assign` baseline (the 3 per-field checks were each gated on that field being non-empty; all-empty skipped every one) | **Fixed** this branch | Plants a `pending` project-invitation row to an arbitrary email with zero authority. Acceptance cannot actually succeed: `inviteMemberWithMode` refuses an empty role (`"a project role is required"`), so no membership/privilege is ever granted — the account gets created, then the grant step fails and the invitation is left pending, not accepted. Bounded to invitation-list pollution and a plausible phishing vector (a real-looking pending invite to an arbitrary address), not privilege escalation. | **Medium** (state pollution / social-engineering surface, not escalation) |
| `UpdateAccessRequestProxy` (approve, no-secret/role-only branch) | **Yes** | Closed | Approving a role-only access request now requires `roles.assign` at the target project even when the suggested role bundles zero permissions. | **Medium-High** (pre-fix: any `system.write` caller could approve access-review-adjacent grants in any project) |
| `CreateAccessRequestApprovalProxy` (same branch) | **Yes** | Closed | Same mechanism, same fix. | **Medium-High** |
| `CreateMembershipProxy` | **Yes** (source fix) + machine-caller tagging fix | Closed | Creating a project membership with a permission-less role now requires `roles.assign` at the target project. | **Medium-High** |
| `TransitionMembershipProxy` | **Yes** (source fix) + machine-caller tagging fix | Closed | Every transition (not just `active`) now requires `roles.assign` at the membership's project — `active->revoked`, `provisioned->revoked`, `identity_verified->provisioned` previously had zero authority check, gated only by state-machine legality. An active membership carrying a zero-permission role grants no RBAC-checked capability on its own (permissions are resolved from the role's bundle, which is empty) — the exploitable value pre-fix was in the CEILING being skippable, not in what a zero-permission role itself confers. | **High** (any `system.write` caller could revoke/transition any project's memberships) |
| `CreateUserWithRoleGrantsProxy` | **Yes** (source fix) + machine-caller tagging fix | Closed | `ValidateRoleGrantAuthority` now requires `users.write` unconditionally. A new account created with empty/zero-permission grants can authenticate but holds no RBAC-checked capability anywhere (a "shell" account) — the exploit's real value pre-fix was bypassing the creator's own authority requirement, not minting a privileged account directly; a subsequent, separately-authorized role grant to that account is a normal, already-gated operation. | **Medium-High** |
| `AddGroupMemberProxy` | No | **Fixed** this branch | **Falsified and re-graded (2026-09-23):** an earlier pass of this review claimed this was reachable as a direct escalation to full `secrets.read`/`write`/`delete` via joining any group already holding `editor`/`project_developer` (the most powerful non-admin-tier default roles). That claim is FALSE — confirmed by actually running the request pre-fix (see the falsification note above). `validateGroupJoinRoles`'s per-grant loop already called `requireGranterHoldsRolePermissions` for every grant a group holds, and its per-permission loop already required the caller to hold each of `editor`'s real, non-empty bundled permissions — a `system.write`-only caller was already refused, both as a human and as an untagged machine relay, both times with `"cannot grant this role: you do not hold permission \"secrets.read\" yourself"`. The REAL, narrower gap: a group with NO role grants at all (`validateGroupJoinRoles`'s outer loop never runs) had no ceiling on this proxy, while the human-facing route requires `roles.assign` unconditionally even then (`RequirePermission(permRolesAssign)`, global scope, router.go) — an availability/parity gap (pre-positioning a membership before a later, separately-gated role grant), not a direct privilege grant. **Fix (unchanged, still correct):** added the same unconditional `roles.assign`-at-global-scope check the human-facing route already requires, via the existing `requireGroupsProxyRolesAssign` helper (already used by `RestoreGroupProxy` in the same file) — this is defense-in-depth on top of `validateGroupJoinRoles`'s own already-adequate per-grant check, not a fix for an escalation that never existed. | **Medium** (parity/pre-positioning gap on a role-less group, not escalation — corrected down from an erroneous Critical claim) |
| `RemoveGroupMemberProxy` | No | **Fixed** this branch | `core.RemoveUserFromGroup` has no actor-authority ceiling at all by design (target-state guards only, same "removal confers nothing" reasoning as `RemoveMachineRoleProxy`) — but the human-facing route still requires `roles.assign` at global scope unconditionally. Pre-fix, a `system.write`-only caller could silently detach any user from any group — including revoking that user's ONLY path to `secrets.read`/`write`/`delete` if the group holds `editor`/`project_developer`. Not privilege escalation (removal grants nothing), but a real, targeted denial capability: the removed member cannot self-recover, only re-adding them (which itself now requires `roles.assign`, closing the loop) restores the access. **Fix:** same `requireGroupsProxyRolesAssign` check, mirroring the human-facing route. | **Medium** (targeted, repeatable access-denial/tampering capability, not escalation — but real, live access is actually lost, not merely at-risk) |

## Walk allowlist corrections

`server/http/system_write_ceiling_walk_test.go`'s `systemCeilingAllowlist`
contained 3 entries whose prose no longer matched (or never fully matched)
the code:

1. **`POST /api/v1/system/invitations`** — claimed the per-field checks alone
   were sufficient; they were each gated on their own field being non-empty,
   so the all-empty case ran none of them. Corrected to describe the new
   unconditional baseline, cites `TestG3Probe_CreateInvitationProxy_SystemWriteOnly_CreatesRoleLessInvitation`.
2. **`PUT /api/v1/system/project-memberships/{id}/transition`** — described
   only the state-machine *legality* check as protection, which read as
   blanket safety but was never an authority claim; the real authority
   ceiling was `to==Active`-only pre-fix. Corrected to say so explicitly,
   cites `TestConformance_TransitionProjectMembershipState`.
3. **`POST /api/v1/system/project-memberships`** — the `roles.assign`
   re-derivation it cited was real for a human caller but unreachable for a
   genuine machine caller (missing `WithSelfMachineGranter` tagging).
   Corrected, cites `TestConformance_CreateProjectMembership`.
4. **`DELETE /api/v1/system/groups/{id}/members/{userId}`** (`RemoveGroupMemberProxy`)
   — was classified in `systemCeilingAllowlist` ("no ceiling, removal is the
   safe direction"). That reasoning is no longer true: this route now
   requires `roles.assign`, more than blanket `system.write`. Moved to
   `systemCeilingDenyChecked` (a dedicated `Test*` proving refusal —
   `TestG3Probe_RemoveGroupMemberProxy_SystemWriteOnly_RemovesMemberFromOrdinaryGroup`
   — is the walk's requirement for that bucket, already satisfied).
   `systemCeilingUnverifiedRatchet` lowered from 41 to 40 accordingly (one
   fewer `unverified` entry now that this route left the allowlist
   entirely).

## Allowlist verification schema (Step 3)

`systemCeilingAllowlist`'s value type changed from a bare `string` reason to
`systemCeilingAllowlistEntry{reason, test, unverified}`. Every remaining
entry (43, after `RemoveGroupMemberProxy` left the allowlist entirely — see
correction 4 above) sets exactly one of `test` (names a real `Test*` function
in the package, existence enforced by
`TestSystemCeilingAllowlistVerificationRatchet` via `go/parser` over the
package's own `*_test.go` files — a citation naming a function that doesn't
exist fails outright) or `unverified` (prose only, explicitly counted).
Current split: **3 verified, 40 unverified**. `systemCeilingUnverifiedRatchet
= 40` is the ceiling on the unverified count — a brand-new allowlist entry
cannot set `unverified` without either citing a real test or an existing
entry being converted to make room, since that would push the count over the
ratchet and fail the test. Red-proofed both failure modes directly (a fake
entry pushing the count over the ratchet; a `test:` citation naming a
nonexistent function) before removing the fake entry and confirming green.

The remaining 40 unverified entries are **not** converted on this branch — per
instruction, that's left to a future mixed-principal authority fuzzer (noted
in the walk file's own doc comment) rather than ~40 hand-written near-identical
tests. Each future conversion should lower `systemCeilingUnverifiedRatchet` by
one in the same commit.

## Second-order fix: machine-caller tagging gap (discovered via this sweep)

Fixing the source-level vacuity exposed that several `/system` proxy handlers
never tag `WithSelfMachineGranter` before calling into a now-baseline-checked
core function — for a genuine machine caller (not a relay), the baseline was
reachable but structurally unsatisfiable (`actorIsMachine` with no tag falls
through to an unconditional `false, nil` refusal in `checkGranterHoldsPermission`).
This is a false-refusal/availability defect for a legitimately-permissioned
machine caller, not an escalation — confirmed via each route's conceptually
equivalent, already-correctly-tagged core function (`InviteToProject`,
`ApproveAccessRequestWithExpiry`). Fixed in 9 handlers, each verified against
its own conformance test: `CreateInvitationProxy`, `UpdateAccessRequestProxy`,
`CreateAccessRequestApprovalProxy`, `TransitionMembershipProxy`,
`CreateMembershipProxy`, `CreateUserWithRoleGrantsProxy`,
`AssignRoleWithExpiryProxy`, `AssignRoleToGroupWithExpiryProxy`,
`AssignMachineRoleProxy`.

**Correction (2026-09-23, CI on this PR):** tagging `WithSelfMachineGranter`
in `/system` proxies was not purely an availability fix. A `/system` caller is,
at the auth layer, indistinguishable from a node credential relaying on behalf
of an unidentified downstream actor, and node credentials legitimately hold
admin-tier roles. `requireGranterHoldsRolePermissions`' own doc forbids this
tag in proxies for exactly that reason. With the tag, a node credential's own
`admin` role authorized admin-tier grants it was only relaying. Three existing
guard tests caught it in CI: `TestInvitationProxy_CreateRejectsProjectAdminRoleWithoutAuthority`,
`TestInvitationProxy_CreateRejectsGlobalSystemRoleWithoutAuthority` and
`TestMembershipProxy_CreateRejectsAdminRoleWithoutAuthority`.
Removing the tags wasn't an option either: every relayed grant then fails
closed (~24 remote-storage/conformance tests), because on `main` relays only
passed through the empty-role vacuity this sweep closed.

Resolution: the 9 proxies now use `core.WithSystemProxyMachineGranter`. It
resolves permissions against the machine exactly like `WithSelfMachineGranter`,
but `requireGranterHoldsRolePermissionsNoBaseline` refuses any admin-tier role
for it: a canonical admin name, or a bundle `roleIsAdminTier` classifies as
administrative (#1685). Non-admin grants relay as before. Admin-tier grants over
a relay fail closed, as they did on `main`. Regression:
`internal/core/authz_system_proxy_relay_ceiling_test.go` plus the three guard
tests above. All red-proofed by disabling the check.

## `actorID == 0 && !actorIsMachine` short-circuit reachability (investigated, not changed)

`requireGranterHoldsRolePermissions`/`requireGranterHoldsRolePermissionsNoBaseline`
both open with `if actorID == 0 && !actorIsMachine { return nil }` — the
documented "local CLI / trusted system pseudo-actor" exemption. If any
HTTP/gRPC path could reach either function with this exact condition while
representing a real, unresolved/attacker-controlled caller, that would be a
genuine bypass of the entire baseline+per-permission check landed in this
PR.

Traced all 16 call sites and their HTTP/gRPC callers. Verdict: **not
reachable**. Two load-bearing facts, both independently verified by direct
code read (not just traced by a subagent):

1. `actorID(r)` (`server/http/handlers/catalog.go`) returns `u.UserID` if a
   `UserContext` exists in the request context, else 0. `isMachineActor(r)`
   returns `false` when there is no context at all, matching `actorID(r)`'s
   0 in that same case — but `RequireScopedPermission`/`RequirePermission`
   (`server/middleware/auth.go`'s `requireUserAndCore`) reject with 401
   BEFORE calling the handler whenever `GetUserFromContext` returns nil.
   Every request that actually reaches an authenticated handler is
   therefore guaranteed to have a non-nil `UserContext` — the "no context"
   case `actorID(r)`'s 0 could otherwise represent is unreachable past the
   middleware.
2. Every `UserContext`/gRPC-interceptor-context construction site (4 total:
   HTTP session/PAT, HTTP machine, gRPC session/PAT, gRPC machine) sets
   `UserID`, `MachineIdentityID`, and `ActorType` together, consistently, at
   one location each — confirmed directly for the HTTP machine path
   (`machineUserContext`, `server/middleware/auth.go`): `UserID: 0,
   MachineIdentityID: &mid, ActorType: core.ActorTypeMachine` in the same
   struct literal. A human session can never produce `UserID==0`; a
   `UserID==0` context is always tagged machine.

Every call site's `actorIsMachine` argument is derived from the live
`isMachineActor(r)`/`ActorKind()` value at call time, not a hardcoded
literal (the one historical instance of that exact bug shape, #PM-006 in
`groups_members.go`, is already fixed). The only genuine
`actorID==0 && !actorIsMachine` occurrences are CLI-only
(`internal/cli/**`, an env-var-driven local-trust sentinel, never
network-reachable) or internal core-to-core calls using 0 as the documented
system pseudo-actor for startup/background processes. No code change made
— none needed.

## Verification

- Branch rebased onto current `origin/main` (fast-forwarded; no local commits
  existed to replay, so no conflict risk) before this final verification pass.
- `go build ./...`: clean.
- `go vet ./server/http/...`: clean.
- `go test ./server/http/...`: green, 0 failed, 0 unexpected skips.
- `go test ./internal/... ./server/... ./cmd/...`: green, 0 failed, full repo.
- All 9 G3 probe tests independently confirmed passing, including
  `TestG3Probe_AddGroupMemberProxy_SystemWriteOnly_AddsMemberToOrdinaryGroup`
  and `TestG3Probe_RemoveGroupMemberProxy_SystemWriteOnly_RemovesMemberFromOrdinaryGroup`
  (previously red, now fixed and green).
- `TestSystemCeilingAllowlistVerificationRatchet` red-proofed both ways
  (ratchet-exceeded, missing-test-citation) before landing green; logs
  "allowlist: 3 verified, 40 unverified (ratchet 40)".
- 7 test fixtures across `groups_s13_test.go`/`handlers_s23_test.go`/
  `handlers_s35_test.go`/`handlers_s11_test.go` needed the established
  repair (an authenticated actor holding the new ceiling's permission, or —
  for the two DB-error tests — migrated to the
  `TestRestoreGroupProxy_DBError_S35` SQL-trigger-isolation pattern so the
  500 is proven to come from the targeted write, not the new auth check).
- `TestGroupEditorEscalationFalsification_HumanCaller_Refused`/
  `_MachineRelay_Refused` (`server/http/group_editor_escalation_falsification_test.go`):
  the falsification regression tests, both green post-fix.

## Not yet done (for review before deciding next steps)

- Per-route commits (one per route, probe as regression test + control case) —
  everything above is currently uncommitted on this branch.
- The remaining 40 unverified allowlist entries (deferred to the fuzzer per
  instruction).
- `docs/security-closures.d/` rows — deferred to after merge, keyed to the
  merge SHA, per instruction (not part of this PR).
