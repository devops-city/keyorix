# FINDING: active-transition admin-rank ceiling and TOTP step-value bound

**Date:** 2026-09-23 (branch `fix/system-proxy-target-authority`, based on
current `origin/main`).
**Components:**
- `server/http/handlers/users_active_transition_proxy.go` (`UpdateUserIfActiveStateMatchesProxy`)
- `server/http/handlers/mfa_management_proxy.go` (`MarkTOTPStepUsedProxy`)
**Status:** Fixed, this branch.
**Severity:** High (admin-rank ceiling), Medium (TOTP step bound).

## Provenance note

This branch's worktree previously held 3 commits from 2026-09-20 addressing
related material. Reconciled against current `origin/main` before continuing:

- The first commit (`users.write` ceiling on this same route) is already
  landed, under a renamed primitive (`RequireUsersWriteAuthority`, folded
  into a broader transactional/panic-safety rewrite of `internal/core/users.go`
  — unrelated later work). Fully redundant; not reapplied.
- The second commit (a `docs/security-closures.d/` row for the above) is
  also fully redundant — `origin/main`'s own row for the same claim
  (`active-transition-proxy-users-write-001`) is already current.
- The third commit (admin-rank ceiling + TOTP step bound — THIS finding) was
  genuinely still needed: neither fix exists on `origin/main` today. Its
  exact diff could not be replayed via `git rebase` (too much surrounding
  code has changed — the panic-safety rewrite above, a `RemoveGroupMemberProxy`-shaped
  fix in a different handler, etc.), so this doc and its accompanying code
  are a fresh implementation against current `origin/main`, informed by the
  original commit's diff and design intent, not a mechanical replay.

## F5 (continued): active-transition proxy — `users.write` alone is not sufficient

`PUT /api/v1/system/users/{id}/active-transition` already requires
`users.write` at global scope (`active-transition-proxy-users-write-001`,
closed). That alone is not sufficient reason to trust a caller against
**every** possible target: a `users.write` holder with otherwise minimal
privilege could still rewrite a much higher-authority account's identity
(email, in particular) and pivot into taking it over via a password-reset
flow. The human-facing route has no equivalent extra ceiling either —
`PUT /api/v1/users/{id}` (`server/http/handlers/users_crud.go`) also gates
on `RequirePermission(permUsersWrite)` alone — but this `/system` proxy is
reachable by ANY `users.write` holder in the install, not just a genuine
admin, which is exactly the shape `core.RequireEqualOrGreaterAdminAuthority`
(the admin-rank ceiling `Impersonate` already applies) exists to close.

### Fix

`server/http/handlers/users_active_transition_proxy.go`:
`UpdateUserIfActiveStateMatchesProxy` now calls, immediately after the
existing `RequireUsersWriteAuthority` check and before any lookup or write:

```go
if err := h.coreService.RequireEqualOrGreaterAdminAuthority(r.Context(), humanActorID, uint(id), "modify"); err != nil {
    writeRemoteAPIError(w, http.StatusForbidden, "PERMISSION_DENIED", clientSafe(err))
    return
}
```

`RequireEqualOrGreaterAdminAuthority` (`internal/core/users.go`) already
exists on `origin/main` — the `/system-proxy-layer` export of
`requireEqualOrGreaterAdminAuthority` (`authz.go`), the same primitive
`Impersonate` uses: the actor must hold every permission the target holds,
at every scope, or be refused. Derived from the target's own effective
privileges, not a fixed threshold. This route is its first caller.

This check is inherently a **human** decision:
`requireEqualOrGreaterAdminAuthority` resolves USER role grants only
(`Authorize`/`scopedRoleIDs`), never a machine identity's. The handler
passes `humanActorID` (captured from `actorID(r)`, 0 for a machine caller
per ADR-030 — a machine identity has no `UserID`) — deliberately NOT
`requestActorKindAndID(r)`'s `principalID` (which resolves to the machine
identity's own row ID for a machine caller; feeding that into a human-only,
user-ID-keyed lookup risks misresolving it against an unrelated real user by
ID collision). `actorID(r)` had to be captured into a separate variable
BEFORE `requestActorKindAndID(r)`'s own `actorType, actorID := ...`
declaration in the same function — that assignment shadows the package-level
`actorID` function for the rest of the function body.

`actorID` 0 correctly refuses whenever the target holds ANY permission at
ANY scope, and passes through unaffected when the target holds none — an
ordinary, unprivileged user has nothing this ceiling exists to protect, so a
routine profile edit for one (relayed by a machine-authenticated downstream
node, the normal `storage.type: remote` topology) is unaffected.

### Regression tests

`server/http/active_transition_admin_rank_ceiling_test.go` (new file; the
base `system.write`-only refusal is already covered by the existing
`TestUpdateUserIfActiveStateMatchesProxy_SystemWriteOnly_CannotRewriteAdminEmail`):

- `TestActiveTransitionProxy_UsersWriteHolder_CanUpdateNonAdminUser_RealServer`
  — control: a principal holding `system.write` + `users.write` can still
  successfully update an ORDINARY, unprivileged user. Proves the admin-rank
  ceiling is an added restriction, not an accidental blanket refusal. The
  target is created via a direct storage insert, not `core.CreateUser`
  (which auto-assigns the `system_viewer` baseline role, which would make
  this test also exercise the ceiling it's meant to isolate from).
- `TestActiveTransitionProxy_UsersWriteHolderWithoutAdminRank_CannotRewriteAdmin_RealServer`
  — the ceiling's own regression: the same legitimate caller from the
  control test, now targeting the seeded admin, is refused. Asserts the
  effect (403, admin email unchanged), not just an error return.
- `TestActiveTransitionProxy_Admin_CanRewriteAdmin_RealServer` — control: an
  actual admin-tier caller can still use the route against a privileged
  target — the ceiling restricts lesser-privilege callers, not every caller
  touching any privileged user.

### Red/green

Temporarily replaced the `RequireEqualOrGreaterAdminAuthority` call site
with a no-op and re-ran `...WithoutAdminRank_CannotRewriteAdmin_RealServer`:
fails (200, admin email actually changes). Restored: passes. Full
`server/http/...` suite (5427 tests) passes with the fix applied, including
all other active-transition tests — no fixture fallout beyond what this
finding's own new tests need.

## F6: `MarkTOTPStepUsedProxy` had no bound on the step value

`POST /api/v1/system/mfa/totp-step-used` persists `MFASecret.LastUsedStep`,
the anti-replay counter TOTP verification checks on every login
(`LocalStorage.MarkTOTPStepUsed`'s conditional `WHERE (last_used_step IS
NULL OR last_used_step < ?)`). The legitimate producer of a step value,
`core.validateTOTPStep` (`internal/core/mfa.go`), only ever returns a step
within 1 period (30s) of the CALLING server's own clock.

Before this fix, the proxy accepted `step` verbatim off the wire with no
bound at all. A caller reaching this route (per its own doc comment, a
caller-scoping fix restricting this route to self-only was attempted and
reverted — the real caller shape is a machine/node credential relaying an
already-verified TOTP check for an arbitrary human's `user_id`, so a
`system.write`-only caller reaching this route unrestricted is accepted as a
known, low-severity, currently-unfixable-without-breaking-the-relay-shape
gap) could set `step` to an arbitrary, far-future value — permanently
advancing `LastUsedStep` past every value a genuine future TOTP code could
ever produce. Every subsequent real code for that user would then always
look like a replay (`last_used_step < ?` never true again), permanently
locking that user out of TOTP login — not "one step blocked" as a first read
of the route might suggest, but an unrecoverable-without-admin-intervention
denial of service against a specific target's second factor.

### Fix

`server/http/handlers/mfa_management_proxy.go`: `MarkTOTPStepUsedProxy` now
rejects (400 `INVALID_BODY`) any `step` more than `maxTOTPStepClockSkew` (20
periods, ~10 minutes) from this server's own clock, before calling
`storage.MarkTOTPStepUsed` at all. The window is generously wider than the
±1-period window a genuine caller's `step` value could ever actually carry,
purely to tolerate real clock skew between two different servers — not to
legitimize a value an honest caller would ever send. `totpStepPeriodSeconds`
(30s) duplicates `internal/core/mfa.go`'s unexported `totpPeriod` rather than
importing it (this package must not reach into core internals for a
constant); a drift between the two is self-limiting (this route would only
ever reject legitimate requests more aggressively, never accept a wider
window than intended).

### Regression tests

`server/http/handlers/mfa_management_marktotp_test.go` (existing file):
- New: `TestMarkTOTPStepUsedProxy_StepFarInFuture_Rejected` — a step
  1,000,000 periods in the future is refused (400), and the target's
  `MFASecret.LastUsedStep` is confirmed untouched (nil) — asserting the
  effect (the counter was never poisoned), not just the status code.
- The five pre-existing tests in this file used a tiny hardcoded `step: 5`,
  which the new bound would now reject as "far from now" before ever
  reaching the behavior each test actually exercises (a coverage-gap premise
  the bound check exposed, not a weakening) — updated to a `nowTOTPStep(t)`
  helper deriving a realistic near-now step value, keeping each test's real
  subject (bad JSON, missing user ID, storage error, fresh vs. replayed
  step) intact.
- `server/http/remote_storage_conformance_tranche4_auth_security_test.go`'s
  `TestConformance_MarkTOTPStepUsed`: its `+100`-step margin (chosen
  arbitrarily, well before this bound existed, purely to be "obviously
  greater than the baseline") exceeded the new window and would have been
  rejected; narrowed to `+2`, which stays well inside the window while still
  being strictly greater than the enrolled baseline — the only property this
  test's local-vs-remote parity check actually needs.

### Red/green

Temporarily short-circuited `totpStepBoundsOK` to `return true` and re-ran
`TestMarkTOTPStepUsedProxy_StepFarInFuture_Rejected`: fails (200, and
`LastUsedStep` is poisoned to the far-future value). Restored: passes. Full
`server/http/...` suite passes with the fix applied, including the
TOTP/MFA conformance tests.

## Verification

- `go build ./...`: clean.
- `go test ./server/http/...`: 5427 passed, 0 failed, full package.
- Both fixes independently red/green-verified by hand (see above).
