# Check-then-act inventory (GUARD-2)

GUARD-2's brief (QA-1 report, pattern #3): find every security-relevant decision in
`internal/core` (and any `server/` path that bypasses it) that reads some current state,
decides based on that read, then writes — and verify the read-decide-write sequence is
serialized **across replicas**, not just within one process. A decision serialized only by an
in-process `sync.Mutex` passes on a single instance and in every unit test (SQLite is
inherently single-connection), and fails silently the moment two replicas of an HA
deployment (ADR-039) each take the request.

This is item 1 of GUARD-2's brief (spec first). The other items it feeds: a reusable
cross-replica race-test harness (`internal/core/concurrency_race_harness_test.go`), a
structural AST guard enforcing this rule on new code going forward
(`internal/core/guards/check_then_act_lock_guard_test.go`, exemptions in
`docs/check-then-act-lock-exempt.tsv`), and CI wiring so every pg-gated test in this family
actually runs against real Postgres on a PR touching `internal/core`/`internal/storage`, not
just on `merge_group`/`ci:full` (`.github/workflows/pg-race-tests.yml`). The invariant itself
is recorded as `internal/core/INVARIANTS.md`'s INV-CORE-41.

Scope: `internal/core`, cross-referenced against `internal/storage/store`'s own row-lock /
conditional-update primitives where the real serialization lives one layer down. Built by
reading every file in internal/core's own authz/state-transition surface directly (sod.go,
account_state.go, scim.go, rbac_management.go, jit_access.go, break_glass.go,
access_review*.go, invitations.go, machine_token.go, webauthn.go, login_lockout.go,
secret_dependencies.go, membership_lifecycle.go, setup_*.go, rbac_roles.go) plus the existing
`concurrency_*_postgres_test.go` / `cross_replica_ops_fuzz_test.go` test files, which is where
most of this bug class's prior closures (#1646, #1780, #1955, #2352, #344, #419) already live
and document their own reasoning in-code.

**Headline finding: this codebase is considerably more hardened against this bug class than
a fresh sweep usually finds.** Roughly a dozen decisions were already closed by a prior
session (mostly #1646's own aftermath) with the correct primitive — `storage.WithNamedLock`
keyed per contended principal, a `SELECT ... FOR UPDATE` inside a real transaction, or a
DB-level conditional `UPDATE ... WHERE state = X`/unique constraint. Two gaps were found that
hadn't been: one fixed in this same PR series (machine-identity SoD grant, no lock of any
kind), one already self-documented in-code as a deliberately deferred follow-up (SCIM
last-admin deactivation, in-process mutex only) — see Items 2 and 3 below for both.

## Table

Legend for "Serialization": **NONE** = no serialization of any kind; **IN-PROCESS** = a
`sync.Mutex`/similar, not cross-replica-safe; **NAMED-LOCK** = `storage.WithNamedLock`
(Postgres advisory lock, cross-replica); **ROW-LOCK** = `SELECT ... FOR UPDATE` inside a real
transaction (cross-replica on Postgres, no-op outside one); **COND-UPDATE** = a DB-level
conditional `UPDATE`/unique-constraint that makes the decision atomic with the write
regardless of locking.

| # | Decision | File:line (check / write) | Serialization | Correct lock key (if gap) | pg-gated test |
|---|---|---|---|---|---|
| 1 | Last-admin deactivation — direct API (`SuspendUser`/`UpdateUser`/`DeleteUser`) | account_state.go:209, users.go:584,802 | NAMED-LOCK (`lastAdminGuardLockKey`) | n/a — closed | y (`concurrency_2352_lastadmin_guard_sweep_postgres_test.go`, `concurrency_remove_user_role_project_postgres_test.go`) |
| 2 | Last-admin deactivation — SCIM (`UpdateSCIMUser`, `DeprovisionSCIMUser`) | scim.go:255-269, scim.go:505-515 | **IN-PROCESS only** (`accountStateMu`) — self-documented gap, scim.go:422-435 | `lastAdminGuardLockKey` (same key as #1, not a new one) | **n — being added this PR series** |
| 3 | SoD preventive check — user role grant (`AssignUserRole`) | rbac_management.go:536-556 | NAMED-LOCK (`sodGrantLockKey("user", userID)`) | n/a — closed | y (`concurrency_sod_grant_postgres_test.go`) |
| 4 | SoD preventive check — group role grant (`AssignRoleToGroup`) + member-side cross-check | rbac_management.go:218-221, 460-520 | NAMED-LOCK (`sodGrantLockKey("group", groupID)` + ordered per-member `sodGrantLockKey("user", id)`) | n/a — closed | y (`concurrency_sod_group_grant_postgres_test.go`) |
| 5 | SoD preventive check — machine identity role grant (`AssignMachineRole`) | machine_token.go:429-448, sod.go:752-792 | **was NONE at all** — fixed this PR series | `sodGrantLockKey("machine", machineID)` (mirrors #3/#4) | **y — added this PR series** (`concurrency_sod_machine_grant_postgres_test.go`) |
| 6 | Dual-control / M-of-K access-request approval | invitations.go:680-700, access_review_revoke.go | NAMED-LOCK (`dualControlLockKey(requestID)`) | n/a — closed | y (`concurrency_dual_control_approval_postgres_test.go`, `concurrency_dual_control_subthreshold_postgres_test.go`) |
| 7 | Access-review item decision (attest vs. revoke) | access_review_campaign.go (`claimItemDecision`) | COND-UPDATE (`WHERE decision = 'pending'`) | n/a — closed | y (`concurrency_access_review_decision_postgres_test.go`) |
| 8 | Access-review campaign close vs. in-flight decision | access_review_campaign.go (`CloseAccessReviewCampaign`) | COND-UPDATE (`WHERE state = 'open'`) | n/a — closed | y (same file as #7) |
| 9 | Break-glass activation vs. project-admin-count guard | break_glass.go:330-355 | NAMED-LOCK (`projectAdminGuardLockKey(projectID)`) + partial unique index (`(project_id,user_id) WHERE state='active'`) | n/a — closed | y (`concurrency_break_glass_project_postgres_test.go`) |
| 10 | Project-scope last-admin guard (`SetProjectMemberRole`/`RemoveProjectMember`, cross-path with `DeleteGroup`) | project_members.go:72-144,425-462 | NAMED-LOCK (`projectAdminGuardLockKey`) | n/a — closed | y (`concurrency_remove_user_role_project_postgres_test.go`, `concurrency_2352_lastadmin_guard_sweep_postgres_test.go`) |
| 11 | Install-wide bootstrap (exactly one admin on first boot) | auth_bootstrap.go | NAMED-LOCK (`WithBootstrapLock`, Postgres advisory) | n/a — closed | y (`concurrency_bootstrap_cross_replica_postgres_test.go`) |
| 12 | Machine-identity state transition (e.g. `suspended`→`revoked` vs. `suspended`→`active`) | machine_identities.go (`TransitionMachineIdentity`) | ROW-LOCK (`LockMachineIdentityForUpdate`) + `canTransitionMachine` gate, invariant is "revoked always wins", not "exactly one write" | n/a — closed | y (`concurrency_row_lock_sites_postgres_test.go`) |
| 13 | Failed-login counter (lockout) read-modify-write | login_lockout.go (`recordFailedLogin`) | ROW-LOCK (`LockUserForUpdate`) inside `WithTransaction`, sharded in-process `loginFailureMu` as fast path | n/a — closed | y (`concurrency_row_lock_sites_postgres_test.go`) |
| 14 | Dynamic-secret-config name uniqueness under concurrent create | dynamic_secrets.go | COND-UPDATE (real DB unique index `uniq_dynamic_secret_configs_project_env_name`, production migration) | n/a — closed | y (`cross_replica_ops_fuzz_test.go`, oracle a) |
| 15 | Secret rotation — no lost update across replicas | secrets.go:51 (`RotateSecret`) | NAMED-LOCK (`storage.EnvironmentSecretGuardLockKey`) + unique index on `(secret_node_id, version_number)` | n/a — closed | y (`cross_replica_ops_fuzz_test.go`, oracle c) |
| 16 | Session / PAT / machine-token revoke honored on the very next read | account_sessions.go, pat.go, machine_token.go | COND-UPDATE (plain `WHERE id=?` revoke write) + no caching at the core layer, so Postgres READ COMMITTED alone gives the bound | n/a — closed (bound is "0 staleness", verified by linearizability check, not a TTL) | y (`cross_replica_ops_fuzz_test.go`, oracle b) |
| 17 | Secret-dependency exclusive creation (cycle prevention) | secret_dependencies.go (`CreateSecretDependencyExclusive`) | COND-UPDATE (one atomic storage call) + in-process `secretDependencyMu` for the common case | n/a — closed | y (existing dependency tests; not re-verified in this pass, flagged in #4 below if gap found) |
| 18 | Membership lifecycle state transition + duplicate-active-membership | membership_lifecycle.go (`TransitionProjectMembershipState`) | COND-UPDATE + DB partial unique index | n/a — closed | — (not independently re-verified this pass) |
| 19 | Setup/invite token single-use consumption | setup_consume.go (`MarkSetupTokenConsumed`) | COND-UPDATE (atomic conditional update) | n/a — closed | — (not independently re-verified this pass) |

### Checked, no security-invariant finding (check-then-act exists, but worst case is availability/UX, not a bypass)

These have a read-then-write shape but the audit explicitly concluded the worst case under a
race is a harmless duplicate, a double-delete error, a rate-limit miss, or a fail-closed
lockout — not a privilege/security-invariant bypass. Listed so "not in the table above" reads
as "checked, found benign" rather than "not looked at":

- **MFA enroll/disable/step-up consume** (mfa.go, mfa_stepup.go): every consume path
  (`MarkTOTPStepUsed`, `ConsumeMFAChallenge`, `ConsumeMFARecoveryCode`,
  `ConsumeMFAStepUpGrant`) is an atomic conditional update already.
- **PAT issue/revoke/expiry** (pat.go, pat_hygiene.go, pat_expiry_enforce.go): revoke/create
  are idempotent; no "last/count" invariant exists on a PAT.
- **Secret sharing accept/revoke** (group_sharing.go, sharing.go, sharing_validation.go): plain
  CRUD, no "last/count" invariant; worst case is a harmless duplicate or a double-delete error.
- **Invitation accept vs. duplicate-pending-request** (invitations.go
  `RequestProjectAccess`): check-then-act, but it's flood-prevention, not a security gate.
- **Setup-token resend throttle** (`checkResendThrottle`): check-then-act, but an abuse
  rate-limit, not a security invariant.
- **WebAuthn last-credential delete**: a concurrent delete of the last two credentials can
  leave `WebAuthnEnabled=true` with 0 credentials — fails closed (produces a lockout, not a
  bypass); an availability bug, not in scope for this inventory's bypass-focused brief.
- **Role delete orphan-row race** (rbac_roles.go `DeleteRole`): documented as inert — role-ID
  reuse is not possible, so a residual orphan row cannot be reattributed to a different role.

## Items found and their status

### Item A — `AssignMachineRole` SoD check had NO serialization at all (fixed this PR series)

`machine_token.go:429` (`AssignMachineRole`) calls `requireMachineGrantNoSoDViolation`
(sod.go:752) then `storage.AssignMachineRole` directly — no `WithNamedLock`, not even an
in-process mutex, unlike the identical pattern for users (`AssignUserRole`,
`sodGrantLockKey("user", ...)`) and groups (`AssignRoleToGroup`,
`sodGrantLockKey("group", ...)`). Two concurrent grants of two individually-clean roles to the
same machine identity could each pass the check against a stale pre-grant permission set and
both commit, jointly completing a toxic SoD pair on a machine credential — the same shape as
#1646, just on the one principal type that pattern never reached.

**Fixed**: wrapped the check+write in `storage.WithNamedLock(ctx,
sodGrantLockKey("machine", machineID), ...)`, mirroring `AssignUserRole` exactly. Regression
test: `TestConcurrency_AssignMachineRole_CrossReplicaPostgres_SoDBypass`
(concurrency_sod_machine_grant_postgres_test.go), using the new
`raceReplicas` harness (concurrency_race_harness_test.go, Item 2 of this spec). Red/green
proof: 10/10 runs against real Postgres reproduce the bypass with the lock removed; 10/10 pass
with it in place. See the fix PR body for both outputs.

### Item B — SCIM last-admin-deactivation races are cross-replica-unsafe (open, next PR)

`scim.go:262` (`UpdateSCIMUser`) and `scim.go:510` (`DeprovisionSCIMUser`) both call
`guardLastAdminDeactivation` then their deactivating write, serialized only by
`c.accountStateMu` — an in-process `sync.Mutex`. The direct human-facing API path
(`SuspendUser`/`UpdateUser`/`DeleteUser`) already wraps the identical sequence in
`storage.WithNamedLock(ctx, lastAdminGuardLockKey, ...)`. The code's own comment
(scim.go:422-435) names this exact gap and says it was deliberately deferred ("their larger,
more deeply nested transaction bodies made a safe mechanical WithNamedLock wrap higher-risk to
land alongside the direct-API fix within the same change") rather than silently carried
forward as already covered.

**Status**: real, live-reproducible (two concurrent SCIM deactivations of two different
admins, routed to two different HA replicas, is a realistic IdP-sync topology — a load
balancer routing two concurrent `PATCH /scim/v2/Users/{id}` calls to two different server
instances). Closed in a follow-up PR in this series (see the GUARD-2 PR table) by swapping
`accountStateMu.Lock()` for `storage.WithNamedLock(ctx, lastAdminGuardLockKey, ...)` wrapping
the guard+write in both functions, keeping `accountStateMu` nested inside (unchanged
in-process fast path / #344 clobber protection), matching `SuspendUser`'s existing
lock-nesting order exactly (already proven safe in production: `setAccountState` takes
`accountStateMu` from inside `WithNamedLock`'s closure today).

## Not independently re-verified this pass

Rows 17-19 in the table above, and anything under `server/` that calls into `internal/core`
for one of these decisions rather than bypassing it (no bypass path was found for any of
these — every write in rows 1-16 above funnels through the `internal/core` function named,
confirmed by grepping for direct `storage.*` writes to the same tables outside
`internal/core`), are carried forward from the existing in-repo test suite's own
documentation rather than freshly re-read line-by-line in this pass. Flagged here rather than
silently presented as equally fresh — if a future pass finds one of these three is actually
a gap, it was missed by inventory, not contradicted by it.
