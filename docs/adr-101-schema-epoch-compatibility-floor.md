# ADR-101: Schema-epoch compatibility floor (replaces monotonic-epoch refusal)

## Status

**Implemented (2026-10-03, #2502).** `minCompatibleSchemaEpoch` / system_metadata key
`schema_min_compatible_epoch` in `internal/storage/factory.go`; see INV-STORAGE-04 in
`internal/storage/INVARIANTS.md` for the guards. Two points the text below leaves open were
resolved with the stricter reading: (1) a database whose `schema_epoch` is newer than the
binary but which has **no** floor recorded keeps ADR-097's unconditional refusal (absence of a
compatibility claim is not a claim); (2) the stored epoch and floor are only ever raised, never
lowered, by `recordSchemaEpoch`, so an older binary the floor lets start cannot stamp the
database back down. `admin restore` keeps the strict rule, since a backup manifest carries no
floor. The remainder of this document is the original design record.

**Accepted — deferred (2026-09-04).** This is a design decision for a fix that has
not been implemented yet. It must land **before `currentSchemaEpoch`
(`internal/storage/factory.go`) is first bumped past 1** (it is now 5: 2 for `secret_nodes.purge_at`, with the floor raised to 2 because an epoch-1 binary does not maintain the column and a stale date could purge early, see ADR-032's amendment; 3 for the additive `pending_audit_events` table together with the v2 audit retention anchor and `secret_nodes.suspend_clear_synced_copies` (one epoch, no release shipped between them), with the floor raised to 3 because an epoch-2 binary misreads the v2 anchor and never writes the suspend-clear column (#3359, #3362); 4 for `machine_identities.cascade_suspended_project_id/_at` (#3433), floor unchanged at 3 because an epoch-3 binary leaves the identities suspended on restore, which fails closed; 5 for the degraded break-glass columns (BREAKGLASS-OWED-1), floor unchanged at 3 because an epoch-4 binary leaves them at their "not degraded" defaults and still drains the owed rows; the floor mechanism itself is implemented, see the status note above) — see
Trigger below. A test enforces this (`TestCurrentSchemaEpoch_Is5_SeeADR101` /
`internal/storage/schema_epoch_tripwire_test.go`); its failure message points here.

Until this lands, ADR-097's guard stays exactly as it is: a hard, unconditional
refusal whenever the database's recorded epoch exceeds the binary's. That refusal
is deliberately NOT weakened by this ADR — see "What this ADR does not do" below.

## Context

Part 2 continuation of the adversarial-review campaign (#1674) found that ADR-097's
guard (`checkSchemaEpoch`, `internal/storage/factory.go:484`) cannot distinguish two
situations that look identical from inside a single process:

- **(a) An ordinary rolling upgrade.** A sibling replica has already migrated to a
  new schema epoch and committed it to the shared database
  (`recordSchemaEpoch`). This pod is still running the old binary and needs an
  unrelated restart (OOMKill, node eviction, liveness-probe failure — not
  necessarily "its turn" in any deliberate rollout order). It sees a newer epoch
  than it knows and refuses to start, even though nothing was actually downgraded.
- **(b) A genuine downgrade.** An operator rolled back to an older release while
  pointing at the same, already-migrated database — the exact case ADR-097 exists
  to catch.

Both produce the identical observable state: `dbEpoch > currentSchemaEpoch`. No
data available inside `checkSchemaEpoch` — not a timestamp, not a retry count —
distinguishes them, because both are, structurally, "this binary is older than
whatever last wrote schema_epoch." ADR-039 (accepted) documents multi-replica,
shared-Postgres deployment as a supported HA topology; #1674 confirmed ADR-097's own
"What this does not solve" section never mentions replicas, rollout, or HA at all —
the guard's threat model was written from a single-instance-operator-rollback
perspective and the multi-replica case wasn't considered.

`currentSchemaEpoch` is still `1` today (confirmed at investigation time) — no
migration has bumped it since ADR-097 shipped, so this condition has never actually
fired in production. That is what makes this the right moment to fix the mechanism
rather than patch the symptom: there is no live incident pressure pushing toward a
quick, wrong answer.

## Decision

**Replace the monotonic epoch-refusal with a declared compatibility floor.**

Today, `checkSchemaEpoch` infers "can this binary safely run against this schema?"
from the *direction* of a version comparison. That conflates two different
questions:

1. Did the schema change since this binary was built? (Answered by the epoch
   today, correctly.)
2. **Can an older binary safely run against the resulting schema?** (NOT answered
   by the epoch — the epoch's monotonic refusal assumes the answer is always "no,"
   for every past migration, forever.)

ADR-097's own Context section already established that most migrations to date are
additive and safe in the old-binary-reads-new-schema direction (the DEFAULT-value
tracing it did for `bypasses_permission_checks`, `environment_id`,
`classification`, and the audit hash chain). The monotonic epoch throws that
analysis away at enforcement time and refuses ANY older binary against ANY newer
epoch, safe or not.

**The fix: each migration that bumps the epoch also declares the minimum binary
version (or epoch) that may run against the schema it produces** — a
`minCompatibleEpoch` (or equivalent) recorded alongside `schema_epoch` in
`system_metadata`, set by the migration author at the point they already have to
reason about default-direction safety (ADR-097's own "still a human judgment call"
acknowledgment). `checkSchemaEpoch` then asserts `currentSchemaEpoch >=
minCompatibleEpoch` — a real compatibility claim the migration author stated, not an
inference from which direction a number moved.

Consequences of this shape:
- A migration that's additive-and-safe (the common case, per ADR-097's own
  investigation) declares `minCompatibleEpoch` unchanged — old replicas satisfy the
  check and boot normally mid-rollout. No CrashLoopBackOff for the common case.
- A migration that genuinely breaks old-binary compatibility (the rare case ADR-097
  was actually trying to catch) raises `minCompatibleEpoch` to itself — old
  replicas correctly refuse, exactly as today, but now because the schema
  genuinely isn't safe for them, not because a number went up for an unrelated
  reason.
- Rollback becomes safe by construction for the additive case: rolling back one
  release lands on a binary whose epoch is still `>= minCompatibleEpoch`, so it
  runs. The dangerous rollback (rolling back past the actual compatibility floor)
  still refuses — correctly, because that's the real unsafe case.

This does not eliminate every refusal — it eliminates the refusals that were never
actually warranted, and keeps the ones that are.

## What this ADR does not do

**It does not modify `checkSchemaEpoch`'s current behavior.** The guard implemented
under ADR-097 continues to hard-refuse on any `dbEpoch > currentSchemaEpoch` exactly
as before. This ADR is a design record for the *next* schema-epoch-bumping change to
implement, not a change to the guard itself. See #1674's own investigation and
Rejected alternatives below for why nothing in this repo weakens the existing
refusal in the meantime.

## Rejected alternatives (from #1674's investigation — recorded so a future
session doesn't "helpfully" re-propose one of these)

- **Time-based grace window.** If the newer epoch was recorded within the last N
  minutes, warn and proceed instead of refusing. **Rejected: this fails open on the
  most likely real downgrade there is.** Deploy v2, it migrates and bumps the epoch,
  v2 turns out bad, the operator rolls back to v1 — fifteen minutes later, which is
  when rollbacks actually happen. v1 sees a recently-recorded newer epoch, the
  window says "probably still rolling out," and it runs against v2's schema
  anyway — the window permits the dangerous case and refuses the harmless one. A
  window sized to survive real rollout durations is, by construction, also sized to
  survive real rollback timing.
- **Exactly-one-epoch (N+1) tolerance.** Allow `dbEpoch == currentSchemaEpoch + 1`
  through with a warning; refuse only at 2+. **Rejected: this permanently legalizes
  the single-version downgrade, which is the normal rollback shape** — it doesn't
  narrow the dangerous case, it just moves the boundary by one and calls the most
  common rollback safe by fiat, with no actual compatibility claim behind that
  safety.
- **In-process retry-with-backoff before refusing.** Retry `checkSchemaEpoch` a few
  times over 1-2 minutes before failing, to ride out a same-second race with a
  sibling's migration commit. **Rejected: this reimplements Kubernetes'
  CrashLoopBackOff inside the process, where the operator can't see it** — it adds
  a second, invisible retry policy on top of the orchestrator's own, without adding
  any actual information the orchestrator-level retry doesn't already have access
  to (via pod status, events, restart counts).
- **The shared premise all three share, and why it's the actual reason they're
  rejected, not just each one's specific flaw:** "old replica mid-rollout" and
  "operator deliberately downgraded" are the same observable state from inside the
  process. Any arithmetic on a timestamp or a retry count is a guess dressed as a
  distinction, not an actual distinction. The compatibility-floor design above is
  the only one of the options considered that resolves this by adding a real fact
  (an explicit, author-declared compatibility claim) instead of inferring one from
  data that doesn't contain it.

## Trigger

**This must land before `currentSchemaEpoch` is bumped past 1.** After the first
bump under the current monotonic-refusal mechanism, an old replica's refusal
becomes a live, real event for the first time — retrofitting the compatibility-floor
design at that point means migrating the migration guard itself while replicas may
already be running with the old semantics, a strictly harder and riskier change
than doing it now, while the mechanism has never fired. `internal/storage/
schema_epoch_tripwire_test.go` enforces this: it fails with a message naming this
ADR the moment anyone raises `currentSchemaEpoch` above `1`, so whoever authors that
change meets this decision at the moment it matters, not by having to already know
to go looking for it.

## Consequences

- A future PR implementing this must extend `system_metadata`'s schema-epoch
  bookkeeping (or add a sibling key) to carry `minCompatibleEpoch`, update
  `recordSchemaEpoch` to write it, and update `checkSchemaEpoch`'s comparison — a
  real, scoped follow-up, not implemented by this ADR.
- Every future migration author must explicitly reason about and declare
  `minCompatibleEpoch`, not just bump `currentSchemaEpoch` — slightly more
  friction per migration, in exchange for the refusal only firing when it's
  actually warranted.
- This ADR does not change anything about the legacy `migrations/*.down.sql`
  files, `#1679`, or any other open finding — scoped strictly to the schema-epoch
  mechanism ADR-097 introduced.
