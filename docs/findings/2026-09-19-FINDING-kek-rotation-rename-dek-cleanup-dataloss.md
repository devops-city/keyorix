# FINDING: KEK-rotation's rename-dek error cleanup can destroy the only DEK recovery path

**Date:** 2026-09-19 (reachability detail + severity acceptance added
2026-09-19, same-day review; **fixed** 2026-09-19 on
`fix/kek-rename-dek-verify-before-cleanup`, branched off the fuzzer branch)
**Component:** `internal/encryption/keymanager_kek_rotation.go` (`commitNewKEKFiles`)
**Status:** **Fixed.** `dekRenameActuallySucceeded` (added in the fix commit)
verifies the actual on-disk DEK content before any rename-dek error cleanup —
see "Fix implemented" below for exactly what landed, in place of the earlier
"Suggested fix (drafted, not implemented)" section this replaces. Closure row:
`docs/security-closures.d/`, claim `kek-rename-dek-cleanup-dataloss-001`,
proving test `FuzzFaultInjectedOperations` (`internal/encryption`).
**Severity: High impact / Low likelihood** (assessed pre-fix; retained here
for context — see "Reachability" and "Impact" below, both still accurate
descriptions of what the bug WOULD have done).

- **Impact:** **every secret in the vault becomes permanently
  undecryptable** once triggered — the DEK ends up wrapped under a KEK
  derived from a salt that no longer exists anywhere on disk, with no
  cryptographic or operational path back to it (see "Impact" below).
- **Likelihood: Low**, and narrower than "any local disk error" — see
  "Reachability" below for the precise trigger conditions, including why a
  directory-fsync (`SyncDir`) error does **not** reach this path. The
  dominant real trigger (NFS-style ambiguous-rename semantics) is itself
  substantially mitigated by modern NFS implementations: **NFSv3's Duplicate
  Request Cache (DRC) is specifically designed to catch a client's RPC retry
  after a reply was lost and return the ORIGINAL (cached) reply instead of
  re-executing or erroring**, which closes most of this ambiguity in
  practice; **NFSv4.1+'s session/sequence-ID mechanism gives exactly-once
  semantics** for the RPC itself, closing it further still. The residual,
  non-mitigated risk is narrower yet: **NFSv3 specifically when the server's
  DRC entry has been evicted** (a bounded-size cache — a long enough delay
  between the client's original request and its retry, or a server restart
  that clears the DRC, can evict the entry before the retry arrives) **or an
  older/non-compliant NFS client or server stack** that does not implement
  these protections correctly. Given this, the residual likelihood is
  genuinely low, not merely "narrow" — but the impact if it does land is
  total and irreversible, which is why this is accepted as High/Low rather
  than downgraded outright.

## Summary

`commitNewKEKFiles` persists a KEK-passphrase rotation via two coupled
write-pending → rename steps: `kek.salt.pending`/`dek.key.pending` are written
first, then `dek.key.pending` is renamed to `dek.key`, then
`kek.salt.pending` is renamed to `kek.salt`. This ordering is deliberate — the
code's own comment says a crash between the two renames leaves a documented,
recoverable "hazard window" (active `dek.key` new, active `kek.salt` old),
which an operator completes manually by renaming the leftover
`kek.salt.pending` into place.

The bug is in the error-handling branch for the **first** rename
(`keymanager_kek_rotation.go:159-163`):

```go
if err := durableRename(pendingDEKFull, activeDEKFull, "kek:rename-dek"); err != nil {
    _ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))
    _ = os.Remove(pendingDEKFull)
    return fmt.Errorf("rotate KEK: promote pending DEK to active: %w", err)
}
```

(`durableRename` here is this task's thin, nil-in-production fault-injection
wrapper around the real `os.Rename` — see `fault_hooks.go`; the underlying
`os.Rename` call and this surrounding error-handling are unchanged from the
pre-existing code.)

This cleanup **unconditionally deletes `kek.salt.pending`** — the file that a
completed-dek-but-incomplete-salt hazard window needs for recovery — on ANY
error from the rename call, without checking whether the rename actually
happened. That is correct when the rename genuinely did not happen (nothing
changed, so removing the leftover `.pending` files is tidy and safe). It is
**not** correct when the rename call reports an error despite having actually
renamed the file.

## Reachability: exact trigger conditions

**Does a directory-fsync (`SyncDir`) error after a successful rename reach
this cleanup? No.** Trace of `commitNewKEKFiles` (`keymanager_kek_rotation.go:159-168`):

```go
if err := durableRename(pendingDEKFull, activeDEKFull, "kek:rename-dek"); err != nil {
    _ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))   // <- the buggy cleanup
    _ = os.Remove(pendingDEKFull)
    return fmt.Errorf("rotate KEK: promote pending DEK to active: %w", err)
}
// best-effort: this SyncDir's error is deliberately discarded ...
_ = securefiles.SyncDir(filepath.Dir(activeDEKFull))
```

The `SyncDir` call is a **separate statement that runs only after the `if
err != nil` block has already been skipped** (i.e., only on the success path
of the rename itself), and its own return value is discarded (`_ =`) —
it is never wired into the `if err != nil` condition and cannot cause that
branch to be taken. A directory-fsync failure at this point is silently
swallowed and `commitNewKEKFiles` proceeds normally to `kek:after-rename-dek`.
**So a local-disk EIO on the directory fsync does NOT trigger this bug** — it
triggers a different, separate, much lower-severity gap (an un-surfaced
`SyncDir` error — already noted in the code's own inline comment as
deliberate best-effort behavior, mirroring the SIEM-spool finding's shape but
not filed separately here since it has no data-loss consequence: the rename
itself, which is what actually matters for recoverability, already succeeded
by the time `SyncDir` runs).

The **actual** trigger is narrower and specific: `os.Rename` (inside
`durableRename`) itself must return a non-nil error despite having actually
applied the rename. `rename(2)` is documented as atomic on a single local
POSIX filesystem — under ordinary local disk I/O errors (EIO, ENOSPC) the
kernel is expected to either fully apply the metadata change or fully fail
without applying it, not both. The realistic, well-documented source of this
exact ambiguity is a filesystem whose operations are executed by a remote
server over a protocol with **at-least-once, non-transactional RPC
semantics**:

- **NFS** (v3 most clearly, and v4 under certain client/server recovery
  paths): a client issues a RENAME RPC; the server executes it and would
  reply success, but the reply is lost (network partition, server briefly
  unresponsive under load, a server reboot between executing the request and
  sending the response). The client's RPC layer times out and surfaces an
  error (`ETIMEDOUT`, `ESTALE`, or a similar I/O error depending on the
  client's mount options and recovery behavior) to the calling process —
  even though the rename already committed server-side. This is the classic
  "at-least-once RPC vs. non-idempotent operation" ambiguity NFS is
  documented to have; RENAME is not safely retryable/idempotent from the
  client's point of view (a retried RENAME of an already-renamed source
  fails with `ENOENT`, which client implementations do not uniformly
  distinguish from "never happened"). This is substantially mitigated in
  practice, not merely theoretical-but-fully-open: see the severity note at
  the top of this document for NFSv3 DRC / NFSv4.1 session mitigations and
  the narrower residual risk window they leave.
- The same class of ambiguity applies to any other client-server network
  filesystem with similar RPC semantics reachable as a POSIX mount — FUSE-
  backed network filesystems and various Kubernetes CSI drivers that proxy to
  network storage (e.g., NFS-backed `PersistentVolume`s, which are common and
  unremarkable in real K8s deployments) share the same characteristic.
- Checked: **Keyorix has no validation, restriction, or documentation
  anywhere in this repository (`docs/`, the encryption package, the CLI, the
  Helm chart) constraining what filesystem backs the key/data directory.**
  Grepped for "NFS"/"nfs" across `docs/`, `internal/encryption/`,
  `internal/cli/encryption/`, and chart/helm directories — no hits. An
  operator deploying Keyorix in Kubernetes with the key directory on an
  NFS-backed volume (a normal, unremarked-upon choice, not a misconfiguration
  the product warns against) is a realistic, currently-supported-by-omission
  deployment shape that can hit this exact ambiguity.
- A raw **local disk EIO exactly at rename-metadata-commit time** is a much
  less certain trigger for this specific ambiguity (most local journaling
  filesystems either fully apply or fully fail a rename transaction) — it is
  not ruled out on every possible local storage stack (e.g., a distributed
  block device presented as "local" disk, or unusual overlay/container
  storage driver edge cases), but it is not the well-documented case the way
  NFS is, and should not be cited as the primary trigger.

This is exactly the "rename error after the write is durable" ambiguous
fault class this task's fault-injection design was built to probe (see
`fault_injected_operations_fuzz_test.go`'s doc comment) — modeled precisely,
not the `SyncDir` path.

## Impact

Once triggered: `dek.key` on disk holds the DEK wrapped under a KEK derived
from `newPass` + the NEW salt. That salt was never promoted to `kek.salt`
(the second rename never got the chance to run), and its only other copy —
`kek.salt.pending` — was just deleted by the buggy cleanup. There is **no
remaining copy of the new salt anywhere**, so the new KEK cannot be
re-derived by any means (operator-known passphrase or otherwise), so the DEK
cannot be unwrapped, so **every secret in the vault encrypted under that DEK
is permanently undecryptable** — a full, unrecoverable data-loss event, not a
partial or single-secret one.

## Adversarial reproduction

Minimized and verified directly via a standalone scratch reproduction
(deleted after verification, not committed — see "How the shipped fuzz
target handles this" below for how the shipped harness itself now exercises
and tolerates this exact case):

1. Seed a fresh `KeyManager` with `oldPass` (creates `dek.key` + `kek.salt`,
   generates DEK `dek0`).
2. Call `RotateKEKPassphrase(oldPass, newPass)` with the `kek:rename-dek` seam
   faulted to *actually perform* the real `os.Rename(dek.key.pending →
   dek.key)` and then still report an error (this task's
   `faultRealEffectThenError` fault kind, modeling the scenario above).
3. Observed: `RotateKEKPassphrase` returns a non-nil error, as expected
   (`rotate KEK: promote pending DEK to active: <injected>`).
4. Observed: `kek.salt.pending` is already gone — deleted synchronously by
   `commitNewKEKFiles`' own cleanup, *before* `RotateKEKPassphrase` even
   returns (not something a later startup step does).
5. Ran the real production startup step, `KeyManager.CleanPendingDEK()` — no
   effect either way (it only ever touches `dek.key.pending`, which was
   already renamed away for real in step 2).
6. Attempted recovery via the existing crash-consistency trilogy's own
   `recoverDEK` helper (`keymanager_crash_consistency_fuzz_test.go`), which
   tries: old passphrase against the active files, new passphrase against the
   active files, then applying the leftover `kek.salt.pending` if present.
   **Result: no recovery path succeeds.** `dek.key` on disk is wrapped under a
   KEK derived from `newPass` + a salt that no longer exists anywhere (it was
   never promoted to `kek.salt`, and its only other copy —
   `kek.salt.pending` — was just deleted). The DEK — and therefore every
   secret encrypted under it — becomes **permanently unrecoverable**.

Log excerpt from the verification run:

```
RotateKEKPassphrase reported (as expected, the ambiguous fault): rotate KEK: promote pending DEK to active: <injected>
confirmed: kek.salt.pending is GONE (deleted by commitNewKEKFiles' rename-dek error-cleanup path itself, synchronously, before RotateKEKPassphrase even returned — the bug)
CONFIRMED DATA LOSS: recoverDEK found no way to recover the DEK (original dek0=ce85328491dab4e275348c1e5a7f4add80c9b91b92fb4601d59136d4761039e0). Neither old-passphrase, new-passphrase, nor apply-pending-salt (file gone) works.
```

The reproduction script itself was a scratch file, deleted after verification
(not committed), per this task's red-proof discipline.

## Why this is a real, security-relevant bug and not a fuzz-harness artifact

- The fault type modeled (a rename call reporting failure after the change
  actually landed) is one of the exact three example fault/seam combinations
  the task's own directive named as needing sound "old-or-new, never a mix"
  handling — it is a documented, anticipated real-world failure shape, not an
  invented one.
- The code's OWN doc comment already acknowledges a closely related hazard
  window is expected and recoverable ("a crash between the two renames...
  The pending salt file allows the operator to complete the rename
  manually") — this finding shows the recovery mechanism the comment
  describes is itself deleted by the adjacent error path under a fault that
  lands one line earlier than the comment's assumed crash point.
- Contrast with the analogous cleanup in `RewrapDEK`
  (`keymanager_rewrap.go`), which only ever removes its OWN pending file
  (there is no second coupled file for that operation) — so the same fault
  shape applied to `rewrap:rename-dek` does **not** reproduce this bug class;
  this is specific to KEK-passphrase rotation's two-coupled-file design.

## History: how the fuzz target handled this before the fix (superseded)

Before the fix (this section is retained for the audit trail — the mechanism
it describes no longer exists in the code):
`FuzzFaultInjectedOperations` did not exclude this exact combination from its
decoder or seed corpus; instead `runKEKRotateFaultCase` tolerated a
`recoverDEK` failure ONLY when it exactly matched this finding's verified
signature (seam exactly `kek:rename-dek`, kind exactly
`faultRealEffectThenError`, and `kek.salt.pending` confirmed absent on disk)
via a function named `isToleratedKnownOpenDataLoss`, so any different or
worse failure still failed the test loudly. That tolerance function and its
call site are **deleted** in the fix commit — see "Fix implemented" below —
because the case it tolerated is no longer a failure at all.

## Fix implemented

Landed on `fix/kek-rename-dek-verify-before-cleanup` (branched off the fuzzer
branch, ships as one PR containing both the finding and the fix), in two
steps.

### Step 1 (commit `121783b8`): boolean verify-before-cleanup

`commitNewKEKFiles`' rename-dek error branch (`keymanager_kek_rotation.go`)
called a new helper, `dekRenameActuallySucceeded(baseDir, dekPath,
newWrappedDEK) bool`, before any cleanup: read the actual on-disk DEK content
and compare it byte-for-byte against `newWrappedDEK`; `true` meant "fall
through and complete the rotation transparently, keep `kek.salt.pending`,"
`false` meant "fall through to the original cleanup." This closed the
original bug (unconditional deletion) but had its own gap — see Step 2.

### Step 2 (this commit): tri-state classification — closes a fail-open-under-uncertainty gap

The boolean version conflated two different situations under `false`:
"confirmed the rename did NOT apply" (safe to clean up) and "COULD NOT
confirm either way — e.g. the verification's own read/stat failed" (NOT safe
to clean up, since the very same transient condition that made the rename
report a spurious error in the first place — an NFS blip, for instance — can
plausibly ALSO disrupt the follow-up read used to verify it). Reviewed and
caught before this reached main: `dekRenameActuallySucceeded` returning
`false` on a read error meant "rename applied, reply lost, and the follow-up
verification read ALSO fails (same blip)" still deleted `kek.salt.pending`
and orphaned the DEK — the exact failure mode this fix exists to prevent, now
reachable through the verification path instead of the original one.

Replaced with `classifyDEKRename`, returning one of three `dekRenameOutcome`
values instead of a bool:

- **`dekRenameNotApplied`** — the rename's SOURCE file (`dek.key.pending`)
  still exists. A rename atomically moves its source, so this alone is
  sufficient and definitive: the rename did not happen. Falls through to the
  original cleanup, unchanged from Step 1's well-behaved case.
- **`dekRenameApplied`** — the source is confirmed gone AND the active
  `dek.key` holds exactly `newWrappedDEK`. Definitively did happen. Falls
  through past the cleanup and completes the rotation transparently, exactly
  as Step 1's `true` case did.
- **`dekRenameUnknown`** — neither could be confirmed: a stat error on the
  source, a read error on the destination, or destination content matching
  neither the old nor the new wrapped DEK. **Deletes nothing** (no `.pending`
  file is removed) and returns an error telling the operator the outcome is
  unconfirmed and to re-run `rotate-kek` or recover manually. This is the new
  state Step 1 didn't have — previously collapsed into "not applied," which
  is what permitted the cleanup to run.

`classifyDEKRename` checks the source's existence FIRST (a plain
existence stat, sufficient on its own for `NotApplied` — no content
comparison needed, unlike the destination check) and only reads the
destination's content when the source is confirmed gone.

Scope unchanged from Step 1: only `commitNewKEKFiles`' rename-dek branch.
`RewrapDEK`'s `rewrap:rename-dek` cleanup and `kek:rename-salt`'s own branch
remain noted v2/follow-up candidates in the fuzzer's doc comment.

### Fuzzer changes

`isToleratedKnownOpenDataLoss` (the known-open tolerance) is deleted (Step
1); `kek:rename-dek`'s ambiguous case is DETERMINISTIC (`RotateKEKPassphrase`
returns `nil`, `recoverDEK` succeeds via `"new-passphrase"` — see
`expectedKEKVia`, `runKEKRotateFaultCase`'s `transparentRecovery`).

Step 2 adds a NEW combined-fault seam,
`kek:rename-dek-verify-unknown` (`runKEKRotateCombinedVerifyUnknownCase`):
arms `kek:rename-dek` with the ambiguous fault AND a second, dedicated
`kek:verify-rename-dek` seam that `classifyDEKRename` itself checks
(nil-in-production, same pattern) to simulate its own verification failing —
the exact "same blip hits both" scenario above. Asserts directly: no
`.pending` file is removed, and the DEK remains fully recoverable (via the
hazard-window path, `apply-pending-salt+*`, since the rotation stops at the
`Unknown` branch without attempting the salt rename).

### Red-proofs

- Step 1: temporarily forced `dekRenameActuallySucceeded` to always return
  `false` — the seed corpus failed at `kek:rename-dek` with `REGRESSION`.
  Restored — green.
- Step 2: temporarily made the `kek:verify-rename-dek` fault path return
  `dekRenameNotApplied` instead of `dekRenameUnknown` (simulating the OLD
  err-collapses-to-false behavior applied to the NEW verification-failure
  case) — the new combined-fault seed immediately failed with `FAIL-SAFE
  VIOLATION: kek.salt.pending was removed despite an UNKNOWN rename-dek
  outcome`. Restored — green, full package suite passing.

Neither red-proof was committed as a toggle.
