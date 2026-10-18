# ADR-010 — KEK Rotation with Full Re-encryption Sweep

**Status:** Decided (May 2026)
**Author:** Andrei Beshkov
**Replaces:** The undocumented behaviour of `RotateDEK()` which was key proliferation, not rotation.

**Corrected 2026-09-07 — three claims below drifted from this document's own
plan as implementation evolved past it; described here rather than as
rewritten body text, since the body is the historical record of the original
design:**

- **Sessions are no longer part of the sweep.** The body below (and its
  worked example in "Sweep output") lists `sessions`/`encrypted_session_token`
  as a swept table. Session tokens are hashed, not encrypted (#1641) — the
  live write path never populated that column, and `sweepSessions` was
  deleted outright rather than kept for legacy data. See
  `internal/encryption/sweep_auth.go`'s own doc comment for the current,
  authoritative account of which auth tables the sweep covers and why.
- **`RotateDEK` is not deprecated-but-kept; it no longer exists.** The body's
  "Alternative C" and Decision sections describe keeping the old function
  deprecated as a transition step. It has been fully removed — nothing in
  the codebase calls it. Describing the removed function's shape here is
  historical context for why `RotateDEKWithSweep` looks the way it does, not
  a claim that `RotateDEK` is still present.
- **KEK rotation (passphrase change) has shipped.** The body describes it as
  a "follow-on item" / "future" command. It exists today as
  `internal/cli/encryption/rotate_kek.go` / `Service.RotateKEKPassphrase`,
  with its own test coverage. The body's framing describes the state at
  this ADR's original writing, not the current codebase.

---

## Context

### The Problem: Key Proliferation

`RotateDEK()` in `keymanager.go` does the following:

1. Generates a new random DEK.
2. Wraps the new DEK with the current KEK.
3. Backs up the old wrapped DEK to `keys/dek.key.backup.<timestamp>`.
4. Writes the new wrapped DEK to `keys/dek.key`.
5. Updates the in-memory `currentDEK` to the new DEK.

This is **not key rotation**. It is **key proliferation**:

- Every `SecretVersion` row in the database was encrypted under the old DEK. After `RotateDEK()`, those rows cannot be decrypted with the new in-memory DEK.
- The server would silently fail to decrypt any existing secret on the next read.
- Old backup DEK files accumulate indefinitely. An attacker who exfiltrated any backup file and knows `KEYORIX_MASTER_PASSWORD` can derive the KEK and unwrap the old DEK — giving them access to secrets encrypted under that generation.

### What Must Happen

True key rotation requires:

1. The old DEK is kept in memory long enough to decrypt all existing ciphertext.
2. Every encrypted row is re-encrypted under the new DEK within a single transaction.
3. Only after all rows are committed does the old DEK leave memory.
4. Old backup files are deleted after a verified successful sweep.

### Scope of Encrypted Data

Three tables carry DEK-encrypted data:

| Table | Column | Encrypted by |
|---|---|---|
| `secret_versions` | `encrypted_value` | `SecretEncryption` / `integration.go` |
| `sessions` | `encrypted_session_token` | `AuthEncryption` |
| `api_tokens` | `encrypted_token` | `AuthEncryption` |
| `api_clients` | `encrypted_client_secret` | `AuthEncryption` |
| `password_resets` | `encrypted_token` | `AuthEncryption` |

`RotateAuthEncryption()` already exists and sweeps sessions, api_tokens, and api_clients. It re-encrypts using the current in-memory DEK — so it works correctly only if called while the old DEK is still in memory, before `currentDEK` is replaced.

There is no equivalent sweep for `secret_versions`.

---

## Decision

### Introduce `RotateDEKWithSweep`

Replace the broken `RotateDEK()` semantics with a new method `RotateDEKWithSweep` in `service.go`. The old `RotateDEK()` is retained but marked deprecated and logs a loud warning.

The new function's invariant: **on success, no row in the database references ciphertext encrypted under the old DEK.**

### Algorithm

```
RotateDEKWithSweep(passphrase, db):
  1. Verify initialization
  2. Read salt from disk
  3. Derive KEK from passphrase + salt (memory, wiped after use)
  4. Generate new random DEK (newDEK)
  5. Wrap newDEK with KEK → store as keys/dek.key.pending
  6. Begin database transaction (tx)
  7.   Re-encrypt all secret_versions rows (old DEK → new DEK)
  8.   Re-encrypt all sessions rows (old DEK → new DEK)
  9.   Re-encrypt all api_tokens rows (old DEK → new DEK)
  10.  Re-encrypt all api_clients rows (old DEK → new DEK)
  11.  Re-encrypt all password_resets rows (old DEK → new DEK)
  12. Commit transaction
  13. On commit success:
       a. Rename keys/dek.key.pending → keys/dek.key (atomic on POSIX)
       b. Wipe old DEK from memory
       c. Replace currentDEK with newDEK
       d. Update keyVersion
       e. Recreate EncryptionService with newDEK
       f. Delete all keys/dek.key.backup.* files
  14. On any error: rollback tx, delete keys/dek.key.pending, keep old DEK active
```

### Secret version re-encryption — AAD handling

Secret versions encrypted under the new AAD scheme (`aad_version: v1`) must be re-encrypted with the correct AAD reconstructed from their row data. The sweep reads `SecretNodeID` and `VersionNumber` from each row and fetches `ProjectID` from the parent `SecretNode` to rebuild `SecretAAD(secretID, projectID, versionNumber)`.

Legacy rows (no `aad_version` in metadata) are decrypted without AAD and re-encrypted **with** AAD — this sweep serves double duty as the M2 legacy re-encryption migration.

### Batch processing

For installations with large numbers of secrets, the sweep processes `secret_versions` in configurable batches (default: 500 rows per batch) within the same transaction. This avoids loading all ciphertext into memory simultaneously. Sessions, api_tokens, api_clients, and password_resets are small tables — no batching required.

### KEK rotation (passphrase change)

Changing `KEYORIX_MASTER_PASSWORD` is a separate concern: new salt + new PBKDF2 derivation → new KEK → re-wrap same DEK with new KEK. This does **not** require a database re-encryption sweep (the DEK is unchanged; only its wrapper changes). Implement as `RotateKEK(oldPassphrase, newPassphrase)` in `keymanager.go`. This ADR covers DEK rotation (the sweep). KEK rotation (passphrase change) is a follow-on item.

### CLI surface (original proposal — superseded, see Addendum below)

**This `key rotate-dek` command was never shipped.** It was superseded before
implementation by extending the existing `keyorix encryption rotate` command
instead — see "Addendum — CLI Wiring" below for the actual shipped surface
and why. Kept here only as the historical record of the original proposal.

```
keyorix-server key rotate-dek   # triggers RotateDEKWithSweep; requires KEYORIX_MASTER_PASSWORD
keyorix-server key rotate-kek   # future: passphrase change
```

Alternatively exposed as a protected admin API endpoint (operator-only, no user-facing exposure).

---

## Consequences

### Positive

- **True rotation:** after a successful sweep, the old DEK is gone from memory and disk. Old backup files are deleted. The attack window from a previously exfiltrated DEK backup is closed.
- **Legacy AAD migration:** the sweep simultaneously upgrades legacy (no-AAD) rows to AAD-bound rows, completing the M2 migration deferred from ADR-004.
- **Atomicity:** the database transaction ensures the system is never in a split state where some rows are encrypted under the new DEK and some under the old.

### Negative / Trade-offs

- **Downtime:** the sweep holds a long-running write transaction. For large installations, this will block concurrent secret reads/writes for the duration. Acceptable at v0.x scale (hundreds of secrets). Document in operator guide. Hot-swap streaming rotation is a v2 concern.
- **Memory pressure:** batched sweep keeps at most 500 plaintext values in memory at once. Acceptable trade-off between memory pressure and transaction duration.
- **Failure mode:** if the server crashes mid-sweep (after `keys/dek.key.pending` is written but before rename), the pending file is orphaned. Recovery: re-run `keyorix encryption rotate --confirm`. The pending file is detected and cleaned up at startup. **⚠️ This description was incomplete and unsafe for one crash window — see "Addendum — Crash-consistency redo recovery (2026-09-17)" below.** Unconditionally discarding the pending file is only correct when the crash landed *before* the sweep transaction committed; a crash *after* the commit but before the rename left the DB re-encrypted under the new DEK while that discard threw the new DEK away, causing permanent data loss. The addendum documents the redo-marker fix.

### Not in scope for this ADR

- Streaming / hot-swap rotation without downtime (requires version field on every row + dual-key read path — v2)
- KEK rotation (passphrase change) — follow-on item
- Shamir's Secret Sharing for KEK (enterprise, KeyProvider Tier 2)

---

## Implementation Plan

### Files to change

| File | Change |
|---|---|
| `internal/encryption/keymanager.go` | Add `RotateDEKWithSweep` (core algorithm). Mark `RotateDEK` deprecated. Add `GetOldDEKForSweep() []byte` helper (returns copy of current DEK before rotation). |
| `internal/encryption/service.go` | Add `RotateDEKWithSweep(passphrase string, db *gorm.DB) error`. Wire it through from `keymanager`. |
| `internal/encryption/sweep.go` | **New file.** `SweepSecretVersions`, `SweepAuthTokens`. Handles batched re-encryption, AAD reconstruction for secret_versions, and the auth token tables. |
| `internal/cli/system/system.go` | ~~Add `key` subcommand with `rotate-dek` action.~~ **Superseded** — wired to the existing `keyorix encryption rotate` command instead; see Addendum below. |

### Test plan

1. **Unit: `TestRotateDEKWithSweep_ReEncryptsAllRows`** — seed DB with N secret versions + sessions + api tokens, call sweep, verify every row decrypts correctly with new DEK and fails with old DEK.
2. **Unit: `TestRotateDEKWithSweep_UpgradesLegacyAAD`** — seed with legacy (no-AAD) rows, call sweep, verify all rows are now AAD-bound.
3. **Unit: `TestRotateDEKWithSweep_RollbackOnError`** — inject a DB error mid-sweep, verify old DEK remains active and no rows were modified.
4. **Unit: `TestRotateDEKWithSweep_PendingFileCleanup`** — simulate crash after pending file write, verify recovery on re-run.
5. **Integration: `TestRotateDEKWithSweep_EndToEnd`** — full server with real DB, create secrets, rotate, read secrets back. All reads must succeed.

---

## Alternatives Considered

### A: Dual-key read path (hot rotation)

Store `dek_version` in every `SecretVersion` row. Server maintains a map of `version → DEK`. Rotation writes a new DEK and updates new writes to use it. Old rows are lazily re-encrypted on read. No downtime.

**Rejected for now:** Requires a migration to add `dek_version` column to three tables, significantly more complexity in the decryption path, and perpetuates the key proliferation problem during the lazy window. Appropriate when Keyorix has high-traffic customers who cannot accept any write-lock. Revisit at v1.0.

### B: Rotate only secret_versions; invalidate auth tokens

Sessions are short-lived. On DEK rotation, delete all sessions and API tokens (force re-login). Only sweep `secret_versions`.

**Rejected:** Forced re-login is disruptive to CI/CD pipelines that use long-lived API tokens. The existing `RotateAuthEncryption()` already has the machinery — use it correctly rather than sidestep it.

### C: Keep `RotateDEK` as-is; accept key proliferation

**Rejected explicitly.** This is what the backlog item exists to fix. Key proliferation violates the security promise of the product. An enterprise security customer asking about key rotation and receiving an answer that amounts to "we keep all old keys forever" is a sales-blocker.

---

## Addendum — CLI Wiring (May 2026)

This addendum closes out the final implementation step of ADR-010: wiring the existing `keyorix encryption rotate` command to call `RotateDEKWithSweep` instead of the deprecated `RotateDEK`.

### Why this is an addendum, not a new ADR

The original ADR specified a `keyorix-server key rotate-dek` subcommand. While that command was being scaffolded, `keyorix encryption rotate` already shipped (calling the deprecated `RotateDEK`). Modifying the existing command in place reuses an existing surface that operators have already learned, avoids two competing rotate commands, and supersedes the M2 backlog item for `keyorix-server key rotate-dek`.

### Decisions

**1. Command surface: extend `keyorix encryption rotate` rather than add a new command.**

The command's contract changes from "rotate keys, secrets get re-encrypted later somehow" to "rotate keys and re-encrypt all DEK-encrypted rows in one transaction." This is what operators already expected. The deprecation message previously printed (`⚠️ Note: Existing secrets will need to be re-encrypted with the new keys`) is removed because it is no longer true.

**2. DB handle acquisition: open a fresh `*gorm.DB` in the CLI, do not expose `LocalStorage.db`.**

`RotateDEKWithSweep(passphrase, db *gorm.DB)` requires a raw `*gorm.DB`. Two options were considered:

- *(rejected)* Add a `DB() *gorm.DB` accessor to `LocalStorage`. This widens the storage abstraction's public API for a one-off CLI operation and invites future callers to bypass the `storage.Storage` interface.
- *(chosen)* Mirror the connection logic from `internal/storage/factory.go` in a small private helper inside the CLI package. The CLI is already a separate process from the server, so opening its own DB connection is consistent with how other admin operations work.

**3. Refuse to run against a remote storage backend.**

If `cfg.Storage.Type == "remote"`, the command must error with a clear message instructing the operator to run rotation on the server host. Rotation must touch the server's actual database; running it against a remote API endpoint is meaningless.

**4. Require an explicit `--confirm` flag.**

ADR-010 documents that the sweep is a write-locking operation that holds a long-running transaction. A typo on `keyorix encryption rotate` must not silently kick off a downtime event. The command refuses to run without `--confirm` and prints a one-line warning explaining what is about to happen.

No interactive `[y/N]` prompt — that would break CI/CD scripted invocations. The `--confirm` flag is the sole gate.

**5. Keep `RotateDEK` as deprecated, do not delete it yet.**

The deprecated function remains for any external integration that may import it directly. Its body already logs an explicit deprecation warning. Removal is M2 cleanup once we are confident no internal caller uses it.

### Operator-facing behaviour

```
$ keyorix encryption rotate
Error: this is a write-locking operation. Re-run with --confirm.

$ keyorix encryption rotate --confirm
⚠️  Rotating DEK and re-encrypting all DEK-encrypted rows. This holds a write lock on the database — stop write traffic before continuing.
🔄 Rotating DEK with full re-encryption sweep...
✅ Sweep committed: 142 secret_versions, 8 sessions, 3 api_tokens, 1 api_clients, 0 password_resets re-encrypted (12 legacy AAD upgraded)
✅ DEK rotated successfully
📋 New key version: v3
```

### Test plan addendum

The sweep itself is already covered by the unit and integration tests listed in the original ADR. The CLI wiring needs only:

- `TestRunRotate_RequiresConfirm` — without `--confirm`, the command returns a non-nil error and does not invoke the sweep.
- `TestRunRotate_RejectsRemoteStorage` — with `cfg.Storage.Type == "remote"`, returns a clear error before opening any DB connection.

These live in a new `encryption_test.go` next to `encryption.go` in the CLI package.

---

## Addendum — Crash-consistency redo recovery (2026-09-17)

This addendum closes a **data-loss window** in the rotation's crash-consistency, found by a
crash-consistency fuzzer (`FuzzDEKSweepCrashConsistency`) and fixed in PR #1918. It corrects
the "Failure mode" bullet in *Consequences*, which described discarding the pending DEK file
on restart as safe recovery.

### The bug

The algorithm (steps 5–13 above) makes two independent durable changes with **no atomicity
or recovery bridge** between them:

1. **step 12 — the sweep transaction COMMITs** (all rows now ciphertext under the *new* DEK, durable in the DB), then
2. **step 13a — rename `dek.key.pending → dek.key`** (the *file* promotion of the new DEK).

A crash (power loss / SIGKILL / OOM) **after the commit but before the rename** leaves:

- DB rows: under the **new** DEK (committed).
- active `dek.key`: still the **old** DEK (rename never ran).
- `dek.key.pending`: the **new** DEK — the *only* copy.

On restart, `CleanPendingDEK()` **unconditionally deleted** `dek.key.pending` as "a leftover
from an interrupted rotation", discarding the only copy of the new DEK. The server then
loaded the old DEK, under which none of the just-re-encrypted rows decrypt → **permanent,
total loss of decryptability of every DEK-encrypted secret** (recoverable only from a
pre-rotation DB backup). The old "re-run `encryption rotate`" advice does not recover it —
the current active (old) DEK can no longer decrypt the new-DEK rows, so a fresh sweep can't
read them either.

The discard is only correct for a crash **before** the commit (step 12), where the rows are
still under the old DEK and the pending file genuinely is a throwaway.

### The fix — write-ahead redo marker + recovery on startup

A textbook redo (write-ahead) record makes recovery deterministic. The recovery decision
hinges on one fact — *did the sweep transaction commit?* — so that fact is recorded **inside
the sweep transaction itself**:

1. **Durable pending file first.** After writing `dek.key.pending`, `fsync` the key
   **directory** (not just the file — `SecureWriteFileSync` synced the data but not the
   directory entry). This guarantees the invariant *marker durable ⇒ new DEK durably present*.
2. **Redo marker in the sweep transaction.** `sweepFn` writes a `system_metadata` row
   `dek_rotation.promote_pending` = new key version **in the same transaction** as the row
   re-encryption, so the marker becomes durable atomically with the rows moving to the new
   DEK. (`system_metadata` is not DEK-encrypted, so the sweep never touches it; the marker
   carries no secret material.)
3. **Recovery before `Initialize`, under the exclusive key lock.**
   `Service.RecoverInterruptedRotation(db)` replaces the bare `CleanPendingDEK()` at both
   startup sites (`server/main.go`) and the rotate CLI:
   - **marker present** ⇒ the sweep committed → promote `dek.key.pending` via
     `KeyManager.PromotePendingDEK()` (an idempotent rename+fsync; a no-op if the rename
     already happened, so a crash *after* the rename but before the marker is cleared replays
     harmlessly), then clear the marker.
   - **marker absent** ⇒ no committed sweep → discard any stray pending file (the original
     `CleanPendingDEK` behavior — correct here, and also for interrupted KEK-rotation/rewrap,
     which keep the *same* DEK).
   No data-probing heuristics: the marker either committed with the rows or it did not.

The rotation self-migrates the marker table (idempotent `AutoMigrate` of `SystemMetadata`; a
no-op on a real DB, where the table already exists for the bootstrap marker and audit
high-water), so the marker never depends on external migration ordering.

### Why this approach (over the alternatives)

- **Decrypt hot path is untouched** — still one authoritative DEK per read. Rejected a
  dual-key / versioned-keyring read fallback (Alternative A above, "hot rotation") because for
  a security product, expanding the read path's key set — even during a window — is new
  attack/oracle surface and can mask integrity failures.
- **Deterministic, auditable** — the explicit committed-or-not marker beats probing a sample
  row to *infer* whether the sweep committed (empty tables / any sweep-gap row could
  misclassify → data loss).
- The old DEK is still retired promptly on completion; confidentiality and availability are
  both preserved.

### Scope

Unique to `RotateDEKWithSweep` — the only rotation that re-encrypts DB rows under a **new**
DEK, so the only one with a DB-vs-file key divergence. KEK-passphrase rotation
(`RotateKEKPassphrase`) and provider migration (`RewrapDEK`, ADR-041) keep the **same** DEK
(only its wrapping changes), so their pending-file crash-consistency was already sound; their
fuzzers (`FuzzKEKRotationCrashConsistency`, `FuzzDEKRewrapCrashConsistency`) were and remain
green, and a stray pending from them is still correctly discarded (no marker ⇒ discard).

### Operator note

A previous minor cost: on a **local** storage backend the server now opens a short-lived DB
connection during encryption init (to read the redo marker), slightly earlier in startup than
before, closed immediately after recovery. Remote storage runs no local sweep, so recovery
falls back to the leftover-cleanup path with no DB access.

### Regression test

`FuzzDEKSweepCrashConsistency` (`internal/encryption/keymanager_sweep_crash_consistency_fuzz_test.go`)
interrupts the real rotation at each durability checkpoint (`sweep:...` labels on the
nil-in-prod `rotationCheckpoint` seam) and asserts every committed row still decrypts under
the recovered active DEK. It passes at every crash point after the fix and goes red if the
ordering/recovery regresses. Runs on in-memory SQLite — CI-runnable, no rig needed.

## Addendum — Cross-replica DEK epoch (2026-10, #3337)

### Problem

`dek.lock` serialises a rotation against a server only on the host that holds
the key directory. With several replicas on one PostgreSQL database (ADR-039)
each replica may hold its own `dek.key`, and nothing told a replica that another
host had rotated: a replica started again with its old `dek.key`, or left running
while the database presence guard (`internal/serverguard`) was bypassed
(`--force`) or lost, kept committing rows under the old DEK. Once the new key
set was distributed those rows were undecryptable.

### Decision

The database records the DEK it is encrypted under: `system_metadata["dek.epoch"]`
= the DEK fingerprint (first 16 bytes of HMAC-SHA256(DEK, "keyorix/dek-fingerprint/v1"),
not key material), or `rotating:<old fingerprint>` while a rotation's sweep is in
flight (`internal/encryption/dek_epoch.go`). PostgreSQL only; SQLite is single-node
and unchanged.

- **Server start-up** refuses unless the epoch is its own fingerprint. An absent
  epoch is seeded, after the DEK decrypts the newest encrypted secret version.
- **Running server**: a goroutine re-reads the epoch every 2 s; `Encrypt*` refuse
  unless a read that started at most 5 s ago matched. Decrypt is never fenced and
  no revocation path encrypts.
- **Rotation**: commit `rotating:<old>`, wait 10 s (> the 5 s staleness bound), then
  sweep in a transaction that holds every swept table in SHARE ROW EXCLUSIVE mode (in-flight
  writers finish first and are swept; new writes wait) and compare-and-sets the
  epoch to the new fingerprint in that same transaction. A failed rotation lifts
  its fence; a fence left by a killed rotation is lifted by the next server start
  holding the old DEK (it holds the presence lock, so no rotation is running; a
  `--force` rotation then fails its compare-and-set and rolls back).

Alternatives rejected: replica acknowledgement rows (needs replica identity and
liveness tracking for little gain over the staleness bound); a per-write
in-transaction epoch check (touches every storage write path); reloading the new
DEK in place (keeps the KEK in memory; a restart is the documented path).

### Not covered

A write encrypted before its replica saw the fence whose INSERT starts more than
5 s (fence wait minus staleness bound) later, in a deployment where the presence
guard was also bypassed or lost. A server binary predating the epoch. Guards:
`internal/encryption/dek_epoch_postgres_test.go`, `dek_epoch_test.go`,
`server/dek_epoch_cross_replica_postgres_test.go`.
