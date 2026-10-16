# Last-used timestamps: coalesced off the request path (OPT-LASTUSED-1)

Status: implemented. Code: `internal/core/last_used_coalescer.go`. Invariant:
`internal/core/INVARIANTS.d/INV-CORE-last-used-off-request-path.md`.

## 1. Inventory

### 1.1 Writes on the request path (before this change)

The same code runs on SQLite and PostgreSQL, with and without
`storage.database.single_writer`.

| Column | Written by | Called from |
|---|---|---|
| `personal_access_tokens.last_used_at` | `KeyorixCore.TouchPATLastUsed` → `Storage.TouchPersonalAccessToken` | HTTP auth middleware after the network check (each auth-cache miss); gRPC auth interceptor (every PAT call, no auth cache) |
| `machine_identity_credentials.last_used_at` | `KeyorixCore.TouchMachineTokenLastUsed` → `Storage.TouchMachineIdentityCredential` | same two call sites, machine tokens |
| `sessions.last_seen_at` | `KeyorixCore.ValidateSessionToken` → `Storage.TouchSession` | HTTP middleware (each cache miss), gRPC interceptor (every call) |

Each was a conditional `UPDATE ... SET col = now WHERE id = ? AND (col IS NULL OR
col < now - 30s)`, run inline. It is a statement on every call even when it matches
no row, and when the 30 s window rolls over every concurrent request of the same
credential waits on that row's lock behind the one that won (behind its commit
fsync under `audit_durability: strict`).

single_writer: the fence trigger on `machine_identity_credentials` is
`WHEN ((to_jsonb(OLD) - 'last_used_at') IS DISTINCT FROM (to_jsonb(NEW) - 'last_used_at'))`
and the statement tracker classifies a `last_used_at`-only UPDATE as bookkeeping
(`FencedTables.UpdateIgnores`). Neither fences nor counts the stamp, before or after
this change; the flush uses the same statement shape.

### 1.2 Similar columns that are NOT on the per-request path (unchanged)

- `web_authn_credentials.last_used_at`: written together with the sign counter in
  `AdvanceWebAuthnCredentialCounter` during a WebAuthn assertion (login / step-up).
  The counter is clone detection and must stay synchronous; it is one write per
  assertion, not per request.
- `users.last_login_at`: written at login.
- `mfa_secrets.last_used_step`: TOTP replay protection at login, synchronous by design.
- `machine_identities.last_seen_at`: has no writer.

### 1.3 Readers and the freshness each needs

| Reader | Surface | Column | Needs |
|---|---|---|---|
| `ListOwnPATs` | `GET /api/v1/auth/tokens`, web PAT list, CLI `pat list` | PAT `last_used_at` | display; minutes |
| `ListPATHygiene` | `GET /api/v1/pat-hygiene?days=N` (default 90 d) | PAT `last_used_at` | days |
| `CountStalePATs` | `GET /api/v1/compliance/credential-trends`, hygiene snapshot | PAT `last_used_at` | days |
| `ListMachineTokens` | `GET /api/v1/projects/{id}/machine-identities/{mid}/tokens`, gRPC `ListMachineTokens`, CLI | credential `last_used_at` | display; minutes |
| `ListMachineTokenHygiene` | `GET /api/v1/machine-token-hygiene` | credential `last_used_at` | days |
| `CountStaleMachineCredentials` | credential trends, hygiene snapshot | credential `last_used_at` | days |
| `GetMachineAuditReport` | `GET /api/v1/machine-identities/audit(.csv)`, CLI `machine audit` (stale = 30 d) | credential `last_used_at` | days |
| `ListOwnSessions` | `GET /api/v1/auth/sessions` (My Account "last seen") | session `last_seen_at` | display; minutes |
| credential lookups (`credential_lookup_raw.go`, folded credential + memo) | auth read path | credential `last_used_at` | loaded into the model, never decided on |

Not readers of these columns, although the names suggest it: the access review's
`last_used_at` and the compliance posture's dormant grants come from secret-access
audit rows; the inactive-users filter and `POST .../suspend-inactive-users` use
`users.last_login_at`.

**Security decisions: none.** Nothing revokes, disables, expires or denies based on
these three columns. If a future feature does, it must not read the column alone:
it has to include this replica's pending value (`lastUsedCoalescer.pendingAt`) and
accept the cross-replica bound in §2, or keep its own synchronous write.

## 2. Mechanism and bounds

- A request records `(kind, id) → newest use time` in memory under a mutex and
  returns. It runs no statement and never waits on a row lock. The record happens
  at exactly the point the old inline stamp did (after the network check, after the
  account-state gate), so a refused request still records nothing (#G60).
- The first pending use arms a timer for `lastUsedFlushInterval` (30 s, the old
  throttle). When it fires, everything pending is written: one autocommit
  `UPDATE ... SET col = t WHERE id = ? AND (col IS NULL OR col < t)` per credential,
  in (kind, id) order. No transaction spans two rows, no request goroutine runs it.
  With nothing pending there is no timer and no goroutine.
- Monotonic across replicas: the WHERE clause is `GREATEST(existing, t)`. Each
  replica flushes its own observations; an older observation flushed after a newer
  one changes nothing.
- A failed write goes back to pending (merged with anything newer) and is retried
  at the next interval.
- More than 50 000 distinct pending credentials starts a flush at once.
- Graceful shutdown (`SIGTERM`/`SIGINT`) flushes after the servers drain
  (`server/main.go`, before the single-writer hold is released).

**Staleness bound:** a use at time `t` is in the database by
`t + 30 s + one flush`. Before, the column could lag the newest use by up to 30 s as
well (the throttle skipped writes while the stored value was younger than 30 s); the
difference is that the *first* use after a quiet period also waits up to 30 s now.

**Crash:** a process killed without a graceful stop loses the uses recorded since
the last flush, at most one interval. The column then shows an earlier use (or
none); the next request records again.

## 3. Tests

- `TestLastUsed_RequestPathRunsNoLastUsedStatement`: 150 authenticated calls (PAT,
  machine token, session), zero last-used UPDATEs; then one UPDATE per credential.
- `TestLastUsed_Postgres_RequestsDoNotWaitOnCredentialRowLock`: with the rows
  locked by another transaction, 16 concurrent clients of one credential return at
  once and no backend waits on a lock.
- `TestLastUsed_FlushIsMonotonicAcrossReplicas`, `TestLastUsed_TimerFlushesWithinInterval`,
  `TestLastUsed_FailedWriteIsRetried`, `TestLastUsed_MaxPendingFlushesEarly`,
  `TestLastUsed_RejectedRequestRecordsNothing`.
- `TestLastUsed_ReadersSeeUseWithinBound`: every reader in §1.3 reports the use
  after one flush.
- `TestLastUsed_OnlyTheCoalescerCallsTheStoreTouches`: static; no non-test code in
  `internal/core` or `server` calls the store's Touch* methods except the coalescer.
