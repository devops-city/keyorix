- **INV-CORE-last-used-off-request-path** An authenticated request never writes
  `personal_access_tokens.last_used_at`, `machine_identity_credentials.last_used_at` or
  `sessions.last_seen_at` itself: `TouchPATLastUsed`, `TouchMachineTokenLastUsed` and
  `ValidateSessionToken` only record the use in the core's `lastUsedCoalescer`, which
  writes at most one UPDATE per credential per `lastUsedFlushInterval` (30 s) from a
  timer goroutine, each row in its own autocommit statement, and on graceful shutdown
  (`server/main.go` → `FlushLastUsed`). The write is
  `SET col = t WHERE id = ? AND (col IS NULL OR col < t)`, so the column never moves
  backwards across replicas, and it stays a bookkeeping-only update for the
  single_writer tracker and fence. Uses are recorded only where the inline stamp was
  (after the network check and the account-state gate, #G60). A crash loses at most one
  interval. No security decision reads these columns; one that ever does must include
  the pending value, not the column alone (`docs/specs/last-used-coalescing.md` §1.3).
  Why: OPT-LASTUSED-1 (HEAD2HEAD-1 INTERIM-1 target 3: the per-request UPDATE averaged
  33 ms under strict durability while clients of one credential queued on the row
  lock). Guard: `TestLastUsed_RequestPathRunsNoLastUsedStatement` (statement count,
  red on main with 150 UPDATEs), `TestLastUsed_Postgres_RequestsDoNotWaitOnCredentialRowLock`
  (pg-gated: no backend waits on a lock while the rows are held),
  `TestLastUsed_FlushIsMonotonicAcrossReplicas`, `TestLastUsed_ReadersSeeUseWithinBound`,
  `TestLastUsed_RejectedRequestRecordsNothing`, and the static
  `TestLastUsed_OnlyTheCoalescerCallsTheStoreTouches` (no `.TouchPersonalAccessToken(` /
  `.TouchMachineIdentityCredential(` / `.TouchSession(` call in non-test `internal/core` or
  `server` code outside the coalescer; red on main at auth.go, machine_token.go, pat.go).
  **Not covered**: a call through a method value, an interface wrapper or a package
  outside those two trees.
