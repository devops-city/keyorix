# Secure Coding Standard

> **Positioning.** These are rules this codebase actually enforces, derived
> from real findings, not a generic checklist. Each rule states *why* (the
> finding that motivated it, with a citation) and *how it's enforced* (the
> guard, test, or structural mechanism that keeps it true — link the file,
> per this repo's own engineering principle of preferring the
> machine-checked over the asserted). Two items referenced in the original
> task brief for this document — "ADR-111" for connector-host rules and
> "ADR-112" for the `insecure_` opt-out rule — do not exist in this repo as
> of this writing (`docs/adr-*.md` runs 1 through 110, then 113+; nothing
> is numbered 111 or 112). Rather than cite ADRs that don't exist, the
> relevant rules below are grounded directly in the real mechanism
> (`internal/envflag`, and the connector architecture already documented in
> [`threat-model.md`](threat-model.md) §4 B7). If those ADR numbers were
> meant for work not yet written, that's a gap to raise with Andrei, not
> something to paper over with an invented citation.

## 1. Fail closed, always

**Rule:** when a security-relevant check can't be evaluated — a flag is
unset, a lookup errors, a config value is malformed — the code must deny,
not allow.

- **Why:** this codebase's recurring defect class, named explicitly in
  `CLAUDE.md`'s engineering-practices section as "opt-in correctness is the
  recurring defect class" — security properties that were allowed by
  default and required an explicit opt-in to become safe decay the moment
  someone forgets the opt-in.
- **How enforced:**
  - `internal/envflag.Enabled` — unset or unparsable environment variable
    returns `false` (disabled), never `true`, for every `insecure_`-style
    opt-in in this codebase (see §6 below).
  - `internal/config.ValidateRemoteStorageNotServer` — unconditional since
    PR #1549; a scheduler-only process that looked safe under an earlier,
    shallower check (only `server.http.enabled`/`.grpc.enabled`) turned out
    to be reachable anyway through `startSchedulers`, fixed in `e98141b7`.
  - [ADR-096](../adr-096-anti-enumeration-403-for-both.md) — an
    authorization check that can't distinguish "exists, no access" from
    "doesn't exist" returns the *same* 403 for both, rather than leaking
    existence through a differently-shaped error.
  - [ADR-097](../adr-097-schema-epoch-downgrade-guard.md)'s
    `checkSchemaEpoch` — an old binary pointed at a newer schema refuses to
    start (loud failure) rather than silently running against
    security-relevant columns it doesn't know about.
- **Example (anti-pattern avoided):** a hand-rolled
  `if os.Getenv("X") == "true" { allow() }` silently allows on a typo'd
  value (`"True"`, `"1 "`) under naive string comparison. `envflag.Enabled`
  uses `strconv.ParseBool` and defaults every unparsable/unset case to
  `false`.

## 2. Transactions and atomicity: never catch-then-commit on Postgres

**Rule:** on Postgres, catching a constraint violation inside a
multi-statement transaction and returning `nil` (intending to `COMMIT`) is
dead code — the transaction is already aborted at the protocol level the
moment the statement fails, and a subsequent `COMMIT` silently downgrades
to `ROLLBACK`. Prevent the conflict (`INSERT ... ON CONFLICT DO NOTHING`,
then read back) instead of catching it after the fact.

- **Why:** `TryAcquireSchedulerLock` (`local_scheduler_lock_lease.go`) was a
  confirmed live instance of exactly this bug — see `CLAUDE.md`'s
  engineering-practices section for the full writeup.
- **How enforced:** a full-repo sweep of every other
  `isUniqueViolation`/constraint-catch site confirmed no other instance
  returns `nil` after a caught violation inside a shared transaction; the
  fixed site uses `ON CONFLICT DO NOTHING` + read-back instead of
  catch-and-ignore. There is no standing lint rule for this shape today —
  it was closed as a found instance, not a guarded class. **Gap**: if this
  recurs, the fix should be a static check (a Semgrep rule matching
  "error-returning-nil inside `WithTransaction`"), not another one-off
  find — see `CLAUDE.md`'s own "if the root cause has sibling call sites,
  the fix is an invariant test, not a site patch."

## 3. Check-then-act serialization: `storage.WithNamedLock`, not a local mutex

**Rule:** a check-then-act decision that must hold across replicas (is this
the last admin, has this role already been assigned) serializes through
`storage.WithNamedLock(ctx, lockKey, fn)` — a Postgres advisory lock, real
across every server instance — never a `sync.Mutex` or package-level
variable, which only serializes within one process.

- **Why:** [`docs/specs/check-then-act-inventory.md`](../specs/check-then-act-inventory.md)
  is the full inventory of every check-then-act decision in this codebase,
  classified by whether it's protected by a real cross-replica primitive
  (`WithNamedLock`) or not. One confirmed real gap from that inventory: the
  last-admin-lockout guard called `storage.AssignMachineRole` directly with
  no lock at all; fixed by wrapping the check+write in
  `storage.WithNamedLock(ctx, lastAdminGuardLockKey, ...)`.
- **How enforced:** `docs/check-then-act-lock-exempt.tsv` is the
  machine-checked allowlist of decisions deliberately *not* locked (because
  the worst case is availability/UX, not a security bypass — e.g. a
  flood-prevention throttle) — anything not on that list and not using
  `WithNamedLock` is a candidate the inventory process re-flags. Test
  coverage for the primitive itself:
  `internal/storage/store/concurrency_named_lock_postgres_test.go`
  (`TestConcurrency_WithNamedLock_MultiInstancePostgres_SameKeySerializes`)
  proves the lock is real across multiple DB connections, not just within
  one process — see `CLAUDE.md`'s own worked example of a test that
  claimed cross-replica safety while actually sharing one process-local
  mutex, and why that's a materially different (weaker) proof.
- **Example (anti-pattern avoided):** `accountStateMu.Lock()` (a
  package-level `sync.Mutex`) serializes two goroutines in one process; it
  does nothing against a second server replica racing the same check. The
  fix keeps the mutex removed and relies on `WithNamedLock` alone.

## 4. Audit-before-disclosure

**Rule:** when returning a secret's *value* (not just metadata) to a
caller, the audit write recording that disclosure must be confirmed
durable before the response is released. This is a required step in the
operation's own contract, never a best-effort/fire-and-forget step — the
opposite of §5's rule for ordinary audit logging.

- **Why:** named explicitly as the one exception to the best-effort pattern
  in `internal/besteffort/besteffort.go`'s own package doc: "Do NOT use
  this package for a step that is part of the operation's own contract and
  must fail closed — e.g. audit-before-disclosure, where a secret's value
  may not be released until its audit write is confirmed durable."
- **How enforced:** `internal/core/guards/secret_read_audit_call_sites_test.go`
  walks every call site of `LogSecretReadWithProject` across the repo via
  `go/ast` (not a hand-maintained list) and fails if a call site that
  actually discloses a value either (a) doesn't check the returned error,
  or (b) calls it from inside a detached `goSafe` goroutine — a checked
  error only a background goroutine sees can't stop a response that
  already went out. One documented, deliberate exception
  (`GetSecretByName`, metadata-only, no value disclosed) is in
  `secretReadAuditCallSiteAllowlist`, not silently excluded.
- **Example:** `GetSecretByName` is allowed to log the read fire-and-forget
  precisely *because* it never returns a value — there's nothing for
  audit-before-disclosure to gate. A handler that later adds a value field
  to that same response without moving its audit call out of `goSafe`
  would be exactly the bug this guard exists to catch.

## 5. No secrets in logs or errors

**Rule:** no secret value, key byte, passphrase, or raw (unhashed) token is
ever written to a log line, panic message, or error string.

- **Why:** the baseline confidentiality promise of a secrets manager —
  a leak via a log sink (often lower-trust, longer-retained, and more
  widely readable than the primary datastore) defeats every other control.
- **How enforced:** audited across every logging sink
  (`docs/security/architecture.md` "No plaintext in logs"); secret-update
  audit diffs carry only a `{"value":{"changed":true}}` marker, never the
  before/after value (`AUDIT-LOG-PROVISIONS.md` §3) — the audit trail
  itself is a logging-adjacent sink and follows the same rule.
- **Example:** an error wrapping a failed decrypt must not do
  `fmt.Errorf("decrypt failed for value %q", plaintext)` — only identifiers
  (secret ID, project, environment) belong in an error message, never the
  value itself, even on a failure path where it might seem like harmless
  debug context.

## 6. The `insecure_`-prefixed opt-out convention

**Rule:** a deliberate security downgrade (disabling TLS verification,
allowing cleartext SMTP) is gated behind an explicit, falsy-by-default
environment variable checked through the shared `internal/envflag` helper
— never a bespoke `os.Getenv` comparison, and never a default-on config
key.

- **Why:** `internal/envflag`'s own package doc: extracted after two
  independent copies (`internal/delivery`, `internal/notifychan`) each grew
  their own identical `envFlagEnabled` implementation that had *also*
  independently duplicated `AllowInsecureSMTP` under two different names —
  exactly the shape that silently diverges when one copy's gate is
  tightened and the other isn't (`keyorix-private/adversarial-review/
  IMPLEMENTATION-ASYMMETRY-SCAN-2026-09-05.md`, finding F6).
- **How enforced:** `internal/envflag.Enabled(name)` is the one shared
  implementation; `AllowInsecureSMTP = "KEYORIX_ALLOW_INSECURE_SMTP"` is
  the current example constant. Unset or unparsable always means disabled
  — there is no code path where a lookup failure defaults to enabled.
- **Correction on this document's own sourcing:** the task brief this
  document was written from cited "ADR-112" for this rule. No such ADR
  exists in the repo; this section is grounded directly in
  `internal/envflag/envflag.go` instead. If a dedicated ADR for this
  convention is wanted, that's a follow-up, not something to retrofit a
  citation for here.

## 7. Best-effort-after-commit: `internal/besteffort.Run`

**Rule:** a non-critical step that runs *after* an operation's primary
write has already committed (session-limit enforcement, notification
fan-out, dependency-event emission) must never turn that already-successful
operation into a reported failure — including on a **panic**, not just a
returned error. Every such step goes through `besteffort.Run`/`RunRecover`,
never a hand-rolled `_ = f()` with no panic recovery.

- **Why:** QA-1 (an internal review campaign) found this exact bug shape
  fixed one call site at a time, 12+ times: a function commits, then runs a
  non-critical step whose *returned* error is deliberately discarded, but a
  *panic* in that step is not recovered, escapes the discard, and the
  caller sees an error (often a 500) for an operation that actually
  succeeded.
- **How enforced:** `besteffort.Run`/`RunRecover` are the one place panic
  recovery, failure logging, and the `keyorix_best_effort_failures_total`
  metric live, so every call site gets all three instead of re-deriving
  (or, as happened repeatedly, omitting the panic half of) its own copy.
  The metric itself makes a swallowed failure observable — before this
  package, a swallowed error went nowhere and a panic went to the generic
  per-request recovery middleware's log line with no per-step signal.
- **The boundary this rule does NOT cover:** §4's audit-before-disclosure
  is the explicit, named counter-example — wrapping that step in
  `besteffort` would silently turn a required, contract-bearing write into
  an optional one.

## 8. Column-scoped writes, not whole-row `Save`

**Rule:** an operation that reads a row, checks something about it, and
then persists a change writes only the columns it actually owns, through a
conditional `UPDATE` — never GORM's `Save` (which upserts the entire
pre-read row and can resurrect a soft-deleted row) or
`Select("*").Updates` (which reverts every column a concurrent, narrower
writer changed in between).

- **Why:** the C-RACE-FIX-B campaign (#2648, #2650, #2653, #2654) found
  this exact cross-replica lost-update shape across multiple operations: a
  whole-row write silently clobbering a concurrent writer's narrower
  change, or resurrecting a row another replica had just soft-deleted.
- **How enforced:**
  `internal/core/guards/column_scoped_write_guard_helpers_test.go` provides shared
  `go/ast` helpers so each fixed operation gets its own guard asserting
  the column-scoped shape on the source directly — stated honestly in the
  helper's own header: it walks one function body syntactically,
  recognizes `<expr>.Name(...)` calls, does not follow calls into other
  functions (each guard names every hop explicitly), and does not evaluate
  a non-literal `Select` argument. A full enumeration of every GORM
  `Save`/`Select("*").Updates` call site across the tree — not just the
  four fixed operations — is the natural next step if this guard's
  coverage needs widening; it is not claimed as exhaustive today.
- **Example (anti-pattern avoided):** reading a secret-share permission
  row, checking its grantee, then calling `db.Save(&row)` to update one
  field writes back every other field as it was read — including
  `deleted_at`, resurrecting the row if a concurrent request soft-deleted
  it in between. `share_permission_column_scoped_guard_test.go` guards
  this specific operation's shape.

## 9. Input size caps on every attacker-reachable body

**Rule:** every HTTP handler that decodes a request body is bounded by
`server/middleware.MaxBodyBytes` (via `http.MaxBytesReader`) before the
handler's own decode runs — a cap below which a handler-specific limit
(e.g. a tighter secret-value size cap) may further narrow, never widen.

- **Why:** an unbounded `r.Body` read lets an attacker force the server to
  buffer an arbitrary amount of data per request — a cheap memory-
  exhaustion denial-of-service with no authentication required, since body
  size can be checked before any auth decision completes.
- **How enforced:** `server/middleware/body_limit.go`'s `MaxBodyBytes`
  wraps `r.Body` in `http.MaxBytesReader`; exceeding the cap fails the read
  (handler sees a decode error, a 4xx) and the server responds 413.
  Secret-value-specific caps are tested directly in
  `server/http/handlers/secret_size_cap_test.go`, and the JSON-decode path
  itself is fuzzed for bounded work in
  `server/http/handlers/json_decode_boundedwork_fuzz_test.go` (confirming
  decode cost scales with the capped size, not with attacker-controlled
  structure inside it).
- **Example:** a handler that calls `json.NewDecoder(r.Body).Decode(&v)`
  without the body-limit middleware ahead of it in the chain is exactly
  the gap this rule closes — the decode itself has no size awareness, so
  the cap has to come from the transport layer, not the handler.

## 10. Connector and rotation-target rules

**Rule:** every outbound call to an external connector, KMS, or rotation
target (AWS/Azure/GCP SDKs, Vault, Postgres/MySQL rotation targets) is
scoped to `(scope, project, environment)`, checked against a per-connector
`allowed_refs` allowlist, and passes through SSRF/link-local address guards
before the request leaves the process — regardless of which SDK or
hand-rolled HTTP client is making the call.

- **Why:** this is boundary **B7** in [`threat-model.md`](threat-model.md)
  §4 — the exact class that already produced one real, shipped, fixed
  path-traversal vulnerability in `rotation_ref` handling, now additionally
  denylist-validated at configuration time. The task brief this document
  was drafted from referred to this as "connector host" rules under an
  "ADR-111, proposed" — **no such ADR, and no "connector host" concept
  (a dedicated execution sandbox for connector code) exists anywhere in
  this repo** as of this writing (confirmed by a repo-wide search for the
  term). The rules below describe the real, shipped architecture — scoped
  authorization and SSRF guarding at the call site — not a sandboxed host
  that was never built. If an isolated connector-host execution model is
  actually planned, that's a real gap worth its own ADR, not something to
  describe here as already existing.
- **How enforced:**
  - [ADR-082](../adr-082-connect-connector-tenant-scoping.md) — tenant
    scoping, ownership enforcement, `ListConnectors` filtering by the
    caller's authorized scope, and a dedicated `connect.platform.use`
    permission gated as a terminal deny with no delegation fallback.
  - `internal/netutil` + `internal/core/dynamic_secrets_ssrf_test.go` +
    `internal/core/admin_dsn_ssrf_fuzz_test.go` — link-local/NAT64 address
    guards on outbound connector/dynamic-secret calls, actively fuzzed
    (`FuzzAzureGenerateUpstreamRef`, `FuzzPostgresQuoting`,
    `FuzzMySQLQuoteString`).
- **Example (the real, fixed historical instance):** `rotation_ref`
  handling once allowed a path-traversal-shaped reference to reach a
  rotation target; the fix added denylist validation at configuration time
  in addition to the runtime SSRF guards, closing both the
  configuration-time and the request-time half of the same class.
