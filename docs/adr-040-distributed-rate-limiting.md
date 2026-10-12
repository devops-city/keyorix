# ADR-040: Cluster-wide login rate limiting

**Status:** Accepted
**Date:** 2026-06-12

## Context

Login brute-force protection was an in-process, in-memory sliding window: a
`map[ip][]time.Time` in the HTTP auth handlers, capping failed attempts at 10 per
IP per 15 minutes. The HA work (ADR-039) flagged this as the one remaining
per-replica gap: with N stateless replicas behind a load balancer, the limit is
enforced *independently* on each replica, so an attacker spreading attempts across
replicas gets up to N× the budget. The recommended mitigation was a gateway/WAF,
but Keyorix should be secure-by-default on-prem without requiring one.

## Decision

Move the limiter into the database so the count is shared across replicas.

- **`login_attempts` table** (`id`, `ip`, `attempted_at`) with a composite
  `(ip, attempted_at)` index. A failed attempt inserts a row; the gate counts an
  IP's rows within the window across the whole cluster.
- **Core API** (`internal/core/rate_limit.go`): `RecordFailedLogin(ctx, ip)`,
  `IsLoginRateLimited(ctx, ip)` (count ≥ `LoginMaxAttempts=10` within
  `LoginWindow=15m`), and `PruneLoginAttempts(ctx)`. The HTTP handlers' old
  free-function limiter is replaced by thin `AuthHandler` methods that delegate
  here — every login surface (password, TOTP verify, WebAuthn second-factor, and
  passwordless) now shares one cluster-wide limit.
- **Fail-open.** *(Superseded 2026-10-10: see the storage-error amendment below.)*
  A storage error in `IsLoginRateLimited` returns `false` (allow).
  Rate limiting is a *backstop* layered on the real password/passkey check, not the
  auth gate itself; a transient DB hiccup must not lock every user out. Recording
  is best-effort for the same reason.
- **Bounded growth.** An always-on, single-replica-gated (ADR-039) maintenance
  goroutine prunes rows past the window on a fixed interval shorter than an hour
  (**corrected 2026-09-07** — this previously said "hourly"; the actual registration
  is `runScheduler(ctx, "login_attempt_prune", 15*time.Minute, ...)`,
  `server/main.go`), independent of the opt-in retention
  purge scheduler — the limiter table must stay bounded even when purge is off.

**Amendment (2026-10-10, #2936).** F2 (2026-09-20) moved the write to *before*
the credential check, to stop a concurrent burst from outrunning the count, and in
doing so started charging successful logins too, which locked whole offices and
demo laptops out. The write still happens up front, but it is now a releasable
reservation: a request that delivers a session (login, MFA verify, passkey finish,
refresh, setup-link consume) deletes its own row, so in net only failures stay
counted, as this ADR originally stated. A step that does not finish its flow (the
password step of an MFA login, a passkey `begin`) keeps its row while the flow is
open, with the row's id stored on the single-use MFA challenge or ceremony row
that carries the flow forward; the step that delivers the session deletes those
rows too, exactly once. A failed, expired or abandoned flow keeps every row it
wrote. Host-side override:
`keyorix-server admin clear-login-lockout --ip ADDR`.

**Amendment (2026-10-10, AUTH-AUDIT-1; #3023 for the login budget, then every
budget).** The fail-open bullet above is replaced. No auth budget fails open or
closed on a storage error. Every budget goes through one shared limiter
(`internal/core/auth_budget.go`):
- the per-IP `login`, `password_reset` and `sso_begin` budgets in this table;
- the per-account lockout (the user row's lockout columns), which is the only
  bound on step-up and recovery-code guessing.

The stored count stays primary. When it cannot be read or written, the attempt
is counted in that budget's own bounded in-memory limiter, with the same limit and
window and the same key (canonical client IP, or account id). The check adds the
in-memory count to the stored one. Each fallback is audited `auth.rate_limit_error`
and counted in `keyorix_auth_rate_limit_fallback_total{budget}`. The client sees
the same response.

The in-memory limiter is per process. During an outage each replica enforces its
own copy. `security.auth_rate_limit_fallback.replicas` (default 1) divides every
in-memory limit by the replica count, never below one attempt, so the cluster
stays near the normal limit. Left at 1 with N replicas, the outage-time bound is
up to N times the limit, which is still a bound, where fail-open had none. A
stored count that could be read is cluster-wide already and keeps the normal
limit.

While the password-reset budget is on its fallback it is tighter: half the per-IP
limit, plus a per-account cap on reset emails, refused silently so the response
does not change. `/health` reports `auth_rate_limit: degraded` while any budget
has fallen back within its window, and names no budget, key or address.

After recovery the stored count is authoritative again. The in-memory attempts
age out with the window and are never merged into the table.

Guards: `TestAuthBudgetStorage_OnlyThroughTheSharedLimiter` (no `login_attempts`
access outside the limiter) and `TestEveryAuthRoute_IsClassifiedAndBudgeted`
(every `/auth/` route in `router.go` is budgeted, authenticated or explicitly
exempt). `TestEveryAuthBudget_HoldsWithItsStorageDown` is the storage-fault sweep:
every budgeted route still answers its normal 429, byte for byte.

## Why the write volume is acceptable

A row is written only on a *failed* attempt, and the gate is checked *first*: once
an IP reaches the budget it is rejected **before** another row is recorded. So a
single attacking IP writes at most ~`LoginMaxAttempts` rows per window before being
throttled. A distributed attack writes proportionally to the number of distinct
IPs — that broad case is still best handled at the gateway (noted below), but the
common single-IP / small-botnet brute force is now bounded cluster-wide by Keyorix
itself.

## Consequences

- The limit now holds across replicas — the ADR-039 per-replica gap is closed for
  the single-IP/small-botnet case.
- Each login does one indexed `COUNT` (and a failed one, one `INSERT`). Login is
  far less frequent than secret reads, so the added DB work is negligible.
- SQLite (single instance) works identically — it is just a table.

## Deferred

A truly distributed (many-IP) brute force, and request-rate limiting in general,
are still best enforced at the load balancer / API gateway / WAF — this ADR
hardens the credential-stuffing case, it does not replace edge rate limiting.
Per-account (not just per-IP) lockout; exponential backoff; CAPTCHA challenge.

## Verification

Core tests over SQLite: an IP is allowed under the budget and blocked at it; a
different IP is unaffected; attempts age out of the window; an empty IP is never
limited; prune removes aged rows. `make build` + full suite + `go vet` green.

## Addendum (2026-07-05): closing the gap under storage.type: remote

ADR-049 lets a Keyorix server itself run with `storage.type: remote` — a chained
deployment proxying every storage call to an upstream Keyorix server over HTTP.
`RemoteStorage` originally had no server endpoint to proxy
`RecordLoginAttempt`/`CountRecentLoginAttempts`/`PruneLoginAttempts` to at all, so
this ADR's rate limiter was a silent, permanent no-op for the whole life of the
process under that backend (#452); a later round (#675) closed the *silent* half by
logging a loud one-time operator warning, but left the underlying gap itself open,
deliberately deferred pending further investigation into whether a real proxied
endpoint was actually achievable without a disproportionate new authorization model.

It was: the upstream API a `RemoteStorage` client already authenticates against for
every other proxied call (full user CRUD, secret CRUD, ...) requires a credential
with far broader privilege than "record/count an IP's recent login attempts" would
ever need, so three new endpoints —
`POST /api/v1/system/login-attempts`,
`GET /api/v1/system/login-attempts/count`,
`POST /api/v1/system/login-attempts/prune` — were added
(`server/http/handlers/login_attempts_proxy.go`, registered in
`server/http/router.go`), gated on the same pre-existing `system.read`/
`system.write` RBAC permissions every other admin-level route in this codebase
already uses. They are thin passthroughs onto this ADR's own
`login_attempts` table via `storage.Storage`'s primitives — no rate-limiting policy
decision is made server-side; the calling server's own `internal/core.KeyorixCore`
still decides the threshold/window, exactly as it does against a local backend.
`RemoteStorage.RecordLoginAttempt`/`CountRecentLoginAttempts`/`PruneLoginAttempts`
(`internal/storage/store/remote_login_attempts.go`) now make real HTTP calls
instead of stubbing out.

A downstream server's forwarded IP shares one cluster-wide budget per key with the
upstream's own direct end-user traffic for that same key (both use the identical
table/columns password-reset rate limiting already shares via its `pwreset:` key
prefix) — the same abusive client IP hitting either front door is the same abuse,
not a conflation of unrelated data.

Verified end-to-end against the REAL production router (not a protocol mock):
`server/http/remote_storage_login_rate_limit_test.go` builds an "upstream" via the
actual `NewRouter`, points a real `store.RemoteStorage` at it as a "downstream"
server's storage, and drives repeated failed logins through
`core.KeyorixCore.RecordFailedLogin`/`IsLoginRateLimited` to prove the Nth attempt is
genuinely throttled.
