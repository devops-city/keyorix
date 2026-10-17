# Read-path caching (PERF-3)

PERF-3's brief: get the per-secret-read DB round-trip count down as close to "zero except
the audit write" as the NON-NEGOTIABLE invariants allow. This is item 1 (spec first). Built
by reading the three hot read paths directly (`internal/core`, `server/middleware/auth.go`,
`server/http/handlers`, `cli/`), cross-referenced against PERF-2's pprof/pg_stat_statements
data (`~/proj/bench-footprint/results/2026-10-03-perf-2/`).

Audit-before-disclosure (a secret value is never returned before its audit record is
durable) and immediate cross-replica revocation (#G18: a revoked token/session/role stops
working on the very next request, on every replica) are NON-NEGOTIABLE. Every cache below
is designed so neither invariant can regress — see "Failure mode" at the end before judging
any one cache in isolation.

## Headline finding, before the query inventory

**The three hot paths are not equally optimized today.** The machine-token path already
got a consolidation pass (#2403/SESSION-PERF): the secret row is resolved exactly once per
request and reused by both the authorization check and the handler. The session path —
and, because of how CLI authenticates, the **PAT path, which is what the CLI actually uses**
— never got that pass. A session- or PAT-authenticated `GET /api/v1/secrets/{id}` fetches
`secret_nodes` up to ~4–5 times and runs two independent, DIFFERENT authorization functions
end to end: the route gate (`RequireScopedSecretPermission` → `AuthorizeSecretPrincipalForSecret`
→ `AuthorizeSecret`, which only consults SecretACL + project RBAC) and the handler
(`GetSecretWithPermissionCheck` → `CheckSecretPermission`, which ALSO consults ownership and
share grants). Because the gate runs first and denies outright on `false`
(`finishScopedPermissionRequest`, `server/middleware/auth.go:874-878`, never reaches
`next.ServeHTTP` on deny), the handler's broader check is structurally unreachable on this
route for a user whose ONLY grant is ownership or a share — see "Finding outside this
session's scope" below. This session does **not** attempt to merge or redesign that
authorization split (an authz-boundary change needs an ADR first, not a performance pass —
see `keyorix-private`'s own authz-design guidance); instead, every cache below targets the
underlying **data** (secret metadata, role→permission mappings), not the **decision**, so
the redundant second authorization pass on the session/PAT path gets dramatically cheaper
without either path's set of allowed callers changing by one byte.

CLI implication: `cli/` is a thin OpenAPI-client wrapper (`cli/internal/apiclient`,
`cli/cmd/client.go:57`) with no embedded core and no separate code path — it attaches
whatever credential is in `~/.../credentials.yaml` as a Bearer token and hits the same HTTP
routes a browser session or a machine identity would. Most real CLI usage authenticates with
a PAT, which runs the middleware's PAT branch (closely mirroring the machine branch — see
§1 below) but the **handler's un-optimized non-machine branch** (§2 below), because
`isMachine` is keyed strictly on `MachineIdentityID != nil`, which a PAT-authenticated
`UserContext` never sets. So "the CLI read path" in practice means: PAT auth (cheap) +
session-shaped handler resolution (expensive). The caches below benefit it exactly as much
as the session path.

## 1. Machine-token read: query inventory (steady state, cache hit)

Route: `GET /api/v1/secrets/{id}?include_value=true`, `Authorization: Bearer kx_machine_...`.

| # | Query | Table(s) | Predicate | Type | Every request? |
|---|---|---|---|---|---|
| 1 | `CurrentMachineTokenRestriction` (`server/middleware/auth.go:45` via `local_machine_credentials.go:45`) | `machine_identity_credentials c JOIN machine_identities m` | `c.token_hash = ?` | SELECT | **Yes — live revocation re-check, see §4** |
| 2 | `TouchMachineTokenLastUsed` (`local_machine_credentials.go:145`) | `machine_identity_credentials` | conditional `UPDATE ... WHERE id=? AND (last_used_at IS NULL OR last_used_at < cutoff)` | UPDATE | Issued yes, writes no (throttled) |
| 3 | `GetSecret` (route gate, `auth.go:721`) | `secret_nodes` | `id = ?` (PK) | SELECT | Yes — **cacheable, §PR-1** |
| 4 | `GetMachineRoleIDsAt` (`local_machine_credentials.go:206`) | `machine_identity_roles LEFT JOIN projects LEFT JOIN environments` | `machine_identity_id=?` AND project/env scope match | SELECT | Yes — left live, see §Design decisions |
| 5 | `RoleSetHasPermission` (`local_rbac.go:806`) | `permissions JOIN role_permissions` | `role_permissions.role_id IN (?) AND permissions.name = 'secrets.read'` | SELECT (COUNT) | Yes — **cacheable, §PR-2** |
| 6 | `GetSecretAccessSchedule` (`secret_schedule.go:31`) | `secret_access_schedules` | `secret_node_id = ?` | SELECT | Yes — **cacheable, §PR-1** |
| 7 | `GetLatestSecretVersion` (`versions.go:122`) | `secret_versions` | `secret_node_id = ?` + latest | SELECT | Yes — **cacheable, §PR-1** |
| 8 | `TryIncrementSecretNodeReadCount` / `TryIncrementSecretReadCount` (`local_secrets.go:1020,1006`) | `secret_nodes` / `secret_versions` | conditional UPDATE, `max_reads` gate | UPDATE | Only if `MaxReads` set (most secrets: never) |
| 9 | `LogAuditEventWithAccessLog` (`local_audit_chain.go:207`) | `audit_events` + `secret_access_logs` | — | 2 INSERTs, one transaction, one fsync | **Always — the one write this plan does not touch** |

Decrypt (`DecryptSecretWithAAD`, `secret_value_crypto.go:68`) is **not a DB query** — see §5.

Already-optimized: the route gate pins its one `GetSecret` resolution on the request
context (`WithResolvedSecret`); the handler's machine branch reuses it, so there's no 2nd
fetch today on this path specifically.

## 2. Session / PAT (= CLI) read: query inventory

Auth middleware is the structural analog of row 1/2 above (`AccountUsabilityAndState` +
`SessionLiveForToken` for sessions; `CurrentPATRestriction` for PATs — same "live re-check
every hit" shape, §4).

Route gate: identical to machine's rows 3–5 (`GetSecret` + `AuthorizeSecret`, which adds a
`HasSecretACL` lookup — `secret_acls` + up to 20 levels of `GetSecretAncestors` walk — before
falling back to the same RBAC resolution as row 4/5, but through `scopedRoleIDs`
(`GetUserRoleIDsAt` + `GetUserGroupRoleIDsAt`, **two** queries where the machine path has
one) instead of `GetMachineRoleIDsAt`).

Handler: `GetSecretWithPermissionCheck` → `CheckSecretPermission` (`permissions.go:104`) runs
ALL of the following **again, independently**, because nothing pins the gate's resolution
for this branch:

- `storage.GetSecret` (2nd fetch)
- `requireLiveOwnerAuthority` → `IsProjectMember` (2 queries: direct + via-group)
- `ListSharesBySecret` (`share_records`)
- `CheckGroupPermissions` → `GetUserGroupsAt`
- `HasSecretACL` again (full ACL + ancestor-walk repeat)
- RBAC fallback again: `GetUserRoleIDsAt` + `GetUserGroupRoleIDsAt` + `RoleSetBypassesPermissionChecks` + `RoleSetHasPermission`
- `checkSecretAccessSchedule` → `GetSecretAccessSchedule`
- `c.GetSecret` (3rd fetch)

If `include_value=true`: `GetSecretValueWithPermissionCheck` runs the **entire block above a
second time** (4th–8th `GetSecret` fetch) before `getSecretValueForUser` does one more
(`storage.GetSecret`, 9th) → `GetLatestSecretVersion` → decrypt. Audit write: identical to
machine row 9.

**This is why §PR-1/PR-2 below benefit the session/PAT/CLI path far more than the raw
query count on the machine path suggests** — the same handful of underlying rows
(`secret_nodes`, `secret_versions`, `secret_access_schedules`, the `role_permissions` join)
are each refetched several times per request on this path; caching them collapses most of
that 9-fetch chain into cache hits without touching a single authorization decision.

## 3. CLI read path

Confirmed: no separate code path. `cli/cmd/secret_crud.go` → generated OpenAPI client →
`GET /api/v1/secrets/{id}` or `GET /api/v1/secrets/value?ref=...` with whatever credential
is stored. PAT is the common case for non-interactive/CI use (machine tokens are typically
reserved for application workloads, not operator CLI use) — see §2 for why that's the
*expensive* branch despite being a bearer-token auth. One pre-existing, independent gap
noted for completeness (not fixed here, out of scope): `GetSecretValueByRef`'s machine
branch calls `GetSecretValue` (not `GetSecretValueResolved`), so it does one avoidable extra
`GetSecret` fetch even on the "already optimized" machine path specifically for by-ref
reads. Flagging so a future session's cache-hit-rate numbers aren't surprised by it.

## 4. Why immediate cross-replica revocation needs no shared cache today — and what that means for new caches

`server/middleware/auth.go`'s `tokenCache` is **in-process only** — no Redis, no DB-backed
cache table, nothing shared across replicas. It is correct across replicas because it
**never caches the revocation decision**: `serveAuthCacheHit` re-reads, live, on every
single hit, from every replica, the one column set that can make a token/session invalid
(`CurrentPATRestriction`, `CurrentMachineTokenRestriction`, `AccountUsabilityAndState` +
`SessionLiveForToken`). `InvalidateAllMachineTokenCache`/`InvalidateTokenCacheByHash` are a
latency optimization on top of a mechanism that was already correct without them — not the
source of correctness. Full contract: `server/middleware/INVARIANTS.md` INV-MW-01 through
INV-MW-11.

**Design decision this spec adopts: do the same thing for the two new caches below.**
Neither PR-1 (secret metadata) nor PR-2 (principal permissions) caches a security decision.
PR-1 caches rows that are read-only data, not an authorization outcome — a cache hit still
flows through the exact same `AuthorizeSecret`/`AuthorizePrincipal` call it does today; only
the *data* those calls and the handler consume is served from cache. PR-2 caches a
role-set → permission mapping (`role_permissions`), not "does principal X have permission
Y" — a principal's *role membership* (`GetMachineRoleIDsAt`/`scopedRoleIDs`/`GetUserGroupRoleIDsAt`)
is deliberately left UNCACHED, live-read every request, exactly like the auth layer leaves
revocation state live. Role grant/revoke is the operation #G18 cares about most directly (a
removed role must stop authorizing immediately); keeping role membership resolution live
means a cache bug in PR-2 can at most make permission *checks* for roles a principal legitimately
and currently holds briefly stale by one generation-check round trip — it structurally cannot let a
revoked role keep authorizing, because the role list itself is never cached.

Both new caches still need **generation-based invalidation** for the data they do cache
(the row/mapping itself can be stale if the cache isn't invalidated when the underlying row
changes), described per-cache below. The precedent for a generation counter already exists
in this codebase (`machineCacheGen`, `auth.go:222`) but it is process-local and solves a
different problem (bulk-invalidate when exact keys are unknown); PR-1/PR-2 introduce the
first **persisted** (DB-column/table) generation counters, checked on every cache hit via one
cheap, indexed read — never trusted blindly across process restarts or multiple replicas.

## 5. Unwrapped DEKs — dropped from this spec's scope

There is no per-read DEK unwrap to cache. `internal/encryption`'s two-tier KEK/DEK scheme
unwraps the DEK exactly once per process, at `Service.Initialize` (`service.go:57-80`): KEK
(from whichever provider — passphrase/KMS/Shamir/TPM) unwraps the on-disk wrapped DEK, the
KEK is wiped immediately, and the unwrapped DEK is held in `EncryptionService` for the
process lifetime (`keymanager_lifecycle.go`). Every read's decrypt
(`DecryptSecretWithAAD`) is an in-memory AES-256-GCM op against that already-resolved DEK —
no KMS/KEK round trip, no per-secret wrapped key (`SecretVersion.EncryptedValue` +
`EncryptionMetadata` only — confirmed no per-secret key material field exists). This matches
PERF-2's own H4 rule-out (DEK/crypto cost absent from the CPU profile's top ~20 nodes). The
only operations that touch the KEK/DEK boundary again are operator-triggered, rare, and
already serialized (`RotateDEKWithSweep`, `RewrapDEK*`, both behind the exclusive key lock) —
not a per-request concern. **Recommendation: do not build a DEK cache; there is nothing to
cache.** Budget reallocated to PR-1/PR-2 and the H3 raw-query work below.

## 6. H3 — prepared raw queries (item 3)

Targets, ranked by PERF-2's own pg_stat_statements capture (clean, c=50): the credential
JOIN (row 1, 93.5ms mean outlier on the `last_used_at` UPDATE specifically — contention, not
a raw-query candidate — but the paired SELECT half of that JOIN is a good candidate), the
`secret_nodes` fetch (row 3, 20,291 calls), and the `audit_events` INSERT (row 9, highest
call count of any statement, 10.3% of total query time per-call despite being individually
cheap). GORM's reflection-based scanning (`reflect.Implements`, `gorm.io/gorm.Scan`) was a
real double-digit-percent CPU cost in PERF-2's profile; these three are the highest-call-count
queries, so a per-call win compounds the most here. Approach: keep the GORM model as the
source of truth (per this repo's "generate/derive, don't duplicate" principle); add a
hand-written `database/sql` prepared statement behind the SAME storage-interface method, a
feature-gated or build-time choice between the two implementations, and a differential test
(fuzzed inputs, including zero/negative/overflow IDs and the AAD-metadata edge cases) that
asserts byte-identical results between the GORM path and the raw path for every input the
fuzz corpus generates. Lands as its own PR after PR-1/PR-2 land (depends on their final
query shapes, since a cache hit means these queries run less often — raw-query work should
target the queries that still fire on a cache MISS, which is PR-1/PR-2's actual implementation,
not the read-path code as it exists today).

## PR-1: secret metadata cache

**Cache**: `secret_nodes` row + latest `secret_versions` row + `secret_access_schedules` row
for a given secret ID. **Key**: secret ID. **Invalidation**: new column
`SecretNode.CacheGeneration uint64` (`gorm:"not null;default:0"`), bumped
(`UPDATE secret_nodes SET cache_generation = cache_generation + 1 WHERE id = ?`) in the SAME
transaction as any write that changes cached data for that secret: `UpdateSecret`,
`updateSecretWithNewVersion`/`RotateSecret` (new version), `SetSecretAccessSchedule`/schedule
change, soft-delete/restore, `TryIncrementSecretNodeReadCount`'s own read-count write (since
`MaxReads` state is part of what's cached). A cache hit re-reads ONLY
`SELECT cache_generation FROM secret_nodes WHERE id = ?` (one cheap indexed PK lookup) and
compares against the cached generation; a mismatch (or a missing row — deleted) is a miss,
falling through to a full live read of all three rows. **This still leaves exactly one DB
round trip per cache hit** (the generation check) — true zero round trips would need a
push-invalidation channel (e.g. Postgres LISTEN/NOTIFY) this spec deliberately does not
propose, because a dropped/reconnecting LISTEN connection with no reconciliation step is a
silent staleness window on a NON-NEGOTIABLE invariant, and this repo's own precedent
(INV-MW-10: fail CLOSED by flushing everything on any uncertainty) argues for the cheap,
always-correct generation-check round trip over a push mechanism's edge cases. Max-reads
counters remain live per-request UPDATEs (never cached) — they are mutated on the read path
itself, so caching them would race the very operation that invalidates them.

**Tests per cache (COMMON-RULES/brief requirement)**:
- Two-pool Postgres cross-replica test (pattern: `internal/core/postgres_contention_helpers_test.go`'s
  `pgOpen`/`pgIsolatedSchemaDSN`, `concurrency_race_harness_test.go`'s `raceReplicas`): replica
  A updates a secret's value/schedule; replica B's very next read (own cache, own DB pool,
  shared schema) must observe the new generation and the new data, never the stale cached row.
- A permission-removal-adjacent case for this cache specifically: access-schedule removal
  (read window closes) takes effect on the very next read on every replica.
- Fail-closed test: a forced generation-check read error (fault-injected) must fall through
  to a live full read, never silently serve a stale cached row and never panic.
- Benchmark: cache hit vs miss, and the 3-fetch-collapsed-to-1-cheap-check shape under the
  W1/W2 loadgen shapes already in `~/proj/bench-footprint`.

## PR-2: principal permissions cache

**Cache**: the `role_permissions` → `permissions` join result, i.e. "does this exact
role-ID set grant permission P" (mirrors `RoleSetHasPermission`'s own signature:
`(roleIDs []uint, permission string) bool`). **Key**: `(sorted(roleIDs), permission)`.
**Invalidation**: a single GLOBAL generation counter — role-permission edits (admin assigns
or revokes a permission from a role) are rare, install-wide, admin-only actions, so a global
counter is both simplest and safest (no per-role invalidation-key bug can under-invalidate).
Stored as a `SystemMetadata` row (`key="role_permissions_generation"` — reuses the existing
generic key/value table, no new migration) bumped in the same transaction as any
`role_permissions` INSERT/DELETE. A cache hit reads
`SELECT value FROM system_metadata WHERE key = 'role_permissions_generation'` (one PK lookup)
and compares; mismatch = miss, falls through to the live join. Role **membership**
(which role IDs a principal currently holds) is explicitly NOT cached here — see §4's design
decision — so a role grant/revoke is immediately live via the existing, unchanged
`GetMachineRoleIDsAt`/`scopedRoleIDs` calls; only the comparatively static role→permission
mapping benefits from caching.

**Tests**:
- Permission-removal-takes-effect-immediately: revoke a permission from a role on replica
  A; replica B's very next `RoleSetHasPermission`-driven authorization for a principal
  holding that role must deny on the next request (role GRANT itself was never cached, so
  this isolates the mapping-cache's own invalidation specifically).
- Two-pool Postgres cross-replica test, same harness as PR-1.
- Fail-closed test: generation-check read error falls through to the live join, never
  serves a stale permission grant and never fails open.
- Differential: cached vs cache-bypassed `RoleSetHasPermission` must agree for a fuzzed set
  of role-ID combinations and permission names, mirroring `FuzzAuthCacheDifferential`'s
  existing pattern (`server/middleware/authcache_differential_fuzz_test.go`) rather than
  inventing a new oracle shape.
- Benchmark: hit/miss, under the same W1/W2 loadgen shapes.

## PR-3 (optional, time-permitting): formalize the existing token/session validity cache's documentation

No code change proposed — `server/middleware`'s existing cache already satisfies "generation
counter, checked per request, fails closed, immediate cross-replica revocation" for
authentication (INV-MW-01 through INV-MW-11 and `machineCacheGen`). If time remains after
PR-1/PR-2/H3, this becomes a docs-only PR cross-linking those invariants from this spec and
seeding 1-2 rows into `docs/adr-conformance-enforced.tsv` (that file's own cross-cutting note
flags zero rows for `server/middleware` despite several real, tested properties) — not a new
mechanism.

## Failure mode (applies to every cache above)

A cache read error (corrupt entry, type assertion failure, a generation-check query itself
failing) is **always** treated as a miss: fall through to the full live read/join, exactly
as a cold cache would. Never serve a cached value past an error, and never deny a request
because the cache layer errored when the underlying live path would have succeeded — the
cache is strictly an optimization on top of a path that must work identically with the cache
removed entirely. (This once cited `server/middleware/auth.go`'s cache-hit degrade
behavior, INV-MW-05's former transient half, as the same principle. Since
CACHE-FAILCLOSED-1 a failed cache-hit re-check of a credential's revocation state refuses
the request with 503 instead — INV-MW-cache-hit-recheck-fails-closed — which is still the
same principle: the live slow path would also answer 503 when it cannot read the
credential.)

## Finding outside this session's scope (recorded for the coordinator, not fixed here)

The route-gate-vs-handler authorization mismatch described in the headline finding above
(`AuthorizeSecretPrincipalForSecret`/`AuthorizeSecret`, gate-only, checks SecretACL + RBAC;
`CheckSecretPermission`, handler-only, additionally checks ownership + shares; the gate denies
first and the handler's broader check is therefore unreachable on `GET /secrets/{id}` and
every other route under `RequireScopedSecretPermission`) may or may not be a live, exploitable
gap — `ShareSecret` requires the recipient to already be a project member
(`IsProjectMember`, itself defined as holding SOME `UserRole` at that project scope), so in
a deployment where every assignable role includes baseline `secrets.read`, the gate would
pass for the same reason the handler's extra ownership/share check would never have mattered.
Whether a role WITHOUT `secrets.read` can still satisfy `IsProjectMember` (making a pure
share-only or ownership-only grant currently return 403 at the gate despite the handler's own
code believing it should be allowed) was not run to ground — it needs its own investigation,
and since it concerns the **authorization decision** (who is allowed), not read-path data
caching, it should NOT be fixed as a side effect of this plan's caches. `authz_share_parity_test.go`
exists and pins HTTP/gRPC parity for share CREATE and LIST, but has no case for share-based
*read* access with a recipient holding no RBAC grant beyond bare project membership —
recommend a dedicated session with an ADR-first authz review, not a PERF-3 side patch.
