# ADR-039: High-availability deployment (multiple API replicas)

**Status:** Accepted
**Date:** 2026-06-12

## Context

Enterprise and on-prem buyers (the ENS/ENISA track) expect to run Keyorix
highly-available: several stateless API replicas behind a load balancer, backed by
an HA PostgreSQL. Most of the server is already replica-safe — sessions and tokens
are DB-backed, the per-replica token/session caches are short-TTL and
stale-tolerant, and the audit hash chain already serializes appends with a
PostgreSQL advisory lock (ADR-029). Two gaps remained:

1. **Encryption keys** were derived from a local passphrase + on-disk salt, which
   each replica would have to reproduce. (Solved by ADR-038: a `file` or `env` KEK
   provider lets every replica read the same externally-managed KEK.)
2. **Background schedulers** (anomaly detection, retention purge, dynamic-secrets
   auto-revoke) ran unconditionally on *every* replica — so N replicas duplicated
   the work: N copies of each anomaly alert, concurrent purge DELETEs, and N
   replicas connecting to the same target databases to revoke the same expired
   leases. None corrupts data (the operations are idempotent), but it is wasteful
   and operationally noisy, and the lease sweep could storm target DBs.

## Decision

Run each background scheduler on **one replica at a time**, gated by a PostgreSQL
**advisory lock**, and document the supported HA topology.

- **Scheduler singleton lock.** `Storage.WithSchedulerLock(ctx, key, fn)` runs `fn`
  only if this process can take the advisory lock `key`. On PostgreSQL it uses a
  session `pg_try_advisory_lock` on a dedicated pooled connection (released with
  `pg_advisory_unlock` before the connection returns to the pool); if another
  replica holds it, the call returns `ran=false` and the tick is skipped. On
  SQLite (inherently single-instance) `fn` always runs. Each of the three
  schedulers uses a distinct, namespaced key, separate from the audit-chain key.
  This is **per-tick** gating — no long-lived leader, no leader-death handling: if
  the running replica dies, the next replica simply wins the next tick.
- **Shared KEK.** For multiple replicas, configure
  `storage.encryption.key_provider` as `file` or `env` (ADR-038) so every replica
  unwraps the same DEK. The default `password` provider also works if every
  replica is given the same `KEYORIX_MASTER_PASSWORD` *and* shares the `kek.salt`
  file — but file/env is the recommended HA path (no shared filesystem needed).
- **DEK epoch (#3337).** Every replica must hold the same DEK. The database records
  which DEK it is encrypted under (`system_metadata["dek.epoch"]`, ADR-010 addendum); a
  replica with another DEK refuses to start, and a DEK rotation fences encrypted writes on
  every replica until it commits. After a rotation, copy the new `dek.key` to every
  replica that does not share the key volume before starting it.
- **PostgreSQL is required for HA.** SQLite is a single-file, single-process store;
  it is supported only for single-instance / development. HA = PostgreSQL (itself
  made HA by the operator: managed Postgres, Patroni, or similar).

## Topology

```
        ┌─ load balancer ─┐
        │        │        │
     replica  replica  replica     (stateless API; identical config)
        └────────┼────────┘
            HA PostgreSQL           (sessions, secrets, audit chain, lock)
                 │
         external KEK source        (KMS / CSI / sealed secret → file or env provider)
```

All replicas are interchangeable. One holds each scheduler's advisory lock at any
moment and does the periodic work; the rest serve API traffic and skip the job.

## Consequences & caveats

- **Per-replica state that is acceptable**: the 30-second token/session caches and
  the negative-auth cache are process-local but short-lived and stale-tolerant —
  eventual consistency within the TTL is fine for session tokens (which are
  revocable and DB-authoritative).
- **Login rate limiting is per-replica** (an in-memory sliding window). Across N
  replicas an attacker could get up to N× the per-replica budget by spreading
  attempts. For HA, enforce login/auth rate limits at the **load balancer / API
  gateway / WAF**, or treat the per-replica limit as a backstop. Documented, not
  yet centralized.
- **No data-loss risk from the schedulers either way**: the gating is an
  efficiency/cleanliness improvement; the underlying operations were already
  idempotent (status checks on revoke, soft-delete cutoffs on purge).
- **A rolling upgrade that bumps the schema epoch (ADR-097) transiently
  CrashLoopBackOffs any replica still on the old binary once a sibling has
  migrated.** This is a real, known gap in this topology — see
  [`docs/SELF_HOSTING.md`'s troubleshooting table](SELF_HOSTING.md) for the
  operator-facing symptom/fix, and [ADR-101](adr-101-schema-epoch-compatibility-floor.md)
  for the actual design fix (deferred; must land before `currentSchemaEpoch` is
  first bumped past its current value of 1). Neither this repo nor the bundled
  Helm chart (pinned to 1 replica) currently orchestrates or tests the rollout
  ordering that would avoid it — a genuine bring-your-own-manifests deployment
  concern for anyone running this topology today.

## Verification

`WithSchedulerLock` runs the job and propagates its result on SQLite (the
single-instance path), and is re-entrant there. The PostgreSQL advisory-lock
semantics (`pg_try_advisory_lock` / `pg_advisory_unlock`) are the same primitive
already relied on by the audit chain (ADR-029). `make build` + full suite + `go
vet` green.

## Deferred

Centralized (Redis/DB-backed) login rate limiting across replicas; making anomaly
detection opt-in; a config-time warning when the `password` KEK provider is used
without a shared salt; automated multi-replica integration tests against a live
PostgreSQL.
