# Sizing a Keyorix server

How to pick hardware, and how to check your pick on your own machine. This page
states **no throughput, latency or footprint figures**, the same rule as
[PERFORMANCE.md](PERFORMANCE.md): benchmark results depend on the host, the
storage and the workload, and a number copied from someone else's rig is a
guess about yours. Where a tier would need a measured figure, the table says
**not measured**. The sections below give what the code and the docs do
establish (limits, defaults, what costs what) and a procedure for measuring the
rest.

## What decides the size

| Driver | Why it matters | Source |
|---|---|---|
| Storage backend | SQLite allows one writer at a time; PostgreSQL does not have that limit. | [PERFORMANCE.md](PERFORMANCE.md#connection-pool), [SELF_HOSTING.md](SELF_HOSTING.md#sqlite-write-contention-503--retry-after) |
| Audit writes | Every secret read writes an audit row, so the write path, not the read path, is the steady load. | [PERFORMANCE.md](PERFORMANCE.md#production-postgresql-profile) |
| Audit durability | `strict` waits for a disk sync on every audited read; `standard` (the PostgreSQL default) does not. SQLite runs `strict` only. | [specs/fast-audit-mode.md](specs/fast-audit-mode.md) section 0 |
| Connection pool | Defaults: 8 open connections for SQLite, 25 for PostgreSQL. | [PERFORMANCE.md](PERFORMANCE.md#connection-pool) |
| Disk | Holds the database, its WAL and the audit log; the audit table grows with every read. | [AIRGAP_RUNBOOK.md](AIRGAP_RUNBOOK.md) |

## Tiers

Pick the tier from your workload (how many secrets, how many readers, how often
they read), then confirm it with the procedure further down.

| | Small | Medium | Larger |
|---|---|---|---|
| Intended use | One team, a few services, occasional reads | Several teams, services reading at startup and on rotation | Many services reading continuously, multiple replicas |
| Backend | SQLite | SQLite or PostgreSQL | PostgreSQL |
| CPU | not measured | not measured | not measured |
| RAM | not measured | not measured | not measured |
| Disk | not measured | not measured | not measured |
| Expected requests/s | not measured | not measured | not measured |
| Idle footprint | not measured | not measured | not measured |

What can be said without a measurement:

- **SQLite** is a single-node choice. Concurrent writers queue, and the server
  answers `503` with `Retry-After` under write contention; see
  [SELF_HOSTING.md](SELF_HOSTING.md#sqlite-write-contention-503--retry-after).
  Because every audited read is a write, a read-heavy workload meets that limit
  sooner than the request rate alone suggests. Stay on SQLite for the small
  tier; move to PostgreSQL when you see those `503`s or need more than one
  replica.
- **PostgreSQL** carries the medium and larger tiers. Size its memory to the
  database host, not to the example values in
  [PERFORMANCE.md](PERFORMANCE.md#production-postgresql-profile), and give the
  WAL volume room for `max_wal_size`.
- **Audit write cost** is the difference between the two durability levels in
  the table in [specs/fast-audit-mode.md](specs/fast-audit-mode.md) (section 0
  describes what each level promises; section 8 records one measurement on one
  rig, which is evidence for the change, not a sizing figure). On your hardware
  the gap is set by your disk's sync latency, so measure it (below) before
  choosing `strict` for a high-read workload.

## Measure on your own hardware

1. **Fix the workload.** Decide the mix before you test: secrets read per
   second, how many distinct secrets, how many concurrent clients, how many
   writes (rotations, creates). The audit write per read is part of every read.
2. **Run the same load at each candidate size**, with the backend and audit
   durability you plan to use, long enough for the database to reach its steady
   state (checkpoints and WAL recycling included). Change one thing per run.
3. **Watch the server's own metrics** at `/metrics`
   ([SELF_HOSTING.md](SELF_HOSTING.md#8-metrics-prometheus)):
   `keyorix_http_requests_total` for the achieved rate and status mix (watch for
   `503` on SQLite) and `keyorix_http_request_duration_seconds` for latency at
   the percentiles you care about.
4. **Watch the host**, with your platform's tools: the server process's memory
   (the container or cgroup limit, if you run one), CPU, disk write rate and
   sync latency of the volume that holds the database and WAL, and the
   database's own size growth per day at your read rate.
5. **Record the idle footprint** separately: start the server with no clients,
   let it settle, and note its memory and CPU before you add load. Idle
   footprint is what you pay for every replica, loaded or not.
6. **Size with headroom** over the highest rate you measured, and re-measure
   after upgrades and after any change to audit durability, pool size or
   replica count.

## Related

- [PERFORMANCE.md](PERFORMANCE.md): the connection pool, the PostgreSQL profile,
  audit durability.
- [SELF_HOSTING.md](SELF_HOSTING.md): deployment, metrics, SQLite contention.
- [AIRGAP_RUNBOOK.md](AIRGAP_RUNBOOK.md): what has to be backed up, which drives disk needs.
