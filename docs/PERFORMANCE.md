# Keyorix performance and tuning

What you can tune, and what you should leave alone. This page gives no throughput
or latency figures: they depend on your hardware, storage and workload, so measure
your own (the server exposes Prometheus metrics at `/metrics`, see
[SELF_HOSTING.md](SELF_HOSTING.md#8-metrics-prometheus)).

## Connection pool

The defaults differ per backend: 8 open connections for SQLite, 25 for PostgreSQL
(`max_idle_conns` defaults to the effective `max_open_conns`). See
[CONFIGURATION.md](CONFIGURATION.md#storage) before overriding them.

```yaml
storage:
  database:
    # max_open_conns: 8
    # max_idle_conns: 8
    conn_max_lifetime_minutes: 30
```

SQLite allows one writer at a time, so a larger pool only adds readers; see
"SQLite write contention" in [SELF_HOSTING.md](SELF_HOSTING.md#sqlite-write-contention-503--retry-after).

## Production PostgreSQL profile

Server-side settings for a PostgreSQL that serves Keyorix in production. They
size memory and WAL for the database; they do **not** touch durability. With
the Helm chart's bundled database, set them under `postgresql.settings` (the
chart renders each as `postgres -c key=value`). With an external database, use
`postgresql.conf` / `ALTER SYSTEM` or your provider's parameter group.

```ini
# Memory: size to the database host / container, not to these numbers.
shared_buffers = 256MB          # ~25% of the memory available to PostgreSQL
effective_cache_size = 768MB    # ~75% of it (a planner hint, allocates nothing)
# WAL volume: every secret read writes an audit row, so WAL is the steady load.
wal_buffers = 16MB
wal_compression = lz4           # PostgreSQL 15+; 'pglz' on older servers
checkpoint_timeout = 15min      # fewer checkpoints = fewer full-page images
max_wal_size = 2GB              # keep well under the volume size
# Durability: leave the defaults. Required, not tunable:
synchronous_commit = on
fsync = on
full_page_writes = on
# commit_delay / commit_siblings: leave at 0 / 5. Keyorix's audit commits go
# through one serialized writer per replica, so there are rarely enough
# concurrent commits for commit_delay to group them.
```

The WAL settings (`wal_compression` with longer checkpoint spacing) reduce the
WAL written per secret read, mostly through fewer and smaller full-page images:
less disk I/O, smaller WAL archives and lighter replication. Raise
`shared_buffers` and `effective_cache_size` with the database's memory when the
audit tables grow beyond it (audit search and export read them). Check any change
against your own workload.

Durability is not part of the profile. The audit entry for a secret read is
committed before the secret is returned. `synchronous_commit = off`,
`fsync = off` or `full_page_writes = off` set on the database would let any
committed write be lost in a crash, secret writes included. The Helm chart accepts only durable values for these three (an
allow-list, so prefixes such as `of` are refused too), and refuses settings that
would override its TLS baseline (`ssl`, `ssl_*`, `hba_file`, `listen_addresses`,
`password_encryption`, and others) or run commands (`archive_command`).
Audit durability is a Keyorix server option, scoped to the audit transaction
alone, not a database setting: see "Audit durability" below.

Behind PgBouncer, set `storage.database.pooler`. In transaction mode
(`pgbouncer-transaction`) the server stops caching prepared statements and
holds each advisory lock inside a transaction, so every statement is planned
again and each lock holder keeps one PgBouncer server connection, which costs
throughput compared with a direct or session-mode connection. Supported modes, the
PgBouncer settings they need and what changes:
[postgresql-poolers.md](postgresql-poolers.md).

## Audit durability

`storage.database.audit_durability` (ADR-112 Amendment 3) chooses whether the
audit commit for a secret read waits for the disk sync. On PostgreSQL the
default is `standard`; SQLite runs `strict` only (`standard` refuses to start on
SQLite). At `strict` a read waits for at least one disk sync; at `standard` it
does not.

| | `strict` | `standard` (PostgreSQL default) | Vault / OpenBao file audit device |
|---|---|---|---|
| Before the secret is returned | audit row committed **and synced to disk** | audit row committed; the disk sync is not awaited | one `write()` to an append-only file, buffered by the OS, never `fsync`ed |
| Audit write fails | request fails | request fails | request fails |
| Server process crash (`kill -9`, OOM, panic) | loses nothing | loses nothing | loses nothing |
| OS crash, power loss, PostgreSQL crash | loses nothing | the last few hundred ms of audit entries as a tail (about 3 × `wal_writer_delay`, 600 ms at its default) | the last dirty-page-writeback interval of entries (Linux defaults) |
| Hash chain after a crash | intact | intact: a lost tail, never a gap or a fork | no hash chain |
| Backends | PostgreSQL, SQLite (SQLite's only level) | PostgreSQL only | — |

Non-audit writes (secret writes, revocations, rotations) commit durably at both
levels: `standard` relaxes only the audit transaction's own commit
(`SET LOCAL synchronous_commit = off`).

Set `audit_durability: strict` to wait for the disk sync. Details, and how to
choose: [hardening guide §5a](security/hardening-guide.md#5a-audit-durability-levels).

## SQLite settings

The server sets `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`,
`busy_timeout=10s` and `BEGIN IMMEDIATE` on every connection; there is nothing
to add. Do **not** set `synchronous` to `NORMAL`: this database carries the audit
hash chain, and `NORMAL` in WAL mode only syncs at checkpoint boundaries, not on
every commit, so a committed audit entry could be lost on an OS crash or power
loss. `FULL` costs a sync per commit; that is the price of "the audit entry was
written" and "the audit entry survives a host crash" being the same claim.
Keep the database file on local SSD rather than network storage.

## Monitoring

`/metrics` exposes the HTTP, scheduler, notification, SIEM-forwarding and
audit-flusher metrics. Names and example alert expressions:
[SELF_HOSTING.md §8](SELF_HOSTING.md#8-metrics-prometheus).

## Finding out what your deployment does

Measure your own workload before tuning. The repository's Go benchmarks and load
tooling are for development; they are not a statement of what your installation
will do.
