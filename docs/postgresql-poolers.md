# Running Keyorix behind a PostgreSQL connection pooler (PgBouncer)

Keyorix can run behind PgBouncer in **session** or **transaction** pooling
mode. Say which one with `storage.database.pooler`. The server cannot reliably
detect a pooler itself: PgBouncer answers `SHOW pool_mode` only on its admin
console, not on the connections a client uses.

```yaml
storage:
  type: postgres
  database:
    host: pgbouncer.internal   # PgBouncer, not PostgreSQL
    port: "6432"
    name: keyorix
    user: keyorix
    ssl_mode: verify-full
    ssl_root_cert: pg-ca.pem
    pooler: pgbouncer-transaction   # none (default) | pgbouncer-session | pgbouncer-transaction
```

Helm: `externalDatabase.pooler` (with `externalDatabase.host`/`port` pointing at
PgBouncer). Docker Compose: set it in `keyorix.docker.yaml`.

## Supported modes

| PgBouncer `pool_mode` | `storage.database.pooler` | Supported | Notes |
|---|---|---|---|
| none (direct) | `none` (default) | yes | Unchanged behaviour. |
| `session` | `pgbouncer-session` (or `none`) | yes | Any PgBouncer version. A client connection keeps one server connection, so it behaves like a direct one. Nothing changes at runtime. |
| `transaction` | `pgbouncer-transaction` | yes | Any PgBouncer version; `max_prepared_statements` may be 0 or more (the server uses no named prepared statements in this mode). See the requirements below. |
| `transaction` | `none` or `pgbouncer-session` | **no** | The server refuses to start when it can tell (see "Start-up check"). |
| `statement` | — | **no** | Multi-statement transactions are not allowed in statement mode, and Keyorix needs them. |

Tested with PgBouncer 1.24.1 and PostgreSQL 16 (`scripts/pgbouncer-matrix.sh`).
Other transaction poolers (PgCat, Odyssey, managed proxies) have not been
tested; see "Other poolers: documented behaviour" at the end.

## What `pgbouncer-transaction` changes

A transaction-mode pooler gives a client a server connection only for the
length of one transaction. Anything a server connection remembers between
transactions is then shared with whichever client gets that server connection
next. Keyorix relies on two such things, and the setting replaces both:

1. **Prepared statements.** By default the PostgreSQL driver (pgx) prepares
   every query once per connection under a name and reuses it. With
   `pgbouncer-transaction`, every Keyorix connection (the request pool, the
   native read pool, the lock pools, the admin commands) runs each statement
   unprepared (pgx `QueryExecModeExec`, no statement or description cache).
   This needs no PgBouncer prepared-statement support.
2. **Session-scoped advisory locks.** Keyorix serializes some work across
   replicas with PostgreSQL advisory locks held across statements: named locks
   (`WithNamedLock`), scheduler job locks, the bootstrap lock, the
   audit-checkpoint lock, the audit list index build lock, the migration lock and the server-presence lock that
   keeps admin commands (`keyorix-server admin ...`) and running servers apart.
   With `pgbouncer-transaction`, each is taken with the transaction-scoped form
   (`pg_advisory_xact_lock`, `pg_try_advisory_xact_lock[_shared]`) inside a
   transaction that stays open for the whole critical section, its lock
   statement sent over the simple query protocol so the open transaction holds
   no snapshot (one would hold back VACUUM and every `CREATE INDEX
   CONCURRENTLY` for as long). While a
   transaction is open, PgBouncer keeps the client on one server connection, and
   the lock ends with that transaction: at the end of the critical section, or
   when PgBouncer closes the server connection of a client that disconnected
   mid-transaction (a crashed replica, a killed admin command).

   Two consequences:
   - A nested named lock under a second key is released when the outermost
     named lock is, not when its own critical section ends: held longer, never
     shorter.
   - The lock transaction is idle while the critical section runs its queries
     on other connections (for the presence lock, the server's whole lifetime).
     Any timeout that ends a transaction ends the lock, silently, while the
     holder still relies on it. For that transaction alone the server sets
     `idle_in_transaction_session_timeout = 0` and, on PostgreSQL 17 or later,
     `transaction_timeout = 0` (`SET LOCAL`; the second only from
     `server_version_num >= 170000`, where the parameter exists), however the
     timeouts were configured (cluster, database or role). Timeouts of the
     pooler itself cannot be overridden from SQL: see "PgBouncer requirements".

In transaction mode the locks are as strong as on a direct connection as long as
the lock transaction lives, and the server protects it from PostgreSQL's own
timeouts as above: mutual exclusion across replicas, the presence guard and the
"a killed holder's lock is released" property hold
(`TestPgBouncer_StorageSlice`, `TestPgBouncer_BlockingLocks_*`,
`TestPgBouncer_Locks_SurviveServerTimeouts`, `TestPgBouncer_ServerGuard_*`).
What they depend on, and what the server does not detect: a lock transaction
ended from outside (PgBouncer timeouts below, a `pg_terminate_backend`, a
PostgreSQL restart, a failover) drops its lock with no signal to the holder. A
server whose presence lock was lost keeps running and an admin command could then
start beside it. Detecting that (a periodic liveness check on the lock
connection that stops the server) is not implemented yet.

What does not change in any mode: the audit record of a secret read is
committed before the secret is returned. At `audit_durability: strict` the
commit waits for the disk sync; at `standard` (the PostgreSQL default) the
audit transaction uses `SET LOCAL synchronous_commit = off`, which ends with
that transaction and never reaches another client.
`TestPgBouncer_StorageSlice/AuditCommit` checks both levels through PgBouncer.

## PgBouncer requirements for transaction mode

- `idle_transaction_timeout = 0` (the default). Each server holds its presence
  lock in a transaction for as long as it runs, and lock holders keep a
  transaction open for the length of their critical section. A nonzero
  timeout would end those transactions and release their locks while the
  holder still relies on them. The same goes for PgBouncer's
  `transaction_timeout` in versions that have it (leave it 0), and for
  `client_idle_timeout` (leave it 0: a replica's lock connection sends nothing
  for as long as the critical section lasts). `query_timeout` only cancels a
  statement that runs too long, such as a blocking bootstrap or audit-checkpoint
  lock wait: that fails the caller with an error and never weakens a lock, but
  set it longer than the longest wait you accept.
- `pool_size` / `default_pool_size`: in transaction mode, each held lock keeps
  one PgBouncer server connection. Per Keyorix replica, allow for:
  1 (presence lock, permanent) + up to 4 (scheduler job locks) + up to 8 (named
  locks) + the request traffic (`max_open_conns`, default 25, and the native
  read pool, 8 by default: `native_read_pool_max`). The lock connections are held only while a lock is held.
- Keep startup parameters out of the DSN (`search_path`, `options`, ...).
  PgBouncer refuses unknown startup parameters (or drops them, with
  `ignore_startup_parameters`), and a transaction-mode pooler cannot keep a
  per-client session setting anyway. `application_name` is fine. Set
  `search_path` on the database role instead (`ALTER ROLE keyorix SET
  search_path = ...`).
- Session mode only: keep `server_reset_query = DISCARD ALL` (the default), so
  a disconnected client's session state, advisory locks included, is cleared
  before the server connection is reused.

On the PostgreSQL side, `idle_in_transaction_session_timeout` and
`transaction_timeout` (PostgreSQL 17+) can stay as configured: the lock
transactions override them for themselves only, and every other Keyorix
transaction is still subject to them. `idle_session_timeout` does not apply to a
session inside a transaction, so it does not touch transaction-mode locks. It
does end an idle session, so in direct and `pgbouncer-session` modes, where the
presence lock and the lock-holding connections are session-level and idle
between statements, leave it unset (0) for the Keyorix role: a session ended
that way drops its locks silently, as above. Nothing else has to change on the
PostgreSQL side.

## Start-up check

With `pooler` unset (or `pgbouncer-session`), the server checks at start-up
whether two of its open connections are served by the same PostgreSQL backend
(`pg_backend_pid()`). That can only happen behind transaction pooling, so the
server refuses to start with a message naming `storage.database.pooler:
pgbouncer-transaction`. Different backends prove nothing, so this is a
backstop for the setting, not a replacement: set `pooler` explicitly. The check
runs before the server takes its presence lock, so a refused start-up leaves no
lock behind on a pooled server connection.

Without this check, transaction pooling with an undeclared pooler either fails
at start-up on prepared statements (PgBouncer `max_prepared_statements = 0`) or,
worse, appears to work (`max_prepared_statements > 0`) while two replicas can
hold the same advisory lock at once and an admin command can run next to a
live server.

## Performance

`none` and `pgbouncer-session` run exactly as a direct connection does.
`pgbouncer-transaction` gives up the prepared-statement cache (each statement
is planned again) and adds a statement or two around each advisory lock, and
each lock holder keeps a PgBouncer server connection. Expect lower throughput
and higher latency than a direct or session-mode connection; use transaction
mode where the connection count on PostgreSQL is the constraint, and session
mode otherwise.

## Testing it yourself

`scripts/pgbouncer-matrix.sh` (Docker and Go) starts PostgreSQL and PgBouncer
in session mode, transaction mode with `max_prepared_statements = 0`, and
transaction mode with `max_prepared_statements = 200`, and runs
`TestPgBouncer_*` (internal/storage, internal/serverguard) through each.
`PGB_POOLER=none scripts/pgbouncer-matrix.sh` shows what an undeclared
transaction pooler does: the server refuses to start.

## Other poolers: documented behaviour (not tested, not supported)

Read from each project's own documentation (2026-10); **none of this has been
run against Keyorix**. Only PgBouncer is supported. The table is what to check
before anyone tries another pooler, against the three things Keyorix depends
on: session advisory locks (direct / session mode), transaction-scoped advisory
locks held in one long-open transaction (`pgbouncer-transaction`), and the
start-up check (two open connections served by one backend).

| | PgBouncer (supported) | PgCat | Odyssey | RDS Proxy (PostgreSQL) |
|---|---|---|---|---|
| Pool modes | session, transaction, statement | session, transaction (default `transaction`) | session, transaction | transaction-level multiplexing, with automatic "pinning" |
| Session advisory lock (`pg_advisory_lock`) | kept in session mode; leaks to the next client in transaction mode | works in session mode only (README) | cleared by the default reset query on return (`pg_advisory_unlock_all`, `pool_discard`, default on) | **pins** the client to one database connection until the client disconnects (documented list); behaves like session mode |
| Transaction-scoped locks (`pg_advisory_xact_*`) | work; the open transaction keeps one server connection | recommended by the README as the transaction-mode alternative | not documented either way | documented as **not** pinning |
| Pooler timeouts that can end an open lock transaction | `idle_transaction_timeout`, `transaction_timeout`, `client_idle_timeout`, `server_lifetime`-class settings (see above) | `idle_client_in_transaction_timeout` (default 0); `server_lifetime` default 24 h, described as applying "even if in active use"; `statement_timeout` per user (default 0) | `pool_idle_in_transaction_timeout` and `pool_client_idle_timeout` (docs table says session pooling only); `server_lifetime` default 3600 s, reclaimed only while idle | client connection max life **24 h, not configurable**; `IdleClientTimeout` default 1800 s (its effect on a client idle inside an open transaction is not stated) |
| Prepared statements in transaction mode | `max_prepared_statements` (0 or more; Keyorix uses none) | `prepared_statements_cache_size` (default 0 = off); docs marked TODO | `pool_reserve_prepared_statement` opt-in; incompatible with a discard query that has `DEALLOCATE ALL` | `PREPARE`/`EXECUTE`/`DEALLOCATE`/`DISCARD` pin; whether protocol-level named statements pin is not stated |
| Session `SET` | per-client state not kept in transaction mode | not documented | `maintain_params` (default on) re-applies client parameters | `SET` and `set_config` **pin** (`SET LOCAL` is not addressed for PostgreSQL) |
| Does our start-up check fire on an undeclared transaction pooler? | yes when the pool hands both connections one backend (LIFO reuse, the normal start-up case) | unknown; depends on server selection order | unknown | no: a pinning proxy gives each client its own backend, which is right, because the session locks then behave |

What this means for Keyorix, as far as the documentation goes:

- **RDS Proxy with `pooler: none`** is the only combination that looks workable
  without code changes: session advisory locks pin, so locks behave as on a
  direct connection. The start-up check passing is correct there. Open problems:
  the fixed 24 h client connection life ends every session lock silently (the
  presence lock included) and `IdleClientTimeout` may do the same; neither is
  detected today (see the lock-loss work for direct and session-mode
  connections). Heavy pinning also removes the pooling benefit.
- **RDS Proxy with `pooler: pgbouncer-transaction`**: transaction-scoped locks do
  not pin, but the lock transaction's `SET LOCAL` setup statements may, and the
  24 h limit applies to a transaction that is meant to live for the server's
  whole lifetime. Untested.
- **PgCat / Odyssey in transaction mode** would need `pooler:
  pgbouncer-transaction` (the setting is named after PgBouncer but selects
  "transaction pooling: no prepared statements, transaction-scoped locks"). The
  timeouts above that can end an idle open transaction must be 0 / off before the
  presence and lock transactions are safe; for both, `server_lifetime` against a
  long-open transaction is not documented well enough to rely on.
- A start-up check pass is never evidence that a pooler is absent (see "Start-up
  check"); with any of these, set `pooler` explicitly.
