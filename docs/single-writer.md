# Single-writer mode (`storage.database.single_writer`)

Opt-in, PostgreSQL only, exactly one Keyorix server. Off by default; with it off nothing changes.
Design and rationale: [specs/single-writer-cache.md](specs/single-writer-cache.md).

```yaml
storage:
  type: postgres
  database:
    single_writer: true
```

## What it does

The server declares itself the only writer of its database:

- **At start-up** it takes a PostgreSQL advisory lock for its schema. A second server with the setting
  refuses to start ("another Keyorix server holds the single-writer lock"). A server *without* the
  setting also refuses to start while one is running. `keyorix-server admin ... --force` is refused too.
- **A write fence**: triggers on the security tables refuse every write from any other database session
  while the server runs. The tables are the machine credentials and identities, their roles, roles and
  permissions, projects and environments, and the secrets' nodes, versions and schedules. The server's
  own sessions carry a per-boot tag the fence checks. With no server running, the fence lets everything
  through, so recovery never needs the server.
- **A write epoch** the server polls every 250 ms, together with proof that it still holds the lock
  and a fingerprint of the installed fence.

If the fence cannot be installed and verified, the server **refuses to start**: the mode never runs
without it.

Not supported, refused at start-up: SQLite, `security.auth_rate_limit_fallback.replicas` above 1,
`storage.database.pooler: pgbouncer-transaction`. PgBouncer in session pooling mode is supported.

## What changes for revocation

- Revocations **through the server** (API, gRPC, CLI, SCIM, schedulers, break-glass): unchanged, they
  take effect on the next request.
- A **direct database write** to a security table while the server runs is **refused**, with an error
  that names the server's backend pid and this page.
- A direct write after the fence has been deliberately bypassed in SQL, or after the server lost its
  lock, takes effect **within 1 second**. In both cases the server notices and stops trusting its
  caches until it is restarted. "Bypassed in SQL" covers a table owner or superuser who disables,
  drops, re-creates or replaces a fence trigger or function, even inside one transaction that puts
  everything back before it commits, and one who adds a table inheriting from a fenced table.
- A write by a session that copied the server's tag (see "Residual risks") passes the fence but moves
  the write epoch. The server discards every cached answer at its next poll, so the write takes effect
  within 1 second too.

## Emergency SQL

To change a security table directly while the server runs (for example, revoke a credential with
`psql` because the API is unavailable to you), use two steps:

```sql
-- 1. End the server's lock session. The fence opens at once.
SELECT pg_terminate_backend(holder_pid) FROM keyorix_sole_writer;
-- 2. Make the change.
UPDATE machine_identity_credentials SET revoked = true WHERE id = 42;
```

The server sees within 1 second that its lock is gone. From then on it confirms every read against
the database, as a server without the setting does, and it does not trust its caches again until it
is restarted. Restart it when you are done. The same text is in the refusal's HINT and in
`keyorix-server admin validate --posture`.

Stopping the server first is the other way: with no server running, the fence lets every write
through.

## Residual risks

What the fence and its checks cannot see, stated precisely:

- **A superuser working below SQL.** A role with superuser rights, or with `pg_execute_server_program`
  or `pg_write_server_files`, can change table data without going through SQL triggers: native code
  loaded into PostgreSQL, writing the data directory, `pg_resetwal`. No trigger fires and no catalog row
  changes, so the server keeps trusting its caches. A change made this way can be served stale for up to
  5 minutes (the cache entry lifetime), or until the server's next write to a security table. Use a
  role that owns the tables but is not a superuser and has neither of those two roles. While it runs
  as such a role, `keyorix-server admin validate --posture` reports a `single_writer` deviation. Other
  superusers in the cluster have the same power; keep them to administrators you would also trust
  with the server's master key.
- **The session tag in statement logs.** The server sets its per-boot tag with
  `SELECT set_config($1, $2, false)`, a bind parameter, so the tag is not in `pg_stat_activity` or
  `pg_stat_statements`. PostgreSQL still writes bind parameters to its log when `log_statement = all`
  (or `log_min_duration_statement = 0`) unless `log_parameter_max_length = 0`. Anyone who can read
  that log can copy the tag and pass the fence. Such a write still moves the epoch (see above), so it is
  seen within 1 second, but it is not refused. Keep `log_parameter_max_length = 0` if you log every
  statement.

Everything else that changes a fence trigger or function, enabled or not, is detected within one poll
(250 ms). The server checks the triggers' and functions' catalog row versions, not just their text, so
a change that is undone before the next poll is still seen.

## Where to see it

- The start-up log line: `single_writer: authoritative (lock held by backend pid …; write fence on 12
  tables; epoch poll 250ms, lease 1s) …`. Each later state change is logged: `single_writer:
  confirming: <reason>`.
- `GET /api/v1/system/info` → `database.single_writer`: state, reason, holder pid, fenced tables,
  epoch, last poll age.
- `keyorix-server admin validate --posture`: a line while the setting is on, with the emergency
  two-step, and a deviation if the installed fence is incomplete.

## Turning it off

Remove the setting and restart. The first start without it removes the fence triggers and the two
tables (`keyorix_sole_writer`, `keyorix_write_epoch`). An older binary that doesn't know the mode
leaves them in place. With no live holder they let every write through.
