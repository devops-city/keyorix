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

**What it buys:** a warm machine-token secret read runs no confirming database statement; the audit write
is the only one left on the request path. Every check is still made on every request, against the last
answer the database gave. Any write this server makes to a security table invalidates that answer before
the call that made it returns. Sessions and personal access tokens are not affected: they confirm every
read as before.

Not supported, refused at start-up: SQLite, `security.auth_rate_limit_fallback.replicas` above 1,
`storage.database.pooler: pgbouncer-transaction`. PgBouncer in session pooling mode is supported.

## What changes for revocation

- Revocations **through the server** (API, gRPC, CLI, SCIM, schedulers, break-glass): unchanged, they
  take effect on the next request.
- A **direct database write** to a security table while the server runs is **refused**, with an error
  that names the server's backend pid and this page.
- A direct write after the fence has been deliberately bypassed (a superuser disabling or dropping a
  trigger), or after the server lost its lock, takes effect **within 1 second**. In both cases the
  server notices and stops trusting its caches until it is restarted.

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
