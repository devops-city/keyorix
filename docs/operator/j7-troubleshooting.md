# Troubleshooting common startup failures

What each of these looks like, and what to do about it. The messages are quoted from the
server; paths and addresses differ on your install.

First step for any start-up failure: `keyorix-server admin diagnose --config ./keyorix.yaml`
runs the checks server start-up depends on (config parse, encryption key access, database
open, migration state) and reports which one fails, without starting a listener. It needs
the master passphrase like the server does.

## Wrong or typo'd config value

```yaml
storage:
  type: sqllite  # typo
```

```
Configuration is invalid: invalid storage.type "sqllite": must be one of "local", "sqlite", "postgres", "postgresql", or "remote"
```

Fix the value to one of the ones listed and restart. Nothing else to do.

## Postgres unreachable

```yaml
storage:
  type: postgres
  database:
    dsn: "host=localhost user=keyorix dbname=keyorix port=59999 sslmode=disable"
```

```
connect to postgres for server-presence check: failed to connect to `user=keyorix database=keyorix`:
	[::1]:59999 (localhost): dial error: dial tcp [::1]:59999: connect: connection refused
```

The exact host/port that failed is in the message — check Postgres is actually running
and reachable at that address, and that `storage.database.dsn` (or `host`/`port`) matches
your real deployment.

## Port already in use

```
HTTP server error: failed to bind HTTP listener: listen tcp :8080: bind: address already in use
```

Something else (possibly an earlier `keyorix-server` you thought you'd stopped) is
already listening on that port. Check for it before assuming your config is wrong:

```bash
lsof -i :8080 -sTCP:LISTEN
```

**Known gap:** if the earlier instance failed to bind for this exact reason, it does not
exit — it keeps running in the background, still holding the encryption-key lock. If you
see `another process already holds the DEK lock` on a retry, this is almost certainly why:
find and stop that earlier process (the `lsof` command above), don't assume it's a new,
unrelated problem.

## An admin command while the server is (still) running

```
Error: a Keyorix server (or another admin command) appears to be using this database
(another process holds this database (a live server, or another admin command) via
<path>/keyorix.db.server.lock) — admin commands must not run concurrently with either;
stop it first, or pass --force if you are certain this is safe.
With Docker Compose, run admin commands in a throwaway container while the server is stopped:
  docker compose stop backend
  docker compose run --rm backend ./keyorix-server admin <command>
  docker compose start backend
```

This is exactly right — every `admin` subcommand (`init`, `migrate`, `backup`,
`encryption rotate`, ...) needs the database to itself. Stop the server, or confirm you
really mean to run alongside it and pass `--force`.

## Expired TLS certificate

**Known gap:** the server does not check its own certificate's expiry at startup — it
starts and serves normally even with an already-expired certificate, with no warning
anywhere in its own logs. The failure only shows up client-side, once someone actually
tries to connect:

```
$ curl https://your-server/health
curl: (60) SSL certificate problem: certificate has expired
```

```
$ keyorix login --server https://your-server ...
Error: contact https://your-server: Post "https://your-server/auth/login": tls: failed to verify certificate: x509: certificate signed by unknown authority
```

If you see either of these against a server you expected to be healthy, check the
certificate's own expiry directly rather than assuming a network problem:

```bash
openssl x509 -in /path/to/server.crt -noout -dates
```
