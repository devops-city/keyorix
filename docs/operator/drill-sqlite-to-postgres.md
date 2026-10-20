# SQLite to PostgreSQL migration check

`scripts/migrate/sqlite-to-pg-check.sh` verifies the Standalone to Server growth path
with real binaries: it seeds a SQLite instance, moves it with `admin backup` and
`admin restore` (the supported path, see
[SELF_HOSTING.md](../SELF_HOSTING.md#moving-from-sqlite-to-postgres)) and then proves
the PostgreSQL copy. It shares its helpers with the other drills
(`scripts/drills/lib.sh`) and needs `curl`, `jq`, Go and `shasum`.

What it does and checks:

1. **Seed** a SQLite instance: projects, secrets with several versions, a soft-deleted
   and a suspended secret, a share, two users with MFA (password + TOTP), a group, a
   machine identity with a live and a revoked token, a dynamic-secret config (its
   admin DSN is encrypted at rest), break-glass history (one activation revoked), 2,000
   events of 30-day-old audit history that a real retention purge then removes (so a
   signed retention anchor exists), 10,000 more audit events, and a signed audit
   checkpoint exported to a directory standing in for off-host media.
2. **Migrate**: `admin backup` of the stopped SQLite instance, `admin restore` into a
   config that points at an empty PostgreSQL database.
3. **Every row present and equal**: row count and an order-independent SHA-256 of every
   row, per table, for all 78 tables. The checksum reads columns through `database/sql`
   and normalises the SQLite/PostgreSQL type differences, so it is independent of the
   backup format. Not compared, by design: `secret_nodes.cache_epoch` and three
   `system_metadata` keys (listed in `scripts/migrate/migratecheck/main.go`).
4. **The migrated instance works**: restore's own `verify-audit` says VALID; the chain
   also verifies against the checkpoint exported from SQLite before the move (no new
   genesis: the only new event is `admin.restore_completed`); the retention anchor is
   byte-identical; schema epoch equal on both sides and to the binary's; the server
   boots on PostgreSQL, the MFA admin and the second MFA user log in, every secret
   decrypts, versions, share, machine token, revoked token, suspended and deleted secret,
   break-glass history, group and dynamic-secret issue all work; the chain still verifies
   after the server has run.
5. **Failure and rollback**: `admin restore` is killed with `kill -9` while migrating the
   target and while loading rows, each time recovered both with `--overwrite-existing`
   and with the manual cleanup. It checks the SQLite file's SHA-256 is unchanged, the
   load left no partial rows, a plain re-run is refused, and each recovery ends with
   tables equal to the source and a VALID chain. Finally the SQLite source still starts.

```sh
# three databases: A (migration target), B (target of the kill legs), C (any database the
# dynamic-secret config points at); each file holds one postgres://user:password@host:port/db
# URL (never on argv). A and B must be EMPTY.
MIGRATE_PG_DSN_FILE=a.txt MIGRATE_PG_DSN_FILE2=b.txt MIGRATE_PG_DSN_FILE3=c.txt \
  scripts/migrate/sqlite-to-pg-check.sh
```

The last line is `SQLITE -> POSTGRESQL MIGRATION CHECK PASSED`. Environment:
`MIGRATE_AUDIT_EVENTS` (default 10000), `DRILL_SERVER_BIN` / `DRILL_CLI_BIN` (default:
build this checkout), `DRILL_KEEP=1` (keep the work area).

What it does **not** cover: the container variants (`docker compose`, Helm) are pending a
run on the e2e VM; the PostgreSQL to SQLite direction; a PostgreSQL target that already
holds data; very large databases (the run is sized for tens of thousands of rows).

## Findings fixed by this check

- `admin restore` reported INDETERMINATE for any database that had been through a
  retention purge, because its automatic `verify-audit` was not given the checkpoint key.
- A restore changed SQL NULL in JSON columns (`secret_nodes.metadata`) to the text `null`.
- SELF_HOSTING.md said the archive contains its own `admin.backup_created` event; it is
  written to the source after the archive.

## Behaviour worth knowing

- The only write the migration makes to the SQLite source is the `admin.backup_created`
  event `admin backup` appends.
- TOTP anti-replay state moves with the data: the same code is refused on PostgreSQL
  inside its 30-second step. The script waits for a fresh code for that reason.
