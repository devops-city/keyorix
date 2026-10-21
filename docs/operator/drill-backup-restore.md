# Backup and restore drill

`scripts/drills/backup-restore.sh` rehearses the disaster-recovery path on throwaway
instances with real binaries, on SQLite or PostgreSQL. It shares its helpers with the
[upgrade drill](drill-upgrade.md) (`scripts/drills/lib.sh`, same environment).

Steps it performs and checks:

1. Provision and seed a **source** instance (MFA admin, projects, secrets with
   versions, share, users, machine token, audit history); a 3-second checkpoint
   schedule makes a signed audit checkpoint exist.
2. PostgreSQL: take a backup **beside the running server**. SQLite: confirm the same
   attempt is refused and leaves no archive.
3. Stop the source; export the checkpoint (`admin audit export-checkpoint`) and its
   verification key (`admin audit export-checkpoint-key`) to a directory standing in
   for off-host media; take the real `admin backup` and confirm it will not overwrite an
   existing archive.
4. Start the source again and write one more secret (this must **not** survive the
   restore: it shows the recovery point).
5. Negative legs: a tampered archive is refused; restoring the old backup over the
   host that has moved on is refused without `--allow-rollback`.
6. Restore into a **fresh** target: new config, no keys, no database (SQLite) or an
   empty database (PostgreSQL). Restore's own `verify-audit` must say VALID; a second
   restore into the populated target is refused without `--overwrite-existing`.
7. `admin verify-audit --anchor <exported checkpoint> --checkpoint-key-file <key>`
   on the restored database: VALID with the anchor authenticated, and the chain has
   exactly the events the source had when the backup was taken.
8. Boot the restored instance: MFA login, every secret decrypts to the seeded value
   (secret 1 at its latest version), versions, share, machine token; the post-backup
   secret is absent.

```sh
scripts/drills/backup-restore.sh                       # SQLite, builds this checkout

# PostgreSQL: three EMPTY databases (source, restore target, tamper-leg target);
# each file holds one postgres://user:password@host:port/db URL (never on argv)
DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt DRILL_PG_DSN_FILE2=b.txt \
DRILL_PG_DSN_FILE3=c.txt scripts/drills/backup-restore.sh
```

**Prerequisites.** A clone of `main` (the scripts are not in any tag up to v0.96.2), a Go
toolchain on `PATH` (the drill builds its own TOTP helper and, by default, the server and
CLI from the checkout; without Go it stops with `go: command not found` / `totpgen build
failed`). Leave `DRILL_SERVER_BIN` and `DRILL_CLI_BIN` unset: the drill
needs a CLI that can take its password from the environment, and the v0.96.2 release
`keyorix` cannot (`Password: Error: read password: EOF`, `DRILL FAILED: first login
failed`). Fetching the Go modules needs the network, so run it on a connected host. On
PostgreSQL the DSN files may end in `?sslmode=require` for a server with TLS. A
PostgreSQL 16 run with binaries built from `main` took about 4 minutes, nearly all of it the
first build, and ended with `BACKUP/RESTORE DRILL PASSED`.

The last line is `BACKUP/RESTORE DRILL PASSED`. What the drill does **not** cover: the
container variants of these commands (`docker compose run ...`, Helm) are pending a
run on the e2e VM; off-host storage of the archive is yours to arrange.

## Findings fixed by this drill

- `admin restore --help` said restoring into PostgreSQL was unsupported; it works, and
  SELF_HOSTING.md documents it. The help now says so (`TestRestoreHelp_DoesNotClaimPostgresUnsupported`).
- `UPGRADING.md` §3 showed `admin restore --output-db`, `admin backup --db` and
  `--target-dsn`; none exist. The page now uses one `--config` per hop.
- Neither page stated a recovery point. SELF_HOSTING.md §5 now does.
