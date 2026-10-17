# Upgrade drill

`scripts/drills/upgrade.sh` rehearses an upgrade on a throwaway instance, with
real binaries, on SQLite or PostgreSQL. Run it before you upgrade a production
install, and whenever you change anything the upgrade path touches (migrations,
key handling, the audit writer).

What it does:

1. Provisions an instance with the **old** `keyorix-server` (`admin init`,
   `admin encryption init`, `admin migrate`) and starts it.
2. Seeds data through the CLI: an admin with MFA enrolled, two projects, three
   secrets (one with three versions), a second user, a share, a machine identity
   with a token and a role; the audit history is whatever those calls wrote.
3. Checks everything on the old release (MFA login, every secret decrypts to the
   seeded value, versions, share, machine token reads, `admin verify-audit`),
   then stops it.
4. Starts the **new** binary on the same data directory or database and checks
   the same list again, writes a new secret, stops it, and runs
   `admin verify-audit` with the new binary. The audit trail must have grown and
   must verify.
5. Starts the old binary on the migrated data once more. If the schema epoch
   advanced between the two releases it must refuse with
   `database schema epoch N is newer than this binary's schema epoch M`
   (see `UPGRADING.md` §7); if it did not, the drill says so.

Run it:

```sh
# build the old release and the build under test
git worktree add ../keyorix-old v0.96.1        # or any clone checked out at the old tag
go build -C ../keyorix-old -o /tmp/keyorix-server-old ./server
DRILL_OLD_SERVER_BIN=/tmp/keyorix-server-old scripts/drills/upgrade.sh

# PostgreSQL: an EMPTY database; the URL is read from a file, not from argv
DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=./pg-dsn.txt \
DRILL_OLD_SERVER_BIN=/tmp/keyorix-server-old scripts/drills/upgrade.sh
```

Environment: `DRILL_SERVER_BIN` / `DRILL_CLI_BIN` (binaries under test; default
is to build this checkout), `DRILL_ROOT` (work area), `DRILL_KEEP=1` (keep the
work area after a pass; it is always kept after a failure, with the server logs).
The master passphrase, admin password and database password are generated or read
per run and travel in the environment or in 0600 files, never on a command line.
The drill drives both server versions with the *current* CLI: the point is the
server's data and behaviour across the upgrade, and the older CLI cannot take its
password from the environment.

The last line is `UPGRADE DRILL PASSED`; any failed check prints
`DRILL FAILED: <what>` and exits non-zero.

## Last run

v0.96.1 to main, SQLite and PostgreSQL 16: every check passed. The new binary
logged the audit index rebuild on PostgreSQL and (PostgreSQL only) the
`audit durability: standard` line described in `UPGRADING.md` §6c. The v0.96.1
binary started on the migrated data (the two releases share a schema epoch).
