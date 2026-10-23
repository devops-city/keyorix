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
5. Starts the old binary on the migrated data once more. If the new release
   raised the compatibility floor above the old binary's schema epoch, the old
   binary must refuse to start and exit 1 with `database declares a minimum
   compatible schema epoch of F (database schema epoch N), above this binary's
   schema epoch M ... Refusing to start (ADR-101)` (see `UPGRADING.md` §6q and §7).
   A database with a newer epoch but no recorded floor gets `database schema epoch
   N is newer than this binary's schema epoch M` instead. The drill only checks for
   the words `schema epoch`, so either message passes. If the two releases share an
   epoch, the old binary starts and the drill says so.

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
binary started on the migrated data (the two releases shared schema epoch 2).
That run predates the floor. Main now records schema epoch 5 with compatibility floor 3
(`UPGRADING.md` §6q), so a v0.96.x binary must refuse in step 5.

Re-run against main `ecd5ce7c1` (2026-10-22, e2e VM), SQLite and PostgreSQL 16, with the
`keyorix-server` binaries taken from the published v0.96.1 and v0.96.3 images: all four
runs of `upgrade.sh` passed, including step 5. A separate run recorded what the old binary does
on the upgraded database (`system_metadata` read `schema_epoch` 5, `schema_min_compatible_epoch` 3):

- `keyorix-server` (start): exit 1, no listener, and it logs
  `failed to initialize core service: failed to initialize storage: failed to migrate database:
  database declares a minimum compatible schema epoch of 3 (database schema epoch 5), above this
  binary's schema epoch 2 (floor recorded at <time>, <n>s ago) -- ... Refusing to start (ADR-101)`.
  It prints the same text on every attempt.
- `keyorix-server admin migrate` on the old binary: the same refusal, exit 1.
  `admin validate` and `admin verify-audit` still work (exit 0, `Verdict: VALID`).
- Nothing changes: the per-table checksums, row counts, schema and key files are identical
  before and after the refused starts and the `admin` commands. The main binary then starts
  and serves the data as before.
- The way back is a restore of the backup taken before the upgrade (`UPGRADING.md` §7).
  With the old binary it restored into a fresh target, and in place over the upgraded database.
  In place on PostgreSQL the database had to be emptied first
  (`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`), and the restore ran with
  `--overwrite-existing --allow-rollback` (without flags it is refused). Secrets decrypted
  afterwards, and `admin verify-audit` said `VALID`. The post-upgrade secret was gone, as expected.
