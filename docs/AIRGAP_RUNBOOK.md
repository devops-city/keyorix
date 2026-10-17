# Air-gap backup / disaster-recovery runbook

For an operator running `keyorix-server` on a single machine with **no internet
access** (ADR-108 §B3): how to take a backup, verify it, move it off-host, and
restore it — either as a routine drill or a real disaster-recovery event.
Everything here uses only `keyorix-server admin <command>` (never a network
call, never a running listener — see `keyorix-server admin --help`) and the
audit hash chain (ADR-029). Nothing in this runbook requires — or should ever
require — reaching out to the internet.

## What a complete backup is

A complete backup is **two files' worth of content, bundled into one
archive**: the database, and every encryption key-material file (the KEK salt
and wrapped DEK — `internal/keyfiles.Registry`, the same enumeration `admin
audit` checks). Neither alone is useful: the database without the keys is
unreadable ciphertext; the keys without the database have nothing to unwrap.
`admin backup`/`admin restore` handle both together, in one archive, so you
never have to separately track which key files go with which database
snapshot.

`admin backup`/`admin restore` cover both SQLite and PostgreSQL (backup format
v2). The commands below are written for the single-binary SQLite case (stop the
server first); for the Docker Compose + Postgres variants, including the
`docker compose run` details, see [SELF_HOSTING.md §5](SELF_HOSTING.md).

## Routine backup

```sh
keyorix-server admin backup --output /path/to/keyorix-backup-$(date +%F).tar.gz
```

On SQLite this takes the same exclusive database lock every other `admin`
command does: it refuses to run alongside a live server or another `admin`
command, rather than risk an inconsistent snapshot, so stop the server first.
On PostgreSQL it reads through one `REPEATABLE READ` snapshot and works beside a
live server; pass `--exclusive` (server stopped) for the stronger lock before a
major upgrade. The master passphrase is read from `KEYORIX_MASTER_PASSWORD`,
`--passphrase-file`, `--passphrase-fd` or `--passphrase-stdin`, because the
archive manifest is signed with a key derived from it.

**`--output` must not already exist** — each backup is a distinct,
timestamped artifact; the date-stamped filename above is not optional
decoration, it's how you avoid accidentally trying to overwrite one.

**Move the archive OFF this host.** A backup that never leaves the machine it
was taken on protects against nothing that machine itself could lose (disk
failure, ransomware, a bad `rm`). Copy it to removable media, a second host,
or an object-lock bucket before you consider the backup done.

## Exporting an audit-chain anchor (do this too, not instead)

A backup archive's manifest is HMAC-signed with a key derived from the master
passphrase, and `admin restore` verifies it before writing anything, so a
tampered or corrupted archive is refused. That does not tell you whether the
*contents* are the history you expect: for that, the ADR-029 audit hash chain
and — for the strongest guarantee this system offers — a checkpoint anchor held
somewhere the backup's own "holder" doesn't control:

```sh
keyorix-server admin audit export-checkpoint --output /path/to/checkpoint-$(date +%F).json
```

This packages the most recently **signed** checkpoint (written periodically by
the audit-checkpoint scheduler — see `audit_checkpoints.schedule` in your
config, default 24h) into a small JSON file. Copy that file to write-once or
otherwise-external media (a burned CD/DVD, a WORM-mode USB stick, an
object-lock bucket) — **held OUTSIDE this host**, ideally not alongside the
backup archive itself. An anchor genuinely held externally is the one check
that constrains even a host admin who holds both the database and its
checkpoint signing key (see `docs/design-b4-offline-audit-verify.md` §2). If
no checkpoint has been written yet, this command fails rather than fabricate
one — wait for the scheduler's next cycle (its interval is logged at server
startup), or lower `audit_checkpoints.schedule` if you need one sooner.

## Restoring (drill, or the real thing)

Restore into a **fresh, empty data directory**, with the **same config**
(same key-material paths) the backup was taken from. Note the host's
`.audit-highwater-witness` file lives *beside* the database: if you wipe only
`keyorix.db*` and `keys/` on the same host and restore a backup that is behind the
host's last state, restore refuses with "this backup's audit trail is N event(s)
BEHIND" and needs `--allow-rollback` (a replacement host has no witness and is
not checked, see SELF_HOSTING.md §5):

```sh
keyorix-server admin restore --input /path/to/keyorix-backup-2026-09-25.tar.gz
```

What this does, in order:

1. The archive manifest's signature is verified before anything is written
   to disk.
2. The archive's key-file set must match this config's encryption settings
   **exactly** — a partial or mismatched key-file restore (e.g. a backup
   taken mid key-rotation) is refused outright rather than silently leaving
   the database undecryptable later.
3. Each file (database and key files alike) is written **atomically** — a
   temp file, fsynced, then renamed/linked into place — so a crash or
   failure partway through never leaves a target file truncated or
   half-written. Refuses to overwrite an existing, non-empty database or key
   file unless `--overwrite-existing` is given; with that flag, the existing
   file is moved aside to `<path>.pre-restore-<timestamp>` rather than
   truncated, so an unrecoverable mistake still has a way back.
4. Pending migrations are applied (idempotent) — so a backup taken on an
   older binary and restored onto a newer one ends up ready to start, not
   merely restored to its old schema.
5. **`admin verify-audit` runs automatically** against the restored database
   and its verdict is printed. Restore **fails (non-zero exit)** if the audit
   chain reports BROKEN. A bare re-walk (no external anchor) can still miss
   tail-truncation or a genesis re-seed — see the next section for the
   stronger check.

Confirm the restore further:

```sh
keyorix-server admin diagnose
```

### Cross-checking against the externally-held anchor

If you exported a checkpoint anchor before things went wrong, verify the
restored database against it directly:

```sh
keyorix-server admin verify-audit --json --anchor /path/to/checkpoint-2026-09-20.json
```

Check `.verdict == "VALID"` and `.external_anchor.supplied == true` /
`.external_anchor.authenticated == true` in the JSON output. `authenticated`
additionally requires `--checkpoint-key-file` (the KEK-derived checkpoint
signing key — never the KEK or passphrase itself). Extract it once, with the
server stopped, using the master passphrase (the same sources as `admin backup`:
`KEYORIX_MASTER_PASSWORD`, `--passphrase-file`, `--passphrase-fd` or
`--passphrase-stdin`):

```sh
keyorix-server admin audit export-checkpoint-key --output /path/to/checkpoint.key
keyorix-server admin verify-audit --json \
  --anchor /path/to/checkpoint-2026-09-20.json \
  --checkpoint-key-file /path/to/checkpoint.key
```

The file is 32 hex-encoded bytes, written `0600`, and the command refuses to
overwrite an existing path. It is never printed; the command prints only the key
version a checkpoint records, so you can match the two. **It is a shared secret:**
anyone holding it plus the database can forge a validly-checkpointed history. Keep
it with the offline auditor's media, not on the audited host, and delete it after
the check. Without it a drill sees `supplied: true, authenticated: false`; a
supplied-but-unauthenticated anchor still cross-checks the chain's head/
chained-event count against the external copy, just without cryptographic
proof it came from this exact key. Read the full report's "What this run
does NOT prove" section (or `--help`) — a compliance claim from this tool
should always be read alongside what it explicitly did not check, not just
the top-line verdict.

## Automated end-to-end drill

`scripts/airgap-e2e.sh` runs this entire flow for real, in a container with
`--network none` (proving none of it needs internet access): boots a real
server, bootstraps an admin user, creates a real project + secret over the
HTTP API, waits out an audit-checkpoint cycle, exports the checkpoint anchor,
stops the server, backs up, restores into a **fresh** data directory,
verify-audits the restored database against the externally-held anchor,
boots a server against the restored data and confirms the secret **value**
round-tripped correctly — then a negative leg: corrupts a byte inside the
archive and confirms restore refuses it (non-zero exit) instead of silently
accepting damaged input.

```sh
./scripts/airgap-e2e.sh
```

Requires Docker or Podman, and `jq` on the host running the script (not
inside the container — the container never needs it). Skips cleanly (exit 0)
if neither Docker nor Podman is available; for you it is a manual drill, not a
build dependency. CI runs it against the air-gapped image (`.github/workflows/ci.yml`),
and covers the archive-parsing/atomic-write layer directly
(`server/admin/backup_restore_*_test.go`, plus `FuzzReadBackupArchive`). The
script waits out a real audit-checkpoint interval, so it takes a while.

To run the drill against the air-gapped image profile, build it yourself and
point the script at it. `make build-server-airgap` builds the matching binary
and `scripts/airgap-dependency-guard.sh` checks that it links no cloud SDK:

```sh
docker build -f server/Dockerfile --build-arg BUILD_TAGS=noaws,noazure,nogcp -t keyorix-airgap .
KEYORIX_AIRGAP_E2E_IMAGE=keyorix-airgap ./scripts/airgap-e2e.sh
```

The image embeds the web dashboard, so one container serves both the API and
the UI. (Not run for this revision: container checks are pending the e2e VM.)

## What this runbook does NOT cover

- **Postgres-backed deployments running this runbook's own drill script
  end to end.** `admin backup`/`admin restore` now support Postgres directly
  (`docs/design-b3-backup-v2.md` §4, §8) — the same commands this runbook
  uses for SQLite work against a Postgres-configured deployment too, and
  `pg_dump`/`psql` remains a reasonable alternative if you already have a
  pipeline built around it (`SELF_HOSTING.md` §5). This runbook's own
  automated drill (above) has not yet been extended to exercise the
  Postgres target end to end — a good follow-up, not a capability gap in
  the underlying commands.
- **Cross-backend migration (SQLite → Postgres) and version-skipping
  upgrades** are documented usage patterns of the same `admin backup`/
  `admin restore` commands — no new subcommand, no separate tool
  (`docs/design-b3-backup-v2.md` §8, `SELF_HOSTING.md` §5). An archive from
  a release that only ever wrote the older v1 (physical, SQLite-only)
  format can only restore into SQLite; restore it there first with the
  current binary, then take a fresh backup of that to move it onward.
