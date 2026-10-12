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

**Egress-blocked check (INSTALL-WALK-1, origin/main 12d5dbcb).** With the host
firewall dropping every non-loopback packet from the server's user (single binary)
and every packet leaving the compose bridge for outside the compose subnet
(`iptables -I DOCKER-USER -s <subnet> ! -d <subnet> -j DROP`), both a SQLite
single binary with TLS and the Compose + Postgres stack restarted, served logins
and returned a stored secret, and the DROP rules' packet counters stayed at 0 over
several minutes (including the anomaly-detection and checkpoint schedulers): the
core product makes no outbound connection attempts.

## Routine backup

```sh
keyorix-server admin backup --output /path/to/keyorix-backup-$(date +%F).tar.gz
```

This takes the same exclusive database lock every other `admin` command does
— it refuses to run alongside a live server or another `admin` command,
rather than risk a torn/inconsistent snapshot. The database snapshot itself
uses SQLite's `VACUUM INTO`, which is internally consistent regardless of
journal mode, then re-opens the snapshot with a **fresh** connection and runs
`PRAGMA integrity_check` before it's trusted — a corrupt snapshot is caught
at backup time, loudly, not discovered later when a restore fails on a host
that may no longer have the original database to re-back-up from.

**`--output` must not already exist** — each backup is a distinct,
timestamped artifact; the date-stamped filename above is not optional
decoration, it's how you avoid accidentally trying to overwrite one.

**Move the archive OFF this host.** A backup that never leaves the machine it
was taken on protects against nothing that machine itself could lose (disk
failure, ransomware, a bad `rm`). Copy it to removable media, a second host,
or an object-lock bucket before you consider the backup done.

## Exporting an audit-chain anchor (do this too, not instead)

A backup archive's checksums (SHA-256 per file) prove the archive was not
**corrupted** in transit — a bad copy, a truncated transfer, bit rot. They do
**not** prove it wasn't **tampered with**: anyone who can edit the archive can
recompute a SHA-256 to match their edit. Tamper evidence comes from the
ADR-029 audit hash chain instead, and — for the strongest guarantee this
system offers — from a checkpoint anchor held somewhere the backup's own
"holder" doesn't control:

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

1. Every file in the archive is checksum-verified against the manifest
   before anything is written to disk.
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
if neither Docker nor Podman is available; this is a manual drill, not a
build dependency. Not run in CI — CI already covers the archive-parsing/
atomic-write layer directly (`server/admin/backup_restore_*_test.go`, plus
`FuzzReadBackupArchive`); this script is for validating the real container
image and the real HTTP-driven flow, which takes real wall-clock time
(tens of seconds, to wait out a checkpoint interval) and a real container
engine CI shouldn't need for every push.

**Verified against the real air-gapped image (2026-09-28, ADR-109 step 6, B7):**
built `server/Dockerfile` with `--build-arg BUILD_TAGS=noaws,noazure,nogcp` (the
same air-gapped profile `make build-server-airgap`/the `<ver>-airgap` published
image use), pointed this script at it (`KEYORIX_AIRGAP_E2E_IMAGE=<tag>
./scripts/airgap-e2e.sh`), and it passed end to end — bootstrap, secret
create, backup, restore into a fresh data directory, `admin verify-audit`
(bare and anchor-cross-checked), the restored secret value round-tripping
correctly, and the negative leg (tampered archive) correctly refused. No
doc or behavior differences found between the full and air-gapped images for
this flow — expected, since none of `admin backup`/`admin restore`/`admin
verify-audit`'s own code paths touch any cloud SDK.

**Resolved (2026-10-05, #2752):** neither published image — `keyorix-server`
nor its `-airgap` variant — used to embed the web dashboard. Both served the
placeholder page ("This build does not bundle the web dashboard") at `/`,
because `server/Dockerfile` compiled the server without ever building `web/`
first, and the only thing git tracks under `server/webui/dist/` is that
placeholder. Getting a dashboard therefore meant also pre-staging a second,
separate `keyorix-web` image that has no `-airgap` variant and was never
profiled for air-gap suitability — which undercut ADR-109's single-artifact
pitch. The release **tarballs** never had this gap (`make release` depends on
`populate-webui-dist`); it was Docker-only. `server/Dockerfile` now builds the
dashboard in its own stage and embeds it, so

```sh
docker build -f server/Dockerfile --build-arg BUILD_TAGS=noaws,noazure,nogcp -t keyorix-airgap .
```

produces **one image that serves both the API and the real dashboard at `/`**,
with no second container. `scripts/docker-webui-embedded-check.sh <tag>` asserts
exactly that against a running container (and refuses a placeholder page); the
air-gap guarantees are unchanged — `scripts/airgap-dependency-guard.sh` still
reports 0 forbidden cloud-SDK packages, and `scripts/airgap-e2e.sh` still passes
end to end with `--network none` against the new image. The three-container
`docker compose` path in [SELF_HOSTING.md](SELF_HOSTING.md) is unaffected and
remains the documented self-host default.

**Resolved (2026-09-25):** `docker build -f server/Dockerfile .` previously
failed on a clean checkout — `server/admin/init.go` imports
`github.com/keyorixhq/keyorix/configs`, but `.dockerignore` excluded
`configs/` from the build context, so the Go build inside the image failed
with `no required module provides package .../configs`. Fixed by #2108
(`.dockerignore` now excludes `configs/*` except the two files
`admin init` actually embeds, `embed.go` and `keyorix.yaml.tpl`) — verified
with a clean `docker build -f server/Dockerfile .` against current `main`.
`KEYORIX_AIRGAP_E2E_IMAGE=<your-tag> ./scripts/airgap-e2e.sh` still works if
you'd rather pre-build the image yourself and skip the build step entirely.

## Estimate: adding PostgreSQL support to `admin backup`/`admin restore`

**Historical — this has since been built** (backup format v2 supports Postgres;
see above and [SELF_HOSTING.md §5](SELF_HOSTING.md)). Kept for the design record.

Not built at the time — an estimate only (ADR-109 step 6, B7). Then, `admin backup`/`admin
restore` refuse non-sqlite storage outright (verified live: `admin backup`
against a Postgres-backed install fails immediately with "admin backup only
supports local/sqlite storage today ... for Postgres, back up with pg_dump
directly"); Postgres users follow the manual `pg_dump`/`psql` procedure
[above](SELF_HOSTING.md#5-backup-and-restore), which this runbook validated
works correctly, including `admin verify-audit` on the restored database.

**Already reusable, no new work:** the exclusive-lock mechanism
(`internal/serverguard.AcquireExclusive`) already branches on storage type and
has a Postgres advisory-lock implementation (`acquirePostgresExclusive`) — the
same lock every other admin command already takes against a Postgres backend
works today. The archive manifest/checksum/key-file-bundling scaffolding
(`server/admin/backup.go`'s `backupManifest`) is already backend-agnostic; only
its `Backend` field and how `DBFile` is captured/restored are SQLite-specific.

**New work required:**
1. **Backup**: SQLite's `VACUUM INTO` (a single, self-consistent snapshot with
   no external tool) has no Postgres equivalent built into the database
   itself. Two paths: (a) shell out to `pg_dump` — fast to build (~1 week) but
   reintroduces an external binary dependency into what is otherwise a
   single-binary, self-contained tool, working against the exact positioning
   ADR-109 (this track) exists to strengthen; or (b) a pure-Go dump (e.g. via
   `pgx`, `COPY`-based table streaming inside one `REPEATABLE READ`
   transaction) — no external binary, consistent with the single-binary/
   air-gapped goal, but meaningfully more work (schema introspection,
   sequences, indexes, constraints, correct quoting/escaping — essentially
   reimplementing the subset of `pg_dump` this tool needs).
2. **Restore**: SQLite restore writes a file into an empty directory; Postgres
   restore needs an already-reachable, already-created (but empty) target
   database — the "fresh, empty data directory" precondition becomes "the
   target database has no application tables," checked before writing
   (mirroring `--overwrite-existing`'s existing sqlite semantics: refuse
   unless explicitly overridden). `admin verify-audit` running automatically
   after restore already works against Postgres (verified live in this
   runbook check) and needs no changes.
3. **Testing**: this repo already has a `KEYORIX_TEST_PG_DSN`-gated
   integration-test pattern for admin commands
   (`admin_integration_postgres_test.go`, `admin_encryption_integration_postgres_test.go`)
   — extending it to backup/restore reuses existing harness code, but still
   needs new fixtures and (for the pure-Go path) new fuzz coverage over
   whatever dump format that path introduces, matching this codebase's
   existing `FuzzReadBackupArchive` coverage for the sqlite path.
4. **Docs**: update this runbook and `docs/SELF_HOSTING.md` §5 once `admin
   backup`/`admin restore` support Postgres — the manual `pg_dump`/`psql`
   procedure would become the fallback, not the only path.

**Rough estimate**: ~1 week for the shell-out-to-`pg_dump` version;
2-3 weeks for a pure-Go, no-external-binary version consistent with this
track's own air-gapped goals — plus this codebase's typical adversarial-review
pass for a backup/restore code path (see `docs/g80-remediation-notes.md`'s own
engineering-practices section on why a first green test here is not the same
as a proven-correct one), realistically putting a production-ready version at
3-4 weeks total.

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
