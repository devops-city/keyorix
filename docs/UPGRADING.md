# Upgrading Keyorix

**Verification status of this guide:** commands below are marked either
UNVERIFIED or VERIFIED. VERIFIED means it was run end to end against a real
environment (real binaries, a real kind cluster, or a real PostgreSQL 16
instance) as part of this release's QA pass. UNVERIFIED means it has not.

## 1. Always back up first

Before any upgrade, take a full backup — database *and* encryption keys, both
required (the database without the keys is unreadable ciphertext; the keys
without the database are useless). See section 4 below for the current
backup command and format, and `docs/SELF_HOSTING.md` §5 for the
Docker-Compose/Postgres procedure.

```sh
keyorix-server admin backup --output backup-$(date +%F).tar.gz
```

**VERIFIED** — run repeatedly during this release's QA (fresh install,
rollback drill, air-gapped drill, version-skip proof), each time producing a
valid, restorable v2 archive.

## 2. Upgrading from v0.95.x → v0.95.2

(Latest release at the time of writing is v0.95.3; the steps are the same.)

This is the normal, in-place upgrade path: same major/minor line, schema
migrations run automatically and are additive.

```sh
# Docker Compose: docker-compose.yml pins the image tags, so edit the backend and
# web tags to the target release first (otherwise `pull` fetches nothing new)
docker compose pull
docker compose up -d

# Single binary
# stop the old process, replace the binary, restart
```

**What you will see when moving a v0.95.3 install to `main`** (verified, SQLite
single binary and Compose + Postgres): a secret written by v0.95.3 reads back
unchanged, `admin verify-audit` is VALID, and the first start logs
`ADR-112 grace period: security.require_mfa now defaults to true, but this is an
upgraded deployment` — MFA is not enforced yet and `admin validate --posture`
(run with the server stopped, like every `admin` command) counts it as a
deviation until each admin enrols (`keyorix mfa enroll` /
`activate`; the v0.95.3 CLI has no `mfa enroll`, so use the new CLI or the web
UI) and `security.require_mfa: true` is set explicitly. Back up with the *old*
release's tooling before swapping: on the v0.95.3 Compose image
`admin backup` beside the live server fails with `failed to acquire the
encryption key lock`; stop `backend` and use `docker compose run` (see
SELF_HOSTING.md §5).

**Your config is not changed.** From the release after v0.95.3, a *fresh*
`keyorix-server admin init` writes the secure baseline (TLS with a generated
self-signed certificate, rate limiting on, a generated `/metrics` token file;
see [CONFIGURATION.md](CONFIGURATION.md#the-generated-config-is-the-secure-baseline)).
An existing `keyorix.yaml` keeps its values, and re-running `admin init` next to
it generates nothing, so `admin validate --posture` keeps reporting the same
deviations until you set the keys listed in
[CONFIGURATION.md](CONFIGURATION.md#hardening-an-older-config-clearing-the-posture-report)
yourself. Scripts that ran `admin init` and then talked plain HTTP need
`admin init --dev` (relaxed, labelled DEV-ONLY) or the generated certificate
(`keyorix config set ca_file <path>`, `--ca-file`, `KEYORIX_CA_FILE`).

**Server image: `entrypoint.sh` is now the image's ENTRYPOINT** (it was its
CMD). `docker run <image> <command>` and `docker compose run backend <command>`
still run `<command>`, after the optional config copy (`KEYORIX_CONFIG_SOURCE`);
only an explicit `--entrypoint` bypasses it. Compose and Helm can opt into the
secure baseline: `docker-compose.secure.yml` / `secureBaseline.enabled=true`
(docs/SELF_HOSTING.md §7); turning it on changes `/metrics` (token required)
and the backend's listener (TLS only).

Schema migrations run on boot. If a rolling multi-replica upgrade hits
`database schema epoch N is newer than this binary's schema epoch M`, that's
expected mid-rollout (see `docs/SELF_HOSTING.md` §9 troubleshooting table) —
not applicable to the bundled Helm chart, which is pinned to 1 replica.

**VERIFIED** — a real, downloaded v0.95.1 release binary provisioned a
SQLite database, stopped, then the v0.95.2 binary migrated and booted that
same database in place and passed a full API smoke sweep with
`verify-audit: VALID` afterward.

## 3. Upgrading from v0.94.x or v0.93.x (version skip)

**What's actually been proven, and what hasn't:** an end-to-end harness
downloads the actual **v0.95.0** release binary, takes a backup with it,
carries that data onto v0.95.2 running against a real PostgreSQL 16
instance, and confirms secrets decrypt identically, the audit chain still
verifies, and authz answers are unchanged. That is a real, binary-level
proof — but it covers exactly one hop: **v0.95.0 → v0.95.2, on Postgres.**
It does **not** cover v0.94.x or v0.93.x as a starting point, and it does
not cover a SQLite-backed install skipping versions. If you're upgrading
from v0.94 or earlier, or on SQLite, there is currently no equivalent proof
— treat the single-hop path below as the only currently-substantiated
route, and open each intermediate release's own upgrade notes if in doubt.

**The mechanical shape that's been proven**: an old release's `admin
backup` writes the v1 (physical, SQLite-only) archive format. v1 can only
restore into SQLite, so getting an old SQLite-era install onto v0.95.2 on
Postgres is a 3-hop procedure, not a direct restore:

1. Restore the old binary's v1 archive into an **intermediate SQLite**
   database, using v0.95.2's `admin restore` (v1 reading is kept
   indefinitely, see section 4).
2. Take a fresh v2 backup of that intermediate SQLite database.
3. Restore that v2 archive into the real Postgres target.

```sh
keyorix-server admin restore --input old-v1-backup.tar.gz --output-db ./intermediate.sqlite
keyorix-server admin backup --db ./intermediate.sqlite --output intermediate-v2.tar.gz
keyorix-server admin restore --input intermediate-v2.tar.gz --target-dsn "$POSTGRES_DSN"
```

**VERIFIED** — run end to end with a real, downloaded v0.95.0 release
binary and the actual v0.95.2 build against a real PostgreSQL 16 instance:
the secret value decrypted byte-identical to what the old binary encrypted,
the audit chain verified at every stage, and two authz probes (one ALLOWED,
one DENIED) matched the old binary's answers exactly after the restore.

If you're going from v0.94/v0.93 straight to v0.95.2, the same 3-hop shape
should still apply mechanically (v1 read support doesn't change), but that
specific starting point has not been run by anyone as of this writing.
**Recommendation:** upgrade to v0.95.1 first (a version with its own direct
RC verification), confirm the install is healthy, then upgrade again to
v0.95.2. Two proven single-version hops beat one unproven multi-version
skip.

## 4. Backup format: v1 vs v2

- **v0.95.2 writes only the v2 format.** `admin backup` produces the new
  backend-neutral, NDJSON/logical archive — there is no v1-output mode.
- **v1 archives still restore.** `admin restore` auto-detects the archive's
  declared format version and dispatches to the right reader; v1-reading
  support is kept "until 1.0" per the design doc's own decision
  (`design-b3-backup-v2.md` §3.6 decision 3). You do not need to convert an
  old v1 archive before restoring it — `admin restore --input old.tar.gz`
  works directly on v0.95.2.
- **v2 supports PostgreSQL.** `admin backup`/`admin restore` now work
  against both SQLite and PostgreSQL targets, not SQLite-only as before.
- **The manifest signing key depends on the KEK, not on anything global.**
  The manifest is HMAC-signed with a key derived (via HKDF) from that
  specific archive's own KEK at the time the backup was taken. Restore
  unwraps the KEK from the **archive's own staged key files**, never the
  live target's — so an archive's manifest stays verifiable on its own
  terms regardless of what happens to the target's keys afterward.
- **What happens after `keyorix-server admin encryption rotate`:** this
  command rotates the **DEK** (the key that encrypts your data), not the
  KEK — the KEK is derived from `KEYORIX_MASTER_PASSWORD`. To change that
  passphrase use `keyorix-server admin encryption rotate-kek`
  ([operator/j6-key-rotation.md](operator/j6-key-rotation.md)); editing the
  variable by hand makes every stored secret undecryptable (see
  `docs/SELF_HOSTING.md` §4). Since the backup manifest
  signing key is HKDF-derived from the KEK alone — never the DEK — a DEK
  rotation does not change it, and does not retroactively affect any
  existing backup archive: an archive taken before the rotation carries its
  own pre-rotation staged key files and restores/verifies exactly as it did
  before, decrypting under the very same (unchanged) KEK. You do not need
  to re-take or migrate old backups because of a DEK rotation.
  **VERIFIED** — ran a real `admin encryption rotate --confirm` against a
  live install (real v0.95.2 binary), then restored a backup taken *before*
  that rotation: the restore's manifest-signature verification succeeded
  using the same `KEYORIX_MASTER_PASSWORD`, `verify-audit` reported VALID,
  and the pre-rotation secret was readable, byte-identical, after booting
  against the restored data.
- **Tamper detection:** v1's archive-level checksums only catch corruption
  (a bad copy, a truncated transfer, bit rot) — anyone with write access to
  the archive can recompute them to match tampered content. v2's HMAC-signed
  manifest additionally requires the KEK-derived key to forge, so it closes
  that specific gap. v2 restore also fails closed on a **stale** backup by
  default: restoring an archive older than the target's own recorded audit
  high-water mark is refused unless you pass `--allow-rollback` explicitly.

## 5. Helm-specific steps

- **Bootstrap token secret.** The chart generates and wires
  `KEYORIX_BOOTSTRAP_TOKEN` automatically (idempotent across `helm
  upgrade`) — the server requires this token to authorize `POST
  /system/init`. `NOTES.txt` prints the retrieval command for a manual
  `keyorix system init` if you need it.
- **Password-length gate.** The chart refuses to render if
  `auth.adminPassword` is under 16 characters. **Check your values file's
  `adminPassword` length before upgrading the chart** — a value that
  rendered before this release may now fail the chart render outright.
- **First-boot bootstrap retryability.** A password rejected at bootstrap
  (e.g. containing the admin username) no longer leaves the database
  half-seeded. The whole bootstrap runs in one transaction, so a rejected
  attempt writes nothing and retrying with a corrected password just works.
- **Bundled PostgreSQL uid (70 on the alpine image).** The chart now runs the
  bundled Postgres as the uid of its image, `postgresql.runAsUser` (default
  `70`, what `postgres:15-alpine` and `docker-compose.yml` use). Charts since
  v0.87.0 ran it as `999`, so a data volume they created is owned by `999`, and
  Postgres refuses to start on a data directory it does not own (the pod
  CrashLoops with `data directory ... has wrong ownership`). Pick one on the
  `helm upgrade` that introduces this chart:
  - `--set postgresql.runAsUser=999` -- keep running as the volume's owner (no
    change to the volume; a Debian-based `postgres:*` image also needs 999); or
  - `--set postgresql.migrateOwnership=true` -- a one-time, opt-in init container
    chowns the volume to `runAsUser`. It runs as root with only `CHOWN` and
    `DAC_READ_SEARCH`, touches only the data volume and only entries not already
    owned by `runAsUser`, and is a no-op on later starts (remove the flag again
    once migrated). A Pod Security "restricted" namespace rejects it. Rolling
    back to an older chart afterwards needs the volume chowned back to `999`.
  Compose volumes need nothing: the compose stack always ran as `70`.

**VERIFIED** — real `helm install` and `helm upgrade` against a kind
cluster with locally built server/web images: the password-length gate
correctly refuses render on a too-short password; a password that passes
the chart's length check but still trips the server's own username-
substring rule fails bootstrap cleanly (403, pod stays `Ready`) and a
retry with a compliant password completes the install immediately, no
wipe needed; `helm upgrade` with identical values regenerated no new
bootstrap token (byte-identical) and preserved existing data.

## 6. Air-gapped image rename

The published air-gapped image tag is renamed from `keyorix-server-lean` to
`keyorix-server-airgap` **and moved onto the main `keyorix-server` image
repository as a `-airgap` tag suffix** — it is not a separate repository.
If you pull this image by tag in a CI pipeline, a compose override, or a
Helm values override, update both the repository and the tag shape before
your next pull.

```sh
# old
ghcr.io/keyorixhq/keyorix-server-lean:0.95.1

# new
ghcr.io/keyorixhq/keyorix-server:0.95.2-airgap
```

**VERIFIED** — both the pre-release build+drill and, after v0.95.2 was
tagged and its release workflow finished, the real published artifact:
`docker pull ghcr.io/keyorixhq/keyorix-server:0.95.2-airgap` succeeded, its
SLSA provenance attestation verified (`gh attestation verify
oci://ghcr.io/keyorixhq/keyorix-server:0.95.2-airgap --repo
keyorixhq/keyorix`, subject digest matched the pulled image exactly), and
it booted healthy under `docker run --network none` (genuine air-gapped
mode), bootstrapped, and served a real secret create/read. Earlier,
pre-tag: building the exact same profile locally (`docker build
--build-arg BUILD_TAGS=noaws,noazure,nogcp`) and running the full
`scripts/airgap-e2e.sh` disaster-recovery drill against it end to end —
real bootstrap, real secret, `admin backup`/`admin restore` with the
checkpoint anchor cross-check, secret value round-tripped, and the
tampered-archive negative leg correctly refused.

Also confirmed the air-gapped profile links **zero** AWS/Azure/GCP SDK
packages (`go list -tags "noaws noazure nogcp" -deps ./server`, 666 total
packages, none matching; cross-checked those three SDK families ARE
present in the unfiltered dependency graph, so this isn't a vacuous pass).

## 6a. BREAKING: the server now binds 127.0.0.1 by default

`server.http.host` and `server.grpc.host` now default to `127.0.0.1` (loopback
only) instead of every interface (#2939 / #2946). An install that keeps its own
config file with **no `host:` line** and is reached from another machine, a
reverse proxy on another host, or through a published container port stops
accepting those connections after the upgrade.

Add the bind address explicitly under `server.http` (and `server.grpc` if you
enable gRPC), then restart:

```yaml
server:
  http:
    host: "0.0.0.0"   # all interfaces; or a specific interface address
```

The shipped `docker-compose.yml` / `keyorix.docker.yaml`, the Helm chart and
`scripts/demo/up.sh` already set `0.0.0.0`; only configs you wrote or mounted
yourself need the line. The startup log prints the bound address, with a note
when it is reachable from the network.

## 7. Rollback

If an upgrade goes wrong:

1. Stop the new version.
2. Restore the backup you took in step 1, using a binary matching the
   version that backup came from (an `admin restore` binary can read
   older-format archives, but restoring into a *newer* schema than the
   backup's own binary understands is not the supported direction — restore
   with the matching or a newer binary, then let migrations run forward
   again, not backward). **Expect `admin restore` to refuse this by
   default** with a message about the archive being behind the host's own
   audit high-water mark — that's the intended rollback-protection
   behavior, not a malfunction, for exactly this scenario (the target has
   moved on since the backup). Pass `--allow-rollback` to proceed; it
   prints a loud warning and records the override to the audit trail.
3. `admin verify-audit` after restore, on whichever binary you rolled back
   to, to confirm the audit chain is intact.
4. If the new version's database has already advanced the recorded schema
   epoch (ADR-097), a straight downgrade of the *binary* while keeping the
   already-migrated database is refused at startup by design (`database
   schema epoch N is newer than this binary's schema epoch M`) — this is
   why step 2 restores data from before the failed upgrade rather than
   attempting to run the new binary's data on the old binary.

**VERIFIED** — a full rollback drill: took a backup, then simulated a bad
upgrade (deleted the pre-backup secret, wrote a new one that should not
survive), then restored the backup in place. The restore was correctly
**refused** without `--allow-rollback` (the archive was behind the host's
own audit high-water mark — exactly the rollback-protection design doing
its job); retrying with `--allow-rollback` succeeded, recorded the override
to the audit trail, and booting against the restored data confirmed the
pre-upgrade secret was back and the post-upgrade one was gone.

## 8. See also

- `docs/SELF_HOSTING.md` §4 (master password / KEK), §5 (backup and
  restore), §6 (upgrades), §9 (troubleshooting).
- `docs/AIRGAP_RUNBOOK.md` for the air-gapped-specific backup/restore
  procedure.
- `CHANGELOG.md` and the GitHub release notes for the full list of changes
  in this release.
- `design-b3-backup-v2.md` for the full backup-v2 design (§3 format, §5
  manifest signing, §6.3 rollback protection, §7 streaming).
