# Upgrading Keyorix

**How far this guide is exercised.** `scripts/release-qa/` holds scripted scenarios
for a fresh install, a SQLite lifecycle and the version-skip path onto PostgreSQL
(section 3), and `scripts/drills/` rehearses backup/restore and upgrades on a
throwaway instance. The rest of this guide is written from the code and the
changelog, not from a drill of every step. Read the release notes and take a backup
first.

## 1. Always back up first

Before any upgrade, take a full backup — database *and* encryption keys, both
required (the database without the keys is unreadable ciphertext; the keys
without the database are useless). See section 4 below for the current
backup command and format, and `docs/SELF_HOSTING.md` §5 for the
Docker-Compose/Postgres procedure.

```sh
keyorix-server admin backup --output backup-$(date +%F).tar.gz
```

To rehearse an upgrade first, on a throwaway instance with your old and new
binaries (SQLite or PostgreSQL), run `scripts/drills/upgrade.sh`; see
[operator/drill-upgrade.md](operator/drill-upgrade.md).

## 2. Upgrading from v0.95.x → v0.95.2

(The steps are the same for every v0.95.x → v0.95.y upgrade, and for the Compose
and single-binary part of v0.95.x → v0.96.x; Compose and Helm have extra steps for
v0.96.0, see "Upgrading Docker Compose or Helm from v0.95.x to v0.96.0" below.)

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

Confirm which build is installed with `keyorix-server --version` (or `keyorix-server
admin version`; in Compose, `docker compose run --rm backend ./keyorix-server
--version`): it prints the version, commit, build date and Go version, and needs no
config file.

**What you will see when moving a v0.95.3 install to v0.96.0 or later** (SQLite
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

**PostgreSQL `ssl_mode: verify-full` (or `verify-ca`) now needs
`storage.database.ssl_root_cert`.** A config with a verifying mode and no CA
refuses to start (it used to connect and verify against `PGSSLROOTCERT`,
`~/.postgresql/root.crt` or the OS store, whichever the driver found). Before
upgrading, set `ssl_root_cert` to the CA's PEM file, or to `system` if the
database's certificate is publicly issued; with `dsn:`, add `sslrootcert=` to
the dsn instead. Helm: `externalDatabase.sslRootCert`. Check with
`keyorix-server admin validate --posture` (server stopped) after updating the
binary: a remaining problem is listed as a `database-tls` deviation. See
[CONFIGURATION.md](CONFIGURATION.md#postgresql-tls). `require` (the default)
is unchanged. A PostgreSQL connection-service file (`service=` in the dsn, or the
`PGSERVICE` environment variable) is refused too, because the file could set the
TLS mode and CA behind this check: move its settings into `storage.database`.
The refusal itself is covered by tests.

**PostgreSQL: two more TLS settings now refuse to start** (the server, and
every `admin` command that connects). (1) An `ssl_mode` outside `disable`,
`allow`, `prefer`, `require`, `verify-ca`, `verify-full` (it used to pass
validation and fail at the first connection); the same applies to the dsn's
`sslmode` and to `PGSSLMODE`. (2) `ssl_mode` set next to a `dsn` whose
`sslmode` differs or is missing (`ssl_mode` was silently ignored): put the
same `sslmode=` in the dsn, or remove `ssl_mode`. Check with `keyorix-server admin validate
--posture` after updating the binary. See
[CONFIGURATION.md](CONFIGURATION.md#postgresql-tls).

**Server image: `entrypoint.sh` is now the image's ENTRYPOINT** (it was its
CMD). `docker run <image> <command>` and `docker compose run backend <command>`
still run `<command>`, after the optional config copy (`KEYORIX_CONFIG_SOURCE`);
only an explicit `--entrypoint` bypasses it. Compose and Helm can opt into the
secure baseline: from v0.96.0 it is the default in `docker-compose.yml` and the
chart (`secureBaseline.enabled=true`; docs/SELF_HOSTING.md §7); it changes
`/metrics` (token required) and the backend's listener (TLS only).

Schema migrations run on boot. If a rolling multi-replica upgrade hits
`database schema epoch N is newer than this binary's schema epoch M`, that's
expected mid-rollout (see `docs/SELF_HOSTING.md` §9 troubleshooting table) —
not applicable to the bundled Helm chart, which is pinned to 1 replica.

### Upgrading Docker Compose or Helm from v0.95.x to v0.96.0

- **Compose: the secure baseline is now `docker-compose.yml`.** `docker-compose.secure.yml`
  and `keyorix.docker.secure.yaml` no longer exist; remove `-f docker-compose.secure.yml`
  from your commands. Pull the new `docker-compose.yml`, `keyorix.docker.yaml`,
  `deploy/compose/keyorix-backend.tls.conf` and `scripts/selfhost/` together and edit
  nothing else before `docker compose pull && docker compose up -d`. The backend then
  serves TLS on 8080 inside the compose network (web talks to it over verified
  HTTPS; the published port 8088 is unchanged), `/metrics` needs the generated token
  (`keyorix_tls` volume, `metrics_token`) and API rate limiting is on. Anything of
  yours that called `http://backend:8080` over the compose network must use HTTPS
  and trust `/app/tls/server.crt`.
- **Compose secrets stay `*_FILE` files** under `./secrets` (written 0640 by
  `scripts/selfhost/init-secrets.sh`; the containers join `KEYORIX_SECRETS_GID`).
  From an `.env`-based install run `./scripts/selfhost/init-secrets.sh --from-env .env`
  first. The server container runs as uid 1001 and refuses a group-readable secret
  file that uid 1001 owns: if your host user is uid 1001, hand the files to root
  (`sudo chown root:<your group> secrets/*`), as `scripts/demo/check.sh` does (#2973).
- **Helm: `secureBaseline.enabled` now defaults to `true`** (chart 0.96.0). An
  upgrade of a release that did not set it turns on TLS between pods, the
  `/metrics` token and rate limiting, and rolls the pods. Pin `image.tag` to
  v0.95.3 or older? Then set `secureBaseline.enabled=false`: those images cannot run it.
- **Helm with the bundled PostgreSQL: the data volume must change owner (uid 999 to 70).**
  The chart now runs the bundled Postgres as uid 70 (`postgresql.runAsUser`, the
  `postgres:15-alpine` user); v0.95.x charts ran it as 999 and own the existing data
  directory as 999. **Symptom if you skip this:** after `helm upgrade` the Postgres pod
  goes into `CrashLoopBackOff` on the existing volume (log:
  `initdb: could not access directory ".../pgdata": Permission denied`, or
  `data directory ... has wrong ownership`), and the server stays unready behind it.
  Run the upgrade with the one-time ownership migration:

  ```sh
  helm upgrade <release> <chart> --version 0.96.1 --reset-then-reuse-values \
    --set postgresql.migrateOwnership=true
  ```

  **Which flag.** Use `--reset-then-reuse-values` (Helm 3.14 or newer): it starts from
  the new chart's defaults, so every value added since your release is present, and
  then applies your previous values on top. Plain `--reuse-values` replaces the new
  chart's defaults with the values of your old release, so a value that did not exist
  then is missing. Chart **0.96.1 and newer** fills those in itself and works with
  either flag. Chart **0.96.0 does not** work with `--reuse-values` from a 0.95.x
  release (`nil pointer evaluating interface {}.enabled` at
  `.Values.secureBaseline.enabled`, and further missing keys behind it): upgrade
  straight to 0.96.1 or use `--reset-then-reuse-values`. On Helm older than 3.14,
  pass your values explicitly with `-f values.yaml` (no `--reuse-values`).

  The init container chowns the data volume to uid 70 (root with only `CHOWN` and
  `DAC_READ_SEARCH`, data volume only) and is a no-op on later starts. Once the pod is
  healthy you may unset it on the next upgrade (`--set postgresql.migrateOwnership=false`
  or drop it from your values); leaving it on is harmless. Alternatively keep running as the
  old owner with `--set postgresql.runAsUser=999` (needed for a Debian-based `postgres:*`
  image). A Pod Security "restricted" namespace rejects the init container. Rolling back
  to a 0.95.x chart afterwards needs the volume chowned back to 999. Details: §5
  "Bundled PostgreSQL uid". Compose volumes need nothing.

### Upgrading Docker Compose from v0.96.x to the next release: Postgres over TLS

The bundled Postgres now serves TLS, and the server connects to it with
`ssl_mode: verify-full`. `ssl_mode: prefer` (the v0.96.0 `keyorix.docker.yaml`) fell
back to plaintext whenever the TLS attempt failed, and `admin validate --posture`
now counts that as a deviation (`storage.database.insecure_allow_plaintext_database_fallback`).
The stack's certificate is generated next to the other secrets, so the upgrade is
one extra command:

1. Back up first (section 1).
2. Pull the new `docker-compose.yml`, `keyorix.docker.yaml` and `scripts/selfhost/`
   together, and bump the image pins to the release that ships this change (the
   v0.96.0 server image does not know `storage.database.ssl_root_cert` and refuses
   the new `keyorix.docker.yaml`).
3. **Generate the Postgres certificate:** `./scripts/selfhost/init-secrets.sh`. It
   keeps every existing file (the database and master passwords must not change)
   and adds `secrets/postgres_tls.crt` and `secrets/postgres_tls.key`. It needs
   `openssl` on the host. If your host user is uid 1001, hand the two new files to
   root as for the others (`sudo chown root:<your group> secrets/*`).
4. `docker compose pull && docker compose up -d`. Postgres restarts once with
   `ssl=on`; the data volume is not touched, nothing is migrated, and the server
   reconnects over TLS.

Check it: `docker compose exec postgres psql -U keyorix -d keyorix -c "select ssl,
version from pg_stat_ssl s join pg_stat_activity a using (pid) where a.usename='keyorix'"`
shows `t` / `TLSv1.3` for the server's connections, and `docker compose run --rm backend
./keyorix-server admin validate --posture` (backend stopped) prints the database TLS
line `ssl_mode=verify-full -- encrypted; certificate chain and host name verified`.

Things to know:

- **No silent fallback.** If you skip step 3, `docker compose up` fails at once (a
  secret file is missing). If Postgres is started without TLS, or presents any other
  certificate, the server refuses to start (`tls error: server refused TLS
  connection`, or an x509 error) instead of connecting in plaintext.
- **The certificate is self-signed and pinned**: the server trusts that one file as
  its `ssl_root_cert` and checks that it names the host `postgres`, the same way the
  web container trusts the backend's generated certificate. There is no CA hierarchy.
  It is valid for about ten years and never leaves the compose network. To rotate it:
  delete both files, run `init-secrets.sh`, then
  `docker compose up -d --force-recreate postgres backend`.
- **Your own Postgres** (not the bundled one): keep your `keyorix.docker.yaml` edits.
  `ssl_mode: prefer` or `allow` is now reported by `admin validate --posture`; use
  `verify-full` with `ssl_root_cert` pointing at your CA (CONFIGURATION.md, "PostgreSQL TLS").
- Anything that connected to the bundled Postgres directly from another container
  (`psql` over the network, a backup job) still works: the server accepts both
  plaintext and TLS clients, and only the Keyorix server insists on TLS.

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

`admin backup` and `admin restore` have no flags for a database path or DSN: the
target is always the one the `--config` file names. So each hop uses its own
config (`intermediate.yaml`: `storage.type: sqlite` with its own `path` and key
paths; `target.yaml`: `storage.type: postgres` and an empty database), with the
same `KEYORIX_MASTER_PASSWORD` throughout:

```sh
keyorix-server admin restore --config intermediate.yaml --input old-v1-backup.tar.gz
keyorix-server admin backup  --config intermediate.yaml --output intermediate-v2.tar.gz
keyorix-server admin restore --config target.yaml --input intermediate-v2.tar.gz
```

(An earlier revision of this page showed `--output-db`, `--db` and `--target-dsn`;
those flags do not exist. The second and third commands are exercised by
`scripts/drills/backup-restore.sh` for v2 archives, SQLite and PostgreSQL targets;
the v1 first hop has not been re-run since.) The restore needs the old install's
master passphrase and the same `dek_path`/`salt_path` in both configs; the target
database and key files start empty. `scripts/release-qa/scenario_version_skip_postgres.sh`
is the scripted form of this sequence.

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
- **Credentials are mounted files, not env vars (needs a server image that
  supports `*_FILE`, i.e. a release containing #2968).** The Secret is mounted
  at `/run/secrets/keyorix` and the pods read `KEYORIX_MASTER_PASSWORD_FILE`,
  `KEYORIX_DB_PASSWORD_FILE`, … (and `POSTGRES_PASSWORD_FILE` for the bundled
  Postgres). The Secret's keys are unchanged, so no Secret edit is needed. With
  `auth.existingSecret`, `helm upgrade` finds the optional
  `KEYORIX_ADMIN_PASSWORD` / `KEYORIX_BOOTSTRAP_TOKEN` keys in the live Secret
  by itself; when rendering with `helm template` or a GitOps tool that cannot
  look the Secret up, set `auth.existingSecretKeys.adminPassword` /
  `.bootstrapToken` to `true`. Prefer `helm upgrade --reset-then-reuse-values`;
plain `--reuse-values` works only from chart 0.96.1 on (it fails on 0.96.0 coming
from a 0.95.x release, see the v0.96.0 section above).
- **Docker Compose: credentials moved from `.env` to `./secrets`.** Run
  `./scripts/selfhost/init-secrets.sh --from-env .env` before `docker compose up
  -d` (details in `docs/SELF_HOSTING.md` §3); it keeps the same master and
  database passwords. The `tls` profile's Caddy now runs as non-root after a
  one-shot `caddy-init` chown of its volumes — no manual step.
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

## 6b. `environment:` in generated configs

`keyorix-server admin init` now writes `environment: production`, and
`admin init --dev` writes `environment: local` (#3217). **An existing config is
never rewritten** (`admin init` leaves it alone unless you pass
`--overwrite-existing`), so an upgrade changes nothing by itself. A config made
by an older `admin init` has no `environment:` line, and system info shows no
environment for it; add `environment: production` if you want the label.

Check one thing in configs you wrote yourself: the exact value
`environment: development` is not only a label. It replaces
`server.http.allowed_origins` with the localhost dev origins
(`http://localhost:3000`, `:5173` and the `127.0.0.1` equivalents). If a real
install says `development`, change it to `production` (or `staging`, `local`, …)
and restart.

## 6c. PostgreSQL: audit durability now defaults to `standard`

`storage.database.audit_durability` (ADR-112 Amendment 3) replaces
`storage.database.insecure_audit_skip_durable_sync`. **An existing PostgreSQL
install that sets neither key moves from `strict` to `standard` on upgrade:**
the audit row for a secret read is still committed before the secret is
returned, and a failed audit write still fails the request, but the commit no
longer waits for the disk sync, so an OS crash, power loss or PostgreSQL crash
can lose the last few hundred ms of audit entries (a tail, never a gap). A server process
crash still loses nothing, and secret writes, revocations and rotations still
commit durably. SQLite installs are unaffected: SQLite runs `strict` only.

To stay on `strict`, add one line under `storage.database` and restart:

```yaml
storage:
  database:
    audit_durability: strict
```

What you will see: the first start after the upgrade logs
`INFO: audit durability: standard (PostgreSQL default; committed before every
disclosure; ...; set audit_durability: strict to wait for the disk sync)`, and
the settings diff records `storage.database.audit_durability` changing from
`""` to `standard` in the audit trail. `admin validate` and
`GET /api/v1/system/info` (`security.audit_durability`) report the level.

The old key keeps working for one minor release, with a deprecation line at
start-up: `insecure_audit_skip_durable_sync: true` means `standard`, an
explicit `false` means `strict`. Setting both keys to conflicting levels
refuses to start. Replace it with `audit_durability`. `GET /api/v1/system/info`
no longer returns `security.audit_durable_sync_skipped` or
`security.audit_durable_sync_skip_not_in_effect_reason`, and the per-start
`admin.audit_durable_sync_skipped_at_startup` audit event is no longer written.

The behaviour is covered by
`TestAuditDurability_PostgresEndToEnd` and
`TestSecurityPostureSnapshot_AuditsAuditDurabilityLevelChange`.

## 6d. Refused secret-value reads are now audited

A refused native secret-value read (REST `GET /secrets/{id}?include_value=true`,
`/secrets/value`, render, copy, environment copy and clone, and gRPC
`GetSecretValue`) now writes a `secret.read` audit row with `success=false`,
`outcome=denied` and a `reason=` class (`forbidden`, `not_found`,
`outside_schedule`, `expired`, `suspended`, `max_reads_exhausted`,
`classification_gate`, `mfa_required`; a read that breaks is `internal_error`
with `outcome=failed`). Before, only federated (`connect.secret_read`) denials
were audited. API responses are unchanged. A burst is aggregated per principal,
reason, path and target (the first refusal at once, then one summary row per
60 seconds), so expect a somewhat higher audit volume under probing, and an
audit export or report that filtered on `event_type=secret.read` now also sees
`success=false` rows: filter on `success=true` for "secrets disclosed". The
dashboard read counts, top readers, billing machine reads and access-review
activity count only successful reads. The row is best-effort: if it cannot be
written, the refusal stands and the failure is logged.

## 6e. New opt-out: `storage.database.insecure_audit_skip_reads`

`storage.database.insecure_audit_skip_reads` (ADR-112 Amendment 4) defaults to
`false`, so an upgrade changes nothing. Do not set it unless you accept that
successful secret reads leave no audit row and no access-log row (writes,
authentication, denied reads, admin and break-glass actions are still audited;
read history, read counts, usage reports and anomaly detection do not see
reads). It is config-file only and a compliance profile refuses it. When on,
every start logs a `WARNING` and writes `admin.audit_reads_skipped_at_startup`,
`admin validate` and `admin validate --posture` report a deviation,
`GET /api/v1/system/info` returns `security.audit_reads_skipped: true`, and the
web UI shows a banner that cannot be dismissed. It is independent of
`audit_durability` (§6c). See [`security/hardening-guide.md`](security/hardening-guide.md) §5b.

## 6f. New opt-in: `storage.database.single_writer` (PostgreSQL)

`storage.database.single_writer` defaults to `false`; with it off nothing changes
except that a start-up refuses while a single-writer server holds the database
and removes a fence one left behind. Turning it on declares this server the
database's only writer: it takes a per-schema advisory lock (a second server, a
server without the setting, and `admin --force` are refused while it runs),
installs triggers that refuse direct writes to the security tables from any
other session, and may then serve warm machine-token secret reads without
re-running the confirming statement. If the fence cannot be installed and
verified, the server refuses to start. Read [`single-writer.md`](single-writer.md)
(including the emergency procedure for a direct database change) before
enabling it, and check `GET /api/v1/system/info` (`database.single_writer`) and
`admin validate --posture` afterwards.

## 6h. A database outage now rejects cached credentials (503)

Behaviour change, no setting. On an HTTP request whose credential is in the
server's ~30-second auth cache, the server re-checks the credential's
revocation state against the database (PAT, machine token, session and its
account, federated OIDC machine identity). When that read fails, the request is
now refused with `503 Service Unavailable`, `Retry-After: 2` and the message
"authentication temporarily unavailable, please retry". Before, the server
authenticated it from the cached login, which also kept a credential revoked
on another replica working during the outage. Expect brief database outages,
failovers and connection-pool exhaustion to show up as 503s on already
authenticated clients rather than only on new logins; make API clients, CI
jobs and agents retry on 503 (gRPC: `Unavailable`, unchanged). Nothing is
evicted, so requests are served from the cache again as soon as the database
answers. A session whose user row was deleted is now refused `401` on its next
request instead of being served until the cache entry expired. See
[`security/threat-models/authentication.md`](security/threat-models/authentication.md) AUTH-11.

## 6g. "Last used" in access recertification now means "within the review period"

The per-user "last used" of the project access review (and of the items a campaign
snapshots from it) used to be the user's most recent secret activity anywhere in the
audit log. It now looks back over the recertification period only,
`recertification.cadence_days` (default 90, at most 366). The meaning changes from
"no activity ever" to **"no activity within the last N days"**: a user whose last
activity is older than the period now shows no last use, so they read as dormant where
before they showed an old date. Expect more entries flagged dormant after the upgrade
if your cadence is shorter than your longest-idle users' last activity. Nothing is
deleted; raise `cadence_days` (up to 366) for a longer look-back.

- API: `GET /api/v1/projects/{id}/access-review` adds `activity_window_days`, and
  campaigns carry `activity_window_days`.
- Campaign CSV export: a new last column, `last_used_window_days` (a CSV parser that
  reads columns by position is unaffected; one that rejects extra columns is not).
  Campaigns opened before the upgrade say `all_history`: their `last_used_at` was
  computed over the whole log and stays as recorded.
- The `dormant-access` control and the digest now say "no use in the last 90 days"; the
  dormant-grant count itself is unchanged (it was always judged against 90 days).
- The campaigns table gets one column, `activity_window_days`, added automatically at
  start-up (nothing to run); a rollback to the previous binary ignores it.

Details: [recertification-activity-window.md](recertification-activity-window.md).

## 6q. Schema epoch 3: v0.96.x cannot run against an upgraded database

This release raises the schema epoch and its compatibility floor to 3 (ADR-101).
Once a server of this release has started against a database, a v0.96.x (epoch 2)
binary refuses to start on it: `database declares a minimum compatible schema
epoch of 3`. That is deliberate. Two formats v0.96.x cannot handle are now in the
database:

- **The v2 audit retention anchor (#3258).** v0.96.x reads it as malformed, so its
  `GET /audit/verify` reports the chain broken. Worse, its audit purge would write
  a v1 anchor, which drops the cumulative purged count for good (`/audit/verify`
  then says "truncated" and `POST /audit/checkpoint` answers 409; #3359).
- **`secret_nodes.suspend_clear_synced_copies` (#3215).** A v0.96.x resume left the
  marker set, so its next plain suspend made the operator and k8s-sync clear the
  synced Kubernetes copies (#3362).

The floor only stops v0.96.x servers from **starting**. For v0.96.x replicas still
running during a rolling upgrade, PostgreSQL triggers installed by the migration
cover the same two cases. An older binary's purge over a v2 anchor is refused and
rolled back whole, so nothing is deleted. Any status change away from `suspended`
clears the marker, whichever binary writes it.

Rolling upgrade from v0.96.x with several replicas:
[SELF_HOSTING.md, "Running more than one replica"](SELF_HOSTING.md#running-more-than-one-replica).
In short:

- let the rollout finish;
- don't run `POST /api/v1/admin/jobs/purge-audit-logs` until it has finished, because a
  request that lands on an old replica fails;
- expect `GET /audit/verify` on old replicas to report "broken" after a purge until
  they are replaced.

Rollback across this release needs a restore (section 7).

## 6s. PostgreSQL: the server checks it holds the database's DEK (DEK epoch)

On PostgreSQL the database now records which DEK it is encrypted under (the DEK
epoch: `system_metadata` key `dek.epoch`, a fingerprint, not key material). The
first server to start after the upgrade records it, after checking that its DEK
decrypts the newest stored secret version. From then on:

- A server whose DEK is not the recorded one refuses to start (it would write
  rows nobody can decrypt once the old DEK is gone). This catches a replica
  started with an old `dek.key` after a DEK rotation on another host.
- A running server refuses encrypted writes (reads and revocations continue)
  while a DEK rotation is in progress or after one finished elsewhere.
- `admin encryption rotate` fences writes on every replica, waits about 10
  seconds, and locks the encrypted tables against writes during its sweep.

Upgrade every replica before the next DEK rotation: an older binary does not
check the epoch. With several replicas, start one that holds the current key
set first. SQLite is unchanged. See
[`operator/j6-key-rotation.md`](operator/j6-key-rotation.md).

## 6i. Start-up refuses a weak SCIM token and an unneeded KMS context fallback

Two behaviour changes at boot, no new setting. Check before upgrading:

- **SCIM token (`scim.enabled: true`).** Besides the 20-character minimum, the token
  must not be one byte repeated, have fewer than 10 distinct characters, contain a
  placeholder (`changeme`, `password`, `example`, `secret` ...), be made only of sample
  words (`test-token-...`), or equal another configured secret. An upgraded deployment
  gets the ADR-112 grace period: the server starts and logs
  `WARNING: SCIM token is too weak: ... ADR-112 grace period ...` until the first start
  with a token that passes (or with SCIM off); after that, and on a fresh install, it
  refuses to start.
  Replace the token with `openssl rand -base64 32` in Keyorix and in the IdP's SCIM
  connector.
- **`storage.encryption.key_provider.insecure_allow_kms_context_fallback`** (aws-kms,
  gcp-kms). When the stored wrapped KEK already opens with its `kms_encryption_context`
  (the migration it exists for is done), the server refuses to start and says the flag
  can be removed. Remove it before upgrading. A KEK that still needs it starts as before.

Messages and fixes: [startup-refusals.md](operator/startup-refusals.md#weak-scim-token),
[KMS context fallback](operator/startup-refusals.md#kms-context-fallback-no-longer-needed--from-code).

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

## 8. See also

- `docs/SELF_HOSTING.md` §4 (master password / KEK), §5 (backup and
  restore), §6 (upgrades), §9 (troubleshooting).
- `docs/operator/startup-refusals.md` for what each start-up refusal means after an
  upgrade or rollback (schema epoch newer than the binary, compatibility floor,
  key files, restore rollback protection) and which fixes are safe in place.
- `docs/AIRGAP_RUNBOOK.md` for the air-gapped-specific backup/restore
  procedure.
- `docs/rolling-upgrade-columns.md` for why a column added by one release does
  not break the previous release's replicas during a rolling upgrade.
- `CHANGELOG.md` and the GitHub release notes for the full list of changes
  in this release.
- `design-b3-backup-v2.md` for the full backup-v2 design (§3 format, §5
  manifest signing, §6.3 rollback protection, §7 streaming).
