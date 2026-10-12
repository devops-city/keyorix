# Self-Hosting Keyorix

Keyorix runs entirely on your own infrastructure — no cloud dependency, no
outbound telemetry. This guide covers a Docker Compose deployment (web UI + API
server + PostgreSQL), the production concerns that actually matter (encryption
keys, backups, upgrades, TLS), and how to recover.

The stack is three containers:

| Service    | Image                              | Purpose                                  |
|------------|------------------------------------|------------------------------------------|
| `web`      | `ghcr.io/keyorixhq/keyorix-web`    | nginx serving the SPA; reverse-proxies `/api/`, `/auth/`, `/system/` to the API |
| `backend`  | `ghcr.io/keyorixhq/keyorix-server` | the Keyorix API server (Go, single binary) |
| `postgres` | `postgres:15-alpine`               | the encrypted data store                 |

## 1. Prerequisites

- Docker Engine 24+ and the Compose plugin (`docker compose version`).
- A host with at least 1 vCPU / 1 GB RAM for a small team.

## 2. Quick start

```sh
git clone https://github.com/keyorixhq/keyorix.git
cd keyorix
cp .env.example .env
./scripts/selfhost/init-secrets.sh     # generates ./secrets/* and records KEYORIX_SECRETS_GID in .env
docker compose up -d
```

Open **http://localhost:8088** and log in as `admin` with the password in
`./secrets/admin_password`. That's it.

> Building from source instead of pulling published images: edit
> `docker-compose.yml` and swap the `backend` service's `image:` for the
> commented-out `build:` block (the `web` image is still pulled). The first
> `docker compose build backend` takes about 3 minutes and the first `up -d`
> about 1–2 minutes more (image pulls); nothing is printed for the 15–35 s the
> backend spends on first-boot migrations and key derivation.

**First boot check.** With `KEYORIX_ADMIN_PASSWORD_FILE` + `KEYORIX_BOOTSTRAP_TOKEN_FILE` set
(the shipped compose file does) the backend creates the admin by calling `/system/init` as soon as the server
answers `GET /health`. The entrypoint waits for that for up to
`KEYORIX_READY_TIMEOUT` seconds (default 180, so a slow first boot on a loaded
host is fine), then retries the bootstrap call up to `KEYORIX_BOOTSTRAP_ATTEMPTS`
times (default 10, 3 s apart). It fails loudly: if the admin still cannot be
created, the entrypoint logs `ERROR: admin bootstrap did not complete ...`, stops
the server and exits non-zero, so the backend restarts instead of sitting
"healthy" with no usable login. On success the log shows `Server is ready after
Ns`, `Bootstrapping admin user` and `Admin bootstrap complete.` in
`docker compose logs backend`. If you see the `ERROR:` lines instead, check that
`./secrets/bootstrap_token` exists and is the one the backend reads, then fix it and run
`docker compose up -d` again (or create the admin by hand with
`keyorix system init --server http://localhost:8088 --admin-username admin --admin-email admin@keyorix.local`
with `KEYORIX_BOOTSTRAP_TOKEN` exported in your shell: the CLI reads the token
and prompts for the admin password; neither goes on the command line).
`docker compose ps` shows `web` as `healthy`: its healthcheck probes
`127.0.0.1` (busybox resolves `localhost` to IPv6 first and nginx listens on IPv4
only).

**Using the CLI against the stack.** The backend's port is not published; the
CLI talks to it through the web container's proxy:
`keyorix login --server http://localhost:8088 --username admin` (and
`--server https://<KEYORIX_DOMAIN>` with the `tls` profile). The first admin
login is confined to MFA enrolment, as in [QUICK_START.md](../QUICK_START.md#enrol-mfa-required-on-first-login).

**Generate your admin recovery key now, before you need it.** If every admin
account is ever locked out (lost password, lost MFA device), the only way back
in is `keyorix-server admin recover-admin` on the server host — and by
default it also requires this key (`security.recover_admin.insecure_keyless_admin_recovery`, formerly
`keyless_mode`, is an
explicit, less-secure opt-out documented in `configs/keyorix.yaml.tpl`, not the
default, `security.recover_admin.insecure_keyless_admin_recovery: true` in server config opts
out). No key exists until you generate one. Like every `keyorix-server admin`
command except a Postgres backup, it needs the database to itself — it holds
the exclusive admin lock for the whole rotation, so a concurrent
`recover-admin` can never see a half-rotated key, and it refuses while the
server is running. Stop `backend`, run it in a throwaway container, start
`backend` again (a few seconds of downtime):

```sh
docker compose stop backend
docker compose run --rm backend ./keyorix-server admin recovery-key rotate
docker compose start backend
```

This prints a 256-bit key **exactly once** — save it somewhere durable and
separate from this host (a password manager, not a file next to `.env`). It is
never written to a log file or the audit chain in plaintext, and losing it
means running the command again (which invalidates the old key). See
`docs/design-b2-recover-admin.md` for the full design.

**"Too many login attempts" (HTTP 429).** Each IP address gets
`LoginMaxAttempts` (10) *failed* login attempts per 15 minutes, shared by the
password, TOTP, passkey and refresh endpoints; successful logins do not count
(#2936), and an MFA or passkey login counts once however many requests it
takes. The count lives in the database, so restarting the server does not
reset it. To lift it early for one address, or to clear one account's
failed-login lockout, use the audited host-side command (it needs the database
to itself, like every admin command):

```sh
docker compose stop backend
docker compose run --rm backend ./keyorix-server admin clear-login-lockout --ip 203.0.113.9
docker compose run --rm backend ./keyorix-server admin clear-login-lockout --user alice@example.com
docker compose start backend
```

Each run writes an `admin.login_lockout_cleared` audit event naming what it
is about to clear, before it clears anything: if the audit write fails, nothing
is cleared and the command fails. If the clear itself then fails, an
`admin.login_lockout_clear_failed` event follows. An admin who can still log in can unlock an account online instead
(`POST /api/v1/users/{id}/unlock`).

## 3. Configuration (`.env` and `./secrets`)

Credentials are **Docker secrets files** under `./secrets` (or `$KEYORIX_SECRETS_DIR`),
not environment variables: they never appear in `docker inspect` or in a container's
process environment. There are **no baked-in default passwords**; the stack refuses to
start if `./scripts/selfhost/init-secrets.sh` has not been run. The script generates
strong values, never overwrites an existing file, and never prints a value.

| File in `./secrets`  | Read through | Notes |
|----------------------|--------------|-------|
| `db_password`        | `KEYORIX_DB_PASSWORD_FILE`, `POSTGRES_PASSWORD_FILE` | PostgreSQL password (shared by `postgres` and `backend`). |
| `master_password`    | `KEYORIX_MASTER_PASSWORD_FILE` | Passphrase the encryption KEK is derived from. **See the warning below.** |
| `admin_password`     | `KEYORIX_ADMIN_PASSWORD_FILE` | The first admin is created on first boot (idempotent). To initialise manually with `keyorix-server admin init` instead, delete the `KEYORIX_ADMIN_PASSWORD_FILE` and `KEYORIX_BOOTSTRAP_TOKEN_FILE` lines from the `backend` service. |
| `bootstrap_token`    | `KEYORIX_BOOTSTRAP_TOKEN_FILE` | `/system/init` always requires a matching bootstrap token; the admin bootstrap needs both. Setting the admin password file without this makes the backend exit at startup with an `ERROR:` message. |

Non-secret settings stay in `.env`: `KEYORIX_ADMIN_USERNAME` (default `admin`),
`KEYORIX_ADMIN_EMAIL` (default `admin@keyorix.local`), `KEYORIX_DOMAIN`, and
`KEYORIX_SECRETS_GID` (written by `init-secrets.sh`).

**Why a group id.** Compose bind-mounts a file secret as-is and ignores its
`uid`/`gid`/`mode` (it warns "not supported"), so a `0600` file on the host would be
unreadable by the containers' non-root users. `init-secrets.sh` writes the files
`0640` with your primary group and records that gid as `KEYORIX_SECRETS_GID`; the
`postgres` and `backend` containers join that group. Nothing is world-readable, and
the server's secret-file permission check (nothing for "other", no group write; a
group-readable file must not be owned by the container's own user) passes. Run the
script as a regular user, not root. If your uid is `1001` (the uid the server
container runs as) the server would refuse the group-readable files it "owns", and the
script says so: hand them to another owner with `sudo chown root:<your gid> secrets/*`
and re-run it. Docker Desktop (macOS/Windows) maps file ownership
differently; this layout is for Linux hosts.

**Upgrading an install that keeps its passwords in `.env`:**

```sh
./scripts/selfhost/init-secrets.sh --from-env .env   # copies the four values byte for byte
# then delete KEYORIX_DB_PASSWORD, KEYORIX_MASTER_PASSWORD, KEYORIX_ADMIN_PASSWORD and
# KEYORIX_BOOTSTRAP_TOKEN from .env, and:
docker compose up -d
```

The master password and the database password are copied unchanged, which is what keeps
your stored secrets decryptable and the existing `postgres_data` volume working.

**Secrets as files, in general.** The server accepts any of its secrets as a file:
set `KEYORIX_<NAME>_FILE` to a path (Docker secrets mount under `/run/secrets/`, a
Kubernetes Secret volume wherever you mount it). Setting both `X` and `X_FILE` is a
startup error, not a precedence rule, and an unreadable or empty file stops the server.
The master-password file must be `0600`/`0400` (or a `0440` mount owned by another user,
e.g. root, in a group the container holds -- Kubernetes `fsGroup`, Docker `group_add`);
a looser one is refused. The container entrypoint passes `X_FILE` through to the server
unchanged and never exports a value it read from a file. Details and the full list of
supported variables: [CONFIGURATION.md](CONFIGURATION.md#secrets-from-files-name_file).

Server configuration (storage, encryption paths, ports) lives in
`keyorix.docker.yaml`, mounted read-only into the `backend` container. The full,
annotated reference is `configs/keyorix.yaml.tpl`.

## 4. ⚠️ The master password and encryption keys — read this

Secrets are encrypted with a Data Encryption Key (DEK) that is itself wrapped by
a Key Encryption Key (KEK) **derived from `KEYORIX_MASTER_PASSWORD`**. The wrapped
DEK and the KEK salt live on the `keyorix_keys` Docker volume.

Two ways to permanently lose every stored secret:

1. **Changing `KEYORIX_MASTER_PASSWORD`** after first boot. The KEK no longer
   derives, the DEK can't be unwrapped. (To rotate it intentionally, use
   `keyorix-server admin encryption rotate-kek` — never by editing `.env`.)
2. **Losing the `keyorix_keys` volume.** Back it up (next section).

### DEK rotation procedure

To generate a new Data Encryption Key and re-encrypt every secret in the database:

```sh
# 1. Stop the server (rotation acquires an exclusive lock; it refuses if the
#    server process is running and holding the key lock).
docker compose stop backend

# 2. Preview what will be re-encrypted — no changes made, no --confirm needed.
docker compose run --rm backend ./keyorix-server admin encryption rotate --dry-run

# 3. Perform the rotation.  --confirm is required (acknowledges write-lock).
docker compose run --rm backend ./keyorix-server admin encryption rotate --confirm

# 4. Restart the server.
docker compose start backend
```

The rotation re-encrypts all secrets, credentials, and session tokens in a
single transaction.  If the server crashes mid-sweep, the orphaned pending key
file is detected and cleaned up automatically on the next `--confirm` run.
Back up the `keyorix_keys` volume after a successful rotation.

Store `KEYORIX_MASTER_PASSWORD` in your own password manager / secret store. It is
not recoverable from the system.

## 5. Backup and restore

A complete backup is **two** things — the database *and* the encryption keys.
Neither alone is sufficient: the DB without the keys is unreadable ciphertext;
the keys without the DB are useless.

`keyorix-server admin backup --output <path>` / `admin restore --input <path>`
bundle both into one archive, on **either** storage backend — SQLite or
Postgres. Unlike a raw `pg_dump`/SQLite-file copy, the archive is
authenticated (HMAC-signed, KEK-derived key, `docs/design-b3-backup-v2.md`
§5) and its checksums catch corruption (a bad copy, a truncated transfer, bit
rot); tampering is a different property a checksum alone can't provide, since
anyone with write access to the archive can recompute one to match — so
`admin restore` also runs `admin verify-audit` automatically against the
restored database and fails if it reports the audit chain BROKEN. Also record
`KEYORIX_MASTER_PASSWORD` separately (it is required to derive the KEK that
unwraps the backed-up DEK).

**Backup** (run inside the `backend` container, against whichever storage
this stack is configured for):

```sh
docker compose exec backend ./keyorix-server admin backup --output /tmp/backup.tar.gz
docker compose cp backend:/tmp/backup.tar.gz ./keyorix-backup-$(date +%F).tar.gz
```

> **Version note.** The live (beside-the-server) Postgres backup below is not in
> the published `0.95.3` images that `docker-compose.yml` pins: there the same
> command fails with `failed to acquire the encryption key lock (another process
> is using it)`. With those images stop `backend` first and use
> `docker compose run --rm -v "$PWD/backups:/out" backend ./keyorix-server admin backup --output /out/keyorix-backup.tar.gz`
> (`mkdir -m 777 backups` first: the container user is uid 1001).

On Postgres, this reads through a single `REPEATABLE READ` snapshot
transaction by default — every table sees the identical point-in-time view,
without taking the database offline, so it runs beside the live `backend`
exactly as shown. The key files are read under the key-rotation read lock
(no `rotate`/`rotate-kek`/`migrate-provider` can change them, or re-encrypt
rows, until the backup's reads are done) and re-checked afterwards; if a key
rotation is in progress or the key files changed mid-backup, the command
fails and leaves no archive — retry it. Pass `--exclusive` instead to take
the same host-level exclusive lock a SQLite backup always holds, if you'd
rather trade availability for that stronger guarantee: that needs the
database to itself, so stop the `backend` service first and use
`docker compose run --rm backend ...` as for restore below.

On **SQLite** (single binary, `QUICK_START.md`), a backup always needs the
database to itself: stop the server, run `keyorix-server admin backup
--output <path>`, start it again. A backup beside a live SQLite server is
refused rather than taken inconsistently.

**Restore** (with the *same* `KEYORIX_MASTER_PASSWORD` and the same storage
config the backup was taken from). `admin restore` always takes this
database's own exclusive lock and refuses if a live server already holds it
— stop the `backend` service first, and run restore via `docker compose run`
(a fresh, throwaway container) rather than `exec` (which needs an already-
running one). The throwaway container has its own filesystem, so mount the
archive into it with `-v` (a `docker compose cp` into the stopped `backend`
container is not visible to `run`, and fails outright after `down -v` because
no container exists). The container user is uid 1001: the archive must be
readable by it (`chmod 644`).

```sh
docker compose stop backend            # (no-op on a freshly wiped host)
chmod 644 ./keyorix-backup-YYYY-MM-DD.tar.gz
docker compose run --rm -v "$PWD/keyorix-backup-YYYY-MM-DD.tar.gz:/tmp/backup.tar.gz:ro" \
  backend ./keyorix-server admin restore --input /tmp/backup.tar.gz
docker compose up -d
```

`run` starts `postgres` for you and `restore` migrates and loads the empty
database and the (also empty) `keyorix_keys` volume, then runs `verify-audit`
(`verify-audit on the restored database: VALID`). Measured for the whole drill
on a 2-vCPU VM with ~200 rows: backup 1.4 s, restore 24 s, back to serving about
40 s after `up -d`. Restore into the wiped volumes before the first `up -d`,
as above (a stack that has already booted holds a non-empty database and keys,
which restore refuses without `--overwrite-existing`).

Restore refuses a non-empty target by default (`--overwrite-existing` to
proceed anyway on a genuine disaster-recovery restore) — the normal flow is
restoring into a fresh database, not overwriting a live one.

**Manual `pg_dump`/`psql`** is still a reasonable choice if you already have
a Postgres backup pipeline built around it and don't need the archive's
built-in authentication/audit-verification — it works exactly as before:

```sh
docker compose exec -T postgres pg_dump -U keyorix keyorix | gzip > keyorix-db-$(date +%F).sql.gz
# Encryption keys (the keyorix_keys volume). The example below assumes your
# Compose project is named "keyorix" (true for a plain `git clone .../keyorix`
# checkout run from that directory) -- Compose prefixes every named volume
# with the project name, so the actual volume is <project>_keyorix_keys. If
# your checkout directory has a different name, or you set
# COMPOSE_PROJECT_NAME explicitly, run `docker volume ls | grep keyorix_keys`
# first and substitute the real name below (verified against a real
# non-"keyorix"-named checkout: ADR-109 step 6, B7 runbook validation).
docker run --rm -v keyorix_keyorix_keys:/keys -v "$PWD":/backup alpine \
  tar czf /backup/keyorix-keys-$(date +%F).tar.gz -C /keys .
```

To restore a manual dump (into a fresh stack, with the *same* `KEYORIX_MASTER_PASSWORD`):

```sh
docker compose up -d postgres
gunzip -c keyorix-db-YYYY-MM-DD.sql.gz | docker compose exec -T postgres psql -U keyorix keyorix
# Same volume-naming caveat as the backup step above.
docker run --rm -v keyorix_keyorix_keys:/keys -v "$PWD":/backup alpine \
  tar xzf /backup/keyorix-keys-YYYY-MM-DD.tar.gz -C /keys
docker compose up -d
```

Verified end to end (ADR-109 step 6, B7): a fresh Postgres-backed stack, real
secret write, `pg_dump`/keys-volume backup, full teardown (`docker compose
down -v`), restore into fresh volumes via `psql`/keys-volume-extract, and
`keyorix-server admin verify-audit` reporting `VALID` against the restored
database — the secret value round-tripped correctly and the audit chain
carried across the dump/restore boundary intact.

### Moving from SQLite to Postgres

`admin restore` doesn't care which backend a backup came from — only which
one the *target* config points at. Take a backup from a SQLite (single-binary)
deployment, point a fresh config at a Postgres database instead, and restore
into it: same command, same code path as any other restore, no separate
migration tool or conversion step (`docs/design-b3-backup-v2.md` §8). This
works directly for any archive a v2-writing binary produced (every release
from the one that introduced this backup format onward). An archive from an
*older* release that only ever wrote the v1 (physical, SQLite-only) format
can only restore into SQLite — restore it there first with the current
binary (which also upgrades its schema), take a fresh backup of that, and
restore *that* into Postgres.

### Version-skipping upgrades

The same property makes skipping releases safe: `admin restore` always
migrates its target to the current schema *before* loading any row, so a
backup taken on an old release restores cleanly on a much newer one in one
step, with no per-version upgrade path to walk through manually. Test it as
a drill before relying on it in production: back up on the old release, spin
up the new release against a fresh database/config, restore, and confirm
`admin verify-audit` reports VALID and a known secret still decrypts to the
expected value.

**Restoring an older backup than this host has already progressed past is
refused by default.** Restoring genuinely can undo history: any revocation
that happened *after* the backup was taken (a suspended account, a deleted
machine credential, a rotated role grant) doesn't exist in that backup's
database, so restoring it silently un-revokes that access. `admin restore`
compares the archive's own certified audit-trail progress against a
host-local witness file (`.audit-highwater-witness`, sibling to the
database, maintained automatically by every server this host runs) *before*
writing anything to disk, and refuses if the archive is behind. This is a
genuine, host-local-only check — it protects against restoring a stale
backup back onto ITS OWN host, but a fresh replacement host (or one whose
data directory, witness file included, was wiped) has nothing to compare
against and cannot be protected by this mechanism alone (see
`docs/design-b3-backup-v2.md` §6.5's stated limitation; a stronger,
externally-anchored check independent of the restoring host's own state is
designed in §6.4 but not yet implemented).

For a genuine disaster-recovery restore of an intentionally older backup,
pass `--allow-rollback`. This proceeds, but writes an explicit audit event
to the restored database (once its chain is writable again) recording how
many events behind the restore went — there is no silent, warning-only
path.

## 6. Upgrades

```sh
# docker-compose.yml pins both images to one release tag (e.g. :0.95.3, no
# leading "v"). `pull` alone fetches nothing new: first edit the `backend` and
# `web` tags to the release you are moving to, then:
docker compose pull          # fetch the published images for those tags
docker compose up -d         # recreate with the new images
```

Schema migrations run automatically on boot and are additive. **Back up first**
(section 5, mind its version note). Verified: a stack on the published `0.95.3`
images with a secret in Postgres, then `docker compose up -d` on a `main`
build — the secret read back unchanged, `verify-audit` VALID, schema epoch
matches. See [UPGRADING.md](UPGRADING.md) for what changes on upgrade (MFA
grace period).

## 7. TLS

**Secure baseline (from the release after v0.95.3).** `docker compose -f
docker-compose.yml -f docker-compose.secure.yml up -d` runs the backend on TLS
with a certificate its entrypoint generates on first start, has nginx verify
it, turns on rate limiting and the `/metrics` token, and copies the config to a
private 0600 file (so the host file's owner and mode no longer matter, #2922).
`admin validate --posture` then reports no deviations. It needs a backend image
newer than the pinned v0.95.3: until that release, build the backend from this
checkout (`build:` in docker-compose.secure.yml). With the next release it
becomes the default compose file. For Helm, the same baseline is
`secureBaseline.enabled=true` (see `deploy/helm/keyorix/README.md`).

**ArgoCD / GitOps with Helm.** ArgoCD renders charts with `helm template`, which
cannot look up the cluster, so the baseline's generated certificates and
`/metrics` token would change on every sync. Create the Secret yourself and set
`secureBaseline.existingSecret` (and `auth.existingSecret`); the chart then
generates nothing. Keys and a `kubectl create secret` example:
[`deploy/helm/keyorix/README.md`](../deploy/helm/keyorix/README.md#secure-baseline-with-an-existing-secret-argocd--gitops).

The default stack serves plain HTTP on `8088`. Two ways to get HTTPS:

**Bundled (recommended) — the `tls` profile.** An optional Caddy front-end that
terminates TLS and proxies to the web container:

```sh
# In .env, set KEYORIX_DOMAIN to your real domain (DNS must point here, and
# ports 80 + 443 must be reachable from the internet for the ACME challenge):
#   KEYORIX_DOMAIN=keyorix.example.com
docker compose --profile tls up -d
```

Caddy automatically provisions and renews a publicly-trusted certificate
(Let's Encrypt / ZeroSSL). Issued certs persist on the `caddy_data` volume so
restarts don't re-request them. For a `localhost` value Caddy uses its internal
CA (browsers warn unless you trust Caddy's root). To use the CLI against it,
export that root and point the CLI at it:
`docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt`
then `keyorix --ca-file $PWD/caddy-root.crt login --server https://localhost ...`, or
store it once with `keyorix config set ca_file $PWD/caddy-root.crt` (CLI releases
after 0.95.3; with an older CLI, `SSL_CERT_FILE=$PWD/caddy-root.crt` works on Linux
only) (verified: login over `https://localhost` works, `http://localhost` answers 308). When running the `tls` profile,
don't also expose web's `8088` publicly — front everything through Caddy on
80/443.

Caddy runs as uid:gid `65532` (not root), with every capability dropped except
`NET_BIND_SERVICE` and a read-only root filesystem. Earlier releases ran it as
root, so an existing `caddy_data` / `caddy_config` volume is root-owned. **Upgrading
needs no manual step:** the one-shot `caddy-init` service (same profile) chowns
both volumes to `65532:65532` before Caddy starts, and Caddy waits for it to
complete. It is idempotent, so it also runs harmlessly on a fresh or
already-migrated volume; the issued certificates and Caddy's internal CA are
kept. `caddy-init` is the only container in the stack that runs as root, with
only `CHOWN` and `DAC_READ_SEARCH` (read/search, not write: Caddy creates its
storage directories `0700`, so once they belong to `65532` root could not open
them on a second run without it) and no network. It touches only the two Caddy
volumes, changes only entries not already owned by `65532:65532`, and exits.

**Memory limits on scratch space.** Every `tmpfs` in the compose file has an
explicit `size=` (`/tmp` 16-64 MiB, nginx cache 64 MiB, nginx logs 32 MiB, runtime
dirs 1 MiB), and every `emptyDir` in the Helm chart has a `sizeLimit`, so a
runaway writer fills its own capped mount instead of the host's RAM or the node's
ephemeral storage. The backend's `/tmp` (64 MiB) also holds `admin restore`
staging: raise that `size=` if you restore a backup larger than it.

**PostgreSQL user.** The bundled `postgres:15-alpine` runs as uid:gid `70:70` in
both the compose file and the Helm chart (the Debian-based `postgres:*` images use
`999`; if you change the image flavour, change the uid in both places -- the Helm
value is `postgresql.runAsUser`). Compose volumes from earlier releases are already
owned by `70`, so that upgrade needs no `chown`. Helm volumes created by charts
older than this one are owned by `999`: see [UPGRADING.md](UPGRADING.md) §5.

**Your own proxy.** Or terminate TLS at an existing Caddy/Traefik/nginx/LB in
front of the `web` container: point it at `web:80` and forward
`X-Forwarded-Proto: https`.

### HSTS behind a TLS-terminating load balancer

The `web` nginx itself only speaks plain HTTP, and `Strict-Transport-Security`
over `http://` is wrong, so it sends HSTS **only** when the request came through
a trusted proxy that says `X-Forwarded-Proto: https`. The header is never
trusted from any other client, and never sent for direct HTTP. (The bundled
Caddy profile adds its own HSTS; the backend adds it only when it serves TLS
itself. API responses keep the backend's API CSP and every other security
header exactly as before; only the `Strict-Transport-Security` decision is new.)

| Setting (`.env`, passed to `web`) | Default | Meaning |
|---|---|---|
| `KEYORIX_WEB_TRUSTED_PROXIES` | empty | Comma-separated IPs/CIDRs of the load balancer(s), **as `web` sees them** (the TCP peer address). Keep it equal to the backend's `server.http.trusted_proxies`. Empty = nothing trusted = no HSTS. |
| `KEYORIX_WEB_HSTS` | `auto` | `auto`: on when trusted proxies are set; `on`: same; `off`: never send HSTS from `web`. |
| `KEYORIX_WEB_HSTS_MAX_AGE` | `31536000` | `max-age` in seconds. |
| `KEYORIX_WEB_HSTS_INCLUDE_SUBDOMAINS` | `true` | Adds `includeSubDomains`; `false` drops it. |

Invalid values (anything that is not an IP/CIDR, a bad mode, a non-numeric
`max-age`) stop the container at start rather than trusting more than intended.
These variables need a `web` image that contains this feature (releases after
0.95.3); older images ignore them and send no HSTS.

Helm: `web.trustedProxies` (list of CIDRs; the address the web pod sees, i.e.
the ingress-controller pods for an in-cluster ingress, not the cloud LB's public
address), `web.hsts.mode` (`auto`|`on`|`off`; `on` without `web.trustedProxies`
fails the render), `web.hsts.maxAge`, `web.hsts.includeSubDomains`. All default to
"no HSTS from this layer". Example:

```yaml
web:
  trustedProxies: ["10.42.0.0/16"]   # ingress-nginx pod CIDR
```

Check it with the proxy's address and header (a request from an untrusted
address must show no `Strict-Transport-Security` even with the header forged):

```sh
curl -sI -H 'X-Forwarded-Proto: https' http://web-host/health | grep -i strict
```

The single-binary `keyorix-server` also supports TLS directly
(`server.http.tls` in the config) for non-Docker deployments. A config written by
`keyorix-server admin init` already has it on, with a generated self-signed
certificate (`certs/server.crt`) and `security.require_transport_tls: true`;
replace the certificate with a CA-issued one, or see
[CONFIGURATION.md](CONFIGURATION.md#the-generated-config-is-the-secure-baseline)
for the proxy-terminated variant.

## 8. Metrics (Prometheus)

The backend exposes Prometheus metrics at **`GET /metrics`**. With
`server.http.metrics_token` or `metrics_token_file` set it requires
`Authorization: Bearer <token>`; a config written by `admin init` points
`metrics_token_file` at a generated `secrets/metrics_token` (0600), so give
Prometheus that token (`authorization: { credentials_file: ... }` in its scrape
config). Without a token it is unauthenticated: keep it inside your perimeter,
don't expose it publicly. It includes Go
runtime + process collectors and per-route HTTP metrics
(`keyorix_http_requests_total`, `keyorix_http_request_duration_seconds`). Point
your own Prometheus at `backend:8080/metrics`.

### Background scheduler health

The periodic jobs (anomaly detection, retention purge, auto-rotation,
certificate-expiry scan, audit checkpoints, …) each export their own health, labelled
by `scheduler`:

| Metric | Type | Meaning |
|--------|------|---------|
| `keyorix_scheduler_runs_total{scheduler,outcome}` | counter | Ticks by outcome: `success`, `failure`, or `skipped`. |
| `keyorix_scheduler_run_duration_seconds{scheduler}` | histogram | Duration of ticks that actually ran (success or failure). |
| `keyorix_scheduler_last_run_timestamp_seconds{scheduler}` | gauge | Unix time of the last tick that ran. |
| `keyorix_scheduler_last_success_timestamp_seconds{scheduler}` | gauge | Unix time of the last **successful** tick. |

`skipped` is normal, not an error: in an HA deployment only one replica holds the
single-writer advisory lock (ADR-039) per tick, so the others skip — and a job can
also stand itself down (e.g. an active legal hold pauses a purge). Alert on a job that
has stopped *succeeding*, e.g.:

```
time() - keyorix_scheduler_last_success_timestamp_seconds{scheduler="auto_rotation"} > 3600
```

or, for a job that has never once succeeded since boot,
`absent(keyorix_scheduler_last_success_timestamp_seconds{scheduler="auto_rotation"})`.
Only enabled schedulers appear; the gauges are absent until a job first runs.

### Notification delivery

Every notification channel (webhook, Slack, Teams, email) exports its delivery health
under a shared `channel` label, so a wedged or failing destination is visible rather
than buried in logs:

| Metric | Type | Meaning |
|--------|------|---------|
| `keyorix_notify_deliveries_total{channel,outcome}` | counter | Deliveries by channel (`webhook`/`slack`/`teams`/`email`) and terminal outcome: `delivered`, `failed` (a permanent error or retries exhausted), or `dropped` (the bounded queue was full). |
| `keyorix_notify_delivery_retries_total{channel}` | counter | Retries made after a transient failure (a 5xx / 429 for HTTP channels, an SMTP/transport error for email). |

Transient failures are retried with exponential backoff; permanent ones (a `4xx`, a bad
address) are not retried. A rising `failed`/`dropped` rate means a destination is
unhealthy or too slow — alert on
`rate(keyorix_notify_deliveries_total{outcome=~"failed|dropped"}[5m]) > 0`.

### SIEM audit forwarding

When SIEM forwarding is enabled, the audit-event forwarder (Splunk HEC / Datadog /
webhook) exports the same delivery health — losing audit events silently is a SOC 2 /
ISO 27001 finding, so a wedged or failing SIEM should page:

| Metric | Type | Meaning |
|--------|------|---------|
| `keyorix_siem_forwards_total{outcome}` | counter | Forwards by terminal outcome: `delivered`, `failed` (a 4xx or retries exhausted), or `dropped` (the bounded queue was full). |
| `keyorix_siem_forward_retries_total` | counter | Forwards retried after a transient (5xx / 429 / transport) failure. |

Transient failures retry with exponential backoff; `4xx` is permanent. Alert on
`rate(keyorix_siem_forwards_total{outcome=~"failed|dropped"}[5m]) > 0` — a SIEM that is
dropping or failing audit events is a compliance gap.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `KEYORIX_SECRETS_GID is required` on `up` | `./scripts/selfhost/init-secrets.sh` has not been run (it creates `./secrets/*` and writes the gid to `.env`). |
| `bind source path does not exist: .../secrets/...` on `up` | Same: run `./scripts/selfhost/init-secrets.sh`, or point `KEYORIX_SECRETS_DIR` at your secrets directory. |
| Backend exits with `KEYORIX_MASTER_PASSWORD_FILE ... permission denied` | `KEYORIX_SECRETS_GID` in `.env` is not the group of the files in `./secrets`. Re-run `init-secrets.sh` (it fixes the gid in `.env` and keeps your files). |
| Backend logs `password authentication failed` | The `postgres_data` volume was initialised with a different password. For a *new* install, `docker compose down -v` and start fresh (this wipes data — only for a clean install). |
| Backend can't decrypt secrets after a change | `KEYORIX_MASTER_PASSWORD` changed or the `keyorix_keys` volume was lost. Restore both from backup (section 5). |
| Login returns 404 | Reverse proxy not forwarding `/auth/` — Keyorix serves login at the root path, not under `/api/`. The bundled `web` image already handles this. |
| Server refuses to start: `database schema epoch N is newer than this binary's schema epoch M` (multi-replica deployments only — see [ADR-039](adr-039-ha-deployment.md); the bundled Helm chart is pinned to 1 replica and cannot hit this) | Two possible causes, and the message can't tell them apart on its own — check the "recorded at ... ago" timestamp in the log line against your own rollout: **(a) rolling upgrade in progress** — a sibling replica already migrated to the new schema epoch, and this pod is still running the old binary. Expected and self-resolving: this pod will be replaced by the new image (or crash-loop briefly) until the rollout completes, then it stops recurring. This repo does not orchestrate that rollout for you (see ADR-039). **(b) genuine downgrade** — this binary was rolled back against a schema a newer version already migrated. Upgrade this binary to match, or restore a backup taken before the newer version ran. The server deliberately refuses to start rather than guess which case applies — see [ADR-097](adr-097-schema-epoch-downgrade-guard.md) and [ADR-101](adr-101-schema-epoch-compatibility-floor.md). |

### SQLite write contention (`503` + `Retry-After`)

SQLite allows one writer at a time, so a single Keyorix process queues its write
transactions behind an in-process gate (first come, first served). A write waits
up to **10 seconds** for its turn. If it does not get one, the request fails fast
with **`503 Service Unavailable`** and a `Retry-After: 5` header (gRPC:
`UNAVAILABLE` with a `retry-after` trailer) instead of stalling or returning a
generic `500`. The response body is fixed and carries no storage detail; the
server logs one `write gate contention: <method> <path> answered 503` line per
affected request.

What to do when you see it:

- **Occasional, during a burst** (bulk import, a rotation job, a CI fleet
  starting at once): expected back-pressure. Clients should honour `Retry-After`
  and retry; idempotent requests can be retried blindly, others should check
  state first, because a request that runs several write transactions may have
  committed an earlier one.
- **Sustained** (a steady stream of `write gate contention` lines): the instance
  is write-saturated. Reduce concurrent writers (stagger jobs, lower client
  parallelism), make sure the database file is on local SSD rather than network
  storage, and check that nothing else holds the file open for writing (a backup
  or admin CLI command running beside the server holds the lock too). If the
  workload is genuinely write-heavy or multi-replica, move to Postgres (see
  "Moving from SQLite to Postgres" in section 5): the gate exists only for SQLite.
- Raising `storage.database.max_open_conns` does **not** help: writes are
  serialized regardless of pool size, and a bigger pool only adds readers.

The login and MFA endpoints (`/auth/...`) are deliberately exempt from the
`503`: a storage failure there after a credential matched is reported exactly as a
wrong credential, so the response cannot be used to confirm a guess.

## 10. Single-binary / air-gapped deployment

For environments where Docker isn't available, `keyorix-server` is a single Go
binary that runs against any PostgreSQL with `KEYORIX_MASTER_PASSWORD` +
`KEYORIX_DB_PASSWORD` set — and it can serve the **web dashboard from the binary
itself**, so the whole product is one file plus a database. No web container, no
nginx.

```sh
make build-ui      # builds web/ (the dashboard, ADR-070) and embeds it into
                   # bin/keyorix-server
KEYORIX_MASTER_PASSWORD=… KEYORIX_DB_PASSWORD=… ./bin/keyorix-server
```

Copy `keyorix-server` to the target host, point it at PostgreSQL, and the API +
UI are served on one port (default 8080). A config from `admin init` serves HTTPS
there with a generated self-signed certificate; point `server.http.tls` at a
CA-issued one for production.

`make build` (without the UI) produces an API-only binary that serves a small
placeholder page in place of the dashboard — use `make build-ui` for the full
single-file deployment.
