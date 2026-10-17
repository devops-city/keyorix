# Pilot install: single node, PostgreSQL, TLS, backups, monitoring

This is the one install path supported for a first pilot. It is deliberately narrow so
that everything on it is documented, tested and recoverable:

- **One host**, Docker Compose, the published images of one release tag.
- **PostgreSQL** (the bundled container, over TLS) as the data store.
- **TLS** terminated by the bundled Caddy front-end (or your own proxy).
- **Audit durability** chosen on purpose: `strict` or `standard`.
- **Off-host backups** and a restore you have rehearsed.
- **Monitoring** of health, metrics and the audit chain.

Not on this path: high availability or several replicas, SQLite, a managed database,
Kubernetes (see the [Helm chart](../../deploy/helm/keyorix/README.md) and
[operator/j8-kubernetes.md](../operator/j8-kubernetes.md)), edge devices
([edge-deployment.md](../edge-deployment.md)) and air-gapped hosts
([AIRGAP_RUNBOOK.md](../AIRGAP_RUNBOOK.md)).

Each step names the document that has the detail. This page was written from the code
and the Compose files; run the whole procedure once on a staging host before the pilot.

## 0. Before you start

- A Linux host with Docker Engine 24+ and the Compose plugin (`docker compose version`),
  and a reliable clock (NTP): the audit trail and checkpoints use the host clock.
- A DNS name pointing at the host, with ports 80 and 443 reachable from the internet
  for the automatic certificate. On a closed network use your own proxy instead
  ([SELF_HOSTING.md §7](../SELF_HOSTING.md#7-tls), "Your own proxy").
- A place **off this host** for backups, and a password manager (or sealed envelope) for
  the master passphrase and the admin recovery key.
- The release tag you will run. Use the newest tag from the
  [releases page](https://github.com/keyorixhq/keyorix/releases); examples below use
  `v0.96.1`.

## 1. Get the release

```bash
git clone --branch v0.96.1 --depth 1 https://github.com/keyorixhq/keyorix.git
cd keyorix
```

At a release tag `docker-compose.yml` pins the server and web images to that same release
(a test keeps them in step). Do not run `main` for a pilot, and never `latest`.
Verifying the release artifacts: [hardening guide §10](../security/hardening-guide.md#10-supply-chain-and-updates).

## 2. Generate the secrets

```bash
cp .env.example .env
./scripts/selfhost/init-secrets.sh
```

Edit `.env`: set `KEYORIX_ADMIN_EMAIL` to the admin's real address (a dot in the domain)
and `KEYORIX_DOMAIN` to your DNS name. `init-secrets.sh` writes the database password,
the **master passphrase**, the first-admin password, a bootstrap token and the
PostgreSQL TLS certificate into `./secrets` (never printing a value), and records
`KEYORIX_SECRETS_GID` in `.env`. Run it as your own user, not root.

**Copy `secrets/master_password` into your password manager now.** It derives the key that
encrypts every secret: changing it after first boot, or losing it together with the
`keyorix_keys` volume, makes every stored secret unrecoverable. Details:
[SELF_HOSTING.md §3 and §4](../SELF_HOSTING.md#3-configuration-env-and-secrets).

## 3. Choose the audit durability

Both levels commit the audit row before a secret is returned. The difference is a crash:

| | `strict` | `standard` (PostgreSQL default) |
|---|---|---|
| OS crash or power loss | loses nothing | can lose the last few hundred milliseconds of audit entries (a tail, never a gap) |
| Server process crash | loses nothing | loses nothing |

Pick `strict` if your compliance position is "every disclosed secret has an audit record
that survives power loss", or if you do not control the host's power and disk cache.
`standard` is reasonable on a UPS-backed host or replicated block storage. To pick
`strict`, add one line under `storage.database` in `keyorix.docker.yaml` **before the
first start**:

```yaml
storage:
  database:
    audit_durability: strict
```

Write down which you chose. Background and the full comparison:
[hardening guide §5a](../security/hardening-guide.md#5a-audit-durability-levels),
[PERFORMANCE.md](../PERFORMANCE.md#audit-durability).

## 4. Start the stack with TLS

```bash
docker compose --profile tls up -d
docker compose ps
docker compose logs backend
```

First boot takes a while (migrations and key derivation). The backend log ends with
`Admin bootstrap complete.`; if it shows `ERROR:` lines instead, see
[SELF_HOSTING.md §2](../SELF_HOSTING.md#2-quick-start) ("First boot check"). Caddy
obtains and renews the certificate. Open `https://<your domain>/`.

The `web` container also publishes plain HTTP on port 8088. **Block 8088 at the host
firewall** so the only way in is Caddy on 443 ([SELF_HOSTING.md §7](../SELF_HOSTING.md#7-tls)).
The bundled PostgreSQL and the backend's port 8080 are not published.

## 5. First login: enrol MFA, set your own password

Log in as `admin` with the password in `./secrets/admin_password` (`security.require_mfa`
is on, so this first session can only enrol a second factor). In the web UI that is
Profile → Security; with the CLI (`change-password` is optional but sensible, since the
generated password sits in a file on the host):

```bash
keyorix login --server https://<your domain> --username admin
keyorix mfa enroll
keyorix mfa activate
keyorix change-password
```

Save the recovery codes `mfa activate` prints, offline. Keep the `admin_password` file:
Compose needs it to exist at every `up`, and it is only read at first boot.
[QUICK_START.md](../../QUICK_START.md#enrol-mfa-required-on-first-login),
[SELF_HOSTING.md §2](../SELF_HOSTING.md#2-quick-start).

## 6. Generate the admin recovery key

If every admin is ever locked out, `keyorix-server admin recover-admin` on the host needs a
recovery key, and none exists until you create one. Admin commands need the database to
themselves, so stop the backend first:

```bash
docker compose stop backend
docker compose run --rm backend ./keyorix-server admin recovery-key rotate
docker compose start backend
```

The key is printed once. Store it offline, away from this host.
[SELF_HOSTING.md §2](../SELF_HOSTING.md#2-quick-start),
[operator/j5-lost-admin.md](../operator/j5-lost-admin.md).

## 7. Prove the posture

```bash
docker compose stop backend
docker compose run --rm backend ./keyorix-server admin validate --posture
docker compose start backend
```

Expected: `No deviations found.` Anything listed is a deviation from the secure baseline;
fix it before real secrets go in ([CONFIGURATION.md](../CONFIGURATION.md#security),
[hardening guide](../security/hardening-guide.md)). Then store a first secret and read it
back ([QUICK_START.md](../../QUICK_START.md#use-it)).

To check the connection from your workstation at any time, run `keyorix status` (server,
logged in, health, version compatibility). There is no `keyorix doctor`; the host-side
checks are `keyorix-server admin diagnose` (stop the backend first, like every `admin`
command) and the posture check above. The `keyorix` CLI also runs on a Mac: the release has
`keyorix_darwin_arm64` and `keyorix_darwin_amd64` ([QUICK_START.md](../../QUICK_START.md#get-the-binaries)).

## 8. Backups

A complete backup is the database **and** the encryption keys in one archive. On
PostgreSQL it runs beside the live backend:

```bash
docker compose exec backend ./keyorix-server admin backup --output /tmp/keyorix-backup-$(date +%F).tar.gz
docker compose cp backend:/tmp/keyorix-backup-$(date +%F).tar.gz ./
```

Schedule it (cron or a systemd timer), copy the archive **off the host** each time, and
delete the copy in the container's `/tmp` (a 64 MiB tmpfs: raise `size=` in
`docker-compose.yml` if your archive is larger). Also:

- Keep `master_password` backed up separately from the archives; an archive without it
  cannot be restored.
- Take an audit anchor and keep it on media you do not keep with the backups. It needs the
  database to itself, so schedule it in a maintenance window:
  `docker compose stop backend`, then
  `docker compose run --rm -v "$PWD/anchors:/out" backend ./keyorix-server admin audit export-checkpoint --output /out/checkpoint-DATE.json`,
  then `docker compose start backend` (create `anchors/` first, writable by uid 1001).
  [AIRGAP_RUNBOOK.md](../AIRGAP_RUNBOOK.md).
- **Rehearse a restore** on a spare host before the pilot starts and after any upgrade
  (`admin restore` runs `verify-audit` and fails if the chain is broken).
  `scripts/drills/backup-restore.sh` runs the whole cycle on a throwaway instance
  ([operator/drill-backup-restore.md](../operator/drill-backup-restore.md)). Your recovery
  point is your backup interval, so choose it with that in mind
  ([SELF_HOSTING.md §5](../SELF_HOSTING.md#5-backup-and-restore), "Recovery point"). A restore into a
  host that has already progressed past the backup is refused unless you pass
  `--allow-rollback`. Procedure and caveats:
  [SELF_HOSTING.md §5](../SELF_HOSTING.md#5-backup-and-restore).

## 9. Monitoring

- **Liveness:** `GET /health` through Caddy (`https://<your domain>/health`); `docker compose
  ps` shows health for each service.
- **Metrics:** the backend serves Prometheus metrics at `GET /metrics` and requires the
  token the entrypoint generated (`/app/tls/metrics_token` in the `keyorix_tls` volume).
  The backend's port is not published, so the scraper has to run on the Compose network
  and be given that token; do not expose `/metrics` publicly. Metric names and ready-made
  alert expressions (scheduler health, notification delivery, SIEM forwarding):
  [SELF_HOSTING.md §8](../SELF_HOSTING.md#8-metrics-prometheus).
- **Audit chain:** a restore drill (step 8) runs `admin verify-audit` for you. For an
  ad-hoc or scheduled check on the live stack, use the maintenance window of step 8: stop
  the backend, run `docker compose run --rm backend ./keyorix-server admin verify-audit`,
  start the backend. Exit code 0 is `VALID`; 1 is `BROKEN` and 2 is `INDETERMINATE`, and
  both need investigating ([AIRGAP_RUNBOOK.md](../AIRGAP_RUNBOOK.md)).
- **SIEM:** for a regulated pilot, forward audit events (`audit.siem`) and alert on
  `rate(keyorix_siem_forwards_total{outcome=~"failed|dropped"}[5m]) > 0`
  ([CONFIGURATION.md](../CONFIGURATION.md#auditsiem)).
- **Disk:** the audit trail dominates growth; watch the `postgres_data` volume and the
  host disk.

## 10. Upgrade and rollback

Back up first (step 8), edit the image tags in `docker-compose.yml` to the new release,
then `docker compose pull && docker compose up -d`. Read the notes for your version jump
in [UPGRADING.md](../UPGRADING.md); rollback is a restore of the pre-upgrade backup.

## When something goes wrong

| Symptom | Where |
|---|---|
| Stack will not start, login refused, TLS or secrets errors | [SELF_HOSTING.md §9](../SELF_HOSTING.md#9-troubleshooting), [operator/j7-troubleshooting.md](../operator/j7-troubleshooting.md) |
| CLI cannot connect or log in | [REMOTE_CLI_TROUBLESHOOTING.md](../REMOTE_CLI_TROUBLESHOOTING.md) |
| Every admin is locked out | [operator/j5-lost-admin.md](../operator/j5-lost-admin.md) |
| Rotating the data key or the master passphrase | [operator/j6-key-rotation.md](../operator/j6-key-rotation.md) |
| Every setting and environment variable | [CONFIGURATION.md](../CONFIGURATION.md) |
