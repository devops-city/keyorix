# Upgrade checklist: v0.96.x to v0.97.0

For operators moving a running install (a pilot, a production instance) from
v0.96.1 or v0.96.2 to v0.97.0. It orders the steps; the reasons and exact
settings are in [UPGRADING.md](../UPGRADING.md) (section numbers below). Work
through it top to bottom and write down the result of every check.

**Status of this page.** Written from the merged changes and from the open pull
requests that will ship in v0.97.0. Anything tagged **(pending #NNNN)** describes
a PR that is not merged yet; re-read it when that PR merges. Nothing here has been
run against a v0.97.0 release build, and nothing has been run in a container, in
Kubernetes or on a second replica (**pending e2e VM**). The single-node procedure
is the one `scripts/drills/upgrade.sh` rehearses on SQLite and PostgreSQL
([drill-upgrade.md](drill-upgrade.md)); rehearse on a copy of your data first.

## 1. Pre-checks (before you touch anything)

### 1.1 Know what you run

- [ ] Version of every running server: `keyorix-server --version`, or
  `GET /api/v1/system/info`. The supported start is v0.96.1 or later; from v0.95.x or
  older, do the v0.96 upgrade first (UPGRADING §2, §3).
- [ ] How many server processes share the database (one, or several replicas), and
  whether the database is SQLite or PostgreSQL. SQLite is one process only.
- [ ] Where the keys live (`storage.encryption.dek_path`, salt, KMS/TPM) and who holds
  the master password or KEK source. Without them a restored database is unreadable.

### 1.2 Back up, then prove the backup

- [ ] `keyorix-server admin verify-audit` prints `VALID` **before** the upgrade. A chain
  that is already broken is much harder to explain afterwards.
- [ ] A full backup of database **and** keys: `keyorix-server admin backup --output
  backup-$(date +%F).tar.gz` (UPGRADING §1, §4). On PostgreSQL a live backup (without
  `--exclusive`) runs next to the server; for the other cases follow SELF_HOSTING §5.
- [ ] The archive restores on a throwaway host with the **old** binary
  (`admin restore`, then `admin verify-audit`). An untested backup is not a rollback plan.
- [ ] Keep the old binary or image tag, the old config file and the old Helm values
  (`helm get values <release> -o yaml > values-before.yaml`). Rolling back is a restore
  with the old binary and the old config together (section 3).

### 1.3 Settings the new version refuses to start with

Check each against your config, environment and (Helm) values. These all stop the
server or an `admin` command at start-up with a message that names the key.

| Check | Refused when | Fix | UPGRADING |
|---|---|---|---|
| PostgreSQL TLS | `ssl_mode` is `verify-full`/`verify-ca` with no `ssl_root_cert`; `ssl_mode` outside the allowed list; `ssl_mode` next to a `dsn` with a different or missing `sslmode`; a `service=`/`PGSERVICE` file | set `ssl_root_cert` (a PEM path, or `system`); make `dsn` and `ssl_mode` agree | §2 |
| PostgreSQL `session_replication_role` **(pending #3366)** | the server's sessions report anything but `origin` (server default, database, role, `PGOPTIONS`, DSN option) | run the two queries in §6n and `RESET` the setting | §6n |
| Bootstrap token **(pending #3341)** | `KEYORIX_BOOTSTRAP_TOKEN` (or `_FILE`) is set and shorter than 32 characters | `openssl rand -hex 32`, or unset it on an initialised install | section in #3341 |
| gRPC `auto_cert` **(pending #3365)** | `server.grpc.tls.auto_cert: true` | remove the line; give gRPC `cert_file`/`key_file` | section in #3365 |
| Audit durability | `audit_durability: standard` on SQLite; `audit_durability` and the old `insecure_audit_skip_durable_sync` set to different levels | remove one, or use `strict` on SQLite | §6c |
| Multi-replica | `single_writer: true` with several replicas; `pooler: pgbouncer-transaction` with `single_writer` | leave `single_writer` off | §6f |
| Non-regular files | a FIFO or device at a key, CA, license or backup path | point it at a regular file | §6p |
| `dsn` and password | a `dsn` with its own password **and** `KEYORIX_DB_PASSWORD`/`storage.database.password` | keep one | §6p |

Then, with the **new** binary and the **old** config, on a stopped server:
`keyorix-server admin validate --posture`. It lists every refusal and every secure-baseline
deviation. Fix refusals before the real start. (Run it after the binary swap in section
2, because it needs the new binary and a stopped server.)

### 1.4 Behaviour that changes for your clients and scripts

- [ ] Scripts that call `keyorix` with `--password`, `--value`, `--mfa-code` or the other 13
  refused flags **(pending #3325)** (§6l). Move them, or set
  `KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1` as a temporary bridge.
- [ ] Scripts that test the CLI exit status for exactly `1` (§6m). Codes 2 to 6 now exist.
- [ ] Anything that pages the audit log by `offset` past 10,000 events (§6p): use `cursor`.
- [ ] Clients that retry on 503 but stop on 401, or that match a 500 on a refused
  secret read (§6p).
- [ ] SIEM rules and reports that filter on `success` for `mfa.failed` and the other
  `*_failed` events **(pending #3365)** (section in #3365). Old rows keep `success=true`.
- [ ] Automation that grants access, and your break-glass procedure, can cope with
  `could not record the change in the audit log; nothing was changed, retry`
  **(pending #3367)** (§6o).
- [ ] If PostgreSQL is the audit store and you want the v0.96 behaviour, decide on
  `audit_durability: strict` now (§6c). The default becomes `standard`.

### 1.5 Platform-specific

- **Compose:** run `./scripts/selfhost/init-secrets.sh` (it keeps existing secrets and
  adds the PostgreSQL TLS pair), bump the image pins, then `docker compose up -d` (§2,
  "Upgrading Docker Compose from v0.96.x").
- **Helm:** no value was renamed or removed. `helm template` / `helm upgrade --dry-run`
  with your values and the new chart first. Use `--reset-then-reuse-values`, not plain
  `--reuse-values` (§2, §5). The chart runs one server replica today.
- **Reverse proxy or load balancer in front of the server:** if it terminates TLS and talks to the
  server directly, list it in `server.http.trusted_proxies` (Helm `server.trustedProxies`) so
  cookies are `Secure` and HSTS is sent (§6p).

## 2. Order of steps

### 2.1 Single node (SQLite, or PostgreSQL with one server)

1. Announce a maintenance window. Stop clients that write (CI jobs, syncs, the operator).
2. Section 1 complete; `admin verify-audit` is `VALID`; the backup is taken and tested.
3. Stop the server (`docker compose stop backend`, `systemctl stop keyorix`,
   `kubectl scale deploy/<name> --replicas=0`).
4. Replace the binary or image tag. Keep the old one beside it.
5. `keyorix-server admin validate --posture` with the old config. Fix every refusal (section 1.3)
   and re-run until it passes or lists only deviations you accept.
6. Start the server. Watch the first start's log for: the schema migration, the audit
   index build (PostgreSQL builds in the background; SQLite prints a progress line per
   index and the first start takes longer on a large trail), and the line
   `audit durability: ...` (§6c).
7. Post-checks (section 4). Re-enable clients one at a time.

### 2.2 Several replicas (PostgreSQL) **(pending #3364, HA-READY-1)**

The procedure below is the one #3364 writes into SELF_HOSTING.md ("Running more than one
replica"). It was tested natively with one v0.96.1 and one current server on one database;
the Kubernetes version is **pending e2e VM**.

1. Section 1 complete. Back up. Confirm every replica has an identical configuration and the
   same key set, and that `single_writer` is off.
2. Do not start a DEK or KEK rotation, `migrate-provider`, `admin restore` or an audit purge
   (`POST /api/v1/admin/jobs/purge-audit-logs`) until the rollout has finished.
3. Roll the replicas to the new image one at a time (`maxUnavailable: 1`). The first new
   replica migrates the schema.
4. While old and new replicas run together, expect: a few 500s from an old replica right after
   the migration (`cached plan must not change result type`, once per pooled connection and
   query); an old replica that restarts is **refused** at start-up once the schema epoch floor is
   3, and stays down until replaced by the new image (that is intended); `GET /audit/verify` on an
   old replica may report the chain broken after a purge.
5. Add new configuration keys (for example `key_dir_lock`) only **after** every replica runs
   v0.97.0, in a second rollout. An older binary refuses a config with a key it does not know,
   and a pod of the old ReplicaSet that is rescheduled mid-rollout reads the new ConfigMap.
6. When the last old replica is gone, run the post-checks (section 4) against the service and
   against each replica.

Until #3364 merges, the supported statement is the one in UPGRADING §2: schema migrations run on
boot, and a rolling multi-replica upgrade that reports `database schema epoch N is newer than this
binary's schema epoch M` is expected mid-rollout.

## 3. Rollback limits

- **Rollback is a restore, not a downgrade.** Once the new binary has started against the
  database, the supported way back is: stop everything, restore the backup from step 1.2
  with the matching **old** binary and the **old** config, then `admin verify-audit` (UPGRADING §7).
  `admin restore` refuses an archive that is behind the host's audit high-water mark; the
  deliberate override is `--allow-rollback`, which is logged to the audit trail.
- **Everything written after the upgrade is lost by a restore:** secrets, audit rows, sessions,
  tokens. Decide how long you can afford that before you start, and keep the post-checks fast.
- **Schema epoch.** On main today the schema epoch is 2 and the compatibility floor is 2, the same
  as v0.96.1, so a v0.96.x binary can still start on a migrated database. It must not be run on
  it: v0.97.0 writes a v2 audit retention anchor (#3258) and a `suspend_clear_synced_copies`
  marker (#3215) that v0.96.x mishandles (a purge loses the purged-event count for good; a plain
  suspend can empty the synced Kubernetes copies). **(pending #3364)** raises the epoch and the
  floor to 3, after which a v0.96.x binary refuses to start on an upgraded database
  (`database declares a minimum compatible schema epoch of 3`) and PostgreSQL triggers protect the
  two cases from still-running old replicas. Plan as if that is already true.
- **The old config.** The previous release refuses a config file that has a key it does not know,
  so restore the config file that matches the binary you roll back to.
- **Keys.** Do not run a DEK or KEK rotation until the upgrade is accepted; a rotation changes the
  key files the old backup does not contain.

## 4. Post-checks

Run all of them against the upgraded server and write down the output.

- [ ] The log shows the expected version; no `WARNING` you do not recognise. Start-up lines to find:
  `audit durability: ...` (§6c), the schema migration, the audit index build finishing.
- [ ] `keyorix-server admin verify-audit` prints `VALID`. The audit trail must have **grown** since
  step 1.2 (the upgrade, your own logins and reads are in it).
- [ ] `keyorix-server admin validate --posture` (server stopped for the command, or as documented
  for your deployment): the deviations match what you accepted before, and none is new.
- [ ] `GET /api/v1/system/info`: the version, `security.audit_durability`, and
  `database.single_writer` are what you set. `GET /readyz` is 200.
- [ ] `keyorix doctor` **(pending #3319; not on main)**: a read-only health checklist of the CLI's
  connection to the server. Until then, `keyorix status` and the next item.
- [ ] A real round trip: log in as a human, read a known secret and compare its value, create
  and delete a test secret, read one as a machine identity or PAT. Each read appears in
  `keyorix audit logs` with the right actor.
- [ ] PostgreSQL only: no index left half-built after the audit index build. This returns no rows
  when everything is valid:
  `SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE NOT i.indisvalid;`
  (an interrupted build is rebuilt at the next start).
- [ ] Your scripts: one run of each CI job that calls `keyorix`, checking exit codes (§6m) and
  that no secret flag is refused (§6l).
- [ ] Multi-replica: every replica is on v0.97.0 (`system/info` through each pod), and an audit
  purge has not been run on a mixed set.
- [ ] Hold the backup from step 1.2 until the upgrade has been accepted, then follow your
  retention policy.

## 5. What to send back

If a step fails, send: the step number, the exact command, the output, `keyorix-server --version`,
and `keyorix-server admin validate --posture`. Do not paste secrets, tokens or the master password.
