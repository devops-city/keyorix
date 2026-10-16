# Running Keyorix on edge and industrial devices

> **Scope.** Single-box installs on small or remote hardware: Raspberry Pi-class
> boards, industrial PCs in factory cabinets, unattended sites, and networks
> with no internet access. This page does not repeat the reference material; it
> tells you which choices matter on such a device and links to where each one
> is specified. Config keys named here exist in
> [CONFIGURATION.md](CONFIGURATION.md); if one does not match your version,
> that file is authoritative. Nothing here is a performance claim: sizing is
> given in qualitative terms only.

## 1. Which build and which backend

- **Binary.** Release builds exist for Linux on `amd64` and `arm64`
  ([RELEASING.md](../RELEASING.md)). A Raspberry Pi needs a 64-bit OS to run the
  `arm64` build. On a device that runs no cloud connectors or cloud KMS, use
  the `keyorix-server-airgap` binary: the cloud SDKs are compiled out, which
  gives a smaller binary and SBOM
  ([ARCHITECTURE.md](ARCHITECTURE.md#full-vs-air-gapped-build-profiles)).
  Configuring a compiled-out backend fails closed.
- **Backend: SQLite (`storage.type: local`) is the edge default.** One process,
  one file, no database server to patch, monitor or keep running on a small
  board. PostgreSQL is the right choice only if the edge site already operates
  one (see [§3](#3-using-postgresql-at-the-edge)).
- **No outbound traffic is required.** With every non-loopback packet dropped,
  the core product served logins and returned stored secrets, and made no
  outbound connection attempts
  ([AIRGAP_RUNBOOK.md](AIRGAP_RUNBOOK.md), "Egress-blocked check"). Features that
  talk to other systems (SSO, SIEM, webhooks, connectors) are off until you
  configure them.

## 2. SQLite on the edge: strict audit durability only

On SQLite the audit commit always waits for the disk sync (`strict`). There is
no setting that relaxes it, and `audit_durability: standard` on SQLite refuses
to start. The reason is structural: SQLite's `synchronous` pragma is
per-connection and Keyorix shares one connection pool across every query, so
relaxing it would relax every table, not only the audit table
([hardening guide §5a](security/hardening-guide.md#5a-audit-durability-levels),
ADR-112 Amendment 3, [spec](specs/fast-audit-mode.md)).

For an edge device this is the right trade. Power is the failure you actually
expect, and `strict` is the level where an audit entry that was committed
before a secret was returned survives that failure. The server also sets
`journal_mode=WAL`, `synchronous=FULL` and `foreign_keys=ON` on every
connection; there is nothing to tune ([PERFORMANCE.md](PERFORMANCE.md#sqlite-settings)).

```yaml
storage:
  type: local
  database:
    path: /var/lib/keyorix/keyorix.db   # on the device's durable volume
    require_existing_path: true         # after first start: never silently create an empty DB
    # audit_durability is not settable to anything but strict on SQLite;
    # leave it unset or write `strict`.
```

`require_existing_path: true` (set it once the database exists) stops a
missing or unmounted data volume from turning into a fresh, empty
installation that looks healthy
([CONFIGURATION.md](CONFIGURATION.md#storage)).

## 3. Using PostgreSQL at the edge

PostgreSQL defaults to `audit_durability: standard`. Here the audit commit does
not wait for the disk sync, which is a reasonable default for a data centre
with a UPS-backed host or replicated block storage. Edge sites are the
opposite case: power and the volatile write cache are usually not under your
control. **If an edge install uses PostgreSQL, set `strict`:**

```yaml
storage:
  type: postgres
  database:
    audit_durability: strict
```

The levels, as specified in [PERFORMANCE.md](PERFORMANCE.md#audit-durability)
(ADR-112 Amendment 3) and the
[hardening guide](security/hardening-guide.md#5a-audit-durability-levels):

| | `strict` | `standard` (PostgreSQL default) |
|---|---|---|
| Before the secret is returned | audit row committed **and synced to disk** | audit row committed; the disk sync is not awaited |
| Audit write fails | request fails | request fails |
| Server process crash (`kill -9`, OOM, panic) | loses nothing | loses nothing |
| OS crash, power loss, PostgreSQL crash | loses nothing | up to ~600 ms (3 × `wal_writer_delay`) of audit entries, as a tail |
| Hash chain after a crash | intact | intact: a lost tail, never a gap or a fork |
| Backends | PostgreSQL, SQLite (SQLite's only level) | PostgreSQL only |

Non-audit writes (secret writes, revocations, rotations) commit durably at
both levels. Keep `standard` only where the host is shut down cleanly on power
loss or sits on storage you know does not lose acknowledged writes. You can
confirm the level in effect from the start-up `INFO` line, `keyorix-server
admin validate`, and `GET /api/v1/system/info` (`security.audit_durability`).

## 4. Power loss: what to expect

With `strict` (always on SQLite):

- A secret that was returned to a client has a committed, synced audit row.
  Nothing a client was told succeeded is lost.
- A request interrupted by the power cut has no audit row and its client never
  got the secret; the client retries after the device is back.
- The audit hash chain is intact after reboot. Run `keyorix-server admin
  verify-audit` after any unclean shutdown you care about.
- SQLite in WAL mode recovers on the next open; there is no manual repair
  step.

What the software cannot do for you:

- **Storage that acknowledges writes it has not made durable** (some SD cards,
  USB adapters and cheap SSDs without power-loss protection) can defeat any
  fsync-based guarantee. This is a property of the medium, not of Keyorix. Use
  industrial-grade storage with power-loss protection for anything audit
  evidence depends on, and avoid SD cards for the data volume where you can.
- **Flash wear.** Every committed read writes an audit row, so a busy device
  writes steadily. Choose media rated for sustained writes, and keep the audit
  retention you need in view when you size the volume ([§5](#5-sizing-guidance)).
- **A UPS or supercapacitor with a clean-shutdown signal** reduces how often
  you rely on crash recovery at all. It is worth having; it is not a
  substitute for `strict`.
- A rollback of the whole volume (restoring an old image onto the device)
  rewinds history, including revocations. See [§6](#6-backup-and-restore).

## 5. Sizing guidance

Qualitative only; measure on your hardware.

- **One process, one device.** Secret reads are bounded by the per-commit disk
  sync at `strict`, not by memory or page cache, so a faster, power-loss-safe
  disk helps more than extra RAM
  ([PERFORMANCE.md](PERFORMANCE.md#sqlite-settings)). A 64-bit Pi-class board
  with a good disk is a reasonable fit for a site's own secrets and a modest
  number of local clients; it is not a hub for a large fleet.
- **Disable swap** ([hardening guide §7](security/hardening-guide.md#7-process-and-host-hardening)).
  On a small-RAM board this means leaving headroom rather than relying on
  swap, so keep co-located services to a minimum.
- **Disk growth is dominated by the audit trail**, not by secrets. Size the
  data volume from the audit retention you must keep (`GET
  /api/v1/audit/retention` reports coverage), and plan an off-box export
  rather than letting the device hold history forever.
- **One server, one writer.** SQLite is not for running several Keyorix
  replicas. If an edge site needs more than one node or high availability, use
  PostgreSQL and treat it as a small data-centre deployment.
- **Time.** The audit trail and checkpoint schedule use the device clock.
  Give an unattended device a reliable clock source (a local NTP server, or an
  RTC with a battery) so that a long power-off does not leave timestamps wrong.

## 6. Backup and restore

A complete backup is the database **and** the key-material files, bundled in
one archive by `keyorix-server admin backup`; neither alone is useful
([AIRGAP_RUNBOOK.md](AIRGAP_RUNBOOK.md), [SELF_HOSTING.md §5](SELF_HOSTING.md)).

```sh
# SQLite: stop the server first, a backup beside a live SQLite server is refused.
keyorix-server admin backup --output /media/usb/keyorix-backup-$(date +%F).tar.gz
keyorix-server admin audit export-checkpoint --output /media/usb2/checkpoint-$(date +%F).json
```

- **Move the archive off the device.** A backup that stays in the cabinet is
  lost with the cabinet. Removable media carried off-site is a normal answer
  at air-gapped sites.
- **Hold the checkpoint anchor separately** from the archive, ideally on
  write-once media. The archive's checksums catch corruption, not tampering;
  an externally-held anchor is what constrains someone with the whole device.
- **Record the master passphrase separately** from both (or, for a TPM- or
  Shamir-based KEK, the custody described in [§9](#9-recommended-hardening)).
- **Restore into a fresh, empty data directory with the same config.**
  `admin restore --input <archive>` verifies every checksum, refuses a
  key-file set that does not match your encryption settings, writes
  atomically, applies pending migrations and runs `admin verify-audit`
  automatically, failing if the chain is broken. `--overwrite-existing` moves
  the old file aside instead of truncating it.
- **Restoring an old backup onto the same device is refused** when the device
  has already progressed past it, because it would undo revocations. A
  replacement device has no witness file and no such check, so restore only
  an archive you trust to be the latest.
- **A TPM-sealed KEK is bound to that TPM.** The sealed blob cannot be
  unsealed on a replacement unit. Plan the replacement path before you need it
  (see [CONFIGURATION.md](CONFIGURATION.md), `tpm` provider).
- **Drill the restore** on a spare device before relying on it.

## 7. Air-gapped updates

There is no network pull. Updates travel as signed update bundles
([air-gap-updates-design.md](air-gap-updates-design.md), ADR-064):

1. On a connected machine, obtain the release bundle and check the release
   artifacts against what you expect.
2. Carry it to the site on removable media.
3. On the site, `keyorix bundle verify <file>` checks the signature against the
   embedded, pinned public key, offline and fail-closed. Do not skip it; it is
   the offline equivalent of an image-digest check
   ([hardening guide §10](security/hardening-guide.md#10-supply-chain-and-updates)).
   `bundle import` re-verifies and is a licensed capability; see the design
   document for the exact gating.
4. **Take a backup and an audit anchor first** (§6), read
   [UPGRADING.md](UPGRADING.md) for the version you are moving to, then replace
   the binary. Pending migrations are applied by the server.
5. Pin a release, never `latest`, so every unit on a site runs a known version
   and rollback is a known step.

Updating an unattended device over a flaky power supply is when to use a UPS or
a maintenance window; an interrupted binary swap is the part this page cannot
make atomic for you, so keep the previous binary until the new one has started
and `admin validate` is clean.

## 7a. Unattended operation: start at boot, recover without anyone

**Start at boot.** Ready-to-adapt service definitions are in
[`deploy/edge/`](../deploy/edge/): `keyorix-server.service` (systemd) and
`io.keyorix.server.plist` (launchd, a LaunchDaemon so it runs with nobody
logged in). Both restart the server after any exit and run it as an
unprivileged user from the data directory, where `keyorix.yaml`, the database
and the key files live together. The systemd unit hands the master passphrase
over as a credential file (`LoadCredential=` +
`--passphrase-file=${CREDENTIALS_DIRECTORY}/…`), so it is neither in the
environment nor on the command line
([ADR-099](adr-099-master-passphrase-sourcing.md)), waits for the data volume
to be mounted, and never gives up retrying. `deploy/edge/edge_units_test.go`
runs the unit's real `ExecStart` line against the built server, kills it and
runs it again, and pins the directives above; it does not boot a real systemd
or launchd (pending the e2e VM).

**Recovering from stuck states.** Each of these is exercised against the real
binary (`server/edge_unattended_integration_test.go`, `scripts/edge/crash-soak.sh`):

| State after an unclean stop | What happens | Operator action |
|---|---|---|
| Stale lock files (`*.lock` beside the database and in the key directory) | Every lock is a kernel `flock`, released when the process dies; only the empty file stays, and its content is never read. | None. Do not delete them by hand while the server runs. |
| Interrupted first-time or upgrade migration (power cut mid-start) | The schema is built idempotently; the next start finishes it. | None. Do not restore an older database to "fix" it. |
| Data volume full | Writes fail with an error response (HTTP 500) and are not acknowledged; nothing acknowledged earlier is lost and the database is not damaged. | Free space, then restart the service. A real full filesystem has not been run yet (pending the e2e VM): the tests simulate failing writes. |
| Crash or `kill -9` at any point | See [§4](#4-power-loss-what-to-expect). | None; run `admin verify-audit` if you care. |

**What an operator must still do.** Monitor free space on the data volume and
alert before it is full: a full disk stops writes, and with them reads that
must be audited. Ship `admin verify-audit --json` and the checkpoint anchor off
the device. Keep the master passphrase credential, the config and the
recovery key backed up separately ([§6](#6-backup-and-restore)). A unit file
only restarts the process: it cannot tell a healthy server from one that is up
and refusing every request, so watch `/health` from outside.

## 8. Securing physical access

Whoever holds the device and its disk is the strongest adversary in the
[threat model](security/threat-model.md); a cabinet lock is part of the
security design, not an extra.

- **Host access equals data access for a file- or password-derived KEK.** With
  that provider, host root already has the material to decrypt the database
  ([hardening guide §2](security/hardening-guide.md#2-encryption-key-management)).
  A KEK that is not stored on the data disk is what makes a stolen disk
  insufficient.
- **TPM provider (`encryption.key_provider.type: tpm`)** seals the KEK to the
  device's TPM 2.0; only the sealed blob is on disk, so a disk pulled from the
  device cannot be decrypted alone, and no passphrase is needed at boot. Two
  limits to state to anyone relying on it: the seal is to that TPM chip, not
  to a measured boot state (no PCR policy yet), so it does not defend against
  a tampered boot chain on the genuine device; and clearing or replacing the
  TPM makes the blob unrecoverable ([CONFIGURATION.md](CONFIGURATION.md)).
- **Password provider** needs `KEYORIX_MASTER_PASSWORD` at every start. On an
  unattended site that means the passphrase is stored somewhere on the device
  or supplied by something else; weigh that honestly. If it sits on the same
  disk, a stolen device gives up everything.
- **Shamir split custody** (`type: shamir`) fits sites where no single person
  or device should hold the key. Always set `shamir_commitment`; losing more
  than N-K shares destroys the data.
- **Keep the recovery key off the device** (`admin recover-admin` needs host
  access *and* a separately-held key). Never enable keyless admin recovery on
  an unattended device; see [§9](#9-recommended-hardening).
- **Seal the physical interfaces.** Disable or lock unused USB ports, serial
  consoles and debug headers, set a boot-loader password and disable booting
  from external media, and use full-disk encryption on the data volume as a
  second layer. These are host controls Keyorix cannot enforce; see
  [hardening guide §11](security/hardening-guide.md#11-what-this-guide-does-not-cover).
- **CLI local mode is equivalent to direct database access.** Keep it for
  the people you would trust with the raw database.
- **Core dumps are suppressed unconditionally** (`RLIMIT_CORE=0`). Do not
  override it in a service unit.

## 9. Recommended hardening

Start from the [hardening guide](security/hardening-guide.md); the edge-specific
summary is:

```yaml
security:
  require_transport_tls: true       # refuse to serve cleartext
  require_mfa: true                 # or scope to sensitive projects
  insecure_allow_unsafe_file_permissions: false
  login_lockout:
    insecure_disable_login_lockout: false     # keep the lockout on

server:
  http:
    ratelimit:
      enabled: true

storage:
  type: local
  database:
    path: /var/lib/keyorix/keyorix.db
    require_existing_path: true
    # audit_durability: strict        # the only level on SQLite; set it on PostgreSQL
  encryption:
    key_provider:
      type: tpm                       # or shamir / a KMS where the site has one

audit_checkpoints:
  insecure_disable_audit_checkpoints: false   # keep checkpoint signing on
```

- Terminate TLS on the device (`server.http.tls`) or in a trusted local proxy;
  a local-only deployment still carries bearer tokens and secret values.
- Run the server as an unprivileged user, keep the data and key directories
  readable only by it, and keep the host patched through the same
  removable-media path as Keyorix itself.
- Keep checkpoint signing on, and run `keyorix-server admin verify-audit` on a
  schedule, appending `--json` to a log that leaves the device. If the site
  has a collector, forward audit with `audit.siem` and use its `spool_dir` so a
  link outage does not drop the off-box copy
  ([hardening guide §5](security/hardening-guide.md#5-audit-and-monitoring)).
- Scope every automation token to the narrowest permissions and the single
  project it serves; a leaked unscoped token has its owner's full reach.

### `insecure_` settings that must stay off

Every `insecure_*` key opts out of a safety check. On an edge device none of
them is needed to make an install work; if one seems to be, fix the cause
(a certificate, a path, a permission) instead. Leave all of these at their
default of `false`:

| Key | What turning it on gives up |
|---|---|
| `storage.database.insecure_audit_skip_reads` | Successful secret reads stop being audited. No record of who read what. |
| `storage.database.insecure_audit_skip_durable_sync` | Deprecated alias of `audit_durability: standard`. Not valid on SQLite; do not use it on PostgreSQL edge installs either. Use `audit_durability: strict`. |
| `audit_checkpoints.insecure_disable_audit_checkpoints` | Signed checkpoints, which make tail-truncation and re-seeding of the audit chain detectable. |
| `security.recover_admin.insecure_keyless_admin_recovery` | Admin recovery with host access alone. On an unattended device, physical access becomes admin access. |
| `security.login_lockout.insecure_disable_login_lockout` | Per-account brute-force lockout. |
| `security.insecure_allow_unsafe_file_permissions` | The refusal to use key or data files with permissive modes. |
| `storage.encryption.key_provider.insecure_allow_weaker_kek_fallback` | Lets a TPM/KMS outage silently downgrade to a weaker KEK source. Unattended hardware fails, so this is the setting most likely to be tempting. |
| `storage.encryption.key_provider.insecure_allow_kms_context_fallback` | Weakens the KMS install-binding check. |
| every `insecure_skip_verify` (`audit.siem`, `notifications.webhook`, `evidence_delivery.webhook`) | Server certificate verification. |
| `insecure_allow_plaintext_*_transport` and `insecure_allow_private_network_*` under `audit.siem`, `dynamic_secrets`, `evidence_delivery.webhook` and `notifications.webhook` | Cleartext transport to, and private-network targets for, outbound integrations. A private-network target is only appropriate if the collector is genuinely on one; each opt-out is logged and they are independent. |
| `sso.providers.insecure_trust_saml_asserted_email`, `sso.providers.saml.insecure_allow_idp_initiated_saml` | SAML identity checks. Only relevant if the site uses SAML. |

`admin validate --posture` reports every deviation from this list; run it
after any config change and as part of commissioning.

## 10. Commissioning checklist

1. Arm64 or amd64 build verified against its release checksums; airgap
   profile if no cloud integrations.
2. Data volume on storage that honours fsync; swap disabled; clock source set.
3. TLS on; MFA on; no `insecure_` key set (`admin validate --posture` clean
   apart from informational lines).
4. KEK provider chosen with its custody and replacement path written down.
5. First backup and checkpoint anchor taken and carried off-site; restore
   drilled on a spare.
6. Update path rehearsed with `bundle verify`.
7. Physical interfaces locked, boot media restricted, cabinet access logged.
