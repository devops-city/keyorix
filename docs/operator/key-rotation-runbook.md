# Key rotation runbook: what to run, what to verify, how to go back, what not to do

[j6-key-rotation.md](j6-key-rotation.md) is the step-by-step with the expected output of each
command, including the several-replicas procedure. This runbook is the operator's wrapper
around it: pick the right rotation, the preflight, the checks afterwards, rollback, and the
mistakes that cost data. Every command below was checked against the cobra definitions of
`keyorix-server admin` and `keyorix` in this repository.

## 1. Which rotation

| You need to... | Run | What changes | What does not |
|---|---|---|---|
| Replace the key that encrypts the data (suspected DEK exposure, policy) | `admin encryption rotate` | A new DEK; every DEK-encrypted row is re-encrypted in **one** transaction (secret versions, API tokens and clients, password resets, MFA secrets, dynamic-secret configs and leases, notification channels). | The master passphrase. |
| Change the master passphrase (departure, exposure, policy) | `admin encryption rotate-kek` | The wrapped DEK, under a KEK derived from the new passphrase and a fresh salt. The evidence-signing and audit-checkpoint keys change with it. | No database row; the DEK value. |
| Move the KEK to another provider (password, file, env, exec, shamir, tpm, aws-kms, gcp-kms, azure-kms) | `admin encryption migrate-provider --to-type ... --confirm` | The DEK wrapping only; the previous wrapped DEK is kept as `<dek_path>.migrate-backup.*`. | Secret values. |
| Replace the lost-admin recovery key | `admin recovery-key rotate` | The recovery verifier; the old key stops working at once. See [j5-lost-admin.md](j5-lost-admin.md). | Not an encryption key. |

Rotating the DEK does not change the audit-checkpoint key (it is KEK-derived); rotating the KEK
does. That matters for the audit chain: section 5.

## 2. Preflight (all of it, every time)

1. **Back up, off the host.** `admin backup` is the only rollback for a DEK rotation.

   ```bash
   keyorix-server admin backup --output /backups/keyorix-pre-rotation-$(date +%F).tar.gz --config ./keyorix.yaml
   ```

   The archive holds the database and every key file (including its own wrapped DEK). On SQLite
   stop the server first; on PostgreSQL it works beside a live server, but fails and leaves no
   archive if a rotation is in progress. `--output` must not exist. The passphrase comes from
   `KEYORIX_MASTER_PASSWORD`, `--passphrase-file`, `--passphrase-fd` or `--passphrase-stdin`.
2. **Check the current state.** Both are read-only and take no lock:

   ```bash
   keyorix-server admin encryption status --config ./keyorix.yaml
   keyorix-server admin encryption validate --config ./keyorix.yaml
   ```

3. **Baseline the audit chain** so any change afterwards is yours to explain, and write a fresh
   external anchor (details in [audit-chain-break-runbook.md](audit-chain-break-runbook.md) §2, §7):

   ```bash
   keyorix-server admin verify-audit --config ./keyorix.yaml          # server stopped; expect VALID, exit 0
   keyorix-server admin audit export-checkpoint --output /media/anchor/checkpoint-$(date +%F).json --config ./keyorix.yaml
   ```

4. **Keep every server stopped** on the database from here to the end of section 3 (stop them
   before step 3 on SQLite; `verify-audit` on the configured database and `export-checkpoint`
   take the same exclusive lock). All rotation commands refuse to run beside a live server or
   another admin command. `--force` overrides that refusal: do not use it here.
   `rotate-kek` and `migrate-provider` open the database for this lock (#3513) even though
   only key files change, so they fail with `cannot connect to the database to check for a
   running server` while the database is unreachable: make sure it is up (and reachable with
   the configured credentials) before you start.
5. **Have both passphrases ready** (for `rotate-kek`): the current one and the new one, the new
   one in a file with mode `0600` owned by you or root (the flag refuses anything group- or
   world-readable). There is no flag that takes a passphrase as an argument, by design.
6. Run on the server host. With `storage.type: remote` the rotation commands refuse ("must run on
   the server host").

## 3. Run it

DEK, preview then do it ([j6](j6-key-rotation.md) shows the output):

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --dry-run
keyorix-server admin encryption rotate --config ./keyorix.yaml --confirm
```

KEK:

```bash
keyorix-server admin encryption rotate-kek --config ./keyorix.yaml --confirm \
  --passphrase-file ./old_master_password --new-passphrase-file ./new_master_password
```

The new passphrase must differ from the old one. When it finishes, set the new value everywhere
the server reads it (`KEYORIX_MASTER_PASSWORD`, the file `KEYORIX_MASTER_PASSWORD_FILE` points at,
or your provider's equivalent) **before** the next start, and update your offline copy.

With several replicas on one PostgreSQL database, follow [j6](j6-key-rotation.md) "Several
server replicas": stop all, rotate on one host, copy `dek.key` (and `kek.salt` for the password
provider) to the others, start. A replica holding an old `dek.key` refuses to start.

## 4. Verify

```bash
KEYORIX_MASTER_PASSWORD_FILE=./new_master_password KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server
keyorix-server admin encryption validate --config ./keyorix.yaml
keyorix secret get --id <id> --show-value        # the value is unchanged
keyorix audit logs --limit 20                    # admin.encryption.rotate / admin.encryption.rotate_kek
keyorix audit verify --full
```

Then take a second backup (`admin backup`, as in the preflight) with the post-rotation keys, and
keep the **old** passphrase for as long as you keep any archive taken before a `rotate-kek`: that
archive restores only with the passphrase that was current when it was taken.

## 5. After `rotate-kek`: the audit chain

Checkpoints signed before the rotation were signed under the old KEK-derived key.

- Online, `keyorix audit verify` reports the latest checkpoint as not verifying under the current
  signing key until a fresh one exists. Write one (the scheduler does it on its next tick, or
  run it now) and the state clears, provided the chain itself is sound:

  ```bash
  keyorix audit checkpoint
  keyorix audit verify --full
  ```

- Offline, `verify-audit --checkpoint-key-file` with a key exported **after** the rotation reports
  an older checkpoint as BROKEN ("does not verify under the supplied checkpoint key"). That is the
  key change, not tampering: compare the key version on the report's `Checkpoint:` line with
  the date of your rotation, take a checkpoint, then export a **new** key and a **new** anchor
  and use those from now on:

  ```bash
  keyorix-server admin audit export-checkpoint-key --output /secure/checkpoint-<date>.key --config ./keyorix.yaml
  keyorix-server admin audit export-checkpoint --output /media/anchor/checkpoint-<date>.json --config ./keyorix.yaml
  ```

- `compliance verify` reports evidence packs and checkpoints signed before the rotation as
  "superseded key version", not tampered (the command says so itself).

Keep the old anchors and the note of which key version signed them; do not overwrite them.

## 6. Rollback

| Where it went wrong | What to do |
|---|---|
| The command was killed or the host lost power mid-way | Nothing special: both rotations are crash-safe. A DEK sweep is one transaction, so either the old or the new DEK is active and every row decrypts; an interrupted promote is finished by the next admin command. A KEK re-wrap leaves either the old or the new wrapped-DEK file, never a torn one. Run `encryption validate`, then re-run the rotation if you still want it. |
| `rotate-kek` done, the server will not start (`wrong passphrase or corrupted key file`) | The configured passphrase is still the old one. Set the new one; nothing is lost. |
| `rotate-kek` done, and you want the old passphrase back | Rotate again with the sources swapped: `--passphrase-file ./new_master_password --new-passphrase-file ./old_master_password`. This re-wraps the same DEK under a fresh salt and again changes the checkpoint key (section 5). |
| A DEK rotation you want to undo | There is no reverse command. Roll forward if you can. Otherwise restore the pre-rotation archive (below). It loses every write made since the backup, and resurrects any revocation made since (SELF_HOSTING.md §5). |
| A replica was left with the old `dek.key` | Copy the current key files to it and start it ([j6](j6-key-rotation.md)). Nothing was written under the old DEK. |
| `migrate-provider` was interrupted after the re-wrap | The previous wrapped DEK is on disk as `<dek_path>.migrate-backup.*` for a human to restore; the DEK's plaintext value did not change. Keep it until you have verified. |

Restoring the archive (server stopped, same config and key paths, passphrase current when the
archive was taken):

```bash
keyorix-server admin restore --input /backups/keyorix-pre-rotation-<date>.tar.gz --overwrite-existing --config ./keyorix.yaml
```

`--overwrite-existing` moves each existing file aside to `<path>.pre-restore-<timestamp>` rather
than truncating it. The restore verifies the archive's signed manifest before writing, runs
`verify-audit` and fails on BROKEN. It refuses an archive that is behind the host's
`.audit-highwater-witness`; `--allow-rollback` overrides that, and records an
`admin.restore_rollback_override` audit event. Whether a pre-rotation archive trips that check
depends on whether the rotation advanced the witness; be ready for either.

## 7. What not to do

- **Do not use `--force`** to run a rotation beside a live server. The lock is what keeps a
  replica from writing under the key you are replacing.
- **Do not skip the backup**, and do not keep it only on the host that is being rotated.
- **Do not lose the old passphrase** while any archive taken before a `rotate-kek` is still one
  you may need.
- **Do not copy `dek.key` alone** to another replica with the password provider: copy `kek.salt`
  with it, or confirm the replicas share the keys volume.
- **Do not delete `*.migrate-backup.*` or `*.pre-restore-*` files** until the result is verified.
  `admin encryption migrate-provider cleanup --dry-run`, then `--confirm`, is the supported
  deletion.
- **Do not put a passphrase on a command line, in shell history or in a shared log.** Use a
  `0600` file, a descriptor, or stdin; the new passphrase on a `migrate-provider` back to the
  password provider comes from `KEYORIX_NEW_MASTER_PASSWORD` or the `--new-passphrase-*` flags.
- **Do not read an offline BROKEN right after `rotate-kek` as tampering** before comparing key
  versions (section 5), and do not treat a rotation as a fix for a broken chain: rotation neither
  repairs nor hides one ([audit-chain-break-runbook.md](audit-chain-break-runbook.md)).
- **Do not lose the key files.** `dek.key` and `kek.salt` are useless without the database and the
  database is unreadable without them; the preflight archive carries both.

## 8. Rehearse and gaps

`scripts/drills/key-rotation.sh` and `scripts/drills/rotation-under-load.sh` rehearse the offline
operations on a throwaway instance (see the end of [j6](j6-key-rotation.md)). The Kubernetes and
container variants, cloud KMS, TPM and Shamir providers are not covered by them: pending the e2e VM.

Gaps in the product today:

- No online rotation: the window is the servers being stopped.
- No command to reverse a DEK rotation other than restoring an archive.
- `verify-audit` has no key-version awareness, so a pre-rotation checkpoint reads BROKEN offline
  once the key has changed (section 5).
