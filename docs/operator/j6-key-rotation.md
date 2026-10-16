# Rotating encryption keys

Two independent rotations exist: the **DEK** (data encryption key — what actually
encrypts secret values) and the **KEK** (key-encryption key, derived from your master
passphrase — what wraps the DEK at rest). The output shown below is illustrative
(version numbers and fingerprints differ on your install).

Both commands need exclusive access to the database — stop the server first. They read the
current master passphrase from `KEYORIX_MASTER_PASSWORD`, `KEYORIX_MASTER_PASSWORD_FILE`,
`--passphrase-file`, `--passphrase-fd` or `--passphrase-stdin`.

## Rotate the DEK (re-encrypts every secret)

Preview first — this makes no changes:

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --dry-run
```

Expected:

```
🔍 Dry run: previewing what a DEK rotation would re-encrypt — no changes will be made to the database or the DEK...
✅ Dry run complete — no changes were made
📋 secret_versions: 1, api_tokens: 0, api_clients: 0, password_resets: 0, mfa_secrets: 0, dynamic_secret_configs: 0, dynamic_secret_leases: 0 (legacy AAD upgraded: 0)
```

Then actually rotate:

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --confirm
```

Expected:

```
✅ DEK rotated and full re-encryption sweep complete. New version: v1790408589
```

A kill at any point during this is safe — the design guarantees exactly one of the old or
new DEK stays consistently active and every row stays decryptable under it, never a
half-rotated database.

## Rotate the KEK (change the master passphrase)

This re-wraps the DEK under a new passphrase; it does **not** touch any database row.

```bash
keyorix-server admin encryption rotate-kek --config ./keyorix.yaml --confirm --new-passphrase-file ./new_master_password
# or --new-passphrase-stdin / --new-passphrase-fd; the file must be mode 0600
```

Expected:

```
KEK rotation complete.
  Evidence-signing key fingerprint:      esk-...
  Audit-checkpoint key fingerprint:      ack-...

Update the master passphrase in your deployment configuration to the new value before restarting the server.
```

The variable to update is `KEYORIX_MASTER_PASSWORD` or the file `KEYORIX_MASTER_PASSWORD_FILE`
points at (or your `key_provider`'s equivalent). The command's own output doesn't name it, so:
whatever you use to set the passphrase today, set it to the new value before the next start,
and update your offline copy of the passphrase.

Note: evidence packs and audit checkpoints signed **before** this rotation will report as
"superseded key version" (not tampered) under `compliance verify` afterward — expected,
not a problem.

## Verify nothing broke

```bash
KEYORIX_MASTER_PASSWORD_FILE=./new_master_password KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server   # restart with the NEW passphrase after rotate-kek (the server has no --config flag)
keyorix secret get --id <id> --show-value
keyorix audit logs --limit 20
```

The secret's value should be unchanged, and `audit logs` should show an
`admin.encryption.rotate` (or `admin.encryption.rotate_kek`) event with the timestamp of your rotation.

## Back up around a rotation

Take an `admin backup` **before** and **after** every rotation (SELF_HOSTING.md §5).
An archive carries its own wrapped DEK, so one taken before a DEK or KEK rotation
still restores: after `rotate-kek`, restore it with the passphrase that was current
when it was taken. Keep each old passphrase for as long as you keep the archives that
need it.

## Rehearse it: `scripts/drills/key-rotation.sh`

The script runs this page's offline operations on a throwaway instance (SQLite or
PostgreSQL) with seeded data and checks, after each one, that every secret decrypts,
MFA login, a share and a machine token still work, and `admin verify-audit` is VALID:

1. `rotate --dry-run` changes nothing; `rotate --confirm` beside a live server is
   refused; a real DEK rotation works.
2. `rotate --confirm` killed with SIGKILL at six points spread over a clean rotation's
   wall time: `encryption validate` still passes, the server starts, data decrypts, and a
   later rotation completes. A SIGKILL cannot be aimed at a particular statement, so this
   shows the property at the sampled points, not at every instruction.
3. `rotate-kek`: the old passphrase is then refused at start (`wrong passphrase or
   corrupted key file`), the new one works, and an archive taken before the rotation
   restores with the old passphrase.
4. `migrate-provider` password to `file` and back to `password`: under `file` the server
   starts with no `KEYORIX_MASTER_PASSWORD`; the new passphrase on the way back comes from
   `KEYORIX_NEW_MASTER_PASSWORD`, never argv.

Not covered (they need infrastructure the drill does not have): cloud KMS, TPM and Shamir
providers, and any container or Kubernetes variant (pending a run on the e2e VM).
Usage and environment are the same as the [upgrade drill](drill-upgrade.md); for PostgreSQL
also set `DRILL_PG_DSN_FILE2` to a second empty database (the restore leg).
