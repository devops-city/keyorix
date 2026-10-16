# Rotating encryption keys

Two independent rotations exist: the **DEK** (data encryption key — what actually
encrypts secret values) and the **KEK** (key-encryption key, derived from your master
passphrase — what wraps the DEK at rest). Every command below was run for real against a
fresh SQLite install with a real secret in it while writing this page.

Both commands need exclusive access to the database — stop the server first (every replica, if you run several; see below).

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

## Several server replicas (PostgreSQL)

With more than one server on one PostgreSQL database (ADR-039; Helm
`server.replicas > 1`), each replica holds the DEK in memory and may have its
own copy of `dek.key`. The rotation only replaces `dek.key` on the host it runs
on. The database records which DEK it is encrypted under (the DEK epoch, a
fingerprint in `system_metadata`, not key material), and every replica checks it:

1. Upgrade every replica to a release with the DEK epoch check first (an older
   binary does not check it).
2. Stop **every** replica, not only the local one. `rotate` refuses while any
   server is attached to the database.
3. Run `rotate --dry-run`, then `rotate --confirm`, on one host. On PostgreSQL
   it first fences encrypted writes on every replica, waits about 10 seconds,
   then re-encrypts with the encrypted tables locked against writes (reads
   continue) and records the new epoch in the same transaction.
4. Copy the new `dek.key` (and `kek.salt` with the password provider) from that
   host to every other replica's key directory, or confirm they share the
   volume (Helm `ReadWriteMany` keys volume).
5. Start the replicas.

A replica whose `dek.key` is still the old one refuses to start:

```
refusing to start: this server's DEK is not the DEK the database is encrypted under:
the database's DEK epoch is "…", this server's DEK fingerprint is "…". …
```

Copy the current key files to it and start it again. Nothing was written under
the old DEK. A replica that was left running (`rotate --force`, or a lost presence
lock) refuses encrypted writes (`encryption refused: this server cannot confirm
that its DEK is the database's current DEK …`) within a few seconds of the
fence and keeps serving reads and revocations; restart it with the new key files.

If a rotation fails before its sweep commits, it lifts the fence itself; a
fence left by a killed rotation is lifted by the next server start that holds
the old DEK, or by re-running `rotate`. SQLite (single server) is unchanged.

## Rotate the KEK (change the master passphrase)

This re-wraps the DEK under a new passphrase; it does **not** touch any database row.

```bash
keyorix-server admin encryption rotate-kek --config ./keyorix.yaml --confirm --new-passphrase-stdin
# (enter the new passphrase when prompted, or pipe it in)
```

Expected:

```
KEK rotation complete.
  Evidence-signing key fingerprint:      esk-...
  Audit-checkpoint key fingerprint:      ack-...

Update the master passphrase in your deployment configuration to the new value before restarting the server.
```

The env var to update is `KEYORIX_MASTER_PASSWORD` (or your `key_provider`'s equivalent) —
the command's own output doesn't name it explicitly, so: whatever you use to set the
passphrase today, set it to the new value before the next start.

Note: evidence packs and audit checkpoints signed **before** this rotation will report as
"superseded key version" (not tampered) under `compliance verify` afterward — expected,
not a problem.

## Verify nothing broke

```bash
KEYORIX_MASTER_PASSWORD='<new passphrase>' KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server   # restart with the NEW passphrase after rotate-kek (the server has no --config flag)
keyorix secret get --id <id> --show-value
keyorix audit logs --limit 20
```

The secret's value should be unchanged, and `audit logs` should show an
`admin.encryption.rotate` (or `admin.encryption.rotate_kek`) event with the timestamp of your rotation.
