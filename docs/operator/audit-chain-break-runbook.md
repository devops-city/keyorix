# Audit-chain break runbook: what the verifier says, tampering or truncation, what to keep

The audit trail is a hash chain (ADR-029): every `audit_events` row carries the hash of the
row before it, and signed checkpoints certify how long the chain was. This runbook covers
the moment a verifier stops saying VALID: what each report means, how to tell a benign
cause from tampering, what you can and cannot do about it, and which evidence to keep.
Background: [ADR-029](../adr-029-audit-log-tamper-evidence.md),
[offline verification](../compliance/OFFLINE-AUDIT-VERIFICATION.md), the
[threat model](../security/threat-models/audit-chain.md), and
[AIRGAP_RUNBOOK.md](../AIRGAP_RUNBOOK.md) for exporting anchors.

**There is no command that repairs or re-seals a broken chain, on purpose.** Silently
"fixing" a chain that may reflect tampering would destroy the evidence
(`server/admin/recover_admin_logic.go` says so). Everything below is
triage, containment and evidence. Section 5 lists what does exist and what is missing.

## 1. Which verifier said it

| Where | Command / signal | Verdicts |
|---|---|---|
| Running server | `keyorix audit verify` (add `--full` for a full walk now, `--json` for the raw result) | `VALID`, `BROKEN`, `NOT PROVEN`; non-zero exit on the last two |
| Prometheus | `keyorix_audit_verify_failure_recorded` (1 while a break is recorded: page on it), `keyorix_audit_verify_state_rejected`, `keyorix_audit_verify_last_success_timestamp_seconds{check="tail"\|"full"}` | |
| Compliance posture | `GET /api/v1/compliance/posture`, field `audit_integrity` | reads the persisted state, walks nothing |
| Offline, independent code | `keyorix-server admin verify-audit` | exit `0` VALID, `1` BROKEN, `2` INDETERMINATE, `3` usage/input error |
| Restore | `keyorix-server admin restore` runs `verify-audit` on the restored database | fails (non-zero) on BROKEN |

How the server treats a break (`docs/specs/audit-incremental-verification.md` §3-§5):

- The first detection appends a `system.audit_chain_verification_failed` event to the chain.
- The failure is **sticky**. It clears only after a passing *full* verification that started
  after it. A real break never passes, so the alarm stays on: that is intended.
- While it is recorded, `POST /api/v1/audit/checkpoint` (and so `keyorix audit checkpoint`)
  refuses with 409: a broken chain is not re-notarised.
- `NOT PROVEN` is not a break. It means the server has no recent full verification, or its
  persisted verification state was untrusted (`system.audit_verification_state_rejected`
  event). Run `keyorix audit verify --full`, which clears it if the chain is sound.
- New audit events keep chaining onto the current tail, so the service keeps working and
  the break stays where it is.

## 2. First steps: freeze before you touch anything

1. **Do not** run `recover-admin`, `migrate-chain-encoding`, `rotate`/`rotate-kek`,
   `restore`, or any SQL against `audit_events`, `audit_checkpoints` or `system_metadata`
   yet. Each either changes the evidence or (for `migrate-chain-encoding`) refuses on a
   chain that is broken for any reason other than the old encoding.
2. Take a copy of the database in a state you can hand to someone else.
   SQLite: stop the server, then copy `keyorix.db` **together with** `-wal` and `-shm`
   (committed rows can still be in the `-wal`; the main file alone can look truncated).
   PostgreSQL: a `pg_dump` of the database, plus the server's data-directory/PITR facts
   (section 6).
3. Record the verdict as a file, from the copy, so the live system is not in the picture:

   ```bash
   keyorix-server admin verify-audit --json --db /evidence/keyorix.db > /evidence/verify-no-key.json
   # PostgreSQL: --pg-dsn "host=... user=keyorix_audit_verify dbname=keyorix sslmode=require"
   echo $?    # 0 VALID, 1 BROKEN, 2 INDETERMINATE, 3 input error
   ```

   `--db` / `--pg-dsn` take no lock and never write. Without `--db`/`--pg-dsn` the command
   verifies the configured live database under the exclusive admin lock, so the server must
   be stopped (`--force` overrides the refusal; do not use it for evidence).
4. Re-run it with the checkpoint key, which is what makes truncation visible. Derive the key
   with the server stopped and keep the file off the audited host (it is a shared secret:
   with the database it can forge a history):

   ```bash
   keyorix-server admin audit export-checkpoint-key --output /secure/checkpoint.key --config ./keyorix.yaml
   keyorix-server admin verify-audit --json --db /evidence/keyorix.db \
     --checkpoint-key-file /secure/checkpoint.key > /evidence/verify-with-key.json
   ```

   The master passphrase comes from `KEYORIX_MASTER_PASSWORD` / `--passphrase-file` /
   `--passphrase-fd` / `--passphrase-stdin`. The command needs `storage.encryption` enabled.
5. If you hold an external anchor (an `export-checkpoint` file, ideally from write-once media),
   add `--anchor /path/checkpoint-<date>.json`; with `--tsa-roots <pem>` an RFC 3161 token is
   re-verified with no shared secret at all. The report's `Anchor source:` line says whether
   the anchor came from the flag or `audit.offline_anchor_path`. A configured
   `audit.offline_anchor_path` that cannot be read, or a config file that exists but fails to
   load, is a hard exit 3, never a silent "no anchor".

Read the whole report, including **What this run does NOT prove**. Without the key a bare
re-walk cannot see tail-truncation at all.

## 3. Reading the reason

`reason` / `first broken id` come from the first check that failed (BROKEN beats
INDETERMINATE beats VALID). Strings are from `internal/auditverify/verify.go`.

| Report says | Kind | Likely causes, in the order to rule them out |
|---|---|---|
| `entry_hash is valid under the pre-#1452 audit-hash encoding but not the current one ... un-migrated upgrade, NOT evidence of tampering` | content | Benign: the chain predates the 2026-08-16 encoding change. Section 4a. |
| `event #N's entry_hash matches neither the current encoding nor the pre-#1452 one` | content | The row changed after it was written: tampering, or storage corruption. |
| `event #N's prev_hash does not link to the preceding event (row inserted, deleted, or reordered)` | linkage | Tampering, a manual `DELETE`, or a database restored/merged from two sources. |
| `event #N has no entry_hash (chain data removed after a chained region began)` | content | Hash columns blanked or rows replaced by unchained rows. |
| `audit trail truncated below signed checkpoint #N: it certified X chained events, only Y remain` | truncation | Rows removed from the tail, **or** the database is an older state (restore, stale copy, PITR). Section 4. |
| `audit trail truncated below the certified high-water mark` | truncation | Same as above, against the separate signed high-water row. |
| `audit event #N certified by checkpoint #M is missing (tail-truncation or genesis re-seed)` | truncation | Same; "genesis re-seed" means a whole replacement chain. |
| `audit event #N hash differs from signed checkpoint #M (certified head was rewritten)` | content | Tampering of the certified head row. |
| `audit checkpoint #N does not verify under the supplied checkpoint key (tampered, or the wrong key was supplied)` | key | Check the key version first (section 4c); tampering only if the key is right. |
| `audit high-water mark fails its signature` / `is missing or malformed although a signed checkpoint exists` | key / tamper | Wrong key, key changed by a KEK rotation or provider migration, or the row was deleted/forged. |
| `earliest surviving audit event #N does not match the authenticated retention re-anchor` | gap | Rows removed outside a sanctioned purge, a stale anchor, or an older binary reading a newer anchor (section 4d). |
| `INDETERMINATE: retention gap present before event #N, unauthenticated` | gap | Usually a sanctioned retention purge verified without the key. Re-run with `--checkpoint-key-file`. |
| `Owed break-glass audit records: N UNSETTLED` | owed | Not a chain defect: [break-glass-runbook.md](break-glass-runbook.md) §2. |

The online report adds `Checkpoint:` (authenticated or not, key version) and `Retention gap:`
(none / SANCTIONED / UNAUTHENTICATED) lines that help here.

## 4. Benign causes first

**a. Un-migrated hash encoding.** Only when the reason says pre-#1452. Preview, then apply in
a maintenance window with no other writers (the migration rewrites every chained row, re-signs
the retention anchor if there is one, and appends an `audit.chain_migrated` event):

```bash
keyorix audit migrate-chain-encoding            # preview, writes nothing
keyorix audit migrate-chain-encoding --confirm
keyorix audit verify --full
```

It refuses a chain that is inconsistent under both encodings, so it cannot be used to paper
over a real break.

**b. A copy that is not the database.** A SQLite file copied without its `-wal`/`-shm`, a
backup mounted from the wrong date, a replica that has not caught up: all look like
truncation. Re-copy correctly and re-run before concluding anything.

**c. A key that changed.** `rotate-kek` and `migrate-provider` change the KEK-derived
checkpoint key; checkpoints signed before then no longer verify under the new key.
Online, that reads as "does not verify under the current signing key ... a KEK-provider
migration occurred and no fresh checkpoint has been written yet", and a checkpoint write
under the new key (the scheduler, or `keyorix audit checkpoint`) re-baselines it, provided
the chain itself walks clean. Offline, `verify-audit` has no notion of key versions and
reports the same mismatch as BROKEN, so compare the key version on the `Checkpoint:` line
with your rotation history before reading it as tampering. See
[key-rotation-runbook.md](key-rotation-runbook.md).

**d. An older binary.** After a retention purge, anchors use the v2 layout (`retanchor-v2`).
A server older than that release reports the chain broken (`docs/CONFIGURATION.md`,
`audit_checkpoints`). Do not downgrade after a purge; upgrade the verifier.

**e. A restored older state.** `admin restore` refuses an archive behind the host's
`.audit-highwater-witness` file unless `--allow-rollback` is given, and then records an
`admin.restore_rollback_override` event saying how many events behind it went. Search the
trail for that event, and ask who restored what.

## 5. Tampering or crash-truncation

A verifier proves *what kind* of evidence is there, not who caused it.

| You see | Reading |
|---|---|
| A content or linkage break (`first broken id` set), a forged-looking checkpoint or high-water signature with the **right** key | Treat as tampering until disproved. A database crash does not rewrite a row's hash or break its link: each append is a single database transaction, serialised under a lock. If it follows a disk or storage fault, say so, but keep the incident open. |
| Only truncation: linkage inside the surviving rows is intact, the chain is shorter than a signed checkpoint or the high-water mark certified | Either rows were deleted from the tail, or the database went back in time. Decide with the infrastructure timeline: a restore, a snapshot revert, a PITR, an unflushed volume. |
| An anchor from before the incident (`--anchor`, or `--tsa-roots`) that the current chain **contradicts** | The history before the anchor's time was changed; independent of the host. |
| An anchor that the chain **satisfies**, plus truncation after it | Rows after the anchor's time are missing or the state rolled back to a point after it; the window is the anchor time to the incident. |
| `INDETERMINATE` only | Nothing is proven broken; fix what the report says it could not authenticate (key, anchor) and re-run. |

Rolled-back state is a security event even when benign: revocations, suspensions and role
changes made after the restore point are not in the restored database (SELF_HOSTING.md §5).
Re-apply them from the audit export you kept, and review recent logins.

## 6. Evidence to keep

Keep it together, read-only, with a `sha256sum` of each file, and note who held what and when.

- The database copy (section 2), including `-wal`/`-shm` for SQLite, and the host's
  `.audit-highwater-witness` (sibling of the database; it is not in backups).
- Every `verify-audit --json` output, with and without the key, with and without anchors. The
  `not_proven` array is part of the evidence: paste the whole object, not just `verdict`.
- The `keyorix audit verify --full --json` result, and the server log lines from the
  scheduler (`Audit-checkpoint error:`, `Audit rolling verification:`).
- The events around the incident, from the trail itself:
  `keyorix audit logs --event-type system.audit_chain_verification_failed`,
  `... --event-type admin.restore_rollback_override`, `... --event-type admin.recover_admin`,
  and a window with `--since` / `--until`; `keyorix audit export --since <time> --all` gives
  NDJSON for a SIEM. Treat these as secondary evidence: the database copy is the primary.
- Every exported checkpoint (`export-checkpoint` file) and TSA token you hold, and where each
  was stored.
- The key-rotation, restore and upgrade history for the host, and PostgreSQL/hypervisor logs
  for the window (restores, PITR, snapshot reverts, who held database credentials).
- Delete the exported checkpoint key (`checkpoint.key`) after use, or store it with the offline
  auditor's media, never on the audited host.

## 7. Containment and the "re-anchor" question

What exists, and none of it repairs a break:

- **Retention re-anchor.** A sanctioned retention purge records a signed anchor for the new
  earliest row, so a purge is not a break. It is written by the purge job, not by an
  operator command.
- **`keyorix audit migrate-chain-encoding --confirm`.** Re-derives hashes and re-signs the
  retention anchor, for the old-encoding case only.
- **A fresh checkpoint under a new key.** After a KEK change (section 4c) when the chain
  itself is sound.
- **A fresh external anchor.** Once the cause is resolved, write a checkpoint, then export it
  to write-once media held off the host:

  ```bash
  keyorix audit checkpoint
  keyorix-server admin audit export-checkpoint --output /media/anchor/checkpoint-$(date +%F).json
  ```

  `export-checkpoint` refuses an existing `--output` path and fails if no checkpoint has been
  written yet.

For a **genuine** break there is no re-seal. The two options are the security owner's call, and
neither deletes the evidence:

1. **Keep running on the same database.** The break stays in every future report as the first
   broken id; the sticky alarm stays on; checkpoints stay refused. Record the decision.
2. **Stand up a clean database from a known-good archive** (`keyorix-server admin restore`, see
   [AIRGAP_RUNBOOK.md](../AIRGAP_RUNBOOK.md)), keep the broken one offline as the exhibit. The
   restore runs `verify-audit` itself and fails on BROKEN. Expect `--allow-rollback` and the
   revocation caveat in section 5.

## 8. Gaps in the product today

- No operator command to accept a verified break and start a new, marked chain segment (the
  design asked for one in `docs/design-b2-recover-admin.md` §4; `recover_admin_logic.go` records
  that it was not implemented). A sticky failure therefore cannot be cleared after a real break.
- `verify-audit` has no key-version awareness, so a pre-rotation checkpoint under a rotated KEK
  reads BROKEN offline (section 4c).
- No documented way to take a consistent evidence snapshot of a broken chain with the product's
  own tooling: this runbook uses file copies and `pg_dump`. Whether `admin backup` accepts a
  broken chain has not been checked, so it is not recommended here.
