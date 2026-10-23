# Recovery options: decisions for the four RUNBOOKS-1 gaps

Status: **proposal for decision** (design only, no code). Session RECOVERY-OPTIONS-1, 2026-10-23.
Inputs: the runbooks from #3542 (`docs/operator/lost-totp-runbook.md`,
`audit-chain-break-runbook.md`, `key-rotation-runbook.md`), the earlier RECOVERY-DESIGN-1 analysis,
#3547 (re-baseline refusal), `docs/design-b2-recover-admin.md`, ADR-029, ADR-112, and origin/main at
`271c91daa`.

Each section gives the premise as checked on main today, two or three options, the security
argument for each, the operating cost, the upgrade impact, and a recommendation. The attacker model
covers four questions: who can run the option, what they need, what the audit trail records, and
what a malicious insider could do with it.

## 0. Premises checked against origin/main

| # | Premise (from the backlog) | On main today | Where |
|---|---|---|---|
| 1 | A non-admin local user with no recovery code has no supported MFA reset | **True.** `recover-admin` refuses an account without a global-admin role. `ReissueOneTimePassword` leaves an enrolled second factor alone on purpose. `DisableMFA` and `DeleteWebAuthnCredential` need the user's own code or password on a session. The OpenAPI document has no admin MFA-reset route. | `server/admin/recover_admin_logic.go:76`, `internal/core/reissue_otp.go:71`, `internal/core/mfa.go:265`, `internal/core/webauthn.go:333` |
| 2 | No command re-seals a genuine chain break, so the sticky alarm never clears | **True.** The sticky `failure` clears only when a full verification that started after it passes, and a real break never passes. The design-b2 §4 "chain restart" was not built; `LogAuditEvent` always chains onto the current tail. Nothing named seal, break record or segment restart exists. | `internal/core/audit_verify_state.go:102`, `server/admin/recover_admin_logic.go:194-209`, spec `audit-incremental-verification.md` §3 |
| 3 | The only reverse for a DEK rotation is an archive restore | **True.** After the sweep commits, the old DEK is wiped and no copy is kept. The sweep decrypts with the old DEK and encrypts with the new one, but never decrypts the new ciphertext before commit. | `internal/encryption/keymanager_rotation.go:31,147`, `internal/encryption/sweep.go:184-192` |
| 4 | rotate-kek makes older checkpoints read BROKEN offline until a fresh one is written | **True, but the scope is wider than stated.** `RotateKEKWithConfig` re-wraps the DEK and prints fingerprints but writes no checkpoint, high-water mark, retention anchor or verification state. Offline, `verify-audit` checks only the **latest** checkpoint and the high-water mark, under **one** supplied key, and reports a signature failure as BROKEN. Online, the retention anchor signed under the old key is ignored as "superseded" (`audit_retention_anchor.go:239`). On an install that has had a retention purge, the online walk then needs genesis and reports a break. That is RECOVERY-DESIGN-1's F2; the code path is unchanged on main but was not re-run for this doc. | `internal/encryptionops/kek.go:55-98`, `internal/auditverify/verify.go:404-480`, `internal/core/audit_retention_anchor.go:239` |
| (backlog 4) | CONFIGURATION.md calls the checkpoint key DEK-derived | **False now.** Fixed by `77fd78cd7`. | `docs/CONFIGURATION.md` |

Three changes since the gaps were listed matter here:

- **#3547 (merged)** pins the newest certified count and head in the signed verification state.
  The write path now refuses to re-baseline over a truncation that this pin proves. A real key
  change still re-baselines, because rotate-kek writes nothing to the database: the state row stops
  authenticating, so it pins nothing. Both §2 and §4 rely on this.
- **AUDIT-VERIFY-STATE-1 (in flight, branch `audit-verify-state-1/fail-closed`, not pushed yet)**
  hardens how a missing or damaged verification-state row is handled, and writes
  "audit-reseal-options.md" in this directory (not on main yet). §2 below defers to that document for the seal command
  itself.
- **#3607 KEYSET-MANIFEST-1 (open)** adds a key-set manifest and a two-phase commit to the
  rotate-kek file writes (`commitNewKEKFiles`). §4's options add a database step to the same
  command, so their implementation goes after #3607 and must keep its crash points.

---

## 1. MFA reset for a local non-admin with no recovery code

The question: who may reset another user's second factor, with what approval, how the user is
notified, and how the reset appears in audit.

### Rules that hold for every option

These follow from the code and from the reason REISSUE-1 kept MFA out of the reissue:

- **A reset is a full credential reset, never "MFA off".** In one transaction it clears the TOTP
  secret, the recovery codes and every WebAuthn credential; issues a one-time password (the
  existing `ReissueOneTimePassword` machinery: restricted account, sessions deleted, PATs evicted);
  and sets a new per-user `mfa_reenroll_required` flag. The setup gate then demands `enroll_mfa`
  even when `security.require_mfa` is off. Clearing MFA and keeping the password would turn a
  stolen password, the threat MFA exists for, into a takeover.
- Refused for: SSO/SCIM accounts (the IdP owns the factor), global admins (they go through
  `recover-admin`), the actor's own account, a suspended or inactive account, and any actor that
  fails `requireAdminRankCeilingForTarget`.
- Not built by extending something else: no `--clear-mfa` flag on `reissue-one-time-password`, no
  non-admin mode for `recover-admin`. Each path gets its own audit event type.
- Guard: a static allowlist over callers of `DeleteMFAForUser` and of WebAuthn credential
  deletion. Today the callers are `DisableMFA`, `recover-admin` and self-service delete; the new
  path or paths are added to the list. Any other caller fails the build.

### Options

| | A. One admin, online | B. Two admins, online, plus a host fallback | C. Host only (offline command) |
|---|---|---|---|
| **Who runs it** | One admin with `users.write` and the rank ceiling over the target | Admin X requests, a different admin Y approves; neither is the target; both meet the ceiling | Host operator: `keyorix-server admin reset-mfa --user U --recovery-key -` |
| **What they need** | An admin session plus a fresh MFA step-up | Two admin sessions, each with a fresh step-up under a new purpose (`mfa_reset`). The request expires after 24 h | Shell on the server host, the master passphrase, the recovery key, and the exclusive key lock (server stopped) |
| **Audited** | `mfa.reset` (actor, target, factors cleared counted, never values) | `mfa.reset_requested` (requester, reason, evidence: `verified_by` in person / video / ticket / other, plus text), `mfa.reset_approved` (approver), `mfa.reset_cancelled` / `_expired` / `_denied`. A self-approval attempt is audited as denied, as risk exceptions already do | `admin.reset_mfa` (host user, recovery-key generation, chain verdict at the time), like `admin.recover_admin` |
| **Notification** | Target and every admin | Every admin when a request is opened and when it is approved; the target when it is approved | Every admin and the target, queued; the command also prints it |
| **What an insider can do** | One rogue or phished admin takes over any lower-ranked MFA account: reset, take the OTP, log in as the user. This is the exact hole REISSUE-1 closed. Notification makes it visible afterwards, not preventable | Needs two colluding admins, or two compromised admin accounts each passing step-up. A stolen session alone is not enough. Social engineering of the approver remains; the evidence field and the named approver make it attributable | Host root plus the recovery key. That holder can already run `recover-admin` and take a global-admin account, so this adds no new power beyond the existing ceiling |
| **Operating cost** | Lowest: a help-desk action | One more person per reset. Installs with a single admin cannot use the online flow and fall back to C | Every reset needs a host shell and downtime (exclusive lock). Wrong default for HA and Kubernetes |
| **Build size** | S | M (online flow) + S (host command) | S (reuses recover-admin plumbing) |

The OTP from an online reset goes to the approver (B) or the actor (A), who passes it to the user
out of band. An in-app notice cannot reach a user who cannot sign in. The target is told through
an email channel when one is configured. Whether today's notification channels can address one
user's email (rather than an admin-wide channel) was not checked; if they cannot, the target
notice becomes an in-app message shown after the next login, and the approver's out-of-band call
serves as the immediate notice. Peer products (Okta, Keycloak) ship A. Vault Enterprise Control
Groups are the nearest analogue to B.

The status quo, D ("deactivate and re-invite"), is not listed as an option. It creates a new
identity, roles must be re-granted by hand, and it is the P1 pilot complaint.

### Upgrade impact (all options)

- Additive schema: one user column (`mfa_reenroll_required`), plus a `mfa_reset_requests` table for
  B. No data migration.
- **Rollback hazard.** An older binary ignores `mfa_reenroll_required`. A user part-way through a
  reset (OTP issued, MFA cleared) who signs in on an older binary with `require_mfa` off would get
  a password-only account. Mitigations: the reset already sets the restricted
  `password_reset_required` state, which older binaries honour. The UPGRADING note tells operators
  to finish or cancel pending resets before a downgrade. For B, the approve call should refuse while any replica
  runs a binary that does not know the flag. No such cluster-wide version check exists today; the
  cross-replica DEK epoch (`internal/encryption/dek_epoch.go`) is the nearest model.
- New API routes and a proto change for B, the CLI (`keyorix user mfa-reset request|approve|cancel|list`)
  and the web UI in one series. ADR needed (amends ADR-112's recovery section).

### Recommendation: B, built host-command first

1. **Ship C first** (`admin reset-mfa`, offline, recovery key, `admin.reset_mfa`). It is small,
   adds no online attack surface, and closes the pilot P1 on single-node installs at once. It is
   also B's permanent fallback for installs with fewer than two eligible admins and for
   air-gapped hosts.
2. **Then B** (request plus a different approver, both with step-up, 24 h expiry). With fewer than
   two eligible admins, the request API refuses and names the host command. A
   `security.mfa_reset.dual_control: false` opt-out for small teams is possible, but only if it
   shows a loud startup warning and a compliance-posture deviation. Recommended: do not offer it
   at first.
3. **Reject A.** It reopens REISSUE-1's single-admin takeover, and a notice does not stop it.

Tests to ask for: effect assertions (factors gone, sessions and PATs gone, setup gate demands
enrolment with `require_mfa` off), the approver rules (self, target, rank, expired, double approve,
approve against cancel on Postgres across replicas), a faultops entry whose oracle is "never MFA
cleared while the old password or a session still works", a CLI journey, and a real-backend
Playwright spec for B.

---

## 2. Sealing a genuine audit-chain break

**Coordination.** AUDIT-VERIFY-STATE-1 owns the options for the seal command itself: who may run
it, what it records, how it appears in the chain, and how verification treats the gap afterwards.
They will be in "audit-reseal-options.md" next to this file, on branch `audit-verify-state-1/fail-closed`,
which was not pushed when this was written. This section does not repeat those options. It covers
what that brief does not: the constraints any chosen option must meet, the interaction with §4
and with recover-admin, upgrade and rollback, and what the runbooks must say.

### Why it matters more after AUDIT-VERIFY-STATE-1

Today the alarm is "sticky", but it lives in one database row. Once that session makes a missing or
damaged state row fail closed, the row can no longer be dropped to start over (which was never
supported anyway). After a genuine break the operator is then left with two choices: run with the
alarm on and checkpoints refused (409) for good, or restore a pre-break archive and lose every
write since. A refused checkpoint is not cosmetic. It means **new** tampering after the break is no
longer notarised. A sanctioned, audited seal is the only way to resume integrity protection on a
live database.

### Constraints for whichever option is chosen (a checklist for judging the AUDIT-VERIFY-STATE-1 options)

1. **Never green again.** A sealed chain reports a status distinct from both VALID and BROKEN
   (online `status`, CLI and `verify-audit` exit codes, compliance posture). Integrity "since seal
   N" may read verified; the whole chain may not.
2. **Offline and keyed.** The seal runs under the exclusive lock with the master passphrase
   (needed for the MAC), not through an online API. A stolen admin session must not be able to
   bless tampering. Same posture as `recover-admin`.
3. **Exact.** It refuses unless a fresh walk reports BROKEN at exactly the id the operator names.
   It does not seal NOT PROVEN, an old encoding, a key mismatch or an unauthenticated gap; those
   have their own runbook paths.
4. **Evidence pinned.** The record pins first-broken, last-good and old-head ids and hashes, the
   actor, the reason (no secrets: it is stored), and an evidence digest the operator supplies (DB
   file or dump hash, `verify-audit --json` hash).
5. **Fail closed on tamper with the seal.** Deleting, altering, moving or replaying a seal record
   must yield BROKEN, never VALID or "sealed".
6. **Survives a key change.** A seal record MAC'd under the checkpoint key must still verify after
   `rotate-kek` / `migrate-provider`. That is §4's job, so **§4 ships before or with the seal**.
   Without it, the first KEK rotation after a seal turns the seal record into an unauthenticated
   row: under constraint 5 that reads BROKEN (a false alarm), or, if the verifier is lenient, it
   reopens an F1-style relabel.
7. **Checkpoints bind to the segment.** A checkpoint written after a seal must not be replayable
   across another seal (include the seal sequence in the checkpoint canonical form).
8. **Both verifiers in one series.** `internal/core` and the independent `internal/auditverify`
   learn the seal together, with a differential test over seeded databases.

### recover-admin

Retire design-b2 §4's idea that recover-admin writes the chain restart. Recover-admin keeps its
current behaviour: it verifies first, records the broken row in its event and warns loudly. Sealing
is a separate, deliberate act with its own evidence. Folding it into an admin recovery would let a
lockout recovery silently bless tampering. Update the comment at
`recover_admin_logic.go:194-209` when the seal lands.

### Upgrade and rollback impact

- New table or rows, a new status value and a v2 checkpoint canonical form. An older binary that
  opens a sealed database must report BROKEN, never VALID (it does not know the record, so the
  segment's first link fails). This is fail-closed by construction if the segment's first
  `prev_hash` is derived from the record rather than the old tail. Ask for a test that pins it.
- Restore: the `.audit-highwater-witness` comparison must understand v2 marks, and a pre-seal
  archive restored after a seal trips `--allow-rollback` as any older archive does.
- Evidence packs and `audit export` carry the seal records verbatim, so an auditor sees the gap.

### Runbook changes when it lands

`audit-chain-break-runbook.md` §7 option 3 ("seal and continue") with the exit codes, §8 drops the
gap, and §6 says which evidence digests to compute before sealing. Until it lands, §7's two options
stand, and §7 should say that a refused checkpoint means new tampering is not notarised.

### Recommendation

Decide among AUDIT-VERIFY-STATE-1's options **using the eight constraints above as the acceptance
list**. RECOVERY-DESIGN-1's "signed break record plus a linked segment genesis" meets all eight. Do
not start the seal before §4's key-transition work, or build them in the same series with §4
first.

---

## 3. Reversing a DEK rotation

### Options

| | A. No command: roll forward, or restore the pre-rotation archive (documented) | B. `rotate --revert` with the previous DEK kept for N days | C. A, plus the rotation insists on a fresh archive |
|---|---|---|---|
| **Who runs it** | Host operator: `admin restore --input <archive> --overwrite-existing` | Host operator, master passphrase | Host operator, as A |
| **What they need** | The archive, and the passphrase that was current when it was taken | The passphrase; the retained old DEK on disk | As A; `rotate` refuses without `--backup-output` (writes the archive itself) or an explicit `--no-backup` acknowledgement |
| **Audited** | `admin.restore` and, if the archive is behind the witness, `admin.restore_rollback_override` | A new `admin.encryption.rotate_revert` | As A, plus the backup event |
| **What an insider can do** | Nothing new. Restoring an archive is already possible for the same holder | A second live data key on disk and in every backup for N days. Anyone who gets the host in that window has the key the rotation was meant to retire. If the rotation answered a DEK exposure, the revert re-exposes everything | Nothing new |
| **Operating cost** | Restore loses every write since the archive and resurrects revocations made since (SELF_HOSTING §5) | A retention timer, GC, crash safety for a second key, and a sweep back (as long as the rotation) | One more file per rotation. Already step 1 of the runbook |
| **Build size** | Docs only | M | S |

A revert is just another full sweep, back to a key the operator chose to retire. Any revert that
is safe (the old key was never exposed) can be done as well by rotating forward again. A revert
that is unsafe (the old key was exposed) should not exist. Archives already carry their own wrapped
DEK, so keeping the old key helps restores in no way.

### Upgrade impact

None for A. B adds key-file state that #3607's manifest would have to track. C adds a flag; existing
scripts that call `rotate --confirm` without `--backup-output` would need `--no-backup`, so make
it a warning for one minor release and then an error.

### Recommendation: A, plus C as a small hardening

**A is the right and sufficient answer**, with one code follow-up that is not a revert: before the
sweep commits, decrypt each new ciphertext under the new DEK in memory and compare it with the
plaintext. A bad sweep then never commits, which removes the main real-world reason for wanting a
revert. Take C if you want the backup step enforced rather than advised.

**What to document** (key-rotation-runbook §6, j6, ADR-010 note):

- "Undo" for a DEK rotation means roll forward (rotate again), or restore the pre-rotation archive.
  Never revert a rotation made because the old DEK was exposed.
- What a restore costs: writes since the archive are lost, revocations since are undone and must be
  re-applied, and sessions and tokens issued since are gone.
- **The witness.** The `.audit-highwater-witness` (SQLite installs) advances on every checkpoint
  write. If the server ran long enough after the rotation to write a checkpoint (one scheduler tick
  or `keyorix audit checkpoint`), the restore refuses the archive as a rollback and needs
  `--allow-rollback`, which is audited. That is expected. It replaces the runbook's "be ready for
  either".
- The archive restores only with the passphrase current when it was taken. If a `rotate-kek`
  happened since, the old passphrase is needed.
- Replicas: stop all of them, restore on one, copy the key files, start all of them.
- If the rotation answered an exposure: once the new DEK is verified, destroy pre-rotation archives
  according to policy. They decrypt with the exposed key.

---

## 4. rotate-kek and audit checkpoints

The question as asked: either auto-write a checkpoint at rotation, or mark old checkpoints
"verified under previous KEK" with a reference to the old key. Premise row 4 shows that the
checkpoint is only one of four things signed under the KEK-derived key: the checkpoint, the
high-water mark, the retention anchor and the verification state. An answer that fixes only the
checkpoint leaves F2 (purged installs read BROKEN online).

### Options

| | A. Re-sign and checkpoint at rotation | B. Mark old checkpoints "verified under previous KEK" | C. A, plus a cross-signed key-transition record |
|---|---|---|---|
| **What happens** | rotate-kek and migrate-provider already hold both keys and the exclusive lock, and already open the database. After the key files commit, in one DB transaction: walk the chain; if VALID, re-sign the high-water mark, retention anchor and verification state under the new key, and write a fresh checkpoint. If not VALID, re-sign nothing, write no checkpoint, and say so (a broken chain is never re-notarised) | At rotation, or at verify time, label the existing checkpoint rows with the old key's id or fingerprint. Verifiers report "superseded (key K1)" instead of BROKEN | Everything in A, plus an `audit_key_transitions` row `{old_key_id, new_key_id, head_id, head_hash, certified}` MAC'd under **both** keys (domain `auditkeytrans-v1`). The offline verifier takes a keyring (`--checkpoint-key-file` repeatable) and follows transitions |
| **Who can trigger it** | Whoever can rotate: host, both passphrases | If written at rotation, as A. If decided at verify time, anyone who can edit the label column | As A |
| **What a DB-write attacker without the key can do** | Nothing new. The online write path still has the lenient "superseded key_version" re-baseline for checkpoints written by **older** binaries, now narrowed by #3547's pin | **This is the F1 class.** The label is not authenticated under the current key (it cannot be, or it would just be option A). A relabel to "superseded K1" turns a forged or truncated checkpoint into "superseded, not tampered". Offline this is worse than today, because today's BROKEN is at least loud. Today's runbook §5 already asks the operator to make this judgement by reading the unauthenticated `key_version` | Nothing. A re-baseline then needs an authenticated transition from the claimed key. The lenient path can be removed for databases that have one transition, which closes the F1 class for good rather than narrowing it |
| **Insider with the key** | Can already forge the whole chain; rotation becomes visible as a checkpoint at a known time | Same as today | Rotation is attested in the chain with both keys; external anchors taken before still verify with the old key off-host |
| **Offline result after rotation** | Under the new key: VALID straight after the rotation (fresh checkpoint and mark). Under the old key: BROKEN for the latest checkpoint, as today. Old anchors still need the old key | "superseded", which an auditor cannot tell apart from a relabel | Keyring: old-era checkpoints and anchors verify with the old key if supplied, otherwise read `superseded (transition-attested)`. Never BROKEN for an honest rotation |
| **F2 (purged install)** | Fixed (the anchor is re-signed) | Not fixed | Fixed |
| **Build size** | S–M | S | M |

### Crash ordering (for A and C)

The key files commit first (#3607's two-phase manifest), then the DB re-sign. A crash between them
leaves today's state: artifacts signed under the old key, which the online lenient path (for the
re-baseline) and the runbook (for offline) handle. The reverse order must never happen. Artifacts
signed under a new key whose files never committed would read as tampering on the next boot under
the old key. Ask for a test at each of #3607's rotate-kek checkpoints plus the new DB step: the old
or the new state verifies, never BROKEN.

### Upgrade impact

- A: none for the schema. Rotations done with older binaries leave no fresh checkpoint, so they keep
  today's behaviour until the next scheduler checkpoint. Document it as "after upgrading, rotate
  with the new binary only". The open #3607 adds the same rule to UPGRADING for the key-set
  manifest.
- C: a new table. A server that refuses an unauthenticated re-baseline would wrongly refuse an install
  whose last rotation was done by an older binary and where no checkpoint has been written since.
  So C needs either a one-time, offline, audited `admin audit accept-key-change --confirm`
  (posture-flagged), or a rule that the lenient path stays for databases with **no** transition
  rows. Recommended: keep the lenient path only while the table is empty, and refuse once any
  transition exists.
- `export-checkpoint-key` writes the key id into the file so the keyring can match keys.

### Recommendation: A now, C with the seal work

- **Reject B.** An unauthenticated "superseded" label is the F1 laundering class moved into the
  verifier. It makes an honest rotation look clean by making a forged one look clean too.
- **Do A now** (S–M, no schema change). It answers the backlog's literal question ("auto-write a
  checkpoint at rotation: yes"), fixes F2, and leaves a fresh, exportable anchor straight after
  every rotation. The runbook §5 manual steps shrink to "export the new checkpoint key and anchor".
- **Add C in the same series as the seal (§2)**, before it. The seal records need to survive a key
  change (constraint 6), and C is what lets the lenient re-baseline path be removed rather than
  only narrowed.
- Also correct `key-rotation-runbook.md` §5 and `audit-chain-break-runbook.md` §4c now: on an
  install that has had a retention purge, a fresh checkpoint does **not** clear the state after a
  `rotate-kek` until A ships (F2).

---

## 5. Summary for decision

| Gap | Recommendation | Size | ADR | Order |
|---|---|---|---|---|
| 1 MFA reset | B: two-admin online reset, always a full credential reset; host `admin reset-mfa` shipped first as the fallback | S then M | yes (ADR-112 recovery) | 1 (pilot P1; independent) |
| 2 Seal a break | Pick among AUDIT-VERIFY-STATE-1's options against the eight constraints in §2; recover-admin does not seal | L | yes (amends ADR-029) | 4 (after §4 C) |
| 3 DEK revert | No revert command. Document roll-forward or restore (witness, passphrase, revocations); add a pre-commit decrypt check; optionally enforce the archive | docs + S | no (ADR-010 note) | any time |
| 4 rotate-kek | A now (re-sign and checkpoint at rotation, fixes F2); C (cross-signed transition, keyring verifier) before the seal; reject the unauthenticated "superseded" label | S–M, then M | yes for C (amends ADR-029) | 2 (A), 3 (C) |

Not verified here (pending e2e VM or not run): container and Kubernetes variants of every host
command; F2 re-run on current main (code path read only); whether notification channels can address
one user's email; behaviour across a mixed-version HA cluster during the MFA-reset rollout.
