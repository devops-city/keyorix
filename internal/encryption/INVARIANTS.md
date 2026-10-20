# internal/encryption invariants

Read this before changing anything in `internal/encryption` (KEK/DEK key management, AEAD
encryption, chunking, key-provider integration). Two-tier key architecture: a Key Encryption
Key (KEK, from `internal/crypto`'s pluggable providers) wraps a Data Encryption Key (DEK) that
actually encrypts secret values.

Format: `INV-ENCRYPTION-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## First-boot / cross-process coordination

- **INV-ENCRYPTION-01** `AcquireExclusiveKeyLock` is acquired BEFORE `Initialize`, not after —
  the loser of a first-boot race is refused immediately at the lock step, before it ever
  touches salt/DEK files, rather than racing key-material generation and only surfacing as a
  corrupted/mismatched key pair on a LATER restart. Why: first-boot key-bootstrap race. Guard:
  `firstboot_lock_order_test.go:TestFirstBootKeyBootstrap_LockBeforeInitialize_ExactlyOneWinner`.
- **INV-ENCRYPTION-02** DEK rotation (`RotateDEKWithSweep`) refuses to run while a live server
  (or another rotation) already holds the exclusive key lock, so the rotation CLI — a separate
  OS process — can never promote a new DEK to disk while the server still caches the old one in
  memory. Why: #92. Guard: `exclusive_lock_test.go:TestRotateDEKWithSweep_RefusesWhileServerHoldsLock`.
- **INV-ENCRYPTION-03** `RewrapDEKWithProvider` (the `migrate-provider` command) also takes the
  cross-process exclusive key lock RotateDEKWithSweep/RotateKEKPassphrase already require — it
  did not, originally, and could race a live server or an in-progress rotation on the same key
  file. Why: G62. Guard: `g62_dek_safety_test.go:TestRewrapDEKWithProvider_RefusesWhileServerHoldsLock`
  (+ positive-control sibling).
- **INV-ENCRYPTION-04** `RewrapDEK` and `RotateDEKWithSweep` running concurrently against a
  shared on-disk DEK and shared database must leave the DEK on disk matching whichever one the
  database was actually re-encrypted under, never a stale superseded one, regardless of which
  operation "wins" the race. Why: #195. Guard: `keymanager_lock_test.go`
  (`TestAcquireExclusiveKeyLock_MutualExclusion`,
  `TestRewrapAndRotate_ConcurrentRace_FinalDEKMatchesDB`).
- **INV-ENCRYPTION-28** Every key-file rewriter (`RotateDEKWithSweep` including its
  re-encryption sweep commit, `RotateKEKPassphrase`, `RewrapDEK*`) holds the key-file rewrite
  lock (`<dek_path>.lock`) EXCLUSIVELY for its whole write, so a holder of that lock in
  SHARED mode (`Service.AcquireKeyFileReadLock`) observes neither a key-file change nor a
  sweep commit. That lock is distinct from the server's `dek.lock` and does not conflict with
  a live server — the property `admin backup`'s live-server path relies on to archive a key
  set consistent with its database snapshot. Why: #2602. Guard:
  `key_file_read_lock_test.go` (`TestAcquireKeyFileReadLock_ExcludesKeyFileRewriters`,
  `TestAcquireKeyFileReadLock_CoexistsWithLiveServerLock`), end to end
  `server/admin/backup_restore_live_test.go:TestAdminBackup_Postgres_LiveServer_RefusesDuringKeyRotation`
  (pg-gated).

## Crash consistency (write-pending → rename → fsync)

- **INV-ENCRYPTION-05** A torn/short write during first-time DEK generation never leaves a
  corrupt-but-existing `dek.key` at the final path — `os.Stat`/`IsNotExist` still sees "no DEK
  yet" on the next attempt, so a retry self-heals instead of failing forever. Why: found via
  `FuzzFaultInjectedOperations`/opInit. Guard:
  `keymanager_init_dek_torn_write_test.go:TestEnsureWrappedDEKExists_ShortWriteSelfHeals`.
- **INV-ENCRYPTION-06** KEK-passphrase rotation's two coupled files (`dek.key`, `kek.salt`) —
  persisted via write-pending → rename → fsync — maintain, at EVERY possible crash point
  between any two steps: AVAILABILITY (some combination of surviving files plus a credential
  the operator legitimately holds recovers EXACTLY the pre-rotation DEK) and CONFIDENTIALITY
  (once rotation has fully completed, the OLD passphrase no longer unwraps the active DEK).
  Guard: `keymanager_crash_consistency_fuzz_test.go:FuzzKEKRotationCrashConsistency`.
- **INV-ENCRYPTION-07** KEK-provider migration (`RewrapDEK`, ADR-041) maintains the same
  AVAILABILITY/CONFIDENTIALITY invariant pair across its own crash points (old provider before
  rename, new provider after). Guard:
  `keymanager_rewrap_crash_consistency_fuzz_test.go:FuzzDEKRewrapCrashConsistency`.
- **INV-ENCRYPTION-08** A true DEK rotation with full re-encryption sweep (`RotateDEKWithSweep`,
  ADR-010) is durable across a crash at any of its four ordered steps (write pending DEK →
  sweep+commit rows under new DEK → rename pending to active → fsync directory);
  on restart `RecoverInterruptedRotation(db)` promotes a leftover `.pending` file when the
  sweep's redo marker committed and removes it otherwise, then the active DEK is loaded (see
  INV-ENCRYPTION-pending-dek-kept-after-commit). Guard: `keymanager_sweep_crash_consistency_fuzz_test.go:FuzzDEKSweepCrashConsistency`.
- **INV-ENCRYPTION-09** Beyond crash-BETWEEN-steps (the trilogy above), the same recoverability
  property holds when the ENVIRONMENT fails WHILE the process keeps running (ENOSPC/EIO/short
  write on the write itself, an fsync reporting failure after data already landed, a SQL
  statement that never executes). Guard:
  `fault_injected_operations_fuzz_test.go:FuzzFaultInjectedOperations` (reuses the trilogy's own
  `recoverDEK`/`recoverRewrap`/`tryOpen`/`tryOpenProvider` oracle helpers).
- **INV-ENCRYPTION-10** DEK-rotation file-durability recovery holds under a REAL process exit
  (SIGKILL/crash), not only an in-process panic — this is the one place in the trilogy that
  actually terminates the process rather than simulating a crash in-process. Guard:
  `keymanager_subprocess_crash_test.go` (re-execs the test binary as a crash-test worker).
- **INV-ENCRYPTION-11** `commitNewKEKFiles`'s rename-dek error cleanup only deletes
  `kek.salt.pending` when the rename is CONFIRMED not to have applied (verified against actual
  on-disk content) — unconditionally deleting it on ANY rename error (including an
  NFS lost-reply/retransmit ambiguity where the rename DID apply) orphans the DEK, making every
  secret undecryptable. Why: security-closures `kek-rename-dek-cleanup-dataloss-001`. Guard:
  `FuzzFaultInjectedOperations`; fix is `dekRenameActuallySucceeded`.

## Key derivation / domain separation

- **INV-ENCRYPTION-12** The audit-checkpoint signing key (ADR-029) is derived from the KEK,
  never the DEK, so a routine DEK rotation does not affect it — it only changes on a genuine
  KEK change (a KEK-provider migration, ADR-041). Why: #502. Guard:
  `audit_checkpoint_key_test.go`.
- **INV-ENCRYPTION-13** The evidence-signing key (used to sign exported compliance-evidence
  packs) is derived from the KEK, never the DEK, so a routine DEK rotation does not silently
  and permanently invalidate every previously-signed pack. Why: #268. Guard:
  `evidence_sign_key_test.go:TestEvidenceSignKey_StableAcrossDEKRotation` (byte-identical
  signing key and version before/after a full `RotateDEKWithSweep`).
- **INV-ENCRYPTION-14** The backup-manifest signing key (design-b3-backup-v2.md §5.2) is
  KEK-derived (not DEK-derived), independently domain-separated from the audit-checkpoint key,
  and wiped on shutdown alongside every other derived key. Guard: `backup_manifest_key_test.go`
  (mirrors `audit_checkpoint_key_test.go`'s own tests).
- **INV-ENCRYPTION-15** A key-provider fallback chain that falls back, AT RUNTIME, to a
  provider weaker than an earlier higher-tier provider in the chain is recorded as a queryable
  audit event (`EventKeyProviderFallbackDowngrade`), not just a log line — distinct from the
  config-time `AllowWeakerFallback` startup refusal, which fires whenever the config PERMITS a
  downgrade regardless of whether one ever actually happens. Guard:
  `key_provider_downgrade.go` wiring + `TestNewKeyProviderFromConfig_WeakFallback_RuntimeAuditEvent`.
- **INV-ENCRYPTION-16** `wireKMSAuditSink` actually connects a `Service`'s audit sink to a
  directly-configured KMS key provider's underlying client for every supported provider shape
  (including gcp-kms) — the production-wiring counterpart to each provider's own
  fallback-audit unit tests. Guard: `gcpkms_audit_sink_wiring_test.go`.

## AEAD / AAD binding

- **INV-ENCRYPTION-17** A ciphertext sealed with `MFASecretAAD(userID)` cannot be decrypted
  under a different user's identity — prevents a DB-write attacker from copying user A's
  encrypted TOTP seed into user B's `mfa_secrets` row to produce a stealthy, persistent MFA
  bypass. Why: #94. Guard: `aad_auth_transplant_test.go:TestAEAD_MFASecretAADBindsCiphertextToOwningUser`.
- **INV-ENCRYPTION-18** The legacy nil-AAD fallback in `DecryptSecretWithAAD` (for rows
  encrypted before the AAD migration, no `AADVersion` set) cannot be used to DOWNGRADE a
  v2 (AAD-sealed) ciphertext — the GCM tag, not the `AADVersion` metadata flag, is the real
  boundary: a ciphertext sealed with AAD simply cannot open with nil AAD, so a downgraded row
  fails closed (at worst bricks the row, never transplants). Guard:
  `aad_downgrade_test.go:TestAAD_NoLegacyDowngradeBypass`.
- **INV-ENCRYPTION-19** Every byte of ciphertext/tag/AAD tamper must be detected by AEAD
  authentication, not silently decrypted. Guard: `aead_tamper_test.go`.
- **INV-ENCRYPTION-20** Chunked encryption of a large secret reassembles byte-identically to
  the original plaintext across chunk-size boundaries. Guard: `chunk_integrity_test.go`.

## Path / permission handling

- **INV-ENCRYPTION-21** An absolute `dek_path`/`salt_path` boots correctly — `baseDir=""`
  (server/main.go's convention for "self-contained path, no base-dir restriction") must be a
  convention `normalizeKeyPaths` actually implements, not one that silently fails every boot.
  Why: regression that went unnoticed because nothing in the test suite used an absolute key
  path before the DAST workflow found it. Guard: `absolute_key_paths_test.go`.
- **INV-ENCRYPTION-22** Azure-KMS has no AAD input for RSA-OAEP key wrap, so a configured
  `kms_encryption_context` can never actually bind the wrapped KEK to this install — this is a
  hard startup error (checked BEFORE `azurekms.New` is reached), never a log warning that's
  easy to miss. Why: #123. Guard:
  `keyprovider_context_test.go:TestNewKeyProviderFromConfig_AzureKMSRejectsEncryptionContext`.
- **INV-ENCRYPTION-23** A KMS `Encrypt` response with a missing/empty/null `CiphertextBlob` is
  rejected as an error, never treated as a successful wrap (a wrapped-KEK file persisted from
  an empty blob appears to succeed at first-run but is unusable on the next restart). Why:
  security-closures `awskms-encrypt-empty-ciphertext-001`; structurally identical to the
  already-fixed `awssm.go` `SecretString==""` gap. Guard:
  `TestAWSKMS_Encrypt_EmptyCiphertextBlobRejected` (internal/crypto/awskms).

## Memory hygiene

- **INV-ENCRYPTION-24** `EncryptionService.dek` (and the pre-rotation `EncryptionService` that
  `RotateDEKWithSweep` discards once superseded) is wiped via `wipeBytes` on shutdown/
  replacement, matching every other DEK-bearing variable in this package — it was not,
  originally. Why: G62. Guard: `g62_dek_safety_test.go`
  (`TestServiceShutdown_WipesEncryptionServiceDEK`, `TestRotateDEKWithSweep_WipesSupersededEncryptionServiceDEK`
  — memory-scan-style tests proving no DEK bytes remain afterward).
- **INV-ENCRYPTION-25** Every KEK/DEK/evidence-sign/audit-checkpoint/backup-manifest key
  variable passed through a `defer wipeBytes(...)` or explicit `wipeBytes(...)` call at the end
  of its rotation/use site. Guard: `wipebytes_sweep_test.go:TestWipeBytesSweep_EveryKeyLocalIsWipedOnEveryReturn`
  — an AST sweep over every non-test file in this package: every local bound from a
  key-material call (`keyMaterialSources`) must be wiped, deferred-wiped, handed off
  (`x.field = v`, a `retainingCallees` call, or returned) on every lexical path to a return;
  every key-shaped callee and every key-shaped `[]byte`-returning function must be classified,
  so a new source cannot go unrecognised. Known gaps on main (3, all error paths) are listed in
  `knownWipeGaps` and reported by the skipped `TestWipeBytesSweep_KnownGaps`; the sweep fails
  if one stops reproducing. Not covered (see the file header): control flow beyond lexical
  nesting, wipe helpers other than `wipeBytes`, key bytes that reach a variable without a
  call, and struct-field wipe-on-overwrite (#2512).

## Shamir / TPM key custody (ADR-038)

- **INV-ENCRYPTION-26** `ShamirKeyProvider` reconstructs the KEK only from K-of-N shares — no
  single custodian holds the key: every K-subset reconstructs, every (K-1)-subset does not.
  Why: ADR-038. Guard (all in `internal/crypto`):
  `shamir_threshold_test.go:TestShamir_ThresholdExhaustive` (every K- and (K-1)-subset across
  nine (K,N) shapes; red against a degree-(K-2) polynomial, zeroed coefficients, and a broken
  Lagrange numerator), plus the pre-existing `shamir_test.go`
  (`TestShamir_RoundTrip_AnyThresholdSubset`, `TestShamir_BelowThresholdDoesNotReveal`) and
  `shamir_provider_test.go:TestShamirKeyProvider_SubThresholdRejected` (provider level). Not
  covered: the information-theoretic secrecy of K-1 shares (that they are independent of the
  secret), only that they do not reconstruct it (#2513).
- **INV-ENCRYPTION-27** The TPM 2.0 KEK provider (tier 2) seals the KEK to the specific TPM —
  it must not unseal on different hardware. Why: ADR-038 tier-2,
  `internal/crypto/tpm_provider.go`. Guard (all in `internal/crypto`, against the go-tpm-tools
  in-process simulator, where "different hardware" is a simulator with a different seed):
  `tpm_provider_test.go:TestTPMKeyProvider_DifferentTPMCannotUnseal`, and
  `tpm_binding_test.go` — `TestTPMBinding_BlobCopiedToOtherHostDoesNotUnseal` (a copied blob
  fails on six other TPMs, never silently re-seals, still unseals on the sealing TPM),
  `TestTPMBinding_DiskBlobDoesNotContainKEK` (no raw/base64/hex KEK in the file),
  `TestTPMBinding_TamperedPrivateDoesNotUnseal`, and `TestTPMSeal_ObjectIsFixedToTPMAndParent`
  (the sealed object carries `FixedTPM`+`FixedParent`, so a real TPM refuses to duplicate it to
  other hardware). **Gap, not automatable in CI today:** CI has no physical TPM, so the
  device-open path (`transport.OpenTPM`) and a real chip's enforcement of `FixedTPM`/
  `FixedParent` are not exercised; the tests check that the provider requests that enforcement,
  not that a chip performs it. Manual check on TPM hardware: seal on host A, copy the blob to
  host B, confirm `KEK()` fails with "unseal failed" and the blob is unchanged. Also not
  covered by design: no PCR policy is enforced (see the `tpm_provider.go` package doc), so the
  seal is bound to the chip, not to a boot state (#2514).
