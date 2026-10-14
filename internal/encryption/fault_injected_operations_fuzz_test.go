//go:build !windows

package encryption

// fault_injected_operations_fuzz_test.go — FuzzFaultInjectedOperations.
//
// Crash-consistency fuzzing (the existing FuzzKEKRotationCrashConsistency /
// FuzzDEKRewrapCrashConsistency / FuzzDEKSweepCrashConsistency trilogy) models a
// process crash BETWEEN two fully-completed durability steps — the write, the
// rename, and the fsync each always run to completion; only the gap between them
// is interrupted. That leaves an uncovered fault class: the ENVIRONMENT failing
// WHILE the process keeps running — ENOSPC/EIO/a short write on the write itself,
// an fsync that reports failure after the data already landed, a SQL statement
// that never executes because the connection/transaction failed. This fuzzer
// targets exactly that class, reusing the trilogy's own recovery-model helpers
// (recoverDEK, recoverRewrap, tryOpen, tryOpenProvider) so the oracle logic for
// "is the DEK still recoverable and uncorrupted" is identical, not reimplemented.
//
// ── Fault model ──────────────────────────────────────────────────────────────
//
// One fuzz input drives ONE operation (of six, below) with ONE injected fault at
// ONE seam within it. Every seam in this catalog is called at most once per
// operation invocation, so "the Nth call to seam S" (STEP 2's stated schedule
// shape) is always N=1 here — there is no loop that calls the same seam twice
// within a single operation. This is a narrower scope than a multi-operation
// fault SEQUENCE would be; see the report accompanying this change for why that
// was the deliberate v1 cut. The fault (operation + seam + kind + byte count) is
// fully encoded in the fuzz input, so every failure reproduces from the corpus
// file alone, matching the multi-fault design's own reproducibility property.
//
// Three fault kinds (fileFaultKind, fault_hooks.go) apply to file seams:
//
//	faultCleanError:      zero bytes reach the real file / the rename never runs.
//	faultShortWrite:      the real file gets exactly K of the real bytes, no fsync.
//	faultRealEffectThenError: the real write/rename DOES happen, error reported anyway.
//
// SQL seams use a fourth, GORM-callback-based mechanism (armSQLFault) requiring
// no production code change at all — a Before-hook's AddError stops GORM's
// default Create/Delete callback chain before it issues the real statement,
// exactly as local_pat_expiry_test.go's existing BulkRevokeExpiredPATsByUser
// fault-injection test already does. Every SQL seam here is a "clean" fault
// (the statement either fully runs or does not — no equivalent of a short write
// at the SQL layer).
//
// ── Ambiguity classification (oracle a) ──────────────────────────────────────
//
// Directive: faults AT OR AFTER the commit/durability point must accept EITHER
// the pre- or post-change state (never a mix); faults BEFORE it must leave the
// model unchanged. Per seam type:
//
//	write seam, ANY kind          → deterministic OLD. Every write seam here
//	    targets a *.pending file; the function that calls it unconditionally
//	    aborts (returns the error without renaming) on ANY write failure — so a
//	    faultRealEffectThenError on a write seam populates the .pending file
//	    correctly but the ACTIVE file is untouched regardless. Given this, the
//	    fuzz decoder never selects faultRealEffectThenError for a write seam
//	    (see seamSpec.kinds below) — it would be a real capability of
//	    fault_hooks.go's applyWriteFault, just not an interesting one here.
//	rename seam, faultCleanError   → deterministic OLD (the rename never ran).
//	rename seam, faultRealEffectThenError → AMBIGUOUS: durableRename performs
//	    the real os.Rename and only returns the injected error if that real
//	    rename succeeded — so the active file IS the post-rename one, even
//	    though the function reports failure. The oracle accepts either via.
//	sync seam (rewrap:syncdir)    → the preceding rename has, by construction,
//	    ALREADY happened for real by the time this seam fires (durableSyncDir is
//	    only ever reached after a successful durableRename) — so any fault here
//	    is inherently post-commit; the oracle accepts either via but in
//	    practice will always observe the post-rename state.
//	SQL seam                       → deterministic OLD for every seam in this
//	    catalog: GORM's Before-hook AddError stops the INSERT/DELETE from ever
//	    running, and none of the six operations retries or partially commits
//	    around a single faulted statement (the multi-statement DELETE is wrapped
//	    in a real db.Transaction, which GORM rolls back whole on any error).
//
// ── Operations (6 of the original 7-item catalog; PAT deferred) ─────────────
//
// secret create / secret update (version rollover) / secret delete are driven at
// the storage+encryption layer directly (raw GORM model calls + Service.
// EncryptSecretWithAAD), NOT through internal/core — core already imports
// encryption, so encryption importing core to call KeyorixCore.CreateSecret
// would be a cycle. This mirrors the EXISTING FuzzDEKSweepCrashConsistency's own
// seeding code, which already creates secret rows this same way. The call
// sequence and transaction boundaries are copied from the real production code
// they model (internal/core/secrets.go CreateSecret/storeSecretVersion,
// internal/storage/store/local_secrets.go DeleteSecret) — CREATE'S two writes
// (node, then version) are genuinely NOT wrapped in one transaction in
// production (storeSecretVersion is a bare CreateSecretVersion call after a
// separate CreateSecret call), so this harness does not invent a stronger
// atomicity guarantee than production actually has for that operation; DELETE's
// three writes ARE wrapped in one real db.Transaction in production
// (LocalStorage.DeleteSecret), reproduced here identically.
//
// DEK rewrap / KEK rotation reuse the crash-consistency trilogy's own
// standalone-KeyManager harness style and recovery-model helpers directly
// (recoverDEK/recoverRewrap/tryOpen/tryOpenProvider, rewrapDEKFile/
// rewrapSaltOld/rewrapSaltNew) — no new recovery logic, only a new way to reach
// the same crash points (a real fault instead of a real crash).
//
// backup/export models core.ExportComplianceEvidence's file-durability
// primitive — a single securefiles.SecureWriteFileSync to a final path with NO
// separate rename (unlike the DEK/KEK operations) — without invoking
// core.ExportComplianceEvidence itself, for the same import-cycle reason as
// secret CRUD above. The oracle (directive 4) is specific to this no-rename
// shape: after a faulted export, the final path must have either no file, or a
// file byte-identical to the intended content (the ambiguous "it actually
// wrote through despite the reported error" case), or a file that fails to
// parse as JSON (a short/garbled write that would be visibly rejected by any
// consumer) — never a THIRD state: a truncated file that happens to still
// parse.
//
// PAT create/revoke is deferred per the approved scope (no durability path
// beyond the generic SQL layer already covered by secret create/update/delete —
// see the investigation report).
//
// ── After every faulted operation ────────────────────────────────────────────
//
// The harness runs the REAL production startup/recovery step for that
// operation's family before checking any oracle:
//   - DEK rewrap / KEK rotation: km.CleanPendingDEK() (production's own startup
//     cleanup for a leftover dek.key.pending). KEK rotation's kek.salt.pending
//     hazard window has no automated recovery in production at all — the
//     existing trilogy's own recoverDEK models the documented MANUAL operator
//     step, reused here unchanged, not reinvented.
//   - secret create/update/delete/backup: no key-material recovery applies (no
//     .pending file is involved); the oracle reads storage/disk state directly.
//
// Then oracles (b)-(e) are checked (oracle (a) atomicity is folded into each
// operation's own state check above, per the ambiguity classification).
//
// ── FIXED: kek:rename-dek's ambiguous fault ──────────────────────────────────
//
// kek:rename-dek's faultRealEffectThenError case WAS a confirmed, filed
// data-loss bug (commitNewKEKFiles' error-cleanup deleted kek.salt.pending
// even when the rename it was cleaning up after had actually succeeded) — see
// docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md
// for the reachability conditions (NFS/network-filesystem rename
// retransmission semantics, NOT a directory-fsync error — that WAS, at the
// time of that finding, a separate, disconnected, silently-discarded call in
// the same function; also since fixed — see "kek:syncdir-dek/-salt" below,
// both now checked seams, not a stale claim about current behavior) and the
// fix (dekRenameActuallySucceeded, keymanager_kek_rotation.go): on a
// rename-dek error, verify the actual on-disk DEK content before any
// cleanup; only clean up when the rename provably did not happen. This is
// now DETERMINISTIC, not ambiguous — see expectedKEKVia and
// runKEKRotateFaultCase's transparentRecovery handling. Red-proofed by
// reverting the fix (fuzzer fails again at this exact seam) and restoring it
// (green again); not committed as a permanent toggle.
//
// ── Known limitation: the hang-guard is not yet load-tolerant ───────────────
//
// faultOpGuardDeadline (30s) is a fixed wall-clock deadline, same as the
// crash-consistency trilogy's own per-target deadlines. Under real system
// contention (verified directly: a `-race` fuzz burst hit this deadline once
// on a 10-core/5-user shared machine with a 15-min load average of 10.66;
// re-running the SAME case in isolation immediately after passed in ~5.6s) a
// deadline trip is NOT on its own evidence of a hang in the code under test —
// it currently conflates "the operation is stuck" with "the machine is busy."
// Treat a rig timeout here as inconclusive, not as a finding, until a
// load-tolerant guard (e.g. adaptive to measured baseline latency, or a
// deadline-miss retry-once-in-isolation check) lands — tracked informally as
// "speed-fix-2," not yet a filed issue.
//
// ── B3 encryption-family extension (STEP 3, 2026-09-24) ─────────────────────
//
// Four more operations, covering the remaining B3 (`keyorix-server admin
// encryption ...`) commands that have real production durability seams and no
// existing environment-fault coverage:
//
//   - opInit: KeyManager.Initialize's FIRST-RUN DEK generation
//     (ensureWrappedDEKExists) — a plain SecureWriteFileSync straight to the
//     final path, no pending/rename indirection (unlike rewrap/KEK-rotation).
//     ensureSaltExists's own first-run write is NOT covered: it only runs on
//     deriveKEK's legacy (km.keyProvider == nil) branch, and Service.NewService
//     — the only production constructor of a KeyManager — always calls
//     SetKeyProvider before Initialize, so that branch is unreachable from any
//     live caller (confirmed empirically, not assumed — see opInit's seam-table
//     comment). This op is also `auth-encryption enable`'s entire state-changing
//     effect (AuthEncryption.Initialize thin-wraps Service.Initialize, byte-for-byte
//     the same call), so one op covers both commands.
//   - opUpgradeAAD: Service.UpgradeAuthAAD's per-row Updates() sweep over
//     mfa_secrets/dynamic_secret_configs/dynamic_secret_leases — the same SQL-seam
//     mechanism as opCreate/Update/Delete, extended to GORM's Update callback
//     (armSQLUpdateFault) since UpgradeAuthAAD uses Model().Where().Updates(map),
//     not Create/Delete.
//   - opAuthMigrate: `auth-encryption migrate`'s MigratePasswordResetTokens sweep —
//     the same Update-seam mechanism, one table (password_resets), with its
//     encrypt-then-NULL-the-plaintext-column update.
//   - opMigrateProviderBackup: `migrate-provider`'s OWN unique durability step — the
//     pre-rewrap backup copy (CopyFile) and the restore-on-verification-failure
//     copy (RestoreBackup→CopyFile). The rewrap step in between reuses
//     Service.RewrapDEKWithProvider → KeyManager.RewrapDEK, the IDENTICAL function
//     opRewrap above already exhaustively fault-tests at the write/rename/sync
//     seam level — re-faulting it here would duplicate, not extend, coverage, so
//     this op runs that step for real and targets only the two copy calls unique
//     to migrate-provider.
//
// Oracles for all four (per the STEP 3 approval, deliberately more general than
// the six-op catalog's precise via-path tracking above): after a fault at ANY
// seam, (1) the data is recoverable under the OLD key/provider or the NEW one,
// never neither; (2) re-running the same operation after the fault converges to
// the same end state a clean run would reach; (3) a status/validate-equivalent
// read never reports success on a state that is actually broken; (4) no key
// material or passphrase appears in an error or log line.
//
// Deliberately NOT extended here, with reasons (matching this file's own
// "PAT deferred" precedent rather than a silent gap):
//
//   - `encryption fix-perms`: FixKeyFilePermissions is a per-file os.Chmod loop —
//     no write/rename/sync durability seam exists to fault (a failed chmod leaves
//     the file's CONTENT untouched, only its mode), and a chmod failure is
//     trivially idempotent-safe to retry. No meaningful fault-injection surface.
//   - `migrate-provider cleanup`: securefiles.SecureDeleteFile's shred-then-unlink
//     has no existing test hook, and it is a widely-shared primitive (used well
//     beyond this command) — adding one here for a worst case of "a redundant,
//     already-superseded backup file survives on disk" (not a data-loss or
//     plaintext-exposure risk: the backup is still wrapped, just under the OLD
//     provider) is a disproportionate blast radius for the value. v2 candidate.
//   - `auth-encryption rotate`: AuthEncryption.RotateAuthEncryption delegates to
//     the SAME Service.RotateDEKWithSweep `encryption rotate` uses — already
//     covered by the pre-existing FuzzDEKSweepCrashConsistency (the
//     crash-consistency class, a deliberate different fault model from this
//     file's environment-failure class per the package doc comment above).
//     Extending THIS fuzzer to RotateDEKWithSweep's own multi-table sweep +
//     redo-marker mechanism is real, distinct scope, not a small addition. v2
//     candidate, not silently dropped.
//
// ── v2 candidates (not implemented here) ─────────────────────────────────────
//
//   - Fault during RECOVERY itself: every case above injects one fault into the
//     original operation, then runs the REAL (unfaulted) recovery/startup step.
//     A second fault dimension — the recovery path itself failing (e.g.
//     CleanPendingDEK's os.Remove erroring, or a second crash during a manual
//     apply-pending-salt recovery) — is not modeled.
//   - A Postgres-gated regression test for the abort-after-constraint-violation
//     trap (CLAUDE.md's documented Postgres hazard: a caught violation that
//     returns nil is dead code there) — SQLite-only today; oracle (c)'s
//     fail-closed check is sound against SQLite, not yet demonstrated against
//     real Postgres transaction-abort semantics specifically.
//   - KMS-provider dependency-error/timeout faults for rewrap (rewrap here only
//     exercises the password-provider path). crypto.KMSClient is already an
//     interface with test fakes (internal/crypto/kms_provider_test.go), so this
//     needs no new production seam — just a fault-injecting fake wired through
//     crypto.NewKMSKeyProvider.
//   - The SAME verify-before-cleanup treatment for kek:rename-salt's own
//     ambiguous case (still genuinely ambiguous after this fix — see
//     expectedKEKVia) and, for defense-in-depth, RewrapDEK's rewrap:rename-dek
//     cleanup (not currently exploitable there — no second coupled file — but
//     the same discipline would prevent the bug class re-appearing if that
//     changes).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/securefiles"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// faultOpGuardDeadline is a HANG backstop, matching the trilogy's own
// per-target deadlines (kekRotationGuardDeadline / rewrapGuardDeadline) rather
// than fuzzutil.Guard's shared 3s (tuned for fast file/parse targets). The
// rewrap/kek-rotate operations run real PBKDF2 KEK derivation, same as their
// crash-consistency counterparts.
const faultOpGuardDeadline = 30 * time.Second

// errInjectedFault is the sentinel error every fault kind returns, so a test
// failure message is unambiguous about its source.
var errInjectedFault = fmt.Errorf("fault-injected-operations: simulated environment failure (ENOSPC/EIO/short-write/SQL-fault)")

// ── seam catalog ──────────────────────────────────────────────────────────

type seamKind int

const (
	seamWrite     seamKind = iota // file write seam: faultCleanError or faultShortWrite
	seamRename                    // file rename seam: faultCleanError or faultRealEffectThenError
	seamSync                      // file sync seam: faultCleanError only (always post-commit)
	seamSQL                       // GORM callback seam: faultCleanError only
	seamCombined                  // two seams faulted simultaneously — see runKEKRotateFaultCase
	seamSQLUpdate                 // GORM Update-callback seam (armSQLUpdateFault): faultCleanError only
)

type seamSpec struct {
	label string
	kind  seamKind
}

type opID int

const (
	opCreate opID = iota
	opUpdate
	opDelete
	opRewrap
	opKEKRotate
	opBackup
	opInit
	opUpgradeAAD
	opAuthMigrate
	opMigrateProviderBackup
	numOps
)

var opSeams = map[opID][]seamSpec{
	opCreate:    {{"sql:create-node", seamSQL}, {"sql:create-version", seamSQL}},
	opUpdate:    {{"sql:update-version", seamSQL}},
	opDelete:    {{"sql:delete-node", seamSQL}, {"sql:delete-shares", seamSQL}, {"sql:delete-acls", seamSQL}},
	opRewrap:    {{"rewrap:write-dek-pending", seamWrite}, {"rewrap:rename-dek", seamRename}, {"rewrap:syncdir", seamSync}},
	opKEKRotate: {{"kek:write-salt-pending", seamWrite}, {"kek:write-dek-pending", seamWrite}, {"kek:rename-dek", seamRename}, {"kek:rename-salt", seamRename}, {"kek:syncdir-dek", seamSync}, {"kek:syncdir-salt", seamSync}, {"kek:rename-dek-verify-unknown", seamCombined}},
	opBackup:    {{"backup:write", seamWrite}},

	// B3 extension — see the package doc comment's "B3 encryption-family
	// extension" section for what each op models and why.
	// init:write-salt is NOT included: ensureSaltExists's legacy branch only runs
	// when km.keyProvider is nil, but Service.NewService — the ONLY production
	// caller of NewKeyManager — always calls SetKeyProvider before Initialize
	// (buildKeyProvider constructs a real provider for every configured type,
	// including "password"). That branch is unreachable from any live caller, so
	// there is no real seam to fault here — confirmed empirically (the fault
	// never fired) before being removed, not assumed.
	opInit: {{"init:write-dek", seamWrite}},
	opUpgradeAAD: {
		{"aad:mfa-secrets", seamSQLUpdate},
		{"aad:dynamic-secret-configs", seamSQLUpdate},
		{"aad:dynamic-secret-leases", seamSQLUpdate},
	},
	opAuthMigrate:           {{"authmigrate:password-resets", seamSQLUpdate}},
	opMigrateProviderBackup: {{"migrate:backup-write", seamWrite}, {"migrate:restore-write", seamWrite}},
}

// decodeFault picks the operation, seam, and fault kind from the fuzz-chosen
// selector bytes, and returns the concrete *fileFault (nil for a seamSQL seam,
// which uses armSQLFault instead).
func decodeFault(opSel, seamSel, kindSel, shortWriteK byte) (op opID, seam string, sk seamKind, ff *fileFault) {
	op = opID(int(opSel) % int(numOps))
	seams := opSeams[op]
	s := seams[int(seamSel)%len(seams)]

	switch s.kind {
	case seamSQL, seamSQLUpdate:
		return op, s.label, s.kind, nil
	case seamWrite:
		// faultRealEffectThenError is deliberately excluded here — see the
		// package doc comment's ambiguity classification: it is not
		// distinguishable from faultCleanError at the active-file level for a
		// write seam, so offering it would just be redundant fuzzing surface.
		if kindSel%2 == 0 {
			return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
		}
		return op, s.label, s.kind, &fileFault{kind: faultShortWrite, k: int(shortWriteK), err: errInjectedFault}
	case seamRename:
		// kek:rename-dek's faultRealEffectThenError combination WAS a confirmed
		// production bug (commitNewKEKFiles' error-cleanup on a rename-dek
		// failure unconditionally deleted kek.salt.pending, destroying the only
		// recovery path when the rename actually succeeded and merely reported
		// failure) — now fixed (classifyDEKRename, keymanager_kek_rotation.go);
		// see docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md
		// for the reachability analysis, reproduction, and fix description. This
		// case is deterministic post-fix — see expectedKEKVia and
		// runKEKRotateFaultCase's transparentRecovery handling.
		if kindSel%2 == 0 {
			return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
		}
		return op, s.label, s.kind, &fileFault{kind: faultRealEffectThenError, err: errInjectedFault}
	case seamSync:
		return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
	case seamCombined:
		// The returned *fileFault is unused for this seam — runKEKRotateFaultCase
		// special-cases s.label and arms its own pair of faults via
		// armMultiFileFault. See its doc comment.
		return op, s.label, s.kind, nil
	}
	return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
}

// armFileFault installs ff at seam via fileFaultHook and returns a restore func.
func armFileFault(seam string, ff *fileFault) (restore func()) {
	prev := fileFaultHook
	fileFaultHook = func(s string) *fileFault {
		if s == seam {
			recordSeamHit(seam)
			return ff
		}
		return nil
	}
	return func() { fileFaultHook = prev }
}

// armMultiFileFault installs a distinct fault per seam simultaneously — used
// only by the combined rename-dek+verification-failure case below, where a
// single armFileFault can't express "two seams fail in the same call."
func armMultiFileFault(faults map[string]*fileFault) (restore func()) {
	prev := fileFaultHook
	fileFaultHook = func(s string) *fileFault {
		if f, ok := faults[s]; ok {
			recordSeamHit(s)
			return f
		}
		return nil
	}
	return func() { fileFaultHook = prev }
}

// armSQLFault registers a GORM Before-hook on db that fails the FIRST matching
// statement for seam, then never runs the real INSERT/DELETE for it — the same
// mechanism (and the same "gorm:before_create"/"gorm:before_delete" hook
// points) local_pat_expiry_test.go's existing
// TestLocalStorage_BulkRevokeExpiredPATsByUser_UpdateFails_ReturnsError uses.
// No production code is touched: GORM's Callback registry is a public API.
func armSQLFault(db *gorm.DB, seam string) (restore func()) {
	name := "fault:" + seam
	match := func(dest any, want string) bool {
		switch want {
		case "sql:create-node", "sql:delete-node":
			_, ok := dest.(*models.SecretNode)
			return ok
		case "sql:create-version", "sql:update-version":
			_, ok := dest.(*models.SecretVersion)
			return ok
		case "sql:delete-shares":
			_, ok := dest.(*models.ShareRecord)
			return ok
		case "sql:delete-acls":
			_, ok := dest.(*models.SecretACL)
			return ok
		}
		return false
	}
	switch seam {
	case "sql:create-node", "sql:create-version", "sql:update-version":
		_ = db.Callback().Create().Before("gorm:before_create").Register(name, func(d *gorm.DB) {
			if match(d.Statement.Dest, seam) {
				recordSeamHit(seam)
				_ = d.AddError(errInjectedFault)
			}
		})
		return func() { _ = db.Callback().Create().Remove(name) }
	case "sql:delete-node", "sql:delete-shares", "sql:delete-acls":
		_ = db.Callback().Delete().Before("gorm:before_delete").Register(name, func(d *gorm.DB) {
			if match(d.Statement.Dest, seam) {
				recordSeamHit(seam)
				_ = d.AddError(errInjectedFault)
			}
		})
		return func() { _ = db.Callback().Delete().Remove(name) }
	}
	return func() {}
}

// armSQLUpdateFault registers a GORM before_update hook on db that fails the
// FIRST matching statement for seam, then never runs the real UPDATE. Unlike
// armSQLFault's Create/Delete hooks (matched via d.Statement.Dest, which GORM
// sets to the model pointer for those callbacks), a Model(&T{}).Where(...).
// Updates(map) call sets d.Statement.Dest to the update PAYLOAD map, not a *T —
// so this matches on d.Statement.Model instead, which Model() always sets to the
// pointer passed to it, regardless of what Updates() is called with.
func armSQLUpdateFault(db *gorm.DB, seam string) (restore func()) {
	name := "fault:" + seam
	match := func(model any, want string) bool {
		switch want {
		case "aad:mfa-secrets":
			_, ok := model.(*models.MFASecret)
			return ok
		case "aad:dynamic-secret-configs":
			_, ok := model.(*models.DynamicSecretConfig)
			return ok
		case "aad:dynamic-secret-leases":
			_, ok := model.(*models.DynamicSecretLease)
			return ok
		case "authmigrate:password-resets":
			_, ok := model.(*models.PasswordReset)
			return ok
		}
		return false
	}
	_ = db.Callback().Update().Before("gorm:before_update").Register(name, func(d *gorm.DB) {
		if match(d.Statement.Model, seam) {
			recordSeamHit(seam)
			_ = d.AddError(errInjectedFault)
		}
	})
	return func() { _ = db.Callback().Update().Remove(name) }
}

// ── secret-CRUD world (create/update/delete/backup) ─────────────────────────

// secretWorldDBTables is the explicit, hand-named set of tables fuzzworld.World.Reset
// clears between fuzz iterations that reuse the same per-worker DB world (see World.Reset's
// doc for why this is a named list, not derived from the migrated model set).
// Dependent-first order: secret_versions/secret_acls/share_records before secret_nodes.
var secretWorldDBTables = []string{"secret_versions", "secret_acls", "share_records", "secret_nodes"}

// secretWorld is a cheap-static-KEK harness for the four operations that don't need a real
// password-derived KEK (their durability seams are the SQL layer or a plain file write, not
// KEK derivation) — mirrors FuzzDEKSweepCrashConsistency's own staticKEKProvider reasoning:
// the KDF is not what's under test here. Its DB comes from a per-worker fuzzworld.World (SQLite
// always, PostgreSQL too when KEYORIX_TEST_PG_DSN is set) reset fresh on every call to
// newSecretWorld — only the key/file directory (dir) is still allocated per call.
type secretWorld struct {
	t         *testing.T
	backend   string
	dir       string
	db        *gorm.DB
	svc       *Service
	seedNode  uint
	seedValue []byte
	canary    string
}

func newSecretWorld(t *testing.T, dbw *fuzzworld.World, canary string) *secretWorld {
	t.Helper()
	if err := dbw.Reset(secretWorldDBTables); err != nil {
		t.Fatalf("[%s] reset: %v", dbw.Backend, err)
	}
	db := dbw.DB
	dir := t.TempDir()

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	svc.keyManager.SetKeyProvider(staticKEKProvider{})
	if e := svc.Initialize("seed-passphrase"); e != nil {
		t.Fatalf("seed Initialize: %v", e)
	}

	seedVal := []byte("seed-value-" + canary)
	node := &models.SecretNode{ProjectID: 1, Name: "seed", IsSecret: true}
	if e := db.Create(node).Error; e != nil {
		t.Fatalf("[%s] seed node: %v", dbw.Backend, e)
	}
	aad := SecretAAD(node.ID, 1, 1)
	enc, meta, e := svc.EncryptSecretWithAAD(seedVal, aad)
	if e != nil {
		t.Fatalf("seed encrypt: %v", e)
	}
	if e := db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error; e != nil {
		t.Fatalf("[%s] seed version: %v", dbw.Backend, e)
	}
	return &secretWorld{t: t, backend: dbw.Backend, dir: dir, db: db, svc: svc, seedNode: node.ID, seedValue: seedVal, canary: canary}
}

// decryptLatest returns the decrypted plaintext of the latest version row for
// nodeID, or ok=false if none exists / decryption fails.
func (w *secretWorld) decryptLatest(nodeID uint) (plaintext []byte, versionNumber int, ok bool) {
	var v models.SecretVersion
	if e := w.db.Where("secret_node_id = ?", nodeID).Order("version_number DESC").First(&v).Error; e != nil {
		return nil, 0, false
	}
	aad := SecretAAD(nodeID, 1, v.VersionNumber)
	pt, e := w.svc.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if e != nil {
		return nil, 0, false
	}
	return pt, v.VersionNumber, true
}

func (w *secretWorld) nodeExists(nodeID uint) bool {
	var n models.SecretNode
	return w.db.First(&n, nodeID).Error == nil
}

// ── plaintext-spill scan (oracle d) ──────────────────────────────────────────

// scanForPlaintext walks every regular file under root and returns the paths
// of any that contain canary verbatim — the DB is in-memory, so this only
// needs to cover the key-directory / backup-directory files, but walks
// everything under root defensively.
func scanForPlaintext(root string, canary []byte) []string {
	var hits []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- test-only scan of a harness temp dir
		if rerr != nil {
			return nil
		}
		if bytes.Contains(data, canary) {
			hits = append(hits, path)
		}
		return nil
	})
	return hits
}

// ── the fuzz target ───────────────────────────────────────────────────────

func FuzzFaultInjectedOperations(f *testing.F) {
	// Built ONCE per testing.F, before f.Fuzz (internal/testutil/fuzzworld) — reopening and
	// migrating a DB per iteration was the dominant per-input cost.
	// SQLite always; PostgreSQL too when KEYORIX_TEST_PG_DSN is set. Only
	// opCreate/opUpdate/opDelete/opBackup (via newSecretWorld) touch this DB at all —
	// opRewrap/opKEKRotate never receive it (see runFaultInjectedCase below); they are pure
	// file/PBKDF2 operations with zero database interaction, so they run once, not once per
	// world.
	dbWorlds := fuzzworld.Worlds(f, "faultopsfuzz", ":memory:", 0) // full production schema (#1947)

	// Seed one case per (operation, seam, kind) combination decodeFault can
	// produce, including kek:rename-dek's ambiguous kind — see decodeFault's
	// comment: that case is deterministic post-fix (transparent recovery), not
	// a tolerated finding anymore.
	for _, s := range allFaultInjectedSeedTriples() {
		f.Add(s.opSel, s.seamSel, s.kindSel, byte(3), "old-pass", "new-pass", "secret-val")
	}
	f.Add(byte(0), byte(0), byte(0), byte(0), "", "", "")

	f.Fuzz(func(t *testing.T, opSel, seamSel, kindSel, shortWriteK byte, oldPassIn, newPassIn, secretVal string) {
		// Prefixed, never just the raw fuzzed string: oracle (e) below checks
		// these passphrases for leakage via strings.Contains against error text
		// that legitimately contains vocabulary like "ENOSPC" — a short or
		// single-character fuzzed passphrase (e.g. "C") coincidentally collides
		// with that vocabulary and false-positives the leak check on pure
		// chance, not an actual leak (confirmed via a -race fuzz run: oldPass=
		// newPass="C" tripped "ERROR HYGIENE" purely because "ENOSPC" contains a
		// "C"). A long, distinctive prefix makes coincidental substring
		// collision with ordinary error vocabulary vanishingly unlikely while
		// still varying meaningfully with the fuzzer's chosen suffix.
		oldPass := "PASSCANARY-old-" + oldPassIn
		newPass := "PASSCANARY-new-" + newPassIn
		canary := "FAULTCANARY-" + secretVal

		done := make(chan struct{})
		go func() {
			defer close(done)
			runFaultInjectedCase(t, dbWorlds, opSel, seamSel, kindSel, shortWriteK, oldPass, newPass, canary)
		}()
		select {
		case <-done:
		case <-time.After(faultOpGuardDeadline):
			t.Fatalf("fault-injected-operations exceeded %s — possible hang", faultOpGuardDeadline)
		}
	})
}

func runFaultInjectedCase(t *testing.T, dbWorlds []*fuzzworld.World, opSel, seamSel, kindSel, shortWriteK byte, oldPass, newPass, canary string) {
	op, seam, sk, ff := decodeFault(opSel, seamSel, kindSel, shortWriteK)

	switch op {
	case opCreate, opUpdate, opDelete, opBackup:
		for _, dbw := range dbWorlds {
			runSecretWorldCase(t, dbw, op, seam, sk, ff, canary)
		}
	case opRewrap:
		runRewrapFaultCase(t, seam, ff, oldPass, newPass)
	case opKEKRotate:
		runKEKRotateFaultCase(t, seam, ff, oldPass, newPass)
	case opInit:
		runInitFaultCase(t, seam, ff, oldPass)
	case opUpgradeAAD:
		for _, dbw := range dbWorlds {
			runUpgradeAADFaultCase(t, dbw, seam, canary)
		}
	case opAuthMigrate:
		for _, dbw := range dbWorlds {
			runAuthMigrateFaultCase(t, dbw, seam, canary)
		}
	case opMigrateProviderBackup:
		runMigrateProviderBackupFaultCase(t, seam, ff, oldPass)
	}
}

// ── create / update / delete / backup ────────────────────────────────────

func runSecretWorldCase(t *testing.T, dbw *fuzzworld.World, op opID, seam string, sk seamKind, ff *fileFault, canary string) {
	w := newSecretWorld(t, dbw, canary)

	var restore func()
	switch sk {
	case seamSQL:
		restore = armSQLFault(w.db, seam)
	default:
		restore = armFileFault(seam, ff)
	}

	var callErr error
	var newNodeID uint
	var backupPath string
	var backupWant []byte

	switch op {
	case opCreate:
		val := []byte(canary)
		node := &models.SecretNode{ProjectID: 1, Name: "created", IsSecret: true}
		if e := w.db.Create(node).Error; e != nil {
			callErr = e
		} else {
			newNodeID = node.ID
			aad := SecretAAD(node.ID, 1, 1)
			enc, meta, eerr := w.svc.EncryptSecretWithAAD(val, aad)
			if eerr != nil {
				callErr = eerr
			} else if e := w.db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error; e != nil {
				callErr = e
			}
		}
	case opUpdate:
		val := []byte(canary)
		aad := SecretAAD(w.seedNode, 1, 2)
		enc, meta, eerr := w.svc.EncryptSecretWithAAD(val, aad)
		if eerr != nil {
			callErr = eerr
		} else {
			callErr = w.db.Create(&models.SecretVersion{SecretNodeID: w.seedNode, VersionNumber: 2, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error
		}
	case opDelete:
		callErr = w.db.Transaction(func(tx *gorm.DB) error {
			res := tx.Delete(&models.SecretNode{}, w.seedNode)
			if res.Error != nil {
				return res.Error
			}
			if e := tx.Where("secret_id = ?", w.seedNode).Delete(&models.ShareRecord{}).Error; e != nil {
				return e
			}
			return tx.Where("secret_id = ?", w.seedNode).Delete(&models.SecretACL{}).Error
		})
	case opBackup:
		// "note" is deliberately NOT the canary: this evidence-pack payload is
		// non-secret metadata by design (core.ExportComplianceEvidence's real
		// export is a plaintext JSON compliance record, never a secret VALUE),
		// so it legitimately belongs in plaintext on disk. Embedding the canary
		// here would make oracle (d)'s plaintext-spill scan below fire on the
		// backup's own intended content — a harness false positive, not a
		// finding (confirmed via a 90s -fuzz burst during verification).
		payload := map[string]any{"generated_at": "2026-09-19T00:00:00Z", "note": "fault-injected-operations-backup-marker", "campaigns": []any{}}
		data, merr := json.MarshalIndent(payload, "", "  ")
		if merr != nil {
			t.Fatalf("marshal backup payload: %v", merr)
		}
		// A dedicated subdir, distinct from w.dir (which holds dek.key/kek.salt) —
		// core.ExportComplianceEvidence's real outputDir is likewise never the key
		// directory, and checkBackupOracle's "no stray file" check would otherwise
		// misreport the key files themselves as unexpected leftovers.
		backupDir := filepath.Join(w.dir, "backup-out")
		if e := os.MkdirAll(backupDir, 0o700); e != nil {
			t.Fatalf("mkdir backup dir: %v", e)
		}
		name := "keyorix-evidence-fault-test.json"
		backupPath = filepath.Join(backupDir, name)
		backupWant = data
		callErr = durableWriteSync(backupDir, name, data, 0o600, seam)
	}
	restore()

	// oracle (c): a faulted operation must report failure, never silent success.
	if callErr == nil {
		t.Fatalf("HARNESS/oracle-c: op=%v seam=%q fault did not fire — the operation returned nil error", op, seam)
	}
	// oracle (e): the error must not leak the plaintext canary.
	if strings.Contains(callErr.Error(), canary) {
		t.Fatalf("ERROR HYGIENE: op=%v seam=%q error leaks plaintext canary: %v", op, seam, callErr)
	}

	switch op {
	case opCreate:
		checkCreateOracle(t, w, seam, newNodeID)
	case opUpdate:
		checkUpdateOracle(t, w)
	case opDelete:
		checkDeleteOracle(t, w)
	case opBackup:
		checkBackupOracle(t, backupPath, backupWant)
	}

	// oracle (d): no plaintext spill anywhere under the harness's own dirs.
	if hits := scanForPlaintext(w.dir, []byte(canary)); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: op=%v seam=%q canary found in: %v", op, seam, hits)
	}
}

func checkCreateOracle(t *testing.T, w *secretWorld, seam string, newNodeID uint) {
	switch seam {
	case "sql:create-node":
		var count int64
		w.db.Model(&models.SecretNode{}).Where("name = ?", "created").Count(&count)
		if count != 0 {
			t.Fatalf("ATOMICITY: sql:create-node fault fired but a node row exists anyway")
		}
	case "sql:create-version":
		if !w.nodeExists(newNodeID) {
			t.Fatalf("ATOMICITY: sql:create-version fault also lost the already-committed node row (id=%d)", newNodeID)
		}
		var vcount int64
		w.db.Model(&models.SecretVersion{}).Where("secret_node_id = ?", newNodeID).Count(&vcount)
		if vcount != 0 {
			t.Fatalf("FAIL-CLOSED VIOLATION: sql:create-version fault fired but a version row exists anyway — the injected fault did not actually prevent the write")
		}
	}
}

func checkUpdateOracle(t *testing.T, w *secretWorld) {
	pt, ver, ok := w.decryptLatest(w.seedNode)
	if !ok {
		t.Fatalf("DATA LOSS: sql:update-version fault also made the seed version unreadable")
	}
	if ver != 1 {
		t.Fatalf("ATOMICITY: sql:update-version fault fired but the latest version is v%d, not the original v1", ver)
	}
	if !bytes.Equal(pt, w.seedValue) {
		t.Fatalf("DATA CORRUPTION: sql:update-version fault fired but the seed version's plaintext changed: got %q want %q", pt, w.seedValue)
	}
}

func checkDeleteOracle(t *testing.T, w *secretWorld) {
	if !w.nodeExists(w.seedNode) {
		t.Fatalf("ATOMICITY: a faulted delete step still removed the secret node — the wrapping transaction did not roll back")
	}
	pt, ver, ok := w.decryptLatest(w.seedNode)
	if !ok {
		t.Fatalf("DATA LOSS: a faulted delete left the node but its version is unreadable")
	}
	if ver != 1 || !bytes.Equal(pt, w.seedValue) {
		t.Fatalf("DATA CORRUPTION: a faulted delete left the seed version altered: v%d %q want v1 %q", ver, pt, w.seedValue)
	}
}

func checkBackupOracle(t *testing.T, path string, wantData []byte) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed harness temp-dir path
	if os.IsNotExist(err) {
		return // no file at the final path — acceptable
	}
	if err != nil {
		t.Fatalf("BACKUP: unexpected stat error on final path: %v", err)
	}
	if bytes.Equal(data, wantData) {
		return // the write actually completed durably despite the injected error
	}
	if json.Valid(data) {
		t.Fatalf("BACKUP CORRUPTION: a non-matching file at the final path parses as valid JSON — a restore step would silently accept truncated/garbled data: %q", data)
	}
	// invalid JSON — a restore step would reject it. Acceptable.

	dir := filepath.Dir(path)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("BACKUP: unexpected stray file left in backup dir: %s", e.Name())
		}
	}
}

// ── DEK rewrap ────────────────────────────────────────────────────────────

func runRewrapFaultCase(t *testing.T, seam string, ff *fileFault, oldPass, newPass string) {
	dir := t.TempDir()
	kmSeed := NewKeyManager(dir, rewrapDEKFile, rewrapSaltOld)
	kmSeed.SetKeyProvider(fastPasswordProvider(oldPass, dir, rewrapSaltOld))
	if err := kmSeed.Initialize(oldPass); err != nil {
		t.Fatalf("seed Initialize(old=%q): %v", oldPass, err)
	}
	dek0 := append([]byte(nil), kmSeed.GetDEK()...)
	newProvider := fastPasswordProvider(newPass, dir, rewrapSaltNew)

	restore := armFileFault(seam, ff)
	err := kmSeed.RewrapDEK(newProvider)
	restore()

	if err == nil {
		t.Fatalf("HARNESS/oracle-c: rewrap seam=%q fault did not fire — RewrapDEK returned nil error", seam)
	}
	if strings.Contains(err.Error(), oldPass) || strings.Contains(err.Error(), newPass) {
		t.Fatalf("ERROR HYGIENE: rewrap seam=%q error leaks a passphrase: %v", seam, err)
	}

	// Real production startup step: clean a leftover dek.key.pending.
	kmSeed.CleanPendingDEK()

	rec, via, ok := recoverRewrap(dir, oldPass, newPass)
	if !ok {
		t.Fatalf("DATA LOSS: no provider recovers the DEK after rewrap fault %q", seam)
	}
	if !bytes.Equal(rec, dek0) {
		t.Fatalf("DEK CORRUPTION after rewrap fault %q via %s: recovered key != original", seam, via)
	}

	// Ambiguity classification (see package doc comment): rewrap:syncdir is
	// always post-rename by construction (durableSyncDir only fires after a
	// real durableRename already succeeded), so it always expects "new-provider"
	// regardless of kind; a write-seam or clean rename-seam fault on the other
	// two seams must leave the OLD provider still valid — the operation must not
	// have silently gone through despite reporting failure.
	want, skip := expectedRewrapVia(seam, ff)
	if !skip && !containsString(want, via) {
		t.Fatalf("FAIL-CLOSED VIOLATION: rewrap fault %q (kind=%v) reported failure but the active DEK recovered via %q, want one of %v — the state moved despite the reported error", seam, ff.kind, via, want)
	}

	if hits := scanForPlaintext(dir, dek0); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: rewrap fault %q left the raw DEK bytes on disk outside key files: %v", seam, hits)
	}
}

// expectedRewrapVia returns the recoverRewrap "via" value(s) a DETERMINISTIC
// (non-ambiguous) fault at seam must produce, or skip=true when the fault is
// the AMBIGUOUS faultRealEffectThenError kind (only availability/integrity are
// checked then — see the package doc comment's ambiguity classification).
// rewrap:syncdir is always post-rename by construction, so it expects
// "new-provider" unconditionally rather than following the kind-based rule.
func expectedRewrapVia(seam string, ff *fileFault) (want []string, skip bool) {
	if seam == "rewrap:syncdir" {
		return []string{"new-provider"}, false
	}
	if ff.kind == faultRealEffectThenError {
		return nil, true
	}
	return []string{"old-provider"}, false
}

func containsString(list []string, s string) bool {
	return slices.Contains(list, s)
}

// ── KEK rotation ──────────────────────────────────────────────────────────

// kekRenameDekVerifyUnknownSeam is the combined-fault seam label: rename-dek
// applies for real but reports an error (faultRealEffectThenError) AND the
// classifyDEKRename verification that would otherwise detect that gets its
// own simulated stat/read failure — the exact "same blip disrupts both"
// scenario the tri-state fix (classifyDEKRename returning dekRenameUnknown)
// exists to fail safe against. Handled entirely separately from the generic
// single-fault seams below: ff is unused (always nil, see decodeFault) since
// this needs two simultaneous faults, not one.
const kekRenameDekVerifyUnknownSeam = "kek:rename-dek-verify-unknown"

func runKEKRotateFaultCase(t *testing.T, seam string, ff *fileFault, oldPass, newPass string) {
	if seam == kekRenameDekVerifyUnknownSeam {
		runKEKRotateCombinedVerifyUnknownCase(t, oldPass, newPass)
		return
	}
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(oldPass); err != nil {
		t.Fatalf("seed Initialize(oldPass=%q): %v", oldPass, err)
	}
	dek0 := append([]byte(nil), km.GetDEK()...)

	restore := armFileFault(seam, ff)
	err := km.RotateKEKPassphrase(oldPass, newPass)
	restore()

	// FIXED behavior (docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md):
	// kek:rename-dek's ambiguous fault (the rename actually applied despite the
	// reported error) is now transparently absorbed by dekRenameActuallySucceeded
	// — commitNewKEKFiles falls through and completes the rotation normally, so
	// RotateKEKPassphrase returns nil here. This is the intended, fixed outcome,
	// not a gap: every other (seam, kind) combination must still report an error.
	transparentRecovery := seam == "kek:rename-dek" && ff.kind == faultRealEffectThenError
	switch {
	case transparentRecovery && err != nil:
		t.Fatalf("REGRESSION: kek-rotate fault %q (kind=%v) should be transparently absorbed by the verify-before-cleanup fix (RotateKEKPassphrase should return nil), but got: %v", seam, ff.kind, err)
	case !transparentRecovery && err == nil:
		t.Fatalf("HARNESS/oracle-c: kek-rotate seam=%q fault did not fire — RotateKEKPassphrase returned nil error", seam)
	}
	if err != nil && (strings.Contains(err.Error(), oldPass) || strings.Contains(err.Error(), newPass)) {
		t.Fatalf("ERROR HYGIENE: kek-rotate seam=%q error leaks a passphrase: %v", seam, err)
	}

	// Real production startup step: clean a leftover dek.key.pending. Note (per
	// the package doc comment): kek.salt.pending has NO automated startup
	// recovery in production — recoverDEK below models the documented manual
	// operator step, unchanged from the existing crash-consistency fuzzer.
	km.CleanPendingDEK()

	rec, via, ok := recoverDEK(dir, oldPass, newPass)
	if !ok {
		t.Fatalf("DATA LOSS: no recovery yields the DEK after kek-rotate fault %q (kind=%v)", seam, ff.kind)
	}
	if !bytes.Equal(rec, dek0) {
		t.Fatalf("DEK CORRUPTION after kek-rotate fault %q via %s: recovered key != original", seam, via)
	}

	want, skip := expectedKEKVia(seam, ff)
	if !skip && !containsString(want, via) {
		t.Fatalf("FAIL-CLOSED VIOLATION: kek-rotate fault %q (kind=%v) reported failure but recovery went via %q, want one of %v — the state moved despite the reported error", seam, ff.kind, via, want)
	}

	if hits := scanForPlaintext(dir, dek0); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: kek-rotate fault %q left the raw DEK bytes on disk outside key files: %v", seam, hits)
	}
}

// runKEKRotateCombinedVerifyUnknownCase drives the combined rename-dek
// fault: the rename applies for real but reports an error, AND the
// verification that would otherwise detect that (classifyDEKRename) gets its
// own simulated failure — dekRenameUnknown, not dekRenameNotApplied. Asserts
// the fail-safe direction directly: no .pending material is removed (the
// concrete fail-open-under-uncertainty gap this case exists to catch — a
// prior version of the fix treated ANY verification failure as "not
// applied," which still permitted deleting kek.salt.pending here) and the
// DEK remains fully recoverable regardless.
func runKEKRotateCombinedVerifyUnknownCase(t *testing.T, oldPass, newPass string) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(oldPass); err != nil {
		t.Fatalf("seed Initialize(oldPass=%q): %v", oldPass, err)
	}
	dek0 := append([]byte(nil), km.GetDEK()...)

	restore := armMultiFileFault(map[string]*fileFault{
		"kek:rename-dek":        {kind: faultRealEffectThenError, err: errInjectedFault},
		"kek:verify-rename-dek": {kind: faultCleanError, err: errInjectedFault},
	})
	err := km.RotateKEKPassphrase(oldPass, newPass)
	restore()

	if err == nil {
		t.Fatalf("HARNESS/oracle-c: kek-rotate seam=%q fault did not fire — RotateKEKPassphrase returned nil error", kekRenameDekVerifyUnknownSeam)
	}
	if strings.Contains(err.Error(), oldPass) || strings.Contains(err.Error(), newPass) {
		t.Fatalf("ERROR HYGIENE: kek-rotate seam=%q error leaks a passphrase: %v", kekRenameDekVerifyUnknownSeam, err)
	}

	// The core assertion: kek.salt.pending must survive an UNKNOWN outcome —
	// deleting it here, on mere uncertainty, is exactly the fail-open gap
	// this case exists to catch.
	if _, statErr := os.Stat(filepath.Join(dir, "kek.salt.pending")); statErr != nil {
		t.Fatalf("FAIL-SAFE VIOLATION: kek.salt.pending was removed despite an UNKNOWN rename-dek outcome (the rename applied for real, but its verification ALSO failed) — this is exactly the fail-open-under-uncertainty gap the tri-state classification exists to close: %v", statErr)
	}

	km.CleanPendingDEK()

	rec, via, ok := recoverDEK(dir, oldPass, newPass)
	if !ok {
		t.Fatalf("DATA LOSS: no recovery yields the DEK after the combined rename-dek+verification-failure fault")
	}
	if !bytes.Equal(rec, dek0) {
		t.Fatalf("DEK CORRUPTION after the combined fault via %s: recovered key != original", via)
	}
	// via is expected to be the hazard-window recovery (apply-pending-salt+*),
	// since the rotation stopped at the Unknown branch without attempting the
	// salt rename — same deterministic state as kek:rename-salt's own case.
	if via != "apply-pending-salt+new-passphrase" && via != "apply-pending-salt+old-passphrase" {
		t.Fatalf("unexpected recovery path after the combined fault: via=%q, want apply-pending-salt+*", via)
	}

	if hits := scanForPlaintext(dir, dek0); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: combined rename-dek+verification-failure fault left the raw DEK bytes on disk outside key files: %v", hits)
	}
}

// expectedKEKVia returns the recoverDEK "via" value(s) a DETERMINISTIC fault
// at seam must produce. "old-passphrase" covers every seam before the DEK
// rename commits (nothing has moved yet); "apply-pending-salt+*" is the
// expected recovery for a deterministic fault at kek:rename-salt, because by
// the time that seam runs, kek:rename-dek has ALREADY unconditionally
// succeeded for real — the correct "unchanged" state for THIS seam is the
// hazard window (dek.key new, kek.salt old, kek.salt.pending still present),
// not plain old-passphrase.
//
// kek:rename-dek's ambiguous (faultRealEffectThenError) case is no longer
// ambiguous after the verify-before-cleanup fix: it is now DETERMINISTIC and
// expects "new-passphrase" (the rotation completes fully, transparently —
// see runKEKRotateFaultCase's transparentRecovery handling). kek:rename-salt's
// ambiguous case remains genuinely ambiguous (skip=true) — no equivalent
// verify-before-cleanup fix exists for it in this commit; a fault there can
// still leave either the hazard window or a fully-completed rotation.
//
// kek:syncdir-dek/-salt (seamSync, always faultCleanError — see decodeFault)
// are DETERMINISTIC, matching the rename step immediately preceding each:
// syncdir-dek fires right after the DEK rename already succeeded for real but
// before the salt rename is attempted (the fix now returns an error there
// instead of proceeding), so the state is the same hazard window
// kek:rename-salt's own deterministic case reaches; syncdir-salt fires after
// BOTH renames already succeeded for real, so the rotation is already fully
// applied on disk regardless of this last fsync's outcome.
func expectedKEKVia(seam string, ff *fileFault) (want []string, skip bool) {
	if seam == "kek:rename-dek" && ff.kind == faultRealEffectThenError {
		return []string{"new-passphrase"}, false
	}
	if ff.kind == faultRealEffectThenError {
		return nil, true
	}
	switch seam {
	case "kek:write-salt-pending", "kek:write-dek-pending", "kek:rename-dek":
		return []string{"old-passphrase"}, false
	case "kek:rename-salt", "kek:syncdir-dek":
		return []string{"apply-pending-salt+new-passphrase", "apply-pending-salt+old-passphrase"}, false
	case "kek:syncdir-salt":
		return []string{"new-passphrase", "old-passphrase"}, false
	}
	return nil, true
}

// ── B3: init (`encryption init` / `auth-encryption enable`) ─────────────────

func runInitFaultCase(t *testing.T, seam string, ff *fileFault, oldPass string) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}

	restore := armFileFault(seam, ff)
	svc := NewService(cfg, dir)
	err := svc.Initialize(oldPass)
	restore()

	if err == nil {
		t.Fatalf("HARNESS/oracle-c: op=init seam=%q fault did not fire — Initialize returned nil error", seam)
	}
	if strings.Contains(err.Error(), oldPass) {
		t.Fatalf("ERROR HYGIENE: op=init seam=%q error leaks the passphrase: %v", seam, err)
	}

	// oracle 2 (idempotent convergence): a clean retry on the SAME dir — the real
	// operator's actual next step — must reach a working state. A fresh install
	// has no prior key material to lose, so "converge to the clean-run end state"
	// here means "the retry succeeds," not "recovers a specific prior key."
	svc2 := NewService(cfg, dir)
	err2 := svc2.Initialize(oldPass)
	if err2 != nil {
		t.Fatalf("CONVERGENCE: op=init seam=%q a clean retry after the fault still fails: %v — a fresh install must self-heal from a single injected environment failure, not stay permanently bricked", seam, err2)
	}

	// oracle 1 (availability): the retried service must actually work.
	probe := []byte("INIT-PROBE-" + oldPass)
	ct, _, eerr := svc2.EncryptSecret(probe)
	if eerr != nil {
		t.Fatalf("AVAILABILITY: op=init seam=%q post-retry service cannot encrypt: %v", seam, eerr)
	}
	pt, derr := svc2.DecryptSecret(ct)
	if derr != nil || !bytes.Equal(pt, probe) {
		t.Fatalf("AVAILABILITY: op=init seam=%q post-retry service round-trip failed: err=%v", seam, derr)
	}

	// oracle 3 (status honesty): a service that DID initialize and round-trips
	// must also validate successfully — `encryption validate` must never
	// contradict a working `encryption status`.
	if verr := svc2.ValidateKeyFiles(); verr != nil {
		t.Fatalf("STATUS HONESTY: op=init seam=%q retried service initialized and round-trips, but ValidateKeyFiles reports it invalid: %v", seam, verr)
	}

	if hits := scanForPlaintext(dir, probe); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: op=init seam=%q probe found on disk outside key files: %v", seam, hits)
	}
}

// ── B3: upgrade-aad / auth-encryption migrate world ──────────────────────────

// authWorldDBTables mirrors secretWorldDBTables's own reasoning (see
// fuzzworld.World.Reset's doc comment) for the four auth-encryption tables
// opUpgradeAAD and opAuthMigrate sweep.
var authWorldDBTables = []string{"mfa_secrets", "dynamic_secret_configs", "dynamic_secret_leases", "password_resets"}

type authWorld struct {
	dir    string
	db     *gorm.DB
	svc    *Service
	canary string
}

// newAuthWorld seeds one LEGACY (no-AAD) row in each of the three AAD-swept
// tables opUpgradeAAD sweeps, plus one plaintext-token password_resets row for
// opAuthMigrate — MigratePasswordResetTokens' own legacy shape is plaintext-in-
// the-token-column, a genuinely different legacy format from the other three
// (see encryptionops.MigrateAuthDataWithConfig's own doc comment on why sessions/
// API clients/tokens are excluded: only password_resets ever held real plaintext
// here). Both ops always have real, unswept work to do.
func newAuthWorld(t *testing.T, dbw *fuzzworld.World, canary string) *authWorld {
	t.Helper()
	if err := dbw.Reset(authWorldDBTables); err != nil {
		t.Fatalf("[%s] reset: %v", dbw.Backend, err)
	}
	db := dbw.DB
	dir := t.TempDir()

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	svc.keyManager.SetKeyProvider(staticKEKProvider{})
	if e := svc.Initialize("seed-passphrase"); e != nil {
		t.Fatalf("seed Initialize: %v", e)
	}

	encLegacy := func(v string) ([]byte, []byte) {
		enc, meta, e := svc.EncryptSecret([]byte(v))
		if e != nil {
			t.Fatalf("[%s] seed encrypt: %v", dbw.Backend, e)
		}
		return enc, meta
	}

	mfaEnc, mfaMeta := encLegacy("TOTP-" + canary)
	if e := db.Create(&models.MFASecret{UserID: 1, SecretEnc: mfaEnc, SecretMeta: mfaMeta}).Error; e != nil {
		t.Fatalf("[%s] seed mfa_secret: %v", dbw.Backend, e)
	}
	dsnEnc, dsnMeta := encLegacy("postgres://admin:pw@db/DSN-" + canary)
	if e := db.Create(&models.DynamicSecretConfig{Name: "seed-cfg", ProjectID: 1, EnvironmentID: 2, AdminDSNEnc: dsnEnc, AdminDSNMeta: dsnMeta}).Error; e != nil {
		t.Fatalf("[%s] seed dynamic_secret_config: %v", dbw.Backend, e)
	}
	credEnc, credMeta := encLegacy(`{"user":"x","pass":"CRED-` + canary + `"}`)
	if e := db.Create(&models.DynamicSecretLease{LeaseID: "seed-lease-" + canary, ConfigID: 9, CredentialEnc: credEnc, CredentialMeta: credMeta}).Error; e != nil {
		t.Fatalf("[%s] seed dynamic_secret_lease: %v", dbw.Backend, e)
	}
	if e := db.Create(&models.PasswordReset{UserID: 1, Token: "RESET-" + canary}).Error; e != nil {
		t.Fatalf("[%s] seed password_reset: %v", dbw.Backend, e)
	}

	return &authWorld{dir: dir, db: db, svc: svc, canary: canary}
}

func runUpgradeAADFaultCase(t *testing.T, dbw *fuzzworld.World, seam, canary string) {
	w := newAuthWorld(t, dbw, canary)

	restore := armSQLUpdateFault(w.db, seam)
	result, err := w.svc.UpgradeAuthAAD(w.db)
	restore()

	// oracle (c): a faulted operation must report failure, never silent success.
	if err == nil {
		t.Fatalf("[%s] HARNESS/oracle-c: op=upgrade-aad seam=%q fault did not fire — UpgradeAuthAAD returned nil error (result=%+v)", dbw.Backend, seam, result)
	}
	// oracle 4 (no leak).
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("[%s] ERROR HYGIENE: op=upgrade-aad seam=%q error leaks plaintext canary: %v", dbw.Backend, seam, err)
	}

	// oracle 1 (availability): the whole sweep transaction rolled back on the
	// fault (ADR-010-style, matching RotateWithConfig's own sweep), so every row
	// is still in its LEGACY form — DecryptSecretWithAAD's documented fallback
	// (auth_encryption.go's own top comment) must still open it.
	checkAuthWorldAADRowsDecryptable(t, w, dbw.Backend, seam)

	// oracle 2 (idempotent convergence): a clean re-run reaches the SAME
	// fully-upgraded end state a fault-free run would (matching
	// TestUpgradeAuthAAD_BindsLegacyRowsWithoutRotatingDEK's own clean-run
	// assertion: all 3 rows swept).
	result2, err2 := w.svc.UpgradeAuthAAD(w.db)
	if err2 != nil {
		t.Fatalf("[%s] CONVERGENCE: op=upgrade-aad seam=%q re-run after the fault failed: %v", dbw.Backend, seam, err2)
	}
	if result2.MFASecretsSwept != 1 || result2.DynamicSecretConfigsSwept != 1 || result2.DynamicSecretLeasesSwept != 1 {
		t.Fatalf("[%s] CONVERGENCE: op=upgrade-aad seam=%q re-run swept counts %+v, want all 3 seeded rows swept", dbw.Backend, seam, result2)
	}
	checkAuthWorldAADRowsDecryptable(t, w, dbw.Backend, seam)

	if hits := scanForPlaintext(w.dir, []byte(canary)); len(hits) > 0 {
		t.Fatalf("[%s] PLAINTEXT SPILL: op=upgrade-aad seam=%q canary found in: %v", dbw.Backend, seam, hits)
	}
}

// checkAuthWorldAADRowsDecryptable re-reads all three AAD-swept seed rows and
// confirms each still decrypts to its known plaintext — DecryptSecretWithAAD
// transparently falls back to the legacy (no-AAD) path, so this is correct
// whether or not the sweep actually upgraded that particular row (oracle 1:
// old-or-new, never neither).
func checkAuthWorldAADRowsDecryptable(t *testing.T, w *authWorld, backend, seam string) {
	var mfa models.MFASecret
	if e := w.db.First(&mfa, "user_id = ?", 1).Error; e != nil {
		t.Fatalf("[%s] DATA LOSS: op=upgrade-aad seam=%q mfa_secrets row missing: %v", backend, seam, e)
	}
	got, derr := w.svc.DecryptSecretWithAAD(mfa.SecretEnc, MFASecretAAD(1))
	if derr != nil || !bytes.Equal(got, []byte("TOTP-"+w.canary)) {
		t.Fatalf("[%s] AVAILABILITY: op=upgrade-aad seam=%q mfa_secrets row no longer decrypts: err=%v", backend, seam, derr)
	}

	var cfgRow models.DynamicSecretConfig
	if e := w.db.First(&cfgRow, "name = ?", "seed-cfg").Error; e != nil {
		t.Fatalf("[%s] DATA LOSS: op=upgrade-aad seam=%q dynamic_secret_configs row missing: %v", backend, seam, e)
	}
	got, derr = w.svc.DecryptSecretWithAAD(cfgRow.AdminDSNEnc, DynamicSecretConfigAAD(cfgRow.ID, 1, 2))
	if derr != nil || !bytes.Equal(got, []byte("postgres://admin:pw@db/DSN-"+w.canary)) {
		t.Fatalf("[%s] AVAILABILITY: op=upgrade-aad seam=%q dynamic_secret_configs row no longer decrypts: err=%v", backend, seam, derr)
	}

	var lease models.DynamicSecretLease
	if e := w.db.First(&lease, "lease_id = ?", "seed-lease-"+w.canary).Error; e != nil {
		t.Fatalf("[%s] DATA LOSS: op=upgrade-aad seam=%q dynamic_secret_leases row missing: %v", backend, seam, e)
	}
	got, derr = w.svc.DecryptSecretWithAAD(lease.CredentialEnc, DynamicSecretLeaseAAD("seed-lease-"+w.canary, 9))
	if derr != nil || !bytes.Equal(got, []byte(`{"user":"x","pass":"CRED-`+w.canary+`"}`)) {
		t.Fatalf("[%s] AVAILABILITY: op=upgrade-aad seam=%q dynamic_secret_leases row no longer decrypts: err=%v", backend, seam, derr)
	}
}

// ── B3: auth-encryption migrate ──────────────────────────────────────────────

// migratePasswordResetTokensForTest mirrors encryptionops.MigratePasswordResetTokens
// exactly (same query, same per-row EncryptPasswordResetToken-then-null-out
// Updates call) — the real function lives in internal/encryptionops, which
// imports this package, so this test file cannot import it back (the same cycle
// constraint the package doc comment's "secret-CRUD world" section explains for
// core.CreateSecret).
func migratePasswordResetTokensForTest(db *gorm.DB, svc *Service) error {
	var resets []models.PasswordReset
	if err := db.Where("token != '' AND encrypted_token IS NULL").Find(&resets).Error; err != nil {
		return err
	}
	for _, reset := range resets {
		enc, meta, err := svc.EncryptSecretWithAAD([]byte(reset.Token), PasswordResetTokenAAD(reset.UserID))
		if err != nil {
			return fmt.Errorf("failed to encrypt password reset token %d: %w", reset.ID, err)
		}
		if err := db.Model(&reset).Updates(map[string]any{
			"encrypted_token": enc,
			"token_metadata":  meta,
			"token":           nil,
		}).Error; err != nil {
			return fmt.Errorf("failed to update password reset token %d: %w", reset.ID, err)
		}
	}
	return nil
}

func runAuthMigrateFaultCase(t *testing.T, dbw *fuzzworld.World, seam, canary string) {
	w := newAuthWorld(t, dbw, canary)

	restore := armSQLUpdateFault(w.db, seam)
	err := migratePasswordResetTokensForTest(w.db, w.svc)
	restore()

	if err == nil {
		t.Fatalf("[%s] HARNESS/oracle-c: op=auth-migrate seam=%q fault did not fire — the migration returned nil error", dbw.Backend, seam)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("[%s] ERROR HYGIENE: op=auth-migrate seam=%q error leaks plaintext canary: %v", dbw.Backend, seam, err)
	}

	// oracle 1 (availability): every SQL seam in this file's catalog is a
	// "clean" fault (the before_update hook stops the statement before it ever
	// runs — see the package doc comment's ambiguity classification for
	// armSQLFault's Create/Delete siblings; armSQLUpdateFault uses the identical
	// mechanism), so the row must still hold its ORIGINAL plaintext token,
	// untouched — never a row with neither a plaintext nor an encrypted value.
	var reset models.PasswordReset
	if e := w.db.First(&reset, "user_id = ?", 1).Error; e != nil {
		t.Fatalf("[%s] DATA LOSS: op=auth-migrate seam=%q password_resets row missing: %v", dbw.Backend, seam, e)
	}
	if reset.Token == "" && len(reset.EncryptedToken) == 0 {
		t.Fatalf("[%s] DATA LOSS: op=auth-migrate seam=%q password_resets row has NEITHER a plaintext token NOR an encrypted one — the value is gone", dbw.Backend, seam)
	}
	if reset.Token != "" && reset.Token != "RESET-"+canary {
		t.Fatalf("[%s] DATA CORRUPTION: op=auth-migrate seam=%q surviving plaintext token changed: got %q", dbw.Backend, seam, reset.Token)
	}

	// oracle 2 (idempotent convergence): a clean re-run finishes the migration.
	if err2 := migratePasswordResetTokensForTest(w.db, w.svc); err2 != nil {
		t.Fatalf("[%s] CONVERGENCE: op=auth-migrate seam=%q re-run after the fault failed: %v", dbw.Backend, seam, err2)
	}
	var reset2 models.PasswordReset
	if e := w.db.First(&reset2, "user_id = ?", 1).Error; e != nil {
		t.Fatalf("[%s] DATA LOSS: op=auth-migrate seam=%q post-convergence row missing: %v", dbw.Backend, seam, e)
	}
	if reset2.Token != "" || len(reset2.EncryptedToken) == 0 {
		t.Fatalf("[%s] CONVERGENCE: op=auth-migrate seam=%q re-run did not reach the fully-migrated end state (token=%q encrypted_len=%d)", dbw.Backend, seam, reset2.Token, len(reset2.EncryptedToken))
	}
	got, derr := w.svc.DecryptSecretWithAAD(reset2.EncryptedToken, PasswordResetTokenAAD(reset2.UserID))
	if derr != nil || string(got) != "RESET-"+canary {
		t.Fatalf("[%s] CONVERGENCE: op=auth-migrate seam=%q post-convergence encrypted token does not decrypt correctly: err=%v", dbw.Backend, seam, derr)
	}

	if hits := scanForPlaintext(w.dir, []byte(canary)); len(hits) > 0 {
		t.Fatalf("[%s] PLAINTEXT SPILL: op=auth-migrate seam=%q canary found in: %v", dbw.Backend, seam, hits)
	}
}

// ── B3: migrate-provider (backup + restore-on-verification-failure) ─────────

// migrateCopyFile mirrors encryptionops.CopyFile's content-write step for
// fault-injection purposes — the real function lives in internal/encryptionops,
// which this package cannot import back (same cycle constraint as
// migratePasswordResetTokensForTest above). Reads srcRel for real (SafeReadFile
// is not itself the durability risk under test) and writes dstRel via
// durableWriteSync at seam, matching CopyFile's own O_TRUNC-then-fsync content
// write; CopyFile's own trailing directory fsync is not separately modeled here,
// mirroring opBackup's existing choice (above) to cover only the content-write
// seam for its own single-write primitive.
func migrateCopyFile(baseDir, srcRel, dstRel, seam string) error {
	data, err := securefiles.SafeReadFile(baseDir, srcRel)
	if err != nil {
		return err
	}
	return durableWriteSync(baseDir, dstRel, data, 0600, seam)
}

// runMigrateProviderBackupFaultCase targets the two durability steps unique to
// `migrate-provider` (the backup copy before re-wrapping, and the restore copy
// on verification failure). The re-wrap itself (Service.RewrapDEKWithProvider →
// KeyManager.RewrapDEK) is the IDENTICAL function runRewrapFaultCase above
// already exhaustively fault-tests — re-faulting it here would duplicate, not
// extend, coverage (see the package doc comment's "B3 encryption-family
// extension" section), so it always runs for real in this case.
func runMigrateProviderBackupFaultCase(t *testing.T, seam string, ff *fileFault, oldPass string) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	if err := svc.Initialize(oldPass); err != nil {
		t.Fatalf("seed Initialize(old=%q): %v", oldPass, err)
	}
	dek0 := append([]byte(nil), svc.keyManager.GetDEK()...)

	probe := []byte("MIGRATE-PROBE-" + oldPass)
	probeCT, _, perr := svc.EncryptSecret(probe)
	if perr != nil {
		t.Fatalf("seed probe encrypt: %v", perr)
	}

	backupRel := "dek.key.migrate-backup.test"

	if seam == "migrate:backup-write" {
		restore := armFileFault(seam, ff)
		backupErr := migrateCopyFile(dir, "dek.key", backupRel, seam)
		restore()

		// oracle (c): a faulted backup must report failure, never silent success.
		if backupErr == nil {
			t.Fatalf("HARNESS/oracle-c: op=migrate-provider seam=%q fault did not fire — backup copy returned nil error", seam)
		}
		if strings.Contains(backupErr.Error(), oldPass) {
			t.Fatalf("ERROR HYGIENE: op=migrate-provider seam=%q error leaks the passphrase: %v", seam, backupErr)
		}
		// Production behavior (MigrateProviderWithConfig): a backup-write failure
		// aborts BEFORE any rewrap is attempted — the real code path never reaches
		// the rewrap call on this error, so the DEK must be completely untouched
		// (deterministic, not merely "old or new").
		svc2 := NewService(cfg, dir)
		if err := svc2.Initialize(oldPass); err != nil {
			t.Fatalf("AVAILABILITY: op=migrate-provider seam=%q old provider can no longer open the DEK after an aborted backup: %v", seam, err)
		}
		if !bytes.Equal(svc2.keyManager.GetDEK(), dek0) {
			t.Fatalf("DEK CORRUPTION: op=migrate-provider seam=%q DEK changed despite an aborted (pre-rewrap) backup failure", seam)
		}
		got, derr := svc2.DecryptSecret(probeCT)
		if derr != nil || !bytes.Equal(got, probe) {
			t.Fatalf("AVAILABILITY: op=migrate-provider seam=%q probe no longer decrypts under the old provider after an aborted backup: err=%v", seam, derr)
		}
		if hits := scanForPlaintext(dir, probe); len(hits) > 0 {
			t.Fatalf("PLAINTEXT SPILL: op=migrate-provider seam=%q probe found on disk: %v", seam, hits)
		}
		return
	}

	// seam == "migrate:restore-write": run the backup for real (unfaulted).
	if err := migrateCopyFile(dir, "dek.key", backupRel, "migrate:backup-write"); err != nil {
		t.Fatalf("harness: unfaulted backup copy failed: %v", err)
	}

	// A TARGET "file" provider with REAL key material, so the rewrap itself
	// succeeds (RewrapDEK's own KEK() call needs to read real bytes) — matching
	// production, where rewrap and verification are the same provider reading
	// the same file, so verification cannot fail independently of rewrap unless
	// something changes the key material in between. Removing the file AFTER a
	// successful rewrap but BEFORE verification models exactly that: real-world
	// causes include an exec/KMS-backed provider flaking transiently, or (for a
	// file provider specifically) the file being on removable/network storage
	// that drops between the two calls.
	tgtFilePath := filepath.Join(dir, "target-key-material")
	if err := os.WriteFile(tgtFilePath, bytes.Repeat([]byte{0x42}, 32), 0600); err != nil { // #nosec G306 -- test-only harness temp file
		t.Fatalf("harness: writing target key material: %v", err)
	}
	tgtCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt",
		KeyProvider: config.KeyProviderConfig{Type: "file", FilePath: tgtFilePath}}
	newProvider, nperr := NewKeyProviderFromConfig(tgtCfg, dir, "")
	if nperr != nil {
		t.Fatalf("harness: building target provider: %v", nperr)
	}

	// The real re-wrap — unfaulted, see the function doc comment above.
	if err := svc.RewrapDEKWithProvider(newProvider); err != nil {
		t.Fatalf("harness: real rewrap failed unexpectedly: %v", err)
	}

	// Sabotage: the target key material disappears between rewrap and
	// verification, forcing MigrateProviderWithConfig's real
	// verification-failure → restore path.
	if err := os.Remove(tgtFilePath); err != nil {
		t.Fatalf("harness: removing target key material: %v", err)
	}
	verifySvc := NewService(tgtCfg, dir)
	if err := verifySvc.Initialize(""); err == nil {
		t.Fatalf("harness: expected verification to fail (target key material removed), got nil")
	}

	restore := armFileFault(seam, ff)
	restoreErr := migrateCopyFile(dir, backupRel, "dek.key", seam)
	restore()

	if restoreErr == nil {
		t.Fatalf("HARNESS/oracle-c: op=migrate-provider seam=%q fault did not fire — restore copy returned nil error", seam)
	}
	if strings.Contains(restoreErr.Error(), oldPass) {
		t.Fatalf("ERROR HYGIENE: op=migrate-provider seam=%q error leaks the passphrase: %v", seam, restoreErr)
	}

	// oracle 1 (availability): the doc comment's own crash-safety claim is that
	// "at worst an operator must manually restore backupRel ... using the
	// printed filename" — so the one thing that must be true regardless of the
	// restore fault's outcome is that the BACKUP FILE ITSELF survives, intact
	// and independently recoverable under the OLD passphrase, for that manual
	// recovery to actually be possible.
	recoverKM := NewKeyManager(dir, backupRel, "kek.salt")
	recoverKM.SetKeyProvider(crypto.NewPasswordKeyProvider(oldPass, dir, "kek.salt"))
	if err := recoverKM.Initialize(oldPass); err != nil {
		t.Fatalf("DATA LOSS: op=migrate-provider seam=%q backup file at %s does not unwrap under the original passphrase after a faulted restore: %v", seam, backupRel, err)
	}
	if !bytes.Equal(recoverKM.GetDEK(), dek0) {
		t.Fatalf("DEK CORRUPTION: op=migrate-provider seam=%q backup file's DEK != original", seam)
	}

	if hits := scanForPlaintext(dir, probe); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: op=migrate-provider seam=%q probe found on disk: %v", seam, hits)
	}
}

// ── seed-reach guard (ported from #2053) ─────────────────────────────────────
//
// decodeFault selecting seam X and seam X's hook actually being consulted by
// production code are two different claims. This guard checks the second one
// directly, so a refactor that silently stops calling a seam (a code path
// rerouted around durableWriteSync, say) fails CI here even if every oracle
// still happens to pass.

var (
	seamHitMu    sync.Mutex
	seamHitCount = map[string]int{}
)

// recordSeamHit is called by the arm*Fault hooks only when the seam they were
// armed for is consulted by real production code, never merely when a case is
// selected.
func recordSeamHit(seam string) {
	seamHitMu.Lock()
	seamHitCount[seam]++
	seamHitMu.Unlock()
}

func resetSeamHitCounts() {
	seamHitMu.Lock()
	seamHitCount = map[string]int{}
	seamHitMu.Unlock()
}

func seamHits(seam string) int {
	seamHitMu.Lock()
	defer seamHitMu.Unlock()
	return seamHitCount[seam]
}

type faultSeedTriple struct {
	opSel, seamSel, kindSel byte
}

// allFaultInjectedSeedTriples enumerates one (op, seam, kind) triple per
// combination decodeFault can produce. FuzzFaultInjectedOperations seeds from
// it and TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam replays it,
// so the two cannot drift apart.
func allFaultInjectedSeedTriples() []faultSeedTriple {
	var triples []faultSeedTriple
	for opSel := range int(numOps) {
		for seamSel := range opSeams[opID(opSel)] {
			for kindSel := range 2 {
				triples = append(triples, faultSeedTriple{byte(opSel), byte(seamSel), byte(kindSel)})
			}
		}
	}
	return triples
}

// TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam replays the committed
// seed set through the same case runner the fuzz target uses and asserts that
// every seam declared in opSeams was consulted by production code at least
// once. A dead seed fails here instead of silently contributing zero coverage.
func TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam(t *testing.T) {
	resetSeamHitCounts()

	dbWorlds := fuzzworld.Worlds(t, "faultopsfuzzreachguard", ":memory:", 0)
	for _, s := range allFaultInjectedSeedTriples() {
		runFaultInjectedCase(t, dbWorlds, s.opSel, s.seamSel, s.kindSel, 3, "old-pass", "new-pass", "secret-val")
	}

	for op, seams := range opSeams {
		for _, s := range seams {
			if s.kind == seamCombined {
				// The combined case fires two sub-seam labels via
				// armMultiFileFault, never its own label.
				for _, sub := range []string{"kek:rename-dek", "kek:verify-rename-dek"} {
					if seamHits(sub) == 0 {
						t.Errorf("DEAD SEED: op=%v combined seam %q: sub-seam %q was never consulted by production code", op, s.label, sub)
					}
				}
				continue
			}
			if seamHits(s.label) == 0 {
				t.Errorf("DEAD SEED: op=%v seam %q was never consulted by production code", op, s.label)
			}
		}
	}
}
