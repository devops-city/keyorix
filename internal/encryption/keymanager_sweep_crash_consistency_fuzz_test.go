//go:build !windows

package encryption

// keymanager_sweep_crash_consistency_fuzz_test.go — FuzzDEKSweepCrashConsistency.
//
// Phase 3 of the rotation crash-consistency spec: crash-consistency fuzzing of a true
// DEK rotation with a full re-encryption sweep (RotateDEKWithSweep, ADR-010). Unlike
// RewrapDEK (same DEK, new wrapping — a one-file swap) this generates a BRAND-NEW DEK and
// re-encrypts every DEK-encrypted DB row under it, then atomically promotes the new DEK
// file. The durable steps are, in order:
//
//   1. write keys/dek.key.pending          (new DEK, KEK-wrapped)              [file]
//   2. sweepFn → BEGIN … re-encrypt rows … COMMIT   (rows now new-DEK)         [DB, durable]
//   3. rename dek.key.pending → dek.key     (active DEK now the new one)        [file]
//   4. fsync the key directory              (rename durable)                    [file]
//
// A process crash (power loss, SIGKILL, OOM) between any two of those leaves an
// intermediate on-disk + in-DB state. On restart the server/CLI runs CleanPendingDEK()
// (which unconditionally REMOVES dek.key.pending as a leftover) and loads the active
// dek.key. This target interrupts the REAL RotateDEKWithSweep at each checkpoint (via the
// nil-in-prod rotationCheckpoint seam, labels "sweep:..."), simulates that recovery, and
// asserts:
//
//   - AVAILABILITY (no data loss): every seeded secret row still decrypts to its ORIGINAL
//     plaintext under the recovered active DEK. A committed row that no longer decrypts
//     under any recoverable key is permanent data loss — never acceptable for a secrets
//     store, so this is asserted at EVERY crash point (it admits no legitimate exception).
//   - VALUE INTEGRITY: a recovered row equals its original plaintext byte-for-byte, never
//     a silently-different value.
//   - CONFIDENTIALITY (retire the old DEK): after a COMPLETED rotation the old DEK must no
//     longer decrypt the rows. Only this deny direction, only on completion.
//
// Sound: the seeded plaintexts are known, so recovery either yields them or does not — no
// "must succeed" direction is asserted against the transport. The DB is in-memory SQLite by
// default (the same dialect sweep_test.go uses), so the whole thing is CI-runnable with no
// external dependency; the committed rows survive the simulated (panic) crash because the
// in-memory DB handle outlives it, exactly as a real on-disk DB's committed rows would.
// PostgreSQL runs too whenever KEYORIX_TEST_PG_DSN is set (see internal/testutil/fuzzworld) — this is
// the one member of the crash-consistency trilogy with a real DB transaction in its
// durability model (RotateDEKWithSweep's sweepFn does BEGIN…re-encrypt…COMMIT around the
// re-encryption sweep, service_rotation.go), so it's the one where SQLite's single-connection
// semantics could plausibly hide a Postgres-specific transaction-visibility bug the other two
// (pure file/PBKDF2, no database at all) structurally cannot have.
//
// Completes the crash-consistency trilogy: FuzzKEKRotationCrashConsistency (KEK passphrase,
// two-file salt+DEK window) and FuzzDEKRewrapCrashConsistency (KEK-provider migration,
// one-file DEK window) are PURE FILE fuzzers — neither touches a database at all — so neither
// gained a PostgreSQL path; only this one, which actually has one, did.

import (
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// sweepDBTables is the explicit, hand-named set of tables fuzzworld.World.Reset clears between
// fuzz iterations that reuse the same per-worker DB world (see World.Reset's doc
// for why this is a named list, not derived from the migrated model set).
// Dependent-first order: secret_versions before secret_nodes (FK). system_metadata is
// included deliberately — it holds RotateDEKWithSweep's redo marker
// (dekRotationPromotePendingKey, service_rotation.go), and every iteration here
// deliberately crashes mid-rotation; a marker surviving from a PRIOR iteration's crash
// would let the NEXT iteration's RecoverInterruptedRotation see the wrong marker and pass
// its recovery oracle for the wrong reason.
var sweepDBTables = []string{
	"secret_versions", "secret_nodes",
	"sessions", "api_tokens", "api_clients", "password_resets",
	"mfa_secrets", "dynamic_secret_configs", "dynamic_secret_leases",
	"system_metadata",
}

// sweepGuardDeadline is a HANG backstop, not the shared fuzzutil 3s amplification guard.
// A legitimate iteration of this target does a full in-memory DB setup (multi-table migrate)
// + real DEK rotation + full re-encryption sweep + recovery — inherently ~1-2s, and under
// -fuzz coverage instrumentation on a loaded continuous-fuzzing rig it brushes 3s. Unlike its
// file-only sibling crash-consistency targets, this one is DB-backed, and its inputs are
// bounded (crashSel, 1-8 rows, a passphrase, a value prefix) with no untrusted-input-driven
// allocation, so there is no amplification to catch on a tight deadline — only a genuine hang
// (an infinite loop / real blowup), which this generous deadline still flags. See the
// 2026-09-17 rig deploy note.
const sweepGuardDeadline = 30 * time.Second

// sweepCrashLabels are the durability checkpoints RotateDEKWithSweep emits, in order.
// Index 0 ("") means "run to completion, no crash".
var sweepCrashLabels = []string{
	"",                              // no crash — clean rotation
	"sweep:after-write-dek-pending", // pending new-DEK written; DB not yet swept; active=old
	"sweep:after-sweep-commit",      // rows COMMITTED under new DEK; active file STILL old (rename pending)
	"sweep:after-rename-dek",        // active file now new-DEK; dir fsync pending
	"sweep:after-syncdir",           // on-disk rotation complete
}

func FuzzDEKSweepCrashConsistency(f *testing.F) {
	// Built ONCE per testing.F, before f.Fuzz (internal/testutil/fuzzworld) — reopening and
	// migrating a DB per iteration was the dominant per-input cost.
	// SQLite always; PostgreSQL too when KEYORIX_TEST_PG_DSN is set.
	worlds := fuzzworld.Worlds(f, "sweepfuzz", ":memory:", 0) // full production schema (#1947)

	for i := range sweepCrashLabels {
		f.Add(uint8(i), uint8(3), "rotate-passphrase", "secret-value-")
		f.Add(uint8(i), uint8(1), "p", "v")
	}
	f.Add(uint8(2), uint8(5), "\x00\x01", "\xff\xfe") // the commit→rename window, odd inputs

	f.Fuzz(func(t *testing.T, crashSel, nRows uint8, pass, valPrefix string) {
		if pass == "" {
			pass = "seed-passphrase"
		}
		target := sweepCrashLabels[int(crashSel)%len(sweepCrashLabels)]
		rows := int(nRows%8) + 1 // 1..8 seeded rows

		for _, w := range worlds {

			// t.TempDir() must run on the test goroutine, not inside the guard goroutine.
			// A fresh dir PER WORLD PER ITERATION — the key-directory/file layer stays
			// per-iteration (per STEP 2 scope: only the DB becomes per-worker), and each
			// world's crash+recovery run must not see file state a DIFFERENT backend's
			// run left behind in a shared dir.
			dir := tmpDirEnv(t)

			// Local hang backstop with a generous deadline (see sweepGuardDeadline) instead of
			// fuzzutil.Guard's shared 3s, which is tuned for fast file/parse targets. A violation
			// inside runSweepCrashCase is signalled by panic (recovered by the testing framework
			// as a fuzz failure); this goroutine+select only catches a true hang.
			done := make(chan struct{})
			go func() {
				defer close(done)
				runSweepCrashCase(w, dir, pass, valPrefix, rows, target)
			}()
			select {
			case <-done:
			case <-time.After(sweepGuardDeadline):
				t.Fatalf("[%s] dek-sweep-crash-consistency exceeded %s — possible hang", w.Backend, sweepGuardDeadline)
			}
		}
	})
}

type sweepSeededRow struct {
	id     uint
	nodeID uint
	projID uint
	ver    int
	val    string
}

// staticKEKProvider returns a fixed KEK with no PBKDF2. Crash-consistency here is about the
// DEK-file/DB durability ordering (write-pending → sweep-commit → rename → fsync → recover),
// NOT the KDF — so a cheap deterministic KEK is faithful to what the oracle tests and keeps
// each iteration fast. The real derivation is 600k-iteration PBKDF2 (DefaultKEKIterations) and
// this harness runs it ~3× per iteration (seed Initialize + rotation deriveKEK + recovery
// Initialize); on a loaded continuous-fuzzing rig that blew past the 3s fuzzutil.Guard
// deadline and flagged a false "possible amplification or hang" (rig deploy, 2026-09-17).
// A static provider removes that cost and multiplies rig throughput. Both the seed and the
// recovery Service use the SAME provider, so the promoted DEK unwraps under the same KEK.
type staticKEKProvider struct{}

func (staticKEKProvider) KEK() ([]byte, error) {
	k := make([]byte, 32)
	copy(k, "keyorix-dek-sweep-fuzz-static-kek")
	return k, nil
}
func (staticKEKProvider) Name() string { return "test-static" }

// runSweepCrashCase resets w's per-worker DB world to a clean state, seeds an initialized
// Service + a DB of secret rows (encrypted under the original DEK), runs RotateDEKWithSweep
// crashing at target, simulates process recovery (CleanPendingDEK + reload), then asserts
// the availability + value-integrity + confidentiality invariants. It panics on any
// violation — matching this function's pre-existing convention (it has no *testing.T; it
// runs on a bare goroutine under FuzzDEKSweepCrashConsistency's hang guard).
func runSweepCrashCase(w *fuzzworld.World, dir, pass, valPrefix string, rows int, target string) {
	if err := w.Reset(sweepDBTables); err != nil {
		panic(fmt.Sprintf("[%s] reset: %v", w.Backend, err))
	}
	db := w.DB

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	svc.keyManager.SetKeyProvider(staticKEKProvider{}) // cheap KEK — see staticKEKProvider doc
	if e := svc.Initialize(pass); e != nil {
		// A fresh temp dir must always initialize; a failure here is a harness bug.
		panic(fmt.Sprintf("seed Initialize(%q): %v", pass, e))
	}
	dek0 := append([]byte(nil), svc.keyManager.GetDEK()...)
	if len(dek0) == 0 {
		panic("seed DEK is empty")
	}

	// Seed secret rows under the ORIGINAL DEK, each with a distinct plaintext + AAD.
	seeds := make([]sweepSeededRow, 0, rows)
	for i := range rows {
		projID := uint(i + 1)
		node := &models.SecretNode{ProjectID: projID, Name: fmt.Sprintf("node-%d", i), IsSecret: true}
		if e := db.Create(node).Error; e != nil {
			panic(fmt.Sprintf("seed node: %v", e))
		}
		val := fmt.Sprintf("%s%d-%x", valPrefix, i, dek0[:2])
		aad := SecretAAD(node.ID, projID, 1)
		enc, meta, e := svc.EncryptSecretWithAAD([]byte(val), aad)
		if e != nil {
			panic(fmt.Sprintf("seed encrypt: %v", e))
		}
		v := &models.SecretVersion{
			SecretNodeID: node.ID, VersionNumber: 1,
			EncryptedValue: enc, EncryptionMetadata: models.JSON(meta),
		}
		if e := db.Create(v).Error; e != nil {
			panic(fmt.Sprintf("seed version: %v", e))
		}
		seeds = append(seeds, sweepSeededRow{id: v.ID, nodeID: node.ID, projID: projID, ver: 1, val: val})
	}

	// Run the rotation, crashing at target.
	runSweepWithCrash(svc, pass, db, target)
	// Model process death after the crash: release the exclusive key lock the rotate
	// acquired (a real crashed process's OS-held locks are freed on exit). Best-effort.
	svc.Shutdown()

	// RECOVERY: a fresh process over the same key dir + same DB, exactly as server/main.go
	// and the rotate CLI start up — RecoverInterruptedRotation(db) (which promotes the
	// pending DEK when the sweep's redo marker committed, else discards a stray pending),
	// then Initialize().
	rec := NewService(cfg, dir)
	rec.keyManager.SetKeyProvider(staticKEKProvider{}) // same KEK as the seed Service, so the promoted DEK unwraps
	if e := rec.RecoverInterruptedRotation(db); e != nil {
		panic(fmt.Sprintf("RecoverInterruptedRotation after crash %q: %v", target, e))
	}
	if e := rec.Initialize(pass); e != nil {
		panic(fmt.Sprintf("recovery Initialize failed after crash %q: %v", target, e))
	}

	// AVAILABILITY + VALUE INTEGRITY: every committed row must recover to its original
	// plaintext under the recovered active DEK.
	for _, s := range seeds {
		var v models.SecretVersion
		if e := db.First(&v, s.id).Error; e != nil {
			panic(fmt.Sprintf("recovery fetch row %d after crash %q: %v", s.id, target, e))
		}
		aad := SecretAAD(s.nodeID, s.projID, s.ver)
		pt, e := rec.DecryptSecretWithAAD(v.EncryptedValue, aad)
		if e != nil {
			panic(fmt.Sprintf("DATA LOSS after sweep crash %q: committed secret row=%d no longer decrypts under the recovered active DEK: %v",
				target, s.id, e))
		}
		if string(pt) != s.val {
			panic(fmt.Sprintf("VALUE CORRUPTION after sweep crash %q: row=%d recovered %q want %q", target, s.id, pt, s.val))
		}
	}

	// CONFIDENTIALITY: after a COMPLETED rotation the old DEK must not decrypt the rows.
	completed := target == "" || target == "sweep:after-rename-dek" || target == "sweep:after-syncdir"
	if completed && len(seeds) > 0 {
		oldEncSvc, e := NewEncryptionService(dek0)
		if e != nil {
			panic(fmt.Sprintf("build old EncryptionService: %v", e))
		}
		s := seeds[0]
		var v models.SecretVersion
		if e := db.First(&v, s.id).Error; e == nil {
			if enc, e := DeserializeEncryptedData(v.EncryptedValue); e == nil {
				aad := SecretAAD(s.nodeID, s.projID, s.ver)
				if _, e := oldEncSvc.DecryptWithAAD(enc, aad); e == nil {
					panic(fmt.Sprintf("RETIRED-DEK LIVE: the old DEK still decrypts a row after a completed rotation (target=%q)", target))
				}
			}
		}
	}
}

// runSweepWithCrash runs RotateDEKWithSweep, arming the rotationCheckpoint seam to panic
// (simulating an abrupt crash) the moment it reaches `target`. target "" runs to
// completion. A non-sentinel panic — a real bug in the code under test — is re-raised so
// the fuzzer records it.
func runSweepWithCrash(svc *Service, pass string, db *gorm.DB, target string) {
	if target == "" {
		_, _ = svc.RotateDEKWithSweep(pass, db)
		return
	}
	prev := rotationCheckpoint
	rotationCheckpoint = func(label string) {
		if label == target {
			panic(rotationCrash{label})
		}
	}
	defer func() {
		rotationCheckpoint = prev
		if r := recover(); r != nil {
			if _, ok := r.(rotationCrash); ok {
				return // our simulated crash — the on-disk + in-DB state is what we test
			}
			panic(r) // a genuine panic in the code under test — let the fuzzer see it
		}
	}()
	_, _ = svc.RotateDEKWithSweep(pass, db)
}
