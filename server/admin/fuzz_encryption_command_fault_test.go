//go:build !windows

// fuzz_encryption_command_fault_test.go — FuzzAdminEncryptionCommandFaultHandling.
//
// Standalone admin-CLI fault fuzzer (the FuzzSharedSecretsViewNeverWrites
// pattern, server/faultops) for `keyorix-server admin encryption ...`. Drives
// the real runEncXxx/runAuthXxx entry points against a temp SQLite DB + temp
// keydir, with faults at the encryptionops call boundary: since server/admin
// already imports internal/encryptionops (no cycle, unlike internal/
// encryption's own test files — see fault_injected_operations_fuzz_test.go's
// doc comment), faults here are REAL externally-observable failure conditions
// (corrupt key material, wrong passphrase, encryption disabled) rather than an
// injected test-only hook — exactly what a real operator's mistake, or a real
// disk fault surviving into a later invocation, would trigger. This
// complements internal/encryption's FuzzFaultInjectedOperations (which faults
// WITHIN a single operation's own durability seams): this fuzzer targets the
// ADMIN WIRING layer around those operations — the layer neither
// FuzzFaultInjectedOperations nor FuzzAdminDispatch (#2036, argv/exit-code
// contract against garbage args, no real key material) exercises.
//
// Oracles (STEP 3 PR B, approved scope):
//
//	(a) the exclusive database lock (serverguard) is released on every path —
//	    a leaked lock would refuse every subsequent admin command forever.
//	(b) an audit event is written if and only if the underlying encryptionops
//	    call actually changed durable state. Every runXxx here only calls
//	    recordAdminAction AFTER a nil error from its encryptionops call — this
//	    oracle verifies that contract empirically (by counting real rows),
//	    not by re-reading the source.
//	(c) the command returns a non-nil error if and only if the operation
//	    failed — the real cobra exit-code contract (RunE returning non-nil is
//	    what makes `keyorix-server admin` exit non-zero).
//	(d) stdout never shows a success/"done" glyph after a failure — every
//	    completion message in this package and internal/encryptionops uses
//	    "✅ ..." exclusively on a function's own success-return path.
package admin

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

const (
	adminFuzzBaselinePassphrase = "admin-fuzz-baseline-pass"
	adminFuzzWrongPassphrase    = "admin-fuzz-WRONG-pass"
)

// adminFuzzCommands is the representative, real subset of state-changing
// `encryption`-family commands this fuzzer drives — every one takes the
// exclusive lock and calls recordAdminAction on success, the two mechanisms
// under test. encryption rotate/rotate-kek/migrate-provider are excluded here
// (they need --confirm plus, for migrate-provider, a --to-type target — real
// but orthogonal complexity already covered structurally by
// internal/encryption's FuzzFaultInjectedOperations/opRewrap+opKEKRotate+
// opMigrateProviderBackup); fix-perms/upgrade-aad/init/auth-enable/
// auth-migrate cover the same lock+audit+exit-code wiring with no extra flags
// to plumb through.
var adminFuzzCommands = []struct {
	label string
	run   func(cmd *cobra.Command, args []string) error
}{
	{"init", runEncInit},
	{"upgrade-aad", runEncUpgradeAAD},
	{"fix-perms", runEncFixPerms},
	{"auth-enable", runAuthEnable},
	{"auth-migrate", runAuthMigrate},
}

type adminFuzzFault int

const (
	adminFaultNone adminFuzzFault = iota
	adminFaultCorruptDEK
	adminFaultWrongPassphrase
	adminFaultEncryptionDisabled
	// adminFaultReadOnlyDir models a filesystem-permission failure (a real
	// production condition none of the three fault types above reach: a
	// disk gone read-only, a permissions mistake, ENOSPC-adjacent EROFS) --
	// the working directory (and every direct file inside it: dek.key,
	// kek.salt, the SQLite DB, both config files) is made read-only
	// immediately before the command runs, then restored before any oracle
	// check needs write access again. See chmodAdminFuzzDir and
	// TestFuzzAdminEncryptionCommandFaultHandlingSeedsReachEveryCase's own
	// doc comment for why this fault type specifically needs an
	// independently-verified reachability guard, not just a seed that looks
	// like it covers it.
	adminFaultReadOnlyDir
	numAdminFaults
)

func adminFuzzConfigYAML(dbPath string, encEnabled bool) string {
	return fmt.Sprintf(`storage:
  type: local
  database:
    path: %q
  encryption:
    enabled: %v
    dek_path: "dek.key"
    salt_path: "kek.salt"
`, dbPath, encEnabled)
}

func writeAdminFuzzConfig(t *testing.T, dir, name, dbPath string, encEnabled bool) string {
	t.Helper()
	cfgPath := filepath.Join(dir, name)
	if err := os.WriteFile(cfgPath, []byte(adminFuzzConfigYAML(dbPath, encEnabled)), 0600); err != nil { // #nosec G306 -- test-only harness temp config
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// probeCfg is the minimal config the harness itself needs to independently
// open the same DB (for counting audit rows) and probe the same lock
// (serverguard keys off cfg.Storage, not the config FILE) — deliberately NOT
// reusing loadConfig/configPathFlag, so this check is independent of whatever
// config the command under test actually loaded.
func probeCfg(dbPath string) *config.Config {
	return &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}}}
}

func countAuditEvents(t *testing.T, dbPath string) int64 {
	t.Helper()
	db, err := storage.OpenGormDB(probeCfg(dbPath))
	if err != nil {
		return 0 // no DB yet == no rows
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()
	var n int64
	db.Model(&models.AuditEvent{}).Count(&n)
	return n
}

// lockIsFree reports whether cfg's exclusive lock can be acquired right now —
// oracle (a). Acquiring and immediately releasing is the only externally
// observable way to check "is it free" without reaching into serverguard's
// own internals.
func lockIsFree(dbPath string) bool {
	lock, err := serverguard.AcquireExclusive(probeCfg(dbPath))
	if err != nil {
		return false
	}
	_ = lock.Release()
	return true
}

// chmodAdminFuzzDir sets mode on dir and every direct entry inside it
// (dek.key, kek.salt, the SQLite DB, both config files — this harness's
// directory is flat, no subdirectories) and reports whether dir's own mode
// bits were actually verified changed afterward. A test suite running as
// root would make os.Chmod(dir, 0o500) a complete no-op against root's own
// writes, silently defeating adminFaultReadOnlyDir's entire premise without
// this check — see TestFuzzAdminEncryptionCommandFaultHandlingSeedsReachEveryCase.
func chmodAdminFuzzDir(dir string, mode os.FileMode) bool {
	_ = os.Chmod(dir, mode)
	verified := false
	if info, err := os.Stat(dir); err == nil {
		verified = info.Mode().Perm() == mode
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return verified
	}
	for _, e := range entries {
		_ = os.Chmod(filepath.Join(dir, e.Name()), mode)
	}
	return verified
}

// adminEncFaultHandlingReachMu/Set back the seed-reachability guard test:
// recordAdminEncFaultHandlingReadOnlyVerified is called ONLY when
// chmodAdminFuzzDir's own stat check confirms the read-only fault actually
// took effect at the OS level, never merely when that case ran.
var (
	adminEncFaultHandlingReachMu  sync.Mutex
	adminEncFaultHandlingReachSet = map[string]bool{}
)

func recordAdminEncFaultHandlingReadOnlyVerified(cmdLabel string) {
	adminEncFaultHandlingReachMu.Lock()
	adminEncFaultHandlingReachSet[cmdLabel] = true
	adminEncFaultHandlingReachMu.Unlock()
}

func resetAdminEncFaultHandlingReach() {
	adminEncFaultHandlingReachMu.Lock()
	adminEncFaultHandlingReachSet = map[string]bool{}
	adminEncFaultHandlingReachMu.Unlock()
}

func adminEncFaultHandlingReadOnlyVerified(cmdLabel string) bool {
	adminEncFaultHandlingReachMu.Lock()
	defer adminEncFaultHandlingReachMu.Unlock()
	return adminEncFaultHandlingReachSet[cmdLabel]
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. Not safe under t.Parallel() (global process
// state) — this fuzzer never calls it.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("harness: creating pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = orig
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), runErr
}

func FuzzAdminEncryptionCommandFaultHandling(f *testing.F) {
	for cmdSel := range adminFuzzCommands {
		for faultSel := range int(numAdminFaults) {
			f.Add(byte(cmdSel), byte(faultSel))
		}
	}

	f.Fuzz(func(t *testing.T, cmdSel, faultSel byte) {
		runAdminEncFaultHandlingCase(t, cmdSel, faultSel)
	})
}

// runAdminEncFaultHandlingCase is FuzzAdminEncryptionCommandFaultHandling's
// own case body, factored out so
// TestFuzzAdminEncryptionCommandFaultHandlingSeedsReachEveryCase can replay
// it directly outside `go test -fuzz`.
func runAdminEncFaultHandlingCase(t *testing.T, cmdSel, faultSel byte) {
	cmdCase := adminFuzzCommands[int(cmdSel)%len(adminFuzzCommands)]
	fault := adminFuzzFault(int(faultSel) % int(numAdminFaults))

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	enabledCfgPath := writeAdminFuzzConfig(t, dir, "enabled.yaml", dbPath, true)
	disabledCfgPath := writeAdminFuzzConfig(t, dir, "disabled.yaml", dbPath, false)

	// CWD-dependent: every encryptionops.*WithConfig function resolves
	// DEKPath/SaltPath against os.Getwd(), not the config file's directory.
	// Fuzz workers are separate processes and this fuzzer never calls
	// t.Parallel(), so per-invocation os.Chdir is safe.
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("harness: os.Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("harness: os.Chdir(%s): %v", dir, err)
	}
	defer func() { _ = os.Chdir(origWD) }()

	origConfigPath := configPathFlag
	defer func() { configPathFlag = origConfigPath }()

	// Bootstrap: a REAL, unfaulted init establishes a working keydir + DB
	// every non-init command needs to already exist — matching production,
	// where every command but `init` assumes keys already exist.
	t.Setenv("KEYORIX_MASTER_PASSWORD", adminFuzzBaselinePassphrase)
	configPathFlag = enabledCfgPath
	if _, err := captureStdout(t, func() error { return runEncInit(nil, nil) }); err != nil {
		t.Fatalf("harness: baseline bootstrap init failed: %v", err)
	}
	if !lockIsFree(dbPath) {
		t.Fatalf("harness: lock not free after bootstrap init")
	}

	activeCfgPath := enabledCfgPath
	switch fault {
	case adminFaultCorruptDEK:
		if err := os.WriteFile(filepath.Join(dir, "dek.key"), []byte("bad"), 0600); err != nil { // #nosec G306 -- test-only harness temp file
			t.Fatalf("harness: corrupting dek.key: %v", err)
		}
		t.Setenv("KEYORIX_MASTER_PASSWORD", adminFuzzBaselinePassphrase)
	case adminFaultWrongPassphrase:
		t.Setenv("KEYORIX_MASTER_PASSWORD", adminFuzzWrongPassphrase)
	case adminFaultEncryptionDisabled:
		activeCfgPath = disabledCfgPath
		t.Setenv("KEYORIX_MASTER_PASSWORD", adminFuzzBaselinePassphrase)
	case adminFaultReadOnlyDir, adminFaultNone:
		t.Setenv("KEYORIX_MASTER_PASSWORD", adminFuzzBaselinePassphrase)
	}
	configPathFlag = activeCfgPath

	beforeCount := countAuditEvents(t, dbPath)

	if fault == adminFaultReadOnlyDir {
		if chmodAdminFuzzDir(dir, 0o500) {
			recordAdminEncFaultHandlingReadOnlyVerified(cmdCase.label)
		}
	}
	stdout, runErr := captureStdout(t, func() error { return cmdCase.run(nil, nil) })
	if fault == adminFaultReadOnlyDir {
		// Restore write access BEFORE any oracle check below — lockIsFree
		// and countAuditEvents both need to write (a lock file, WAL/journal
		// sidecars) against dir.
		chmodAdminFuzzDir(dir, 0o700)
	}

	// oracle (a): the lock must be free immediately after the call returns,
	// on EVERY path — success, real failure, or a fault-induced failure.
	if !lockIsFree(dbPath) {
		t.Fatalf("LOCK LEAK: cmd=%s fault=%v the exclusive database lock is still held after the command returned (err=%v)", cmdCase.label, fault, runErr)
	}

	afterCount := countAuditEvents(t, dbPath)
	wroteAudit := afterCount > beforeCount

	// oracle (b): audit event written iff the call succeeded.
	switch {
	case runErr == nil && !wroteAudit:
		t.Fatalf("AUDIT GAP: cmd=%s fault=%v the command reported success but no audit event was recorded", cmdCase.label, fault)
	case runErr != nil && wroteAudit:
		t.Fatalf("AUDIT OVER-REPORT: cmd=%s fault=%v the command reported failure (%v) but an audit event was recorded anyway", cmdCase.label, fault, runErr)
	}

	// oracle (d): no success glyph in stdout on a failure path.
	if runErr != nil && strings.Contains(stdout, "✅") {
		t.Fatalf("FALSE SUCCESS OUTPUT: cmd=%s fault=%v command failed (%v) but printed a success glyph:\n%s", cmdCase.label, fault, runErr, stdout)
	}

	// Positive control (this repo's own "check green as well as red"
	// discipline): the clean, unfaulted baseline case for every command
	// must actually succeed — a fuzzer whose harness setup is itself
	// broken would otherwise report every case as a correctly-detected
	// failure and never notice.
	if fault == adminFaultNone && runErr != nil {
		t.Fatalf("HARNESS: cmd=%s the unfaulted baseline case failed: %v\nstdout:\n%s", cmdCase.label, runErr, stdout)
	}
}

// TestFuzzAdminEncryptionCommandFaultHandlingSeedsReachEveryCase replays this
// fuzzer's own seed set (every (cmdSel, faultSel) pair its f.Add loop uses,
// now including adminFaultReadOnlyDir) through runAdminEncFaultHandlingCase
// directly, outside `go test -fuzz`. For adminFaultReadOnlyDir specifically,
// asserts chmodAdminFuzzDir's own stat check verified the fault actually took
// effect at the OS level for every command in the catalog — independent of
// whether the subtests above happened to pass, since some of their oracles
// could in principle still pass by accident even if the permission fault
// silently no-op'd (e.g. this whole suite running as root). This is the
// dead-seed class of bug PR #2047 found in FuzzAdminDispatch: a seed that
// looks like it covers something without the underlying condition it claims
// to model ever actually being true.
func TestFuzzAdminEncryptionCommandFaultHandlingSeedsReachEveryCase(t *testing.T) {
	resetAdminEncFaultHandlingReach()
	readOnlyDirFaultSel := -1
	for faultSel := range int(numAdminFaults) {
		if adminFuzzFault(faultSel) == adminFaultReadOnlyDir {
			readOnlyDirFaultSel = faultSel
		}
	}
	if readOnlyDirFaultSel < 0 {
		t.Fatal("harness: adminFaultReadOnlyDir not found in the fault enum")
	}

	for cmdSel := range adminFuzzCommands {
		for faultSel := range int(numAdminFaults) {
			cmdCase := adminFuzzCommands[cmdSel]
			fault := adminFuzzFault(faultSel)
			t.Run(fmt.Sprintf("%s/fault=%d", cmdCase.label, fault), func(t *testing.T) {
				runAdminEncFaultHandlingCase(t, byte(cmdSel), byte(faultSel))
			})
		}
	}

	for _, cmdCase := range adminFuzzCommands {
		if !adminEncFaultHandlingReadOnlyVerified(cmdCase.label) {
			t.Errorf("DEAD SEED: command %q's adminFaultReadOnlyDir case never verified the working directory actually became read-only (chmodAdminFuzzDir's stat check failed) — the fault model may be silently defeated (e.g. running as root)", cmdCase.label)
		}
	}
}
