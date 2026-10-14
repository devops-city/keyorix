// audit_offline_anchor_test.go covers the CLI/config wiring this file's
// sibling audit_export_checkpoint.go/audit_verify.go add for ADR-108 §B4's
// offline anchor source (docs/design-b4-offline-audit-verify.md §10 Q5):
// resolveOfflineAnchorPath's config fallback, and the end-to-end
// export-checkpoint -> offline anchor file -> verify-audit round trip. The
// bundle-level authentication logic itself (tampered signature, wrong
// verifier key, truncation-after-export) is already covered by
// internal/auditverify's own differential tests
// (TestDifferential_ExternalAnchor_*) against the same crossCheckExternalAnchor
// this command calls into -- this file only exercises what's new here: the
// CLI/config resolution layer around it.
//
// Not t.Parallel(): every test here mutates the package-level cobra flag
// vars (verifyAudit*, exportCheckpointOutput, configPathFlag) and os.Stdout,
// matching this package's existing convention (see
// fuzz_encryption_command_fault_test.go's captureStdout doc comment).
package admin

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var offlineAnchorTestKey = []byte("01234567890123456789012345678901")[:32]

// resetVerifyAuditAndExportFlags restores every package-level cobra flag
// this file's tests touch, so state never leaks across tests (these commands
// are ordinarily driven by cobra parsing fresh CLI args every process
// invocation -- calling their RunE functions directly, as this whole
// package's tests do, means we own resetting what cobra would otherwise
// reset for us).
func resetVerifyAuditAndExportFlags(t *testing.T) {
	t.Helper()
	origDB, origPG, origKey, origAnchor, origTSA, origJSON := verifyAuditDBPath, verifyAuditPGDSN, verifyAuditKeyFile, verifyAuditAnchorFile, verifyAuditTSARootFile, verifyAuditJSON
	origExportOut := exportCheckpointOutput
	origCfgPath := configPathFlag
	origForce := forceFlag
	verifyAuditDBPath, verifyAuditPGDSN, verifyAuditKeyFile, verifyAuditAnchorFile, verifyAuditTSARootFile, verifyAuditJSON = "", "", "", "", "", false
	exportCheckpointOutput = ""
	t.Cleanup(func() {
		verifyAuditDBPath, verifyAuditPGDSN, verifyAuditKeyFile, verifyAuditAnchorFile, verifyAuditTSARootFile, verifyAuditJSON = origDB, origPG, origKey, origAnchor, origTSA, origJSON
		exportCheckpointOutput = origExportOut
		configPathFlag = origCfgPath
		forceFlag = origForce
	})
}

// seedCheckpointedDB builds a real SQLite file at dbPath through the actual
// server write path (store.LocalStorage + core.KeyorixCore), matching
// internal/auditverify's own diffFixture, and writes one signed checkpoint
// under offlineAnchorTestKey. The gorm handle is closed before returning so
// the admin commands under test can open the same file themselves without
// lock contention.
func seedCheckpointedDB(t *testing.T, dbPath string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlitedialect.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{}))

	local := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(local)
	c.SetAuditCheckpointKey(offlineAnchorTestKey, "v1")

	tr := true
	for range 5 {
		require.NoError(t, local.LogAuditEvent(t.Context(), &models.AuditEvent{
			EventType: "secret.read",
			Success:   &tr,
			ActorType: "user",
		}))
	}
	_, written, err := c.WriteAuditCheckpoint(t.Context())
	require.NoError(t, err)
	require.True(t, written, "test bug: no checkpoint was written to seed this fixture")

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}

func writeOfflineAnchorTestConfig(t *testing.T, dir, dbPath, offlineAnchorPath string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := "storage:\n  type: local\n  database:\n    path: " + dbPath + "\n"
	if offlineAnchorPath != "" {
		content += "audit:\n  offline_anchor_path: " + offlineAnchorPath + "\n"
	}
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	return cfgPath
}

func writeOfflineAnchorTestKeyFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "checkpoint.key")
	require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(offlineAnchorTestKey)), 0600))
	return path
}

// TestVerifyAudit_OfflineAnchor_ConfigDefault_RoundTrip is the round trip the
// design's own test plan calls for: `export-checkpoint` writes an offline
// anchor file, `audit.offline_anchor_path` in config points verify-audit at
// it with NO --anchor flag passed, and verification succeeds VALID with the
// anchor cross-checked and authenticated -- proving the config-driven
// default actually resolves to a real, working anchor source end to end.
func TestVerifyAudit_OfflineAnchor_ConfigDefault_RoundTrip(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)

	anchorPath := filepath.Join(dir, "checkpoint-export.json")
	cfgPath := writeOfflineAnchorTestConfig(t, dir, dbPath, anchorPath)
	configPathFlag = cfgPath

	exportCheckpointOutput = anchorPath
	require.NoError(t, runExportCheckpoint(nil, nil), "export-checkpoint should succeed against the seeded checkpoint")
	if _, err := os.Stat(anchorPath); err != nil {
		t.Fatalf("export-checkpoint did not write %s: %v", anchorPath, err)
	}

	// verifyAuditAnchorFile is deliberately left empty: the whole point of
	// this test is that audit.offline_anchor_path from config supplies it.
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)

	err := runVerifyAudit(nil, nil)
	require.NoError(t, err, "verify-audit should report VALID using the config-resolved offline anchor")
}

// TestVerifyAudit_OfflineAnchor_MissingConfiguredFile_ClearError proves that
// when audit.offline_anchor_path names a file that does not exist (moved,
// not yet copied over from write-once media, typo'd path), verify-audit
// fails LOUD with a clear, actionable error -- never silently proceeding as
// if no anchor had been configured at all. Fail-closed is the whole point of
// an anchor source (design §2): a configured-but-unreadable anchor must
// never be indistinguishable from "no anchor configured."
func TestVerifyAudit_OfflineAnchor_MissingConfiguredFile_ClearError(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)

	missingAnchorPath := filepath.Join(dir, "does-not-exist.json")
	cfgPath := writeOfflineAnchorTestConfig(t, dir, dbPath, missingAnchorPath)
	configPathFlag = cfgPath
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)

	err := runVerifyAudit(nil, nil)
	require.Error(t, err, "a configured but missing anchor file must be a hard error, never a silent skip")
	require.Contains(t, err.Error(), missingAnchorPath)

	var ece *exitCodeError
	require.ErrorAs(t, err, &ece)
	require.Equal(t, 3, ece.code, "a missing/unreadable anchor file is a usage/input error (exit 3), not a verdict")
}

// TestVerifyAudit_OfflineAnchor_ExplicitFlagOverridesConfig proves --anchor
// always wins over audit.offline_anchor_path when both are set (design §10
// Q5's stated precedence) -- pointing config at a nonexistent file must not
// matter when --anchor names a real, valid export.
func TestVerifyAudit_OfflineAnchor_ExplicitFlagOverridesConfig(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)

	realAnchorPath := filepath.Join(dir, "checkpoint-export.json")
	// config points at a file that was never written -- must never be read,
	// since --anchor below takes precedence.
	cfgPath := writeOfflineAnchorTestConfig(t, dir, dbPath, filepath.Join(dir, "never-written.json"))
	configPathFlag = cfgPath

	exportCheckpointOutput = realAnchorPath
	require.NoError(t, runExportCheckpoint(nil, nil))

	verifyAuditAnchorFile = realAnchorPath
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)

	err := runVerifyAudit(nil, nil)
	require.NoError(t, err, "the explicit --anchor flag must be used, not the nonexistent configured path")
}

// writeMalformedConfig overwrites cfgPath with syntactically-valid YAML that
// config.Load nonetheless refuses: an unrecognized top-level key, rejected by
// its KnownFields(true) decoder (internal/config/config.go's own documented
// reason -- this is deliberately NOT a missing file, the case this test
// suite must distinguish from).
func writeMalformedConfig(t *testing.T, cfgPath string) {
	t.Helper()
	require.NoError(t, os.WriteFile(cfgPath, []byte("this_is_not_a_real_config_field: true\n"), 0600))
}

// runVerifyAuditCapturingJSON forces --json, runs verify-audit, and decodes
// stdout into an auditverify.Result -- used to inspect Result.AnchorSource,
// which runVerifyAudit's return value alone does not expose.
func runVerifyAuditCapturingJSON(t *testing.T) (*auditverify.Result, error) {
	t.Helper()
	verifyAuditJSON = true
	out, runErr := captureStdout(t, func() error { return runVerifyAudit(nil, nil) })
	var result auditverify.Result
	require.NoError(t, json.Unmarshal([]byte(out), &result), "verify-audit --json must always emit parseable JSON, got: %s", out)
	return &result, runErr
}

// TestVerifyAudit_OfflineAnchor_ConfigPresentButUnloadable_NoAnchorFlag_FailsClosed
// is the fix for the gap found in review of #2084: buildVerifyAuditOptions
// used to take a bare *config.Config that was nil both when there was no
// config file at all AND when a config file existed but failed to load --
// collapsing "nothing to check" and "couldn't check" into the same silent
// "no anchor" outcome. A config file that EXISTS but is broken must never be
// silently treated as "operator didn't configure an anchor."
func TestVerifyAudit_OfflineAnchor_ConfigPresentButUnloadable_NoAnchorFlag_FailsClosed(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	writeMalformedConfig(t, cfgPath)
	configPathFlag = cfgPath
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)
	// Deliberately no --anchor and no --db: this must fail before ever
	// reaching openVerifyAuditTarget's own (separate, pre-existing) config
	// error, so the assertion below is on buildVerifyAuditOptions's specific
	// fail-closed message, not just "some exit-3 error occurred."

	err := runVerifyAudit(nil, nil)
	require.Error(t, err, "a present-but-unloadable config with no --anchor must be a hard error, never a silent no-anchor run")
	require.Contains(t, err.Error(), "audit.offline_anchor_path could not be checked")

	var ece *exitCodeError
	require.ErrorAs(t, err, &ece)
	require.Equal(t, 3, ece.code)
}

// TestVerifyAudit_OfflineAnchor_ConfigPresentButUnloadable_ExplicitAnchorFlag_StillVerifies
// proves the fix doesn't overcorrect: an explicit --anchor must still work
// even when config is broken, since it doesn't depend on config at all.
// Uses --db so openVerifyAuditTarget also never touches the broken config.
func TestVerifyAudit_OfflineAnchor_ConfigPresentButUnloadable_ExplicitAnchorFlag_StillVerifies(t *testing.T) {
	resetVerifyAuditAndExportFlags(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyorix.db")
	seedCheckpointedDB(t, dbPath)

	anchorPath := filepath.Join(dir, "checkpoint-export.json")
	cfgPath := writeOfflineAnchorTestConfig(t, dir, dbPath, "") // valid config, no offline_anchor_path yet
	configPathFlag = cfgPath
	exportCheckpointOutput = anchorPath
	require.NoError(t, runExportCheckpoint(nil, nil), "export-checkpoint must succeed while config is still valid")

	// Now break the config -- simulating an operator whose config developed a
	// problem sometime after the anchor was exported.
	writeMalformedConfig(t, cfgPath)

	verifyAuditDBPath = dbPath // bypasses openVerifyAuditTarget's config dependency entirely
	verifyAuditAnchorFile = anchorPath
	verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)

	err := runVerifyAudit(nil, nil)
	require.NoError(t, err, "an explicit --anchor must still verify even with a broken config, reason: %v", err)
}

// TestVerifyAudit_AnchorSourceReported covers the report contract itself
// (design §10 Q5 addendum): Result.AnchorSource must be exactly "flag",
// "config (audit.offline_anchor_path)", or "none" depending on how the
// anchor bundle (or lack of one) was resolved.
func TestVerifyAudit_AnchorSourceReported(t *testing.T) {
	t.Run("flag", func(t *testing.T) {
		resetVerifyAuditAndExportFlags(t)
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "keyorix.db")
		seedCheckpointedDB(t, dbPath)

		anchorPath := filepath.Join(dir, "checkpoint-export.json")
		configPathFlag = writeOfflineAnchorTestConfig(t, dir, dbPath, "") // no offline_anchor_path set
		exportCheckpointOutput = anchorPath
		require.NoError(t, runExportCheckpoint(nil, nil))

		verifyAuditAnchorFile = anchorPath
		verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)
		result, err := runVerifyAuditCapturingJSON(t)
		require.NoError(t, err)
		require.Equal(t, anchorSourceFlag, result.AnchorSource)
	})

	t.Run("config", func(t *testing.T) {
		resetVerifyAuditAndExportFlags(t)
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "keyorix.db")
		seedCheckpointedDB(t, dbPath)

		anchorPath := filepath.Join(dir, "checkpoint-export.json")
		configPathFlag = writeOfflineAnchorTestConfig(t, dir, dbPath, anchorPath)
		exportCheckpointOutput = anchorPath
		require.NoError(t, runExportCheckpoint(nil, nil))

		// verifyAuditAnchorFile deliberately left empty.
		verifyAuditKeyFile = writeOfflineAnchorTestKeyFile(t, dir)
		result, err := runVerifyAuditCapturingJSON(t)
		require.NoError(t, err)
		require.Equal(t, anchorSourceConfig, result.AnchorSource)
	})

	t.Run("none, no config file, --db only", func(t *testing.T) {
		resetVerifyAuditAndExportFlags(t)
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "keyorix.db")
		seedCheckpointedDB(t, dbPath)

		// Never written -- exercises design §10 Q2's deliberately-tolerated
		// "no config file at all" case, distinct from the malformed-config
		// tests above.
		configPathFlag = filepath.Join(dir, "never-written.yaml")
		verifyAuditDBPath = dbPath

		result, err := runVerifyAuditCapturingJSON(t)
		require.NoError(t, err, "a --db run with no config file at all must still succeed (design §10 Q2)")
		require.Equal(t, anchorSourceNone, result.AnchorSource)
	})
}
