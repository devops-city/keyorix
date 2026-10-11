//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// n6NewMasterPassword is the passphrase `admin encryption rotate-kek`
// rewraps the DEK under -- RotateKEKWithConfig (internal/encryptionops/kek.go)
// refuses if this equals the old passphrase, so it must differ.
const n6NewMasterPassword = "e2e-smoke-master-password-sqlite-ROTATED-n6"

// n6AbsolutePathRe matches an absolute filesystem path -- used to prove the
// generated config's storage/key paths are RELATIVE (resolved against
// whichever dir the admin command's cwd is), which is what makes "restore
// into a completely separate directory, source deleted first" a genuine
// proof rather than an accident of both dirs sharing an absolute path.
var n6AbsolutePathRe = regexp.MustCompile(`(?m)^\s*(path|dek_path|salt_path):\s*"(/[^"]*)"`)

// TestJourney_DisasterRecovery: seed a known state (N1's appGetsSecret) on a
// real server, take a real `admin backup`, DELETE the source's database and
// key files, restore the backup onto a completely separate, fresh install,
// and confirm the restored install has the same secret value and version
// history, that a revoked machine token is still revoked, and that the
// audit chain verifies VALID with the same event count as the source --
// then rotate the master passphrase (`admin encryption rotate-kek`) and
// confirm the secret is still readable, the encrypted ciphertext itself is
// byte-identical (only the wrapping changed), the OLD passphrase no longer
// boots the server, and a backup taken BEFORE the rotation still restores
// correctly under the OLD passphrase. Five negative cases (tampered
// archive, truncated archive, wrong passphrase, non-empty target, an older
// backup without --allow-rollback) are each asserted refused. Every step
// runs the real keyorix-server binary's admin subcommands, never a mock.
//
// `admin backup`/`admin restore`/`admin encryption rotate-kek` are NOT CLI
// (`keyorix`) commands -- they are `keyorix-server admin ...` subcommands
// (server/admin/{backup,restore,encryption}.go), confirmed by reading the
// actual cobra command tree rather than assumed.
func TestJourney_DisasterRecovery(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)

	// ── Source: seed a known state (N1) ───────────────────────────────────
	src := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	requireMFAEnrolmentPremise(t, src, "smoketestadmin", harness.BootstrapAdminPassword)
	srcAdminToken, adminFactor := enrolTOTPFactor(t, src, "smoketestadmin", harness.BootstrapAdminPassword)
	seeded := appGetsSecretAs(t, src, cliBin, srcAdminToken)

	beforeValue, beforeVersions := secretValueAndCount(t, src, srcAdminToken, seeded.SecretID)
	// Pin the actual expected value -- without this, an empty-string bug on
	// BOTH sides of a later before/after comparison would still pass.
	if beforeValue != n1ValueV1 {
		t.Fatalf("source secret value before backup: mismatch (redacted; want-len=%d got-len=%d)", len(n1ValueV1), len(beforeValue))
	}
	if beforeVersions != 3 {
		t.Fatalf("source secret version count before backup: want 3 (create+rotate+rollback), got %d", beforeVersions)
	}
	// A second, revoked-by-THIS-journey machine token (independent of N1's
	// own already-revoked one, whose raw value appGetsSecretResult never
	// returns) -- issued and immediately revoked here so this journey holds
	// the raw value itself, to prove a revocation survives restore.
	aEnv := adminEnv(src, srcAdminToken)
	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", n1MachineName,
		"--project", n1ProjectName, "--name", "n6-revoked-token")
	n6RevokedToken, n6RevokedTokenID := parseIssuedToken(t, issueOut)
	runCLI(t, cliBin, aEnv, "machine", "token", "revoke", n1MachineName,
		strconv.Itoa(n6RevokedTokenID), "--project", n1ProjectName, "--force")

	// A third token for the SAME machine identity, issued BEFORE the backup
	// and never revoked -- the positive control for the revoked-token check
	// below. Issued here (not fresh after restore) so it actually proves a
	// pre-existing credential survives backup/restore; a token minted AFTER
	// restore would only prove that issuing NEW tokens still works
	// post-restore, a weaker claim that doesn't exercise the restore path
	// for this credential at all.
	controlIssueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", n1MachineName,
		"--project", n1ProjectName, "--name", "n6-positive-control-token")
	n6ControlToken, _ := parseIssuedToken(t, controlIssueOut)

	// secret.read is logged via a DETACHED, fire-and-forget goroutine (see
	// N3's own doc comment on this exact issue) -- wait for the count to
	// settle before taking the reference total this journey compares the
	// restored DB's verify-audit chained_events against, or a still-in-
	// flight async write would make the source total read LOW here and
	// HIGH once backup captures it moments later.
	waitForAuditEventsToSettle(t, src, srcAdminToken)
	srcAuditTotal := auditTotal(t, src, srcAdminToken)

	// admin backup needs the database to itself (SQLite: the same exclusive
	// lock every admin command takes). Stop the source server before taking
	// the backup, the same way a real disaster-recovery runbook would.
	src.Close()

	backupPath := filepath.Join(t.TempDir(), "n6-backup.tar.gz")
	out, err := harness.RunAdminCmd(serverBin, src.Dir, src.Env,
		"backup", "--config", "./keyorix.yaml", "--output", backupPath)
	if err != nil {
		t.Fatalf("admin backup: %v\n%s", err, out)
	}
	fi, statErr := os.Stat(backupPath)
	if statErr != nil {
		t.Fatalf("backup archive not created at %s: %v\n%s", backupPath, statErr, out)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("backup archive mode: want 0600, got %o", fi.Mode().Perm())
	}

	// ── Prove a REAL wipe: the config's storage/key paths are relative (so
	// restore resolves them against the TARGET dir, not the source's), and
	// the source's actual DB + key files are deleted before restore runs --
	// an absolute-path config could otherwise let "restore" silently reuse
	// the still-existing source and pass trivially. ────────────────────────

	srcCfgRaw, err := os.ReadFile(filepath.Join(src.Dir, "keyorix.yaml")) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatalf("read source config: %v", err)
	}
	if m := n6AbsolutePathRe.FindSubmatch(srcCfgRaw); m != nil {
		t.Fatalf("generated config has an ABSOLUTE storage/key path (%s: %q) -- restore onto a separate dir would not be a real test", m[1], m[2])
	}
	if err := os.Remove(filepath.Join(src.Dir, "keyorix.db")); err != nil {
		t.Fatalf("delete source database (proving a real wipe): %v", err)
	}
	if err := os.RemoveAll(filepath.Join(src.Dir, "keys")); err != nil {
		t.Fatalf("delete source key files (proving a real wipe): %v", err)
	}

	// ── Target: a completely separate, fresh install, same config (same
	// relative key-material paths -- restore.go's own doc comment requires
	// this), restore ────────────────────────────────────────────────────────

	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, "keyorix.yaml"), srcCfgRaw, 0o600); err != nil {
		t.Fatalf("write target config: %v", err)
	}
	targetPort := harness.FreeTCPPort(t)
	harness.RewritePort(t, targetDir, targetPort)

	// Same master passphrase as the source (the archive's key material is
	// wrapped under it), different HOME -- derived from src.Env rather than
	// a hardcoded literal, so this doesn't silently drift from whatever
	// harness.StartServer actually sets.
	targetEnv := replaceHome(src.Env, targetDir)

	rout, rerr := harness.RunAdminCmd(serverBin, targetDir, targetEnv,
		"restore", "--config", "./keyorix.yaml", "--input", backupPath)
	if rerr != nil {
		t.Fatalf("admin restore: %v\n%s", rerr, rout)
	}

	// The restored files genuinely live under targetDir, not merely
	// "restore reported success" -- a real, physical assertion.
	if _, err := os.Stat(filepath.Join(targetDir, "keyorix.db")); err != nil {
		t.Fatalf("restored database not found under targetDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "keys")); err != nil {
		t.Fatalf("restored key files not found under targetDir: %v", err)
	}

	// admin restore already runs `admin migrate` and `admin verify-audit`
	// against the restored database automatically, and fails non-zero if
	// the audit chain is reported BROKEN. Run verify-audit again here too,
	// directly, for a standalone assertion -- VALID, and the SAME event
	// count as the source (not just "didn't fail").
	verdict := runVerifyAuditJSON(t, serverBin, targetDir, targetEnv)
	if verdict.Verdict != "VALID" {
		t.Fatalf("admin verify-audit on restored DB: want VALID, got %+v", verdict)
	}
	// +1, not equal: `admin restore` itself records ONE new chained audit
	// event (server/admin/restore.go's own recordAdminAction("admin.restore_
	// completed", ...), confirmed by reading the source, not guessed after
	// a live mismatch) documenting the restore operation -- legitimately
	// present in the restored DB but never in the source's own pre-backup
	// total.
	if want := srcAuditTotal + 1; verdict.ChainedEvents != want {
		t.Errorf("admin verify-audit on restored DB: chained_events=%d, want %d (source total %d + 1 for admin.restore_completed)", verdict.ChainedEvents, want, srcAuditTotal)
	}

	// Boot the restored server directly -- NOT admin init / encryption init
	// / migrate again (restore already recreated and migrated the DB and
	// key files), and no POST /system/init bootstrap call either (the admin
	// user itself was restored from the backup, not recreated).
	restored := bootRestoredServer(t, serverBin, targetDir, targetEnv, targetPort)
	t.Cleanup(restored.Close)

	restoredToken := loginWithTOTP(t, restored, "smoketestadmin", harness.BootstrapAdminPassword, adminFactor)

	// Every t.Run below (through the negative cases at the end of this
	// function) is ORDER-DEPENDENT, not an independent subtest: each one
	// mutates shared state the next one relies on -- the two rollbacks in
	// "restored secret has the same value..." advance the secret to v2,
	// which the pre-rotation backup/boot-and-readback subtest and the
	// post-rotation value/version checks both assert against;
	// n6RevokedToken/n6ControlToken are issued once, before the backup, and
	// read by the revoked-token subtest; preRotationBackupPath and
	// ciphertextBefore are captured once, between the "restored" and KEK-
	// rotation sections, for subtests that run later. Running a subset via
	// `-run` (other than the whole TestJourney_DisasterRecovery) will fail
	// on a precondition a skipped earlier subtest was supposed to establish
	// -- this is expected, not a flake.
	//
	// restored.Close()/postRotate.Close() are each called explicitly below
	// (restore/backup/verify-audit all need the database to themselves)
	// AND via their own t.Cleanup registration -- calling Close twice is
	// deliberate, not a bug: harness.Server.Close() discards any error from
	// a second Kill()/Wait() on an already-exited process.
	t.Run("restored secret has the same value and full version history as the source", func(t *testing.T) {
		afterValue, afterVersions := secretValueAndCount(t, restored, restoredToken, seeded.SecretID)
		if afterValue != beforeValue {
			t.Errorf("restored secret value: mismatch (redacted; want-len=%d got-len=%d)", len(beforeValue), len(afterValue))
		}
		if afterVersions != beforeVersions {
			t.Errorf("restored version count: want %d, got %d", beforeVersions, afterVersions)
		}
		// Every version's actual VALUE, not just the count. N1's create/
		// rotate/rollback sequence leaves: v1=n1ValueV1, v2=n1ValueV2,
		// v3=n1ValueV1 (the rollback-to-v1). The current value already
		// equals v3's (checked above); roll back to v1 and v2 in turn
		// (each APPENDS a new version, per secret_lifecycle.go's own
		// design) to prove those two are also intact post-restore.
		aEnv := adminEnv(restored, restoredToken)
		runCLI(t, cliBin, aEnv, "secret", "rollback", "--id", strconv.Itoa(seeded.SecretID), "--version", "1")
		v1Readback, _ := secretValueAndCount(t, restored, restoredToken, seeded.SecretID)
		if v1Readback != n1ValueV1 {
			t.Errorf("restored version 1's value: mismatch (redacted; want-len=%d got-len=%d)", len(n1ValueV1), len(v1Readback))
		}
		runCLI(t, cliBin, aEnv, "secret", "rollback", "--id", strconv.Itoa(seeded.SecretID), "--version", "2")
		v2Readback, _ := secretValueAndCount(t, restored, restoredToken, seeded.SecretID)
		if v2Readback != n1ValueV2 {
			t.Errorf("restored version 2's value: mismatch (redacted; want-len=%d got-len=%d)", len(n1ValueV2), len(v2Readback))
		}
	})

	t.Run("a token revoked before backup is still revoked after restore", func(t *testing.T) {
		mEnv := machineEnv(restored, n6RevokedToken)
		_, err := runCLIRaw(cliBin, mEnv, "secret", "get", "--ref", seeded.ProjectRef)
		if err == nil {
			// Deliberately NOT printing the CLI's own output here -- a
			// successful `secret get` prints the decrypted value, and this
			// IS the branch where it unexpectedly succeeded.
			t.Fatal("revoked machine token succeeded reading a secret after restore (should be denied)")
		}
		restEnv := restCall(t, restored, n6RevokedToken, http.MethodGet,
			"/api/v1/secrets/value?ref="+url.QueryEscape(seeded.ProjectRef), nil)
		if restEnv.StatusCode != http.StatusUnauthorized {
			t.Errorf("revoked machine token REST read after restore: want exactly %d, got %d", http.StatusUnauthorized, restEnv.StatusCode)
		}

		// Positive control: n6ControlToken was issued for the SAME machine
		// identity BEFORE the backup and never revoked -- it must still
		// succeed after restore. Without this, the denial above could just
		// as easily mean the restored route/credentials wiring is broken
		// generally, not that revocation specifically survived. Issued
		// before backup (not fresh after restore), so this actually proves
		// a pre-existing credential survives backup/restore.
		controlEnv := machineEnv(restored, n6ControlToken)
		if _, err := runCLIRaw(cliBin, controlEnv, "secret", "get", "--ref", seeded.ProjectRef); err != nil {
			t.Errorf("positive control: a pre-existing, non-revoked token for the same machine identity was denied after restore -- restored credential wiring itself is broken, not just revocation")
		}
	})

	// ── KEK rotation on the restored install ───────────────────────────────
	restored.Close()

	// Ciphertext BEFORE rotation -- read directly from the (stopped)
	// restored DB file via sqlite3, matching N3's tamperAuditRow pattern.
	targetDBPath := filepath.Join(targetDir, "keyorix.db")
	ciphertextBefore := secretCiphertextHex(t, targetDBPath, seeded.SecretID)

	// A backup taken BEFORE rotation -- must still restore correctly under
	// the OLD passphrase even after the live install's own KEK is later
	// rotated (backups are frozen, independent snapshots).
	preRotationBackupPath := filepath.Join(t.TempDir(), "n6-pre-rotation-backup.tar.gz")
	pbOut, pbErr := harness.RunAdminCmd(serverBin, targetDir, targetEnv,
		"backup", "--config", "./keyorix.yaml", "--output", preRotationBackupPath)
	if pbErr != nil {
		t.Fatalf("admin backup (pre-rotation): %v\n%s", pbErr, pbOut)
	}

	rotateEnv := append(append([]string{}, targetEnv...), "KEYORIX_NEW_MASTER_PASSWORD="+n6NewMasterPassword)
	krout, krerr := harness.RunAdminCmd(serverBin, targetDir, rotateEnv,
		"encryption", "rotate-kek", "--config", "./keyorix.yaml", "--confirm")
	if krerr != nil {
		t.Fatalf("admin encryption rotate-kek: %v\n%s", krerr, krout)
	}

	ciphertextAfter := secretCiphertextHex(t, targetDBPath, seeded.SecretID)
	if ciphertextBefore != ciphertextAfter {
		t.Error("secret ciphertext changed across KEK rotation -- rotation should only re-wrap the DEK, never re-encrypt values")
	}

	rotatedEnv := replaceEnvVar(targetEnv, "KEYORIX_MASTER_PASSWORD", n6NewMasterPassword)

	t.Run("the OLD passphrase no longer boots the server after rotation", func(t *testing.T) {
		// MUST reuse targetPort, the port the config file on disk actually
		// has (harness.RewritePort baked it in earlier) -- a fresh port
		// here would poll a port nothing is listening on regardless of
		// whether decryption actually failed, making this check pass
		// vacuously. targetPort is free at this point: postRotate (below)
		// hasn't booted yet.
		failedBoot := attemptBoot(t, serverBin, targetDir, targetEnv, targetPort)
		defer failedBoot.Close()

		// A genuine decrypt failure exits the process fast -- wait for the
		// REAL exit and assert it's non-zero, instead of only polling
		// /health for an arbitrary window (the previous version of this
		// check used a 5s bound here against WaitHealthy's 30s for a
		// successful boot, an unexplained asymmetry: a slow-but-correct
		// failure could have been indistinguishable from "didn't check long
		// enough"). 10s is generous for a fail-fast decrypt error; unlike
		// WaitHealthy's 30s, it is not trying to rule out a slow SUCCESSFUL
		// boot, so it doesn't need to match that bound.
		exitCode, exited := waitProcessExit(failedBoot, 10*time.Second)
		if !exited {
			t.Fatal("server process using the OLD passphrase after KEK rotation did not exit within 10s -- expected a fast decrypt-failure exit, not a hang")
		}
		if exitCode == 0 {
			t.Error("server exited 0 using the OLD passphrase after KEK rotation -- should have failed non-zero")
		}
		// The process has already exited at this point, so this is a cheap
		// confirmatory check, not the primary signal.
		if healthy := waitHealthyBounded(failedBoot, 1); healthy {
			t.Error("server reported healthy using the OLD passphrase after KEK rotation -- should have failed to start")
		}
		logBytes, _ := os.ReadFile(failedBoot.LogPath) // #nosec G304 -- this test's own harness-managed log path
		if !strings.Contains(string(logBytes), "passphrase") && !strings.Contains(string(logBytes), "decrypt") && !strings.Contains(string(logBytes), "KEK") {
			t.Errorf("expected the failed-boot log to mention a passphrase/decryption/KEK failure, got:\n%s", logBytes)
		}
	})

	postRotate := bootRestoredServer(t, serverBin, targetDir, rotatedEnv, targetPort)
	t.Cleanup(postRotate.Close)

	postRotateToken := loginWithTOTP(t, postRotate, "smoketestadmin", harness.BootstrapAdminPassword, adminFactor)

	t.Run("secret still readable, version history intact, after KEK rotation", func(t *testing.T) {
		afterValue, afterVersions := secretValueAndCount(t, postRotate, postRotateToken, seeded.SecretID)
		if afterValue != n1ValueV2 { // the last rollback in the "restored" subtest above left it at v2
			t.Errorf("post-rotation secret value: mismatch (redacted; want-len=%d got-len=%d)", len(n1ValueV2), len(afterValue))
		}
		if afterVersions != beforeVersions+2 { // +2 for the two rollback-appended versions in the earlier subtest
			t.Errorf("post-rotation version count: want %d, got %d", beforeVersions+2, afterVersions)
		}
	})

	t.Run("audit chain still verifies VALID after KEK rotation", func(t *testing.T) {
		postRotate.Close() // verify-audit needs the DB to itself, same as backup/restore
		verdict := runVerifyAuditJSON(t, serverBin, targetDir, rotatedEnv)
		if verdict.Verdict != "VALID" {
			t.Errorf("admin verify-audit after KEK rotation: want VALID, got %+v", verdict)
		}
	})

	t.Run("a backup taken BEFORE rotation still restores under the OLD passphrase", func(t *testing.T) {
		preRotationTargetDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(preRotationTargetDir, "keyorix.yaml"), srcCfgRaw, 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		preRotationPort := harness.FreeTCPPort(t)
		harness.RewritePort(t, preRotationTargetDir, preRotationPort)
		preRotationEnv := replaceHome(targetEnv, preRotationTargetDir) // targetEnv still carries the OLD passphrase
		out, err := harness.RunAdminCmd(serverBin, preRotationTargetDir, preRotationEnv,
			"restore", "--config", "./keyorix.yaml", "--input", preRotationBackupPath)
		if err != nil {
			t.Fatalf("restore of a pre-rotation backup under the OLD passphrase: %v\n%s", err, out)
		}

		// Boot it and read the secret back -- "restore reported success" on
		// its own doesn't prove the restored data is actually usable;
		// matches the same value/version-count shape the main "restored"
		// subtest above asserts. At this point in the journey the secret is
		// at v2 (n1ValueV2) after the two rollbacks in that earlier
		// subtest, beforeVersions+2 versions total -- preRotationBackupPath
		// was taken after both, right before rotate-kek.
		preRotationServer := bootRestoredServer(t, serverBin, preRotationTargetDir, preRotationEnv, preRotationPort)
		defer preRotationServer.Close()
		preRotationToken := loginWithTOTP(t, preRotationServer, "smoketestadmin", harness.BootstrapAdminPassword, adminFactor)
		value, versions := secretValueAndCount(t, preRotationServer, preRotationToken, seeded.SecretID)
		if value != n1ValueV2 {
			t.Errorf("pre-rotation backup's restored secret value: mismatch (redacted; want-len=%d got-len=%d)", len(n1ValueV2), len(value))
		}
		if versions != beforeVersions+2 {
			t.Errorf("pre-rotation backup's restored version count: want %d, got %d", beforeVersions+2, versions)
		}
	})

	// ── Negative cases: each must be refused, non-zero exit ────────────────

	t.Run("negative: tampered archive is refused", func(t *testing.T) {
		tamperedPath := corruptedCopy(t, backupPath, func(b []byte) {
			mid := len(b) / 2
			b[mid] ^= 0xFF
		})
		// Not "integrity check" specifically: the archive is gzip-compressed,
		// so a single flipped byte in the COMPRESSED stream almost always
		// desyncs DEFLATE decoding from that point on (confirmed live,
		// deterministically, across repeated runs -- never once reached
		// backup_v1_legacy.go's own per-entry size/checksum integrity
		// check), surfacing as archive/tar's own "invalid tar header"
		// instead. Both are genuine proof the corruption was caught and the
		// restore refused -- this journey's actual claim -- just at
		// different layers (gzip/tar framing vs. post-extract content
		// checksum); which one fires depends on exactly where in the
		// compressed stream the flipped byte lands. "archive" matches both
		// messages (and matches the sibling "truncated archive" case below,
		// which already asserts this same broader substring for the same
		// reason).
		assertRestoreRefused(t, serverBin, targetEnv, srcCfgRaw, tamperedPath, "archive")
	})

	t.Run("negative: truncated archive is refused", func(t *testing.T) {
		raw, err := os.ReadFile(backupPath) // #nosec G304 -- this journey's own tempdir path
		if err != nil {
			t.Fatalf("read backup for truncation: %v", err)
		}
		truncatedPath := filepath.Join(t.TempDir(), "n6-truncated.tar.gz")
		if err := os.WriteFile(truncatedPath, raw[:len(raw)/2], 0o600); err != nil {
			t.Fatalf("write truncated archive: %v", err)
		}
		assertRestoreRefused(t, serverBin, targetEnv, srcCfgRaw, truncatedPath, "archive")
	})

	t.Run("negative: wrong passphrase is refused", func(t *testing.T) {
		wrongEnv := replaceEnvVar(targetEnv, "KEYORIX_MASTER_PASSWORD", "definitely-the-wrong-passphrase-n6")
		assertRestoreRefused(t, serverBin, wrongEnv, srcCfgRaw, backupPath, "passphrase")
	})

	t.Run("negative: restore into a non-empty target is refused without --overwrite-existing", func(t *testing.T) {
		nonEmptyDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(nonEmptyDir, "keyorix.yaml"), srcCfgRaw, 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		harness.RewritePort(t, nonEmptyDir, harness.FreeTCPPort(t))
		nonEmptyEnv := replaceHome(targetEnv, nonEmptyDir)

		// A REAL prior restore makes the target genuinely non-empty -- a
		// synthetic placeholder file here would only prove refuseNonEmpty-
		// Existing's os.Stat(path).Size()>0 check, not that the guard fires
		// against actual previously-restored data.
		seedOut, seedErr := harness.RunAdminCmd(serverBin, nonEmptyDir, nonEmptyEnv,
			"restore", "--config", "./keyorix.yaml", "--input", backupPath)
		if seedErr != nil {
			t.Fatalf("restore a real backup first (to make the target genuinely non-empty): %v\n%s", seedErr, seedOut)
		}

		out, err := harness.RunAdminCmd(serverBin, nonEmptyDir, nonEmptyEnv,
			"restore", "--config", "./keyorix.yaml", "--input", backupPath)
		if err == nil {
			t.Fatalf("admin restore into a non-empty target unexpectedly succeeded:\n%s", out)
		}
		if !strings.Contains(out, "overwrite-existing") {
			t.Errorf("expected the refusal to mention --overwrite-existing, got:\n%s", out)
		}
	})

	t.Run("negative: an older backup is refused without --allow-rollback", func(t *testing.T) {
		// preRotationBackupPath is STRICTLY newer than backupPath (more
		// audit events happened between them: the restore, the two
		// rollbacks in an earlier subtest, and this journey's own machine-
		// token issue/revoke). Restore the newer one into a fresh target
		// first (establishes that target's own rollback-protection witness
		// at the newer high-water mark), then attempt the OLDER backup into
		// the SAME target with --overwrite-existing but WITHOUT
		// --allow-rollback.
		rollbackDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(rollbackDir, "keyorix.yaml"), srcCfgRaw, 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		harness.RewritePort(t, rollbackDir, harness.FreeTCPPort(t))
		rollbackEnv := replaceHome(targetEnv, rollbackDir)

		out, err := harness.RunAdminCmd(serverBin, rollbackDir, rollbackEnv,
			"restore", "--config", "./keyorix.yaml", "--input", preRotationBackupPath)
		if err != nil {
			t.Fatalf("restore the newer backup (to establish the rollback witness): %v\n%s", err, out)
		}

		out2, err2 := harness.RunAdminCmd(serverBin, rollbackDir, rollbackEnv,
			"restore", "--config", "./keyorix.yaml", "--input", backupPath, "--overwrite-existing")
		if err2 == nil {
			t.Fatal("restoring an OLDER backup without --allow-rollback succeeded -- should have been refused")
		}
		if !strings.Contains(out2, "rollback") {
			t.Errorf("expected the refusal to mention rollback protection, got:\n%s", out2)
		}
	})
}

// bootRestoredServer starts binary as a background process against an
// ALREADY-provisioned dir/config (a restored or post-rotation install --
// never admin init/encryption init/migrate'd by this helper, and never
// POST /system/init'd either) and waits for it to report healthy.
func bootRestoredServer(t *testing.T, binary, dir string, env []string, port string) *harness.Server {
	t.Helper()
	s := attemptBoot(t, binary, dir, env, port)
	harness.WaitHealthy(t, s)
	return s
}

// attemptBoot starts binary as a background process without waiting for
// health -- used both by bootRestoredServer (which waits itself, fatally on
// timeout) and the "old passphrase fails to boot" negative case (which
// polls with its OWN bounded, non-fatal wait via waitHealthyBounded).
func attemptBoot(t *testing.T, binary, dir string, env []string, port string) *harness.Server {
	t.Helper()
	serverEnv := append(append([]string{}, env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	s := &harness.Server{
		T: t, Dir: dir, ConfigPath: "./keyorix.yaml", BaseURL: "http://127.0.0.1:" + port,
		Binary: binary, Env: env, LogPath: filepath.Join(dir, "e2e-server-"+filepath.Base(binary)+"-boot-attempt.log"),
	}
	harness.StartBackgroundProcess(t, s, serverEnv)
	return s
}

// waitHealthyBounded polls s.BaseURL/health for up to seconds, returning
// true the moment it reports 200, false if the deadline passes -- NON-fatal
// (unlike harness.WaitHealthy), for a negative case that EXPECTS the server
// never to become healthy.
func waitHealthyBounded(s *harness.Server, seconds int) bool {
	client := http.Client{}
	for i := 0; i < seconds*2; i++ {
		resp, err := client.Get(s.BaseURL + "/health") // #nosec G107 -- fixed test harness URL
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		// A tight, bounded, deliberately-short poll -- this case wants a
		// fast negative, not harness.WaitHealthy's full 30s.
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// waitProcessExit waits up to timeout for s's subprocess to exit on its own,
// returning its exit code and whether it exited within the deadline --
// `exited=false` means it's still running (a hang, not a fast failure).
// Used by the "old passphrase" negative case, which expects a genuine,
// fast decrypt-failure exit, not merely "never became healthy" (which is
// equally consistent with a hang). Waits via s.Exited() rather than calling
// s.Cmd.Process.Wait() itself (the old approach): harness.startProcess
// (#2459) now has its own background goroutine permanently blocked in
// Wait() on this same process from the moment it starts, and os/exec
// documents concurrent Wait() calls on one process as unsafe -- s.Exited()
// is the one channel that goroutine closes once it has already reaped the
// process, so this never races it. Safe to call even though the caller
// also `defer`s s.Close(): Close() only Kills (never waits a second time)
// once s.exited is already closed.
func waitProcessExit(s *harness.Server, timeout time.Duration) (exitCode int, exited bool) {
	if s.Cmd == nil || s.Cmd.Process == nil {
		return 0, false
	}
	select {
	case <-s.Exited():
		if s.Cmd.ProcessState == nil {
			return -1, true
		}
		return s.Cmd.ProcessState.ExitCode(), true
	case <-time.After(timeout):
		return 0, false
	}
}

// secretValueAndCount reads a secret's current decrypted value (admin-only
// include_value=true readback, same route journey1 uses) plus its version
// count (secretVersionCount, journey1_app_gets_secret_test.go).
func secretValueAndCount(t *testing.T, s *harness.Server, adminToken string, secID int) (string, int) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secID), nil, http.StatusOK)
	var data struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		// Never echo env.Data here -- it's the include_value=true response
		// body and carries the secret's PLAINTEXT value; only the decode
		// error and the body's length are safe to print on failure.
		t.Fatalf("decode secret readback: %v (body length %d)", err, len(env.Data))
	}
	return data.Value, secretVersionCount(t, s, adminToken, secID)
}

// auditTotal returns GET /api/v1/audit/search's own reported total (same
// field waitForAuditEventsToSettle/N3 use) -- this journey's source-side
// reference count for the post-restore chained_events comparison.
func auditTotal(t *testing.T, s *harness.Server, adminToken string) int64 {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/audit/search?limit=1", nil, http.StatusOK)
	var data struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode audit search total: %v\nraw: %s", err, env.Data)
	}
	return data.Total
}

// n6VerifyAuditVerdict mirrors internal/auditverify.Result's wire shape --
// the fields this journey needs (Verdict, ChainedEvents, FirstBrokenID).
type n6VerifyAuditVerdict struct {
	Verdict       string  `json:"verdict"`
	ChainedEvents int64   `json:"chained_events"`
	FirstBrokenID *uint64 `json:"first_broken_id,omitempty"`
}

// runVerifyAuditJSON runs `keyorix-server admin verify-audit --json` against
// dir's own config (the server must already be stopped) and decodes the
// verdict -- errors (a BROKEN verdict's non-zero exit) are NOT fatal here,
// since some callers (the negative-case helpers) expect exactly that; those
// callers check the returned struct/error themselves.
func runVerifyAuditJSON(t *testing.T, binary, dir string, env []string) n6VerifyAuditVerdict {
	t.Helper()
	out, _ := harness.RunAdminCmd(binary, dir, env, "verify-audit", "--config", "./keyorix.yaml", "--json")
	var v n6VerifyAuditVerdict
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("decode verify-audit --json output: %v\noutput:\n%s", err, out)
	}
	return v
}

// assertRestoreRefused writes cfg into a FRESH target dir, then runs `admin
// restore --input archivePath` there and asserts a non-zero exit -- used by
// every negative case (tampered/truncated archive, wrong passphrase). env
// must already carry the right KEYORIX_MASTER_PASSWORD/HOME for the case
// under test (a caller testing "wrong passphrase" passes a deliberately
// wrong one via replaceEnvVar).
func assertRestoreRefused(t *testing.T, binary string, env []string, cfg []byte, archivePath, wantReasonSubstr string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), cfg, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	harness.RewritePort(t, dir, harness.FreeTCPPort(t))
	env = replaceHome(env, dir)
	out, err := harness.RunAdminCmd(binary, dir, env, "restore", "--config", "./keyorix.yaml", "--input", archivePath)
	if err == nil {
		t.Fatalf("admin restore unexpectedly succeeded (should have been refused):\n%s", out)
	}
	// Refused for the RIGHT reason, not just "some non-zero exit" -- a
	// wrong-passphrase archive that happened to fail for an unrelated I/O
	// error would otherwise pass this check just as well.
	if !strings.Contains(out, wantReasonSubstr) {
		t.Errorf("admin restore refusal: want reason containing %q, got:\n%s", wantReasonSubstr, out)
	}
}

// corruptedCopy copies src to a new tempfile and applies mutate to its
// bytes before writing -- used to build a tampered archive from a real one.
func corruptedCopy(t *testing.T, src string, mutate func([]byte)) string {
	t.Helper()
	raw, err := os.ReadFile(src) // #nosec G304 -- this journey's own tempdir path
	if err != nil {
		t.Fatalf("read %s to corrupt: %v", src, err)
	}
	mutate(raw)
	dst := filepath.Join(t.TempDir(), "n6-corrupted.tar.gz")
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatalf("write corrupted copy: %v", err)
	}
	return dst
}

// secretCiphertextHex reads the raw encrypted_value bytes (hex-encoded) for
// secID's CURRENT (highest-id) version row directly from dbPath via the
// sqlite3 CLI -- dbPath's server must already be stopped. Used to prove KEK
// rotation re-wraps the DEK without touching stored ciphertext.
func secretCiphertextHex(t *testing.T, dbPath string, secID int) string {
	t.Helper()
	stmt := fmt.Sprintf(
		"SELECT hex(encrypted_value) FROM secret_versions WHERE secret_node_id = %d ORDER BY id DESC LIMIT 1;", secID)
	cmd := exec.Command("sqlite3", dbPath, stmt) // #nosec G204 -- dbPath is this test's own tempdir-derived path, secID is an int from this test's own prior REST resolution, never attacker input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sqlite3 read ciphertext failed: %v\n%s", err, out)
	}
	hex := strings.TrimSpace(string(out))
	if hex == "" {
		t.Fatalf("sqlite3 read ciphertext: no row found for secret_node_id=%d", secID)
	}
	return hex
}

// replaceHome returns a copy of env with HOME= replaced by newHome.
func replaceHome(env []string, newHome string) []string {
	out := make([]string, len(env))
	copy(out, env)
	for i, e := range out {
		if strings.HasPrefix(e, "HOME=") {
			out[i] = "HOME=" + newHome
		}
	}
	return out
}

// replaceEnvVar returns a copy of env with key's value replaced by value
// (appended if key wasn't already present).
func replaceEnvVar(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	found := false
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			out = append(out, key+"="+value)
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		out = append(out, key+"="+value)
	}
	return out
}
