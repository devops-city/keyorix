// review_coverage_test.go — REVIEW-COVERAGE-2 item 2: what the key-changing
// admin commands do to an interrupted DEK rotation, to missing key files, and to
// existing Shamir share files.
package encryptionops

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// dekRotationRedoMarkerKey mirrors internal/encryption's
// dekRotationPromotePendingKey (unexported there).
const dekRotationRedoMarkerKey = "dek_rotation.promote_pending"

// interruptedRotationFixture leaves the key directory and database exactly as a
// DEK rotation killed between its sweep commit and the dek.key.pending ->
// dek.key rename leaves them: the rows are under the NEW DEK, the redo marker is
// committed, dek.key still holds the OLD wrapped DEK and dek.key.pending holds
// the only copy of the NEW one. Built from a real rotation, then rolled back on
// disk.
func interruptedRotationFixture(t *testing.T) (cfg *config.Config, plaintext string, userID uint) {
	t.Helper()
	cfg, plaintext, userID = rotateFixture(t)
	oldWrapped, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := captureOutput(t, func() error { return RotateWithConfig(cfg, true, false, zeroPassSrc()) }); err != nil {
		t.Fatalf("RotateWithConfig: %v", err)
	}
	if err := os.Rename("dek.key", "dek.key.pending"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("dek.key", oldWrapped, 0o600); err != nil {
		t.Fatal(err)
	}
	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)
	if err := db.Create(&models.SystemMetadata{Key: dekRotationRedoMarkerKey, Value: "vtest"}).Error; err != nil {
		t.Fatal(err)
	}
	// A not-yet-migrated row, for `auth-encryption migrate` to encrypt.
	if err := db.Create(&models.PasswordReset{UserID: plaintextResetUserID, Token: plaintextResetToken}).Error; err != nil {
		t.Fatal(err)
	}
	return cfg, plaintext, userID
}

const (
	plaintextResetUserID = 43
	plaintextResetToken  = "plaintext-reset-token-to-migrate"
)

// decryptAfterNextBoot does what the next server start does (crash recovery
// from the redo marker, then Initialize) and decrypts the fixture's row, and
// every other encrypted password-reset row.
func decryptAfterNextBoot(t *testing.T, enc *config.EncryptionConfig, passphrase string, userID uint) (string, error) {
	t.Helper()
	db := migrateEncOpsTables(t, testDBFile)
	defer closeTestDB(db)
	baseDir, _ := os.Getwd()
	svc := encryption.NewService(enc, baseDir)
	if err := svc.RecoverInterruptedRotation(db); err != nil {
		return "", err
	}
	svc.Shutdown()
	authEnc := encryption.NewAuthEncryption(enc, baseDir, db)
	if err := authEnc.Initialize(passphrase); err != nil {
		return "", err
	}
	defer authEnc.Shutdown()
	var rows []models.PasswordReset
	if err := db.Where("encrypted_token IS NOT NULL").Find(&rows).Error; err != nil {
		return "", err
	}
	var got string
	for _, row := range rows {
		plain, err := authEnc.DecryptPasswordResetToken(row.EncryptedToken, []byte(row.TokenMetadata), row.UserID)
		if err != nil {
			return "", fmt.Errorf("password reset row of user %d: %w", row.UserID, err)
		}
		if row.UserID == userID {
			got = plain
		}
	}
	return got, nil
}

// TestKeyWriters_AfterInterruptedRotation_NewDEKSurvives: every key-changing
// command run after a rotation was killed between its sweep commit and the
// rename must finish that rotation (or leave it for the next start-up), never
// discard or overwrite the pending new DEK. Before REVIEW-COVERAGE-2,
// upgrade-aad and rotate-kek deleted dek.key.pending without reading the redo
// marker and migrate-provider overwrote it, so every row the sweep had moved
// to the new DEK became undecryptable.
func TestKeyWriters_AfterInterruptedRotation_NewDEKSurvives(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "raw.key")
	raw := bytes.Repeat([]byte{7}, crypto.KEKSize)
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(raw)), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		run  func(cfg *config.Config) error
		// the deployment's key config and passphrase after the command
		after func(cfg *config.Config) (*config.EncryptionConfig, string)
	}{
		{"rotate", func(cfg *config.Config) error { return RotateWithConfig(cfg, true, false, zeroPassSrc()) },
			func(cfg *config.Config) (*config.EncryptionConfig, string) {
				return &cfg.Storage.Encryption, testBaselinePassphrase
			}},
		{"upgrade-aad", func(cfg *config.Config) error { return UpgradeAADWithConfig(cfg, zeroPassSrc()) },
			func(cfg *config.Config) (*config.EncryptionConfig, string) {
				return &cfg.Storage.Encryption, testBaselinePassphrase
			}},
		{"rotate-kek", func(cfg *config.Config) error {
			return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
		}, func(cfg *config.Config) (*config.EncryptionConfig, string) {
			return &cfg.Storage.Encryption, testNewPassphrase
		}},
		{"migrate-provider", func(cfg *config.Config) error {
			return MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: keyFile}, true, zeroPassSrc(), zeroPassSrc())
		}, func(cfg *config.Config) (*config.EncryptionConfig, string) {
			enc := cfg.Storage.Encryption
			enc.KeyProvider = config.KeyProviderConfig{Type: "file", FilePath: keyFile}
			return &enc, ""
		}},
		{"auth-encryption rotate", func(cfg *config.Config) error {
			return RotateAuthEncryptionWithConfig(cfg, true, zeroPassSrc())
		}, func(cfg *config.Config) (*config.EncryptionConfig, string) {
			return &cfg.Storage.Encryption, testBaselinePassphrase
		}},
		{"auth-encryption migrate", func(cfg *config.Config) error {
			return MigrateAuthDataWithConfig(cfg, false, zeroPassSrc())
		}, func(cfg *config.Config) (*config.EncryptionConfig, string) {
			return &cfg.Storage.Encryption, testBaselinePassphrase
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chdirTemp(t)
			setNewPassphraseEnv(t, testNewPassphrase)
			cfg, plaintext, userID := interruptedRotationFixture(t)
			out, err := captureOutput(t, func() error { return tc.run(cfg) })
			if err != nil {
				t.Fatalf("%s after an interrupted rotation: %v\n%s", tc.name, err, out)
			}
			enc, pass := tc.after(cfg)
			got, err := decryptAfterNextBoot(t, enc, pass, userID)
			if err != nil || got != plaintext {
				t.Fatalf("DATA LOSS: after %s the row the interrupted rotation swept no longer decrypts (got %q, err %v)", tc.name, got, err)
			}
		})
	}
}

// TestKeyOps_MissingKeyFiles_RefuseAndCreateNothing: every command that works on
// an existing install's keys refuses when the wrapped DEK is not where the
// config says (run from the wrong directory, a wrong dek_path, an unmounted
// volume) instead of generating a new salt and DEK there. rotate-kek and
// migrate-provider used to "succeed" on such fresh keys and tell the operator to
// change the passphrase or provider, after which the server could no longer
// open its real keys; status and validate, documented read-only, wrote key files.
func TestKeyOps_MissingKeyFiles_RefuseAndCreateNothing(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "raw.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(bytes.Repeat([]byte{9}, crypto.KEKSize))), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := []struct {
		name      string
		run       func(cfg *config.Config) error
		returnsOK bool // status reports problems instead of failing
	}{
		{"rotate", func(cfg *config.Config) error { return RotateWithConfig(cfg, true, false, zeroPassSrc()) }, false},
		{"rotate --dry-run", func(cfg *config.Config) error { return RotateWithConfig(cfg, false, true, zeroPassSrc()) }, false},
		{"upgrade-aad", func(cfg *config.Config) error { return UpgradeAADWithConfig(cfg, zeroPassSrc()) }, false},
		{"validate", func(cfg *config.Config) error { return ValidateWithConfig(cfg, zeroPassSrc()) }, false},
		{"status", func(cfg *config.Config) error { return StatusWithConfig(cfg, zeroPassSrc()) }, true},
		{"fix-perms", func(cfg *config.Config) error { return FixPermsWithConfig(cfg, zeroPassSrc()) }, false},
		{"rotate-kek", func(cfg *config.Config) error { return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc()) }, false},
		{"migrate-provider", func(cfg *config.Config) error {
			return MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: keyFile}, true, zeroPassSrc(), zeroPassSrc())
		}, false},
		{"auth-encryption status", func(cfg *config.Config) error { return AuthStatusWithConfig(cfg, zeroPassSrc()) }, false},
		{"auth-encryption rotate", func(cfg *config.Config) error { return RotateAuthEncryptionWithConfig(cfg, true, zeroPassSrc()) }, false},
		{"auth-encryption migrate", func(cfg *config.Config) error { return MigrateAuthDataWithConfig(cfg, false, zeroPassSrc()) }, false},
		{"auth-encryption validate", func(cfg *config.Config) error { return ValidateAuthEncryptionWithConfig(cfg, false, zeroPassSrc()) }, false},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			dir := chdirTemp(t)
			setPassphraseEnv(t, testBaselinePassphrase)
			setNewPassphraseEnv(t, testNewPassphrase)
			db := migrateEncOpsTables(t, testDBFile)
			closeTestDB(db)
			cfg := testConfig(true)
			out, err := captureOutput(t, func() error { return op.run(cfg) })
			if !op.returnsOK && err == nil {
				t.Errorf("%s with no key files succeeded; output:\n%s", op.name, out)
			}
			msg := out
			if err != nil {
				msg += err.Error()
			}
			if !strings.Contains(msg, "does not create keys") {
				t.Errorf("%s: the refusal must say the command works on existing keys only; got %q", op.name, msg)
			}
			for _, f := range []string{"dek.key", "kek.salt", "dek.key.pending"} {
				if _, serr := os.Stat(filepath.Join(dir, f)); serr == nil {
					t.Errorf("%s created %s in a directory that had no keys", op.name, f)
				}
			}
		})
	}
}

// TestShamirSplit_OutDir_RefusesToOverwriteExistingShares: re-running
// shamir-split into the directory that holds the live shares must not replace
// them (the old KEK could then never be reconstructed and the install could not
// start). Nothing is written when any target exists.
func TestShamirSplit_OutDir_RefusesToOverwriteExistingShares(t *testing.T) {
	for _, existing := range []string{"share-2.hex", "commitment.hex"} {
		t.Run(existing, func(t *testing.T) {
			out := t.TempDir()
			live := []byte("live-share-material\n")
			if err := os.WriteFile(filepath.Join(out, existing), live, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := captureOutput(t, func() error { return ShamirSplitWithConfig(3, 2, out) })
			if err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("expected a refusal naming the existing file, got %v", err)
			}
			got, _ := os.ReadFile(filepath.Join(out, existing))
			if !bytes.Equal(got, live) {
				t.Fatalf("%s was overwritten", existing)
			}
			entries, _ := os.ReadDir(out)
			if len(entries) != 1 {
				t.Fatalf("a refused split must write nothing, found %d entries", len(entries))
			}
		})
	}
}
