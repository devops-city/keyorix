// keymanager_lifecycle.go — KeyManager struct, constructor, and key initialisation.
//
// Handles first-boot key generation and subsequent startup unwrapping:
// NewKeyManager, Initialize, ensureSaltExists, ensureWrappedDEKExists, unwrapDEK.
//
// Primitive helpers (wrapKey, unwrapKey, wipeBytes) also live here — used by
// both lifecycle and rotation code.
//
// ADR-004 envelope encryption model:
//
//	Startup: passphrase → PBKDF2 → KEK (memory only)
//	         KEK unwraps wrapped DEK from disk → DEK (memory, process lifetime)
//	         KEK wiped from memory immediately after unwrap
//	On disk: keys/kek.salt (random salt, plaintext)
//	         keys/dek.key  (DEK wrapped with KEK, AES-256-GCM)
//	Never:   raw KEK on disk
//
// For rotation see keymanager_rotation.go. For get/validate/wipe see keymanager_io.go.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// KeyManager handles key lifecycle and storage.
type KeyManager struct {
	dekPath  string
	saltPath string
	baseDir  string
	// configErr records a key-path configuration that cannot be honoured,
	// detected at construction. NewKeyManager cannot return an error (it is
	// called from NewService, which cannot either, from seven call sites), so
	// the error is held here and returned by Initialize -- the first method
	// that touches a key file, and the one whose failure stops a boot.
	configErr  error
	currentDEK []byte
	// dekSnapshot is the raw wrapped-DEK bytes read from disk at the moment
	// currentDEK was last set (Initialize/RotateDEKWithSweep). It
	// lets RewrapDEK detect — under the exclusive key lock — whether another
	// process has changed dek.key since, so it never overwrites a
	// concurrently-completed rotation with a stale value (#195).
	dekSnapshot []byte
	keyVersion  string
	// keyProvider sources the KEK (ADR-038). nil = the legacy passphrase+salt
	// derivation below; set to a crypto.KeyProvider (password/file/env) by the
	// Service to obtain the KEK from elsewhere. Either way the KEK still wraps the
	// same on-disk DEK, so the data path is unchanged.
	keyProvider crypto.KeyProvider
	// evidenceSignKey/evidenceSignKeyID are a 32-byte HMAC key and its public
	// fingerprint, derived from the KEK (NOT the DEK) via HKDF-SHA256 at
	// Initialize time — before the KEK is wiped below. Used to sign/verify
	// exported compliance-evidence packs (internal/core/evidence_signing.go).
	// Deriving from the KEK rather than the DEK is the point (#268): a routine
	// DEK rotation (RotateDEKWithSweep, ADR-010) re-wraps a brand-new DEK under
	// the SAME KEK, so this key — and its fingerprint — is completely unaffected
	// by it, and a previously-signed evidence pack stays verifiable across a DEK
	// rotation. Only a genuine KEK change (KEK-provider migration, RewrapDEK /
	// ADR-041 — a far rarer, deliberate operator action) changes it; when that
	// happens VerifyEvidenceSignature correctly reports an older signature as
	// made under a superseded key version rather than as tampered, same as
	// before. Never persisted to disk — held only in memory, like currentDEK.
	evidenceSignKey   []byte
	evidenceSignKeyID string
	// auditCheckpointKey/auditCheckpointKeyID are a 32-byte HMAC key and its public
	// fingerprint, derived from the KEK (NOT the DEK) via HKDF-SHA256 at Initialize
	// time — before the KEK is wiped below. Used to sign/verify audit-chain
	// checkpoints (ADR-029, internal/core/audit_checkpoint.go). Deriving from the
	// KEK rather than the DEK is the point (#502, mirroring #268's fix for
	// evidenceSignKey above): a routine DEK rotation (RotateDEKWithSweep, ADR-010)
	// re-wraps a brand-new DEK under the SAME KEK, so this key — and its
	// fingerprint — is completely unaffected by it, and a checkpoint signed before a
	// DEK rotation stays verifiable after one (previously, deriving from the DEK
	// meant every DEK rotation followed by a server restart caused every existing
	// checkpoint to fail its signature check and `audit verify` to report the trail
	// invalid until the next checkpoint write re-baselined it — a real, if
	// self-healing, false-tamper-alarm window). Only a genuine KEK change
	// (KEK-provider migration, RewrapDEK / ADR-041 — a far rarer, deliberate
	// operator action) changes it; when that happens the existing superseded-key
	// handling in enforceAuditCheckpoint/writeAuditCheckpointLocked correctly
	// treats the stale checkpoint as needing re-baselining rather than as tampered,
	// same as before. Never persisted to disk — held only in memory, like
	// currentDEK/evidenceSignKey.
	auditCheckpointKey   []byte
	auditCheckpointKeyID string
	// backupManifestKey/backupManifestKeyID are a 32-byte HMAC key and its
	// public fingerprint, derived from the KEK via
	// auditverify.DeriveBackupManifestKey at Initialize time -- the exact
	// same treatment as auditCheckpointKey immediately above (KEK-derived
	// so a DEK rotation never invalidates an already-signed manifest;
	// re-derived on KEK rotation; wiped on shutdown), but its own
	// independently domain-separated key: design-b3-backup-v2.md §5.2's
	// explicit decision that the manifest-signing key must never be the
	// audit-checkpoint key reused for a second protocol. Never persisted to
	// disk -- held only in memory, like every other key here.
	backupManifestKey   []byte
	backupManifestKeyID string
	mu                  sync.RWMutex
}

// evidenceSignKeyInfo/evidenceSignKeyIDInfo domain-separate the evidence-signing
// key (and its public fingerprint) from any other use of the KEK (HKDF info
// parameter). Bump the suffix only if the derivation scheme changes.
const (
	evidenceSignKeyInfo   = "keyorix-evidence-signature-kek-v2"
	evidenceSignKeyIDInfo = "keyorix-evidence-signature-kek-id-v2"
)

// auditCheckpointKeyInfo/auditCheckpointKeyIDInfo domain-separate the
// audit-checkpoint signing key (and its public fingerprint) from any other use of
// the KEK (HKDF info parameter). Bump the suffix only if the derivation scheme
// changes. The "-v1" DEK-derived label this superseded (#502) remains allowlisted
// in .gitleaks.toml for historical/git-blame reasons but is no longer used.
const (
	auditCheckpointKeyInfo   = "keyorix-audit-checkpoint-kek-v2"
	auditCheckpointKeyIDInfo = "keyorix-audit-checkpoint-kek-id-v2"
)

// deriveEvidenceSignKey derives the 32-byte evidence-signing HMAC key and its
// 16-byte public key-ID fingerprint from kek via HKDF-SHA256 (two independently
// domain-separated outputs of the same KEK, so the fingerprint reveals nothing
// about the key itself). Both are pure, deterministic functions of the KEK alone,
// so they are stable across a DEK rotation (same KEK) and only change when the KEK
// itself does (KEK-provider migration).
func deriveEvidenceSignKey(kek []byte) (key []byte, keyID string, err error) {
	keyR := hkdf.New(sha256.New, kek, nil, []byte(evidenceSignKeyInfo))
	key = make([]byte, 32)
	if _, err = io.ReadFull(keyR, key); err != nil {
		return nil, "", fmt.Errorf("derive evidence-signing key: %w", err)
	}
	idR := hkdf.New(sha256.New, kek, nil, []byte(evidenceSignKeyIDInfo))
	idBytes := make([]byte, 16)
	if _, err = io.ReadFull(idR, idBytes); err != nil {
		wipeBytes(key)
		return nil, "", fmt.Errorf("derive evidence-signing key id: %w", err)
	}
	return key, "esk-" + hex.EncodeToString(idBytes), nil
}

// deriveAuditCheckpointKey derives the 32-byte audit-checkpoint-signing HMAC key
// and its 16-byte public key-ID fingerprint from kek via HKDF-SHA256, exactly
// mirroring deriveEvidenceSignKey above (independently domain-separated so
// neither output reveals anything about the other, or about the KEK itself).
// Both are pure, deterministic functions of the KEK alone, so they are stable
// across a DEK rotation (same KEK) and only change when the KEK itself does.
func deriveAuditCheckpointKey(kek []byte) (key []byte, keyID string, err error) {
	keyR := hkdf.New(sha256.New, kek, nil, []byte(auditCheckpointKeyInfo))
	key = make([]byte, 32)
	if _, err = io.ReadFull(keyR, key); err != nil {
		return nil, "", fmt.Errorf("derive audit-checkpoint key: %w", err)
	}
	idR := hkdf.New(sha256.New, kek, nil, []byte(auditCheckpointKeyIDInfo))
	idBytes := make([]byte, 16)
	if _, err = io.ReadFull(idR, idBytes); err != nil {
		wipeBytes(key)
		return nil, "", fmt.Errorf("derive audit-checkpoint key id: %w", err)
	}
	return key, "ack-" + hex.EncodeToString(idBytes), nil
}

// SetKeyProvider configures where the KEK comes from. Must be called before
// Initialize / rotation. nil restores the legacy passphrase+salt derivation.
func (km *KeyManager) SetKeyProvider(p crypto.KeyProvider) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.keyProvider = p
}

// deriveKEK returns the KEK from the configured provider, or — when none is set —
// the legacy passphrase + on-disk salt PBKDF2 derivation (byte-identical to the
// pre-ADR-038 behaviour). The caller wipes the returned key.
func (km *KeyManager) deriveKEK(passphrase string) ([]byte, error) {
	if km.keyProvider != nil {
		return km.keyProvider.KEK()
	}
	if passphrase == "" {
		return nil, fmt.Errorf("master passphrase must not be empty")
	}
	salt, err := km.ensureSaltExists()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure salt exists: %w", err)
	}
	return GenerateKEK(passphrase, salt, DefaultKEKIterations), nil
}

// KeyInfo contains metadata about encryption keys.
type KeyInfo struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
}

// NewKeyManager creates a new KeyManager.
func NewKeyManager(baseDir, dekPath, saltPath string) *KeyManager {
	base, dek, salt, err := normalizeKeyPaths(baseDir, dekPath, saltPath)
	return &KeyManager{
		dekPath:    dek,
		saltPath:   salt,
		baseDir:    base,
		keyVersion: "v1",
		configErr:  err,
	}
}

// normalizeKeyPaths reconciles a configured (baseDir, dekPath, saltPath) with
// what internal/securefiles actually accepts: a base directory plus a path
// RELATIVE to it. securefiles.safeRelComponents rejects any absolute path
// outright ("must be relative"), and isPathInsideBase resolves an empty base
// via filepath.Abs("") -- the process working directory -- so an absolute key
// path was refused as "outside" it.
//
// That made an absolute dek_path/salt_path impossible to boot with: server/
// main.go set baseDir="" for absolute paths intending "self-contained, no
// base-dir restriction", but no securefiles primitive implements that
// convention. First-boot key generation failed with
//
//	failed to write wrapped DEK: access denied: file %q is outside of ""
//
// on every start. (Found via the DAST workflow, which configures
// /tmp/keyorix-dast.dek and had failed on every run for ~19 hours.)
//
// The convention applied here -- absolute wins, relative resolves under
// baseDir -- is the one this codebase already uses in two other places:
// internal/keyfiles/registry.go's resolve() and internal/startup's
// resolveKeyPath(). internal/encryption is the component that never got it.
//
// Three rules, and the reasoning for each:
//
//   - Both paths relative: returned UNCHANGED. This is deliberate and load
//     bearing. Splitting a relative path into Dir/Base would turn a rejection
//     into an escape: dek_path "../../etc/x" is refused today because
//     safeRelComponents rejects the ".." component, but as
//     (base="../../etc", name="x") both checks would pass. Only absolute
//     paths are rewritten.
//
//   - Both absolute and sharing a directory: reduced to that directory plus
//     the two base names. baseDir is the join root for more than these two
//     files -- the DEK lock (keymanager_filelock.go), the ".pending" siblings
//     (keymanager_kek_rotation.go, keymanager_rewrap.go, keymanager_rotation.go)
//     and the server lock (exclusive_lock.go) all hang off it -- so keeping a
//     single base directory leaves every one of those join sites working
//     unchanged, with locks and pending files landing beside the keys where an
//     operator expects them.
//
//   - Anything else (one absolute and one relative, or two absolute paths in
//     different directories): refused with a clear error rather than guessed
//     at. Supporting split directories would mean inventing a placement rule
//     for the lock and .pending files that no caller has asked for; a loud
//     refusal is the honest answer until one does.
//
// Containment is not weakened by the rewrite. The property that actually
// defends key material is SecureOpenBeneath's per-component O_NOFOLLOW walk,
// which still refuses a symlink planted anywhere in the key directory. The
// base-directory check only ever guarded against traversal inside a RELATIVE
// configured value, and that path is untouched. An operator who writes an
// absolute dek_path has chosen that directory explicitly.
//
// An empty path is left alone: it means "not configured", and
// keyfiles.Registry already skips empty entries.
func normalizeKeyPaths(baseDir, dekPath, saltPath string) (string, string, string, error) {
	dekAbs := filepath.IsAbs(dekPath)
	saltAbs := filepath.IsAbs(saltPath)

	if dekPath == "" || saltPath == "" || (!dekAbs && !saltAbs) {
		return baseDir, dekPath, saltPath, nil
	}

	if dekAbs != saltAbs {
		return baseDir, dekPath, saltPath, fmt.Errorf(
			"encryption key paths must both be absolute or both be relative: "+
				"dek_path %q is %s but salt_path %q is %s",
			dekPath, absOrRel(dekAbs), saltPath, absOrRel(saltAbs))
	}

	dekDir := filepath.Dir(filepath.Clean(dekPath))
	saltDir := filepath.Dir(filepath.Clean(saltPath))
	if dekDir != saltDir {
		return baseDir, dekPath, saltPath, fmt.Errorf(
			"absolute encryption key paths must live in the same directory "+
				"(the DEK lock, the server lock and the .pending rotation files are all "+
				"placed alongside them): dek_path is in %q but salt_path is in %q",
			dekDir, saltDir)
	}

	return dekDir, filepath.Base(dekPath), filepath.Base(saltPath), nil
}

func absOrRel(abs bool) string {
	if abs {
		return "absolute"
	}
	return "relative"
}

// Initialize sets up the key manager.
// First run: generates salt + DEK, wraps DEK with passphrase-derived KEK.
// Subsequent runs: loads salt, derives KEK, unwraps DEK, wipes KEK.
func (km *KeyManager) Initialize(passphrase string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// A key-path configuration NewKeyManager could not honour. Reported here
	// because this is the first method to touch a key file, so a bad config
	// stops the boot rather than surfacing later as a confusing I/O error.
	if km.configErr != nil {
		return km.configErr
	}

	kek, err := km.deriveKEK(passphrase)
	if err != nil {
		return err
	}
	defer wipeBytes(kek)

	if err := km.ensureWrappedDEKExists(kek); err != nil {
		return fmt.Errorf("failed to ensure wrapped DEK exists: %w", err)
	}

	dek, err := km.unwrapDEK(kek)
	if err != nil {
		return err // unwrapDEK's errors name the step ("failed to unwrap DEK — wrong passphrase ...")
	}

	// Derive the evidence-signing key from the KEK (still in scope here, before the
	// deferred wipe above runs) — NOT from dek, so it survives a later DEK rotation
	// unchanged (#268).
	esk, eskID, err := deriveEvidenceSignKey(kek)
	if err != nil {
		// dek was already unwrapped above and would otherwise leak, unwiped, on
		// this error path — matching how RotateKEKPassphrase wipes its own
		// same-shaped intermediate on the identical derivation-failure branch.
		wipeBytes(dek)
		return fmt.Errorf("failed to derive evidence-signing key: %w", err)
	}

	// Derive the audit-checkpoint signing key from the KEK too (#502), for the same
	// reason: NOT from dek, so a checkpoint signed before a DEK rotation stays
	// verifiable after one.
	ack, ackID, err := deriveAuditCheckpointKey(kek)
	if err != nil {
		wipeBytes(dek)
		wipeBytes(esk)
		return fmt.Errorf("failed to derive audit-checkpoint key: %w", err)
	}

	// Derive the backup-manifest signing key from the KEK too (design-b3-
	// backup-v2.md §5.2), same reasoning, its own independently
	// domain-separated derivation (internal/auditverify.
	// DeriveBackupManifestKey, not this function -- that package's own
	// dependency guard requires it to independently re-derive everything it
	// verifies, so the construction is duplicated there, not imported here).
	bmk, bmkID, err := auditverify.DeriveBackupManifestKey(kek)
	if err != nil {
		wipeBytes(dek)
		wipeBytes(esk)
		wipeBytes(ack)
		return fmt.Errorf("failed to derive backup-manifest key: %w", err)
	}

	km.currentDEK = dek
	km.evidenceSignKey = esk
	km.evidenceSignKeyID = eskID
	km.auditCheckpointKey = ack
	km.auditCheckpointKeyID = ackID
	km.backupManifestKey = bmk
	km.backupManifestKeyID = bmkID
	return nil
}

// ensureSaltExists returns the existing salt or generates a new one. Only
// reached via deriveKEK's legacy (km.keyProvider == nil) branch — unreachable
// from any live production caller today (Service.NewService, the only
// production constructor of a KeyManager, always calls SetKeyProvider before
// Initialize), so no fault-injection seam is wired here; see
// FuzzFaultInjectedOperations/opInit's doc comment.
func (km *KeyManager) ensureSaltExists() ([]byte, error) {
	saltFullPath := filepath.Join(km.baseDir, km.saltPath)

	if _, err := os.Stat(saltFullPath); os.IsNotExist(err) {
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
		if err := securefiles.SecureWriteFileSync(km.baseDir, km.saltPath, salt, 0600); err != nil {
			return nil, fmt.Errorf("failed to write salt: %w", err)
		}
		fmt.Printf("✅ Generated new KEK salt at %s\n", saltFullPath)
		return salt, nil
	}

	salt, err := securefiles.SafeReadFile(km.baseDir, km.saltPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}
	if len(salt) != 32 {
		return nil, fmt.Errorf("invalid salt size: expected 32 bytes, got %d", len(salt))
	}
	return salt, nil
}

// ensureWrappedDEKExists generates and wraps a new DEK if none exists on disk.
//
// Writes via a .pending file, renamed into place, rather than straight to
// dekFullPath (durableWriteSync's "init:write-dek" / durableRename's
// "init:rename-dek" seams, FuzzFaultInjectedOperations/opInit): a short/torn
// write straight to the final path would leave a file that EXISTS (so the
// os.Stat/IsNotExist check below never regenerates it) but fails to unwrap —
// permanently bricking that install's encryption bootstrap until an operator
// manually deletes the corrupt file, since first-run generation (unlike
// rewrap/KEK-rotation) previously had no recovery step at all. A leftover
// .pending file from a prior interrupted attempt is never read — this branch
// only runs when dekFullPath itself doesn't exist yet, so a retry simply
// overwrites the stale .pending in place before renaming; no CleanPendingDEK
// equivalent is needed here.
func (km *KeyManager) ensureWrappedDEKExists(kek []byte) error {
	dekFullPath := filepath.Join(km.baseDir, km.dekPath)

	if !km.wrappedDEKExists() {
		dek, err := GenerateRandomKey(32)
		if err != nil {
			return fmt.Errorf("failed to generate DEK: %w", err)
		}
		defer wipeBytes(dek)

		wrapped, err := wrapKey(dek, kek)
		if err != nil {
			return fmt.Errorf("failed to wrap DEK: %w", err)
		}
		pendingRel := km.dekPath + ".pending"
		if err := durableWriteSync(km.baseDir, pendingRel, wrapped, 0600, "init:write-dek"); err != nil {
			return fmt.Errorf("failed to write wrapped DEK: %w", err)
		}
		pendingFullPath := filepath.Join(km.baseDir, pendingRel)
		if err := durableRename(pendingFullPath, dekFullPath, "init:rename-dek"); err != nil {
			_ = os.Remove(pendingFullPath)
			return fmt.Errorf("failed to commit wrapped DEK: %w", err)
		}
		if err := durableSyncDir(filepath.Dir(dekFullPath), "init:syncdir-dek"); err != nil {
			return fmt.Errorf("failed to sync key directory: %w", err)
		}
		fmt.Printf("✅ Generated and wrapped new DEK at %s\n", dekFullPath)
	}

	return nil
}

// wrappedDEKExists reports whether the wrapped DEK file is present. Any stat
// error other than "not exist" counts as present, exactly as the first-run
// generation gate in ensureWrappedDEKExists has always treated it (never
// generate over a file we merely failed to stat).
func (km *KeyManager) wrappedDEKExists() bool {
	_, err := os.Stat(filepath.Join(km.baseDir, km.dekPath))
	return !os.IsNotExist(err)
}

// unwrapDEK reads the wrapped DEK from disk and decrypts it with the KEK.
func (km *KeyManager) unwrapDEK(kek []byte) ([]byte, error) {
	wrapped, err := securefiles.SafeReadFile(km.baseDir, km.dekPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read wrapped DEK: %w", err)
	}

	dek, err := unwrapKey(wrapped, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK — wrong passphrase or corrupted key file: %w", err)
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size after unwrap: expected 32 bytes, got %d", len(dek))
	}
	km.dekSnapshot = append([]byte(nil), wrapped...)
	return dek, nil
}

// wrapKey encrypts plainKey with kek using AES-256-GCM.
// Output: nonce (12 bytes) || ciphertext.
func wrapKey(plainKey, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plainKey, nil), nil
}

// unwrapKey decrypts a wrapped key using AES-256-GCM with kek.
func unwrapKey(wrapped, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, fmt.Errorf("wrapped key too short")
	}
	nonce, ciphertext := wrapped[:nonceSize], wrapped[nonceSize:]
	plainKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM open failed: %w", err)
	}
	return plainKey, nil
}

// wipeBytes overwrites a byte slice with zeros.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
