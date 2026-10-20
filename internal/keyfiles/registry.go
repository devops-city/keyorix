// Package keyfiles is the single, shared enumeration of every on-disk
// encryption key-material file a key-permission checker must inspect.
//
// Before this package existed, four independent call sites each hand-built
// their own []securefiles.FilePermSpec list for the same underlying key
// material: the old CLI's `system audit` and `system fixfileperm` commands
// (both deleted; the audit check now lives in server/admin/audit.go,
// `keyorix-server admin system audit`, per ADR-108),
// internal/startup/validation.go (every server boot), and
// internal/encryption/keymanager_io.go (KeyManager.ValidateKeyFiles /
// FixKeyFilePermissions). All four only ever listed the KEK salt and the
// wrapped DEK (ADR-004) -- true for the original password-only provider, but
// no longer complete once ADR-038 (TPM) and ADR-041 (cloud KMS) added a
// SEPARATE wrapped-KEK blob (KeyProviderConfig.WrappedKeyPath) that none of
// the four lists ever grew to include.
//
// Registry replaces all four hand-copied lists with one enumeration driven by
// *config.EncryptionConfig itself: a future 5th KeyProviderConfig provider
// type that writes new key material to disk needs to be added HERE once (see
// the guard test in registry_exhaustiveness_test.go) to be picked up by every
// caller, instead of requiring four separate, easy-to-miss edits -- which is
// exactly how WrappedKeyPath got missed in the first place.
package keyfiles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// keyMaterialMode is the permission mode required for every file this
// registry enumerates: private key material, readable/writable only by the
// process owner.
const keyMaterialMode = 0600

// writeCapableProviderTypes are the KeyProviderConfig.Type values whose
// provider constructor (internal/encryption/service.go's buildSingleProvider)
// persists key material to WrappedKeyPath -- see
// registry_exhaustiveness_test.go, which re-derives this list from the actual
// source rather than trusting it blindly. "shamir" is handled separately
// below: crypto.ShamirKeyProvider itself never writes, but its share files
// are written by a different tool (`keyorix-server admin encryption shamir-split`) and are
// config-driven the same way, so they belong in this registry too.
var writeCapableProviderTypes = map[string]bool{
	"tpm":       true,
	"aws-kms":   true,
	"gcp-kms":   true,
	"azure-kms": true,
}

// SafePath cleans path and rejects it if the cleaned form still contains a
// ".." segment. Every path this package adds to a Registry() result passes
// through this first: these paths come from several independently-authored
// config fields (salt, DEK, per-provider wrapped-key/shamir-share paths,
// recursively through Fallbacks) that securefiles.FixFilePerms will
// Lstat/Chmod/Chown, so a config-driven path-traversal can't steer it at an
// unintended file.
func SafePath(label, path string) (string, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("%s path is unsafe (contains '..'): %s", label, path)
	}
	return clean, nil
}

// resolve maps a configured key-material path to its on-disk location: an
// absolute path is used as-is, a relative one is resolved under baseDir.
// Mirrors internal/startup's resolveKeyPath. A naive filepath.Join(baseDir,
// path) is NOT equivalent when path is absolute -- Join silently discards the
// leading slash (filepath.Join(".", "/etc/x") == "etc/x", not "/etc/x"), which
// would turn a configured absolute key path into the wrong relative one.
func resolve(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

// Registry enumerates every on-disk key-material file governed by enc, rooted
// at baseDir, as the FilePermSpec list a key-permission checker should pass to
// securefiles.FixFilePerms.
//
// Included:
//   - The KEK salt and wrapped DEK (enc.SaltPath / enc.DEKPath, ADR-004) --
//     required: FixFilePerms itself fails closed if either is missing,
//     matching this repo's existing behavior (an operator provisions these
//     via `keyorix-server admin encryption init` before the server's first real
//     boot; see internal/startup/validation.go's identical pre-existing
//     requirement for these same two paths).
//   - Their ".pending" rotation-staging siblings
//     (internal/encryption/keymanager_{rotation,rewrap,kek_rotation}.go) --
//     OPTIONAL: only added when the file currently exists. These exist only
//     during an in-flight key rotation; requiring them unconditionally would
//     fail every ordinary boot.
//   - Every KeyProviderConfig-driven path this repo's own provider code
//     writes to disk, for the primary provider (enc.KeyProvider) AND every
//     entry in its Fallbacks (one level -- Fallbacks' own nested Fallbacks
//     field is never read by buildSingleProvider either, so it is not a live
//     configuration shape): the TPM/cloud-KMS wrapped-KEK blob
//     (WrappedKeyPath, required) and Shamir KEK share files
//     (ShamirShareFiles, required -- they must already exist for the shamir
//     provider to reconstruct the KEK at all).
//
// Deliberately excluded (see the PR description for the full reasoning):
//   - The "file" provider's FilePath. It is externally managed (e.g. a
//     Kubernetes/CSI secret mount, a sealed/SOPS-decrypted file) and already
//     self-checked at read time by crypto.FileKeyProvider.KEK() with looser,
//     mount-appropriate semantics (rejects group/world read-or-write, but
//     does not require exact 0600 or same-UID ownership). This registry's
//     stricter requirement would misfire on a legitimately-safe-but-
//     differently-owned mount (e.g. a K8s Secret volume, commonly root-owned
//     0440 via fsGroup).
//   - "env" / "exec" providers: no file at all.
//   - `migrate-provider`'s timestamped `<dekPath>.migrate-backup.*` files:
//     glob-named, not a fixed path this registry's list shape can express,
//     and already self-protected at write time (copyFile always chmods to
//     0600 even when reusing an existing destination, internal/cli/
//     encryption/migrate_provider.go).
//   - `trust-keygen`'s ed25519 signing keypair (internal/cli/trust/trust.go,
//     ADR-062) -- the offline key that signs update bundles and licenses.
//     Not config-driven: no *config.EncryptionConfig field names its path
//     (it's a CLI `--dir`/`--key-id` argument, often on a separate, offline
//     signing workstation this registry's baseDir has no reach into anyway),
//     so there is no mechanical way for a config-shape-driven enumeration to
//     include it. It IS written at 0600 via SecureWriteFileSync at creation
//     time -- but unlike the "file" provider above, there is no ongoing
//     self-check anywhere in this codebase: if its permissions drift later
//     (a backup tool, a manual copy, an operator `chmod`), nothing would ever
//     catch it. This is a real, currently-untracked residual gap, not one
//     this registry's design can close -- worth a dedicated follow-up (a
//     permission self-check callable at signing time, or in `trust-keygen`
//     itself), not silently accepted as equivalent to the exclusions above.
func Registry(enc *config.EncryptionConfig, baseDir string) ([]securefiles.FilePermSpec, error) {
	if enc == nil {
		return nil, nil
	}

	var files []securefiles.FilePermSpec
	seen := make(map[string]bool)

	add := func(label, path string, requireExists bool) error {
		if path == "" {
			return nil
		}
		clean, err := SafePath(label, path)
		if err != nil {
			return err
		}
		full := resolve(baseDir, clean)
		if seen[full] {
			return nil
		}
		if !requireExists {
			if _, statErr := os.Stat(full); statErr != nil {
				return nil // optional/transient file not currently present -- skip
			}
		}
		seen[full] = true
		files = append(files, securefiles.FilePermSpec{Path: full, Mode: keyMaterialMode})
		return nil
	}

	if err := add("KEK salt", enc.SaltPath, true); err != nil {
		return nil, err
	}
	if err := add("DEK", enc.DEKPath, true); err != nil {
		return nil, err
	}
	if enc.SaltPath != "" {
		if err := add("KEK salt rotation-staging", enc.SaltPath+".pending", false); err != nil {
			return nil, err
		}
	}
	if enc.DEKPath != "" {
		if err := add("DEK rotation-staging", enc.DEKPath+".pending", false); err != nil {
			return nil, err
		}
	}

	// No capacity pre-sizing: this list is at most a handful of entries, built
	// once per process start, never a hot path -- the arithmetic capacity hint
	// this used to carry (1+len(Fallbacks)) is exactly the shape CodeQL's
	// go/allocation-size-overflow query flags, and it bought nothing here.
	providers := []config.KeyProviderConfig{enc.KeyProvider}
	providers = append(providers, enc.KeyProvider.Fallbacks...)

	for i := range providers {
		kp := &providers[i]
		if writeCapableProviderTypes[kp.Type] {
			if err := add(kp.Type+" wrapped KEK", kp.WrappedKeyPath, true); err != nil {
				return nil, err
			}
		}
		if kp.Type == "shamir" {
			for j, share := range kp.ShamirShareFiles {
				label := fmt.Sprintf("shamir share file [%d]", j)
				if err := add(label, share, true); err != nil {
					return nil, err
				}
			}
		}
	}

	return files, nil
}
