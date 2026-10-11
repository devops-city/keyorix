// service.go — Service struct, constructor, and encrypt/decrypt operations.
//
// For rotation, key validation, and shutdown see service_rotation.go.
package encryption

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
)

// Service provides high-level encryption operations for the application.
type Service struct {
	keyManager        *KeyManager
	encryptionService *EncryptionService
	config            *config.EncryptionConfig
	mu                sync.RWMutex
	initialized       bool
	// serverLock is held for as long as this Service is the live DEK holder (set
	// by AcquireExclusiveKeyLock, released by Shutdown). See exclusive_lock.go.
	serverLock *os.File
	// auditSink optionally records security-relevant runtime events (e.g. a
	// key-provider fallback chain actually firing a downgrade, see
	// key_provider_downgrade.go) as audit events. Guarded by its own mutex, not mu:
	// it is read from deep inside Initialize (via the MultiKeyProvider downgrade
	// hook) while mu is already held for writing, and mu is not reentrant.
	auditSink   AuditSink
	auditSinkMu sync.RWMutex
}

// NewService creates a new encryption Service.
func NewService(cfg *config.EncryptionConfig, baseDir string) *Service {
	if !cfg.Enabled {
		log.New(os.Stderr, "", 0).Println(`
╔══════════════════════════════════════════════════════════════════╗
║  ⚠️  WARNING: ENCRYPTION IS DISABLED                             ║
║                                                                  ║
║  All secrets and tokens will be stored as PLAINTEXT.             ║
║  This is only acceptable in local development environments.      ║
║  NEVER run with encryption disabled in production.               ║
╚══════════════════════════════════════════════════════════════════╝`)
	}
	return &Service{
		config:     cfg,
		keyManager: NewKeyManager(baseDir, cfg.DEKPath, cfg.SaltPath),
	}
}

// Initialize sets up the encryption service.
// passphrase is used to derive the KEK via PBKDF2 — never stored.
func (s *Service) Initialize(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	provider, err := s.buildKeyProvider(passphrase)
	if err != nil {
		return err
	}
	s.keyManager.SetKeyProvider(provider)
	if err := s.keyManager.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	dek := s.keyManager.GetDEK()
	encSvc, err := NewEncryptionService(dek)
	if err != nil {
		return fmt.Errorf("failed to create encryption service: %w", err)
	}
	s.encryptionService = encSvc
	s.initialized = true
	return nil
}

// buildKeyProvider selects the KEK source for this service from its own config.
// If the result is a fallback chain (crypto.MultiKeyProvider), wires this
// Service's audit sink so a downgrade that actually FIRES at KEK() time — not
// just one the config permits — is recorded as more than a log line.
func (s *Service) buildKeyProvider(passphrase string) (crypto.KeyProvider, error) {
	provider, err := newKeyProviderFromConfig(s.config, s.keyManager.baseDir, passphrase, s.auditKMSContextFallback)
	if err != nil {
		return nil, err
	}
	if mp, ok := provider.(*crypto.MultiKeyProvider); ok {
		mp.SetDowngradeHook(s.auditKeyProviderDowngrade)
	}
	s.wireKMSAuditSink(provider)
	return provider, nil
}

// wireKMSAuditSink connects this Service's audit sink (if any) to a directly-
// configured KMS-backed key provider's underlying client, so a security-relevant
// runtime event the client itself detects (currently just gcpkms's AAD-fallback
// decrypt, see gcpkms.AuditSink / gcpkms.EventGCPKMSAADFallback) is recorded as a
// queryable audit event, not just a log line — mirroring auditKeyProviderDowngrade's
// wiring for MultiKeyProvider fallback-chain downgrades just above. Only wires the
// single, non-fallback-chain case: a KMS provider nested inside a Fallbacks chain
// is not reachable here since MultiKeyProvider does not expose its member
// providers, and that gap is no worse than the pre-existing log-only behavior.
func (s *Service) wireKMSAuditSink(provider crypto.KeyProvider) {
	kp, ok := provider.(*crypto.KMSKeyProvider)
	if !ok {
		return
	}
	// wireGCPKMSAuditSinkFn is nil in a nogcp build (kms_gcpkms_nogcp.go) — there
	// is no gcp-kms client to wire in that build, so this is simply a no-op.
	if wireGCPKMSAuditSinkFn == nil {
		return
	}
	s.auditSinkMu.RLock()
	sink := s.auditSink
	s.auditSinkMu.RUnlock()
	if sink == nil {
		return
	}
	wireGCPKMSAuditSinkFn(kp, sink)
}

// NewKeyProviderFromConfig builds the KEK source described by an EncryptionConfig
// (ADR-038/ADR-041). The default and the absent/zero value is the passphrase
// provider, byte-identical to the historical derivation; file/env supply
// externally-managed raw key material, exec fetches it from a resolver command,
// shamir reconstructs it from K-of-N shares, and tpm seals it to the host TPM; the
// *-kms providers envelope-wrap the KEK with a cloud KMS key. When Fallbacks are
// configured, wraps all providers in a MultiKeyProvider that tries them in order.
// baseDir resolves provider-relative paths (salt / wrapped_key_path). Exported so
// the KEK-provider migration tool can build a *target* provider from a different
// config than the running service's — the returned provider gets no
// kms-context-fallback audit wiring (see newKeyProviderFromConfig), which is
// correct here since a migration-target provider is never used to serve a live
// decrypt.
func NewKeyProviderFromConfig(cfg *config.EncryptionConfig, baseDir, passphrase string) (crypto.KeyProvider, error) {
	return newKeyProviderFromConfig(cfg, baseDir, passphrase, nil)
}

// newKeyProviderFromConfig is NewKeyProviderFromConfig's implementation, with an
// added kmsFallbackHook wired only from Service.buildKeyProvider (the live-serving
// path) so a KMSAllowContextFallback decrypt actually firing gets recorded as more
// than a log line — see KMSFallbackHook and Service.auditKMSContextFallback.
// Kept unexported rather than added as a new exported parameter so the many
// existing NewKeyProviderFromConfig call sites (tests, the migration CLI) that
// have no audit sink to wire don't need updating for an audit path that doesn't
// apply to them.
func newKeyProviderFromConfig(cfg *config.EncryptionConfig, baseDir, passphrase string, kmsFallbackHook KMSFallbackHook) (crypto.KeyProvider, error) {
	// Re-derive the same (baseDir, saltPath) normalizeKeyPaths already computes for
	// the KeyManager built from this same config (NewKeyManager, above), rather than
	// trusting cfg.SaltPath as-is: cfg is the Service's own config pointer, and
	// nothing mutates it when NewKeyManager normalizes an absolute dek_path/salt_path
	// into its own private fields — so cfg.SaltPath stays the ORIGINAL, possibly
	// absolute, value forever. Passing that raw value into buildSingleProvider sends
	// the password provider's salt write through securefiles with an absolute path,
	// which safeRelComponents unconditionally rejects, even though the baseDir
	// parameter here (when called from Service.buildKeyProvider) is already the
	// normalized km.baseDir. Recomputing from (baseDir, cfg.DEKPath, cfg.SaltPath)
	// directly — rather than requiring a live KeyManager to read normalized fields
	// from — also fixes the exact same bug in NewKeyProviderFromConfig's other real
	// caller, the KEK-provider migration tool, which builds a target provider with no
	// KeyManager of its own to normalize on its behalf.
	normBaseDir, _, normSaltPath, err := normalizeKeyPaths(baseDir, cfg.DEKPath, cfg.SaltPath)
	if err != nil {
		return nil, err
	}
	primary, err := buildSingleProvider(&cfg.KeyProvider, normBaseDir, passphrase, normSaltPath, kmsFallbackHook)
	if err != nil {
		return nil, err
	}
	if len(cfg.KeyProvider.Fallbacks) == 0 {
		return primary, nil
	}
	providers := []crypto.KeyProvider{primary}
	for i := range cfg.KeyProvider.Fallbacks {
		fb, err := buildSingleProvider(&cfg.KeyProvider.Fallbacks[i], normBaseDir, passphrase, normSaltPath, kmsFallbackHook)
		if err != nil {
			return nil, fmt.Errorf("fallback provider [%d] (%s): %w", i, cfg.KeyProvider.Fallbacks[i].Type, err)
		}
		providers = append(providers, fb)
	}
	// Fail closed on a fallback chain that can silently downgrade KEK-sourcing
	// strength (e.g. a TPM/KMS-backed primary falling back to a software-derived
	// key on any transient failure) unless the operator has explicitly opted in.
	// This is a config-SHAPE check — it fires whenever the chain CAN downgrade,
	// regardless of whether a fallback ever actually happens at runtime; see
	// MultiKeyProvider.KEK / SetDowngradeHook for the separate runtime signal that
	// fires only when a fallback to a weaker provider actually occurs.
	if d, downgrades := crypto.DetectFallbackDowngrade(providers); downgrades && !cfg.KeyProvider.AllowWeakerFallback {
		return nil, fmt.Errorf(
			"key_provider fallback [%d] (%q, %s) is weaker than an earlier provider in the configured chain (%s) — a fallback chain that can silently downgrade encryption strength requires explicit storage.encryption.key_provider.insecure_allow_weaker_kek_fallback: true; refusing to start without it",
			d.Index-1, d.Provider, d.ToTier, d.FromTier)
	}
	return crypto.NewMultiKeyProvider(providers)
}

// buildSingleProvider constructs a single KeyProvider from one KeyProviderConfig.
// saltPath is the encryption config's salt file path (used by the password provider).
// kmsFallbackHook is wired into an aws-kms provider only (see NewKeyProviderFromConfig).
func buildSingleProvider(kp *config.KeyProviderConfig, baseDir, passphrase, saltPath string, kmsFallbackHook KMSFallbackHook) (crypto.KeyProvider, error) {
	switch kp.Type {
	case "", "password":
		return crypto.NewPasswordKeyProvider(passphrase, baseDir, saltPath), nil
	case "file":
		return crypto.NewFileKeyProvider(kp.FilePath), nil
	case "env":
		return crypto.NewEnvKeyProvider(kp.EnvVar), nil
	case "exec":
		return crypto.NewExecKeyProvider(kp.ExecCommand), nil
	case "shamir":
		return crypto.NewShamirKeyProvider(kp.ShamirShareFiles, kp.ShamirShareEnv, kp.ShamirCommitment), nil
	case "tpm":
		return crypto.NewTPMKeyProvider(kp.TPMDevice, baseDir, kp.WrappedKeyPath), nil
	case "aws-kms", "gcp-kms", "azure-kms":
		// Dispatches through the cloud-KMS registry (kms_registry.go, ADR-109
		// step 6) rather than importing internal/crypto/{awskms,azurekms,gcpkms}
		// directly here — each is registered from its own //go:build !no<x>
		// file, so a no<x> build never links that SDK. ok=false means this
		// build was compiled with the corresponding no<x> tag: fail closed with
		// a clear error naming the type, never a silent no-op.
		provider, ok, err := newCloudKMSProvider(context.Background(), kp.Type, kp, baseDir, kmsFallbackHook)
		if !ok {
			return nil, fmt.Errorf("encryption key_provider type %q is not available in this build (its cloud SDK was excluded at compile time) — rebuild without the matching no<provider> tag to use it", kp.Type)
		}
		return provider, err
	default:
		return nil, fmt.Errorf("unknown encryption key_provider type %q (supported: password, file, env, exec, shamir, tpm, aws-kms, gcp-kms, azure-kms)", kp.Type)
	}
}

// IsEnabled returns whether encryption is enabled in config.
func (s *Service) IsEnabled() bool {
	return s.config.Enabled
}

// IsInitialized returns whether the service has been initialised.
func (s *Service) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

// AuditCheckpointKey returns the 32-byte HMAC key used to sign/verify audit-chain
// checkpoints (ADR-029), alongside its fingerprint ("key version"). Like
// EvidenceSignKey below, this key is derived from the KEK, not the DEK (see
// KeyManager.deriveAuditCheckpointKey and #502 — mirroring #268's fix for
// EvidenceSignKey): a routine DEK rotation (RotateDEKWithSweep, ADR-010) re-wraps a
// brand-new DEK under the SAME KEK, so this key is completely unaffected by it, and
// a checkpoint signed before a DEK rotation stays verifiable after one. Domain-
// separated from secret encryption and from EvidenceSignKey, held only in
// application memory and never written to the database — a checkpoint therefore
// cannot be forged from database access alone. Returns ok=false when encryption is
// disabled or uninitialised (no KEK has been derived), in which case signed
// checkpoints are unavailable.
func (s *Service) AuditCheckpointKey() (key []byte, keyVersion string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.config.Enabled || !s.initialized {
		return nil, "", false
	}
	return s.keyManager.GetAuditCheckpointKey()
}

// BackupManifestKey returns the KEK-derived backup-manifest signing key and
// its fingerprint ("key version"), for `admin backup` to sign a manifest
// with and `admin restore` to verify one against (design-b3-backup-v2.md
// §5.2/§5.3) -- the raw KEK itself is never exposed outside this package;
// every caller reaches a KEK-derived key only through a getter like this
// one. ok=false when encryption is disabled or uninitialised, exactly like
// AuditCheckpointKey immediately above.
func (s *Service) BackupManifestKey() (key []byte, keyVersion string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.config.Enabled || !s.initialized {
		return nil, "", false
	}
	return s.keyManager.GetBackupManifestKey()
}

// EvidenceSignKey returns the 32-byte HMAC key used to sign exported compliance-
// evidence packs, alongside its fingerprint ("key version"). Unlike
// AuditCheckpointKey, this key is derived from the KEK, not the DEK (see
// KeyManager.evidenceSignKey and #268): a routine DEK rotation
// (RotateDEKWithSweep, ADR-010) re-wraps a brand-new DEK under the SAME KEK, so
// this key is completely unaffected by it, and a previously-signed evidence pack
// stays verifiable across a DEK rotation. Held only in application memory, never
// persisted, exactly like the DEK — so an archived evidence pack's authenticity
// is provable on the server without the key ever touching the database or the
// export. Returns ok=false when encryption is disabled or uninitialised (no KEK
// has been derived).
func (s *Service) EvidenceSignKey() (key []byte, keyVersion string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.config.Enabled || !s.initialized {
		return nil, "", false
	}
	return s.keyManager.GetEvidenceSignKey()
}

// EncryptSecret encrypts plaintext and returns (encryptedBytes, metadataBytes, error).
func (s *Service) EncryptSecret(plaintext []byte) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := s.encryptionService.Encrypt(plaintext, s.keyManager.GetKeyVersion())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}
	encBytes, err := SerializeEncryptedData(encrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize encrypted data: %w", err)
	}
	metaBytes, err := json.Marshal(encrypted.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize metadata: %w", err)
	}
	return encBytes, metaBytes, nil
}

// EncryptSecretWithAAD encrypts plaintext bound to the given AAD.
// Use SecretAAD(secretID, projectID, versionNumber) to construct the AAD.
func (s *Service) EncryptSecretWithAAD(plaintext, aad []byte) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := s.encryptionService.EncryptWithAAD(plaintext, s.keyManager.GetKeyVersion(), aad)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret with AAD: %w", err)
	}
	encBytes, err := SerializeEncryptedData(encrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize encrypted data: %w", err)
	}
	metaBytes, err := json.Marshal(encrypted.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize metadata: %w", err)
	}
	return encBytes, metaBytes, nil
}

// DecryptSecret decrypts a secret from encryptedData bytes.
func (s *Service) DecryptSecret(encryptedData []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := DeserializeEncryptedData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}
	return s.encryptionService.Decrypt(encrypted)
}

// DecryptSecretWithAAD decrypts a secret, using AAD for v1 rows and falling
// back to legacy nil-AAD for rows encrypted before the AAD migration.
// Logs a warning on the legacy path — schedule re-encryption in the M2 sweep.
func (s *Service) DecryptSecretWithAAD(encryptedData, aad []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}
	encrypted, err := DeserializeEncryptedData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}
	if encrypted.Metadata.AADVersion != "" {
		return s.encryptionService.DecryptWithAAD(encrypted, aad)
	}
	log.Printf("[WARN] decrypting legacy secret row without AAD — schedule re-encryption in M2 migration")
	return s.encryptionService.Decrypt(encrypted)
}

// EncryptLargeSecret encrypts large secrets using chunking.
func (s *Service) EncryptLargeSecret(plaintext []byte, chunkSizeKB int) ([][]byte, [][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, nil, fmt.Errorf("encryption service not initialized")
	}
	chunks, err := s.encryptionService.EncryptChunked(plaintext, chunkSizeKB*1024, s.keyManager.GetKeyVersion())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt chunked secret: %w", err)
	}
	var encChunks, metaChunks [][]byte
	for i, chunk := range chunks {
		eb, err := SerializeEncryptedData(chunk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize chunk %d: %w", i, err)
		}
		mb, err := json.Marshal(chunk.Metadata)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize metadata for chunk %d: %w", i, err)
		}
		encChunks = append(encChunks, eb)
		metaChunks = append(metaChunks, mb)
	}
	return encChunks, metaChunks, nil
}

// DecryptLargeSecret decrypts a chunked large secret.
func (s *Service) DecryptLargeSecret(encryptedChunks [][]byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("encryption service not initialized")
	}
	var chunks []*EncryptedData
	for i, ec := range encryptedChunks {
		c, err := DeserializeEncryptedData(ec)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize chunk %d: %w", i, err)
		}
		chunks = append(chunks, c)
	}
	return s.encryptionService.DecryptChunked(chunks)
}
