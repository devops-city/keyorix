package crypto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// KMSClient is the minimal envelope-encryption surface a cloud KMS exposes: wrap
// (Encrypt) and unwrap (Decrypt) a small blob with a key that never leaves the
// KMS/HSM. Keeping it an interface keeps this package free of any cloud SDK — the
// AWS / GCP / Azure implementations live in subpackages, and tests use a fake.
// ciphertext is opaque, provider-specific KMS output.
type KMSClient interface {
	Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, err error)
}

// ContextFallbackKMSClient is a KMSClient that can retry a context-bound Decrypt
// without its encryption context (insecure_allow_kms_context_fallback, #123):
// aws-kms and gcp-kms. KMSKeyProvider uses it to tell whether the wrapped KEK
// still needs that retry (#3398).
type ContextFallbackKMSClient interface {
	KMSClient
	// ContextFallbackEnabled reports whether the no-context retry can happen:
	// the flag is set and an encryption context is configured.
	ContextFallbackEnabled() bool
	// DecryptReportingFallback is Decrypt that also reports whether the
	// plaintext came from the no-context retry.
	DecryptReportingFallback(ctx context.Context, ciphertext []byte) (plaintext []byte, usedFallback bool, err error)
}

// ErrKMSContextFallbackNotNeeded is returned by KMSKeyProvider.KEK when
// insecure_allow_kms_context_fallback is set but the wrapped KEK decrypted WITH
// its encryption context: no unbound blob is left to migrate, so the flag only
// keeps the weaker unbound path open (a blob planted with no context would
// still unwrap). MultiKeyProvider does not try the next provider on it.
var ErrKMSContextFallbackNotNeeded = errors.New("storage.encryption.key_provider.insecure_allow_kms_context_fallback is set, but the wrapped KEK already decrypts with its encryption context: there is nothing left to migrate, so the flag is no longer needed and can be removed (it only keeps the unbound no-context decrypt path open) -- refusing to start until it is removed")

// kmsCallTimeout bounds a single KMS round-trip at startup.
const kmsCallTimeout = 30 * time.Second

// KMSKeyProvider sources the KEK via cloud-KMS envelope encryption (ADR-041): a
// random 32-byte KEK is wrapped by the KMS key and the *wrapped* blob is stored on
// disk; at startup the KMS unwraps it into memory. The KMS key (CMK) never leaves
// the KMS, and the on-disk blob is ciphertext. First run generates and wraps the
// KEK; subsequent runs decrypt the stored blob.
type KMSKeyProvider struct {
	client         KMSClient
	baseDir        string
	wrappedKeyPath string
	name           string
}

// NewKMSKeyProvider builds a KMS-backed provider. name identifies the backend
// (e.g. "aws-kms") for logging/metadata; wrappedKeyPath is resolved under baseDir.
func NewKMSKeyProvider(client KMSClient, name, baseDir, wrappedKeyPath string) *KMSKeyProvider {
	return &KMSKeyProvider{client: client, name: name, baseDir: baseDir, wrappedKeyPath: wrappedKeyPath}
}

func (p *KMSKeyProvider) Name() string { return p.name }

// Client returns the underlying KMSClient this provider wraps, so a caller that
// needs backend-specific behavior unavailable through the KeyProvider interface
// (e.g. wiring an audit sink onto a *gcpkms client for its AAD-fallback event, see
// encryption.Service.wireKMSAuditSink) can type-assert it to the concrete
// backend's client type.
func (p *KMSKeyProvider) Client() KMSClient { return p.client }

func (p *KMSKeyProvider) KEK() ([]byte, error) {
	if p.client == nil {
		return nil, fmt.Errorf("%s key provider: no KMS client configured", p.name)
	}
	if p.wrappedKeyPath == "" {
		return nil, fmt.Errorf("%s key provider: wrapped_key_path is required", p.name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), kmsCallTimeout)
	defer cancel()

	full := filepath.Join(p.baseDir, p.wrappedKeyPath)
	if _, err := os.Stat(full); os.IsNotExist(err) {
		return p.generateAndWrap(ctx)
	}
	wrapped, err := securefiles.SafeReadFile(p.baseDir, p.wrappedKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%s key provider: read wrapped KEK: %w", p.name, err)
	}
	fc, ok := p.client.(ContextFallbackKMSClient)
	if !ok || !fc.ContextFallbackEnabled() {
		kek, err := p.client.Decrypt(ctx, wrapped)
		if err != nil {
			return nil, fmt.Errorf("%s key provider: KMS decrypt failed: %w", p.name, err)
		}
		return validateKEK(kek, p.name)
	}
	// #3398: the fallback flag is only needed while the stored KEK is unbound.
	// One decrypt answers it: the context-bound attempt runs first, so a KEK
	// that opens without the retry is already bound.
	kek, usedFallback, err := fc.DecryptReportingFallback(ctx, wrapped)
	if err != nil {
		return nil, fmt.Errorf("%s key provider: KMS decrypt failed: %w", p.name, err)
	}
	if !usedFallback {
		clear(kek)
		return nil, fmt.Errorf("%s key provider: %w", p.name, ErrKMSContextFallbackNotNeeded)
	}
	return validateKEK(kek, p.name)
}

// generateAndWrap creates a fresh KEK, wraps it with the KMS key, persists the
// wrapped blob (0600), and returns the plaintext KEK. First-run only.
func (p *KMSKeyProvider) generateAndWrap(ctx context.Context) ([]byte, error) {
	kek := make([]byte, KEKSize)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, fmt.Errorf("%s key provider: generate KEK: %w", p.name, err)
	}
	wrapped, err := p.client.Encrypt(ctx, kek)
	if err != nil {
		return nil, fmt.Errorf("%s key provider: KMS encrypt failed: %w", p.name, err)
	}
	// Durably persist the wrapped KEK before returning it: the caller will wrap
	// the DEK under this KEK, and the wrapped-KEK blob is the only way to recover
	// it on restart. A non-durable write lost to a crash would orphan the DEK.
	if err := securefiles.SecureWriteFileSync(p.baseDir, p.wrappedKeyPath, wrapped, 0600); err != nil {
		return nil, fmt.Errorf("%s key provider: persist wrapped KEK: %w", p.name, err)
	}
	return kek, nil
}
