// secret_value_crypto.go — application-layer encryption of secret VALUES at rest.
//
// Secret values are encrypted at the core layer, on the value bytes, BEFORE they are
// handed to the storage backend (c.storage.CreateSecretVersion). This is what makes
// storage.encryption.enabled actually protect secret values, and it works uniformly
// across every backend (local SQLite, Postgres, and remote/ADR-049) precisely because
// it operates on bytes rather than reaching into a *gorm.DB — unlike the former,
// never-wired encryption.SecretEncryption path it replaces.
//
// The scheme is envelope AES-256-GCM (ADR-004) with additional authenticated data
// bound to the secret's identity (SecretAAD: secretID:projectID:versionNumber, #94)
// so a ciphertext blob cannot be transplanted onto a different secret/version and
// still decrypt.
//
// Fail-closed is the governing rule for a security product: an encryption failure on
// write is surfaced, never silently downgraded to a plaintext write; and a row whose
// own metadata marks it encrypted — or whose metadata is malformed/ambiguous rather
// than the confirmed-empty plaintext marker — is never returned as if it were
// plaintext when no key is available (or no algorithm can be determined) to decrypt
// it.
package core

import (
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// encryptVersionValue produces the at-rest representation of a secret value for a new
// version: (storedValue, metadata).
//
//   - With a secret-value encryptor wired (production, storage.encryption.enabled):
//     returns the AAD-bound ciphertext and its serialized metadata. An encryption
//     error is returned as-is — the value is NEVER written in plaintext in this mode.
//   - With no encryptor wired (encryption disabled — dev/test, which prints the loud
//     "ENCRYPTION IS DISABLED" banner at startup): returns the raw value and nil
//     metadata (the caller records empty "{}" metadata, marking a plaintext row).
func (c *KeyorixCore) encryptVersionValue(secret *models.SecretNode, value []byte, versionNumber int) (storedValue []byte, metadata []byte, err error) {
	if c.secretValueEncryptor == nil {
		return value, nil, nil
	}
	aad := ports.SecretAAD(secret.ID, secret.ProjectID, versionNumber)
	ciphertext, meta, err := c.secretValueEncryptor.EncryptSecretWithAAD(value, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret value: %w", err)
	}
	return ciphertext, meta, nil
}

// decryptVersionValue returns the plaintext value of a stored version, fail-closed.
//
// The row's OWN EncryptionMetadata decides the path, not the presence of a key:
//   - Encrypted row (metadata carries an algorithm): it MUST be decrypted with a wired
//     encryptor. If none is available, this errors rather than handing back ciphertext
//     as though it were plaintext.
//   - Plaintext row (empty "{}"/nil metadata — written while encryption was
//     disabled): returned as-is.
//   - Ambiguous row (metadata fails to parse, or parses but has no usable
//     "algorithm"): this can only happen via data corruption — every current writer
//     sets EncryptedValue and EncryptionMetadata together — but if it does, we cannot
//     tell whether EncryptedValue is real ciphertext or plaintext, so this errors
//     rather than guessing.
//
// The AAD is reconstructed from the row's identity exactly as encryptVersionValue
// bound it, so a transplanted ciphertext fails authentication.
func (c *KeyorixCore) decryptVersionValue(secret *models.SecretNode, version *models.SecretVersion) ([]byte, error) {
	switch versionMetadataStatus(version.EncryptionMetadata) {
	case metadataPlaintext:
		return version.EncryptedValue, nil
	case metadataAmbiguous:
		// The metadata is neither the confirmed-plaintext empty marker nor a
		// well-formed encrypted envelope. We cannot tell whether EncryptedValue
		// holds real ciphertext or plaintext, so we refuse to guess — handing back
		// the raw bytes here would risk leaking ciphertext (or corrupting a
		// genuine plaintext value) as if it were the secret's real value.
		return nil, fmt.Errorf("secret version %d has malformed encryption metadata; refusing to guess whether it is plaintext", version.ID)
	}
	if c.secretValueEncryptor == nil {
		return nil, fmt.Errorf("secret version %d is encrypted at rest but no encryption key is available to decrypt it — refusing to return raw ciphertext (check storage.encryption / KEYORIX_MASTER_PASSWORD)", version.ID)
	}
	aad := ports.SecretAAD(secret.ID, secret.ProjectID, version.VersionNumber)
	plaintext, err := c.secretValueEncryptor.DecryptSecretWithAAD(version.EncryptedValue, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret value: %w", err)
	}
	return plaintext, nil
}

// metadataStatus classifies a stored version's EncryptionMetadata for routing in
// decryptVersionValue. There are three distinct states, and they must NOT be
// collapsed into a single bool: only metadataPlaintext is safe to read verbatim.
type metadataStatus int

const (
	// metadataPlaintext: the confirmed plaintext marker — metadata is nil/empty
	// (exactly "{}" or len==0). Written by the current code path only when
	// encryption is disabled. Safe to return EncryptedValue as-is.
	metadataPlaintext metadataStatus = iota
	// metadataEncrypted: well-formed JSON with a non-empty "algorithm" field.
	// Must be decrypted with a wired encryptor; decryptVersionValue errors if
	// none is available rather than returning ciphertext.
	metadataEncrypted
	// metadataAmbiguous: metadata that is neither of the above — JSON that fails
	// to parse at all, or well-formed JSON whose "algorithm" field is empty or
	// absent. This can only arise from data corruption (the two columns are
	// always written together today), but if it does, EncryptedValue's true
	// nature is unknown and must NOT be treated as plaintext.
	metadataAmbiguous
)

// versionMetadataStatus classifies a stored version's EncryptionMetadata into one of
// the three metadataStatus states described above. Only a genuinely empty object
// (nil/len==0 bytes, or a well-formed "{}" with no fields at all) is treated as
// confirmed plaintext. Anything that fails to parse as JSON, or parses but carries a
// non-empty object without a usable "algorithm" field, is ambiguous and must fail
// closed in decryptVersionValue rather than being silently treated as plaintext.
func versionMetadataStatus(meta models.JSON) metadataStatus {
	if len(meta) == 0 {
		return metadataPlaintext
	}
	if len(meta) == 2 && meta[0] == '{' && meta[1] == '}' {
		return metadataPlaintext
	}
	// One decode on the common (encrypted) path. Syntax errors and non-object
	// documents fail here exactly as they failed the old map decode, and a
	// non-string "algorithm" fails exactly as it failed the old struct decode.
	var m struct {
		Algorithm string `json:"algorithm"`
	}
	if err := json.Unmarshal(meta, &m); err != nil {
		return metadataAmbiguous
	}
	if m.Algorithm != "" {
		return metadataEncrypted
	}
	// No usable algorithm: an empty object (or null) is the plaintext marker,
	// anything with other fields is ambiguous.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(meta, &fields); err != nil || len(fields) != 0 {
		return metadataAmbiguous
	}
	return metadataPlaintext
}
