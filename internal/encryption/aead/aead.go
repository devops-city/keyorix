package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync/atomic"
	"time"
)

const (
	AESCipherSuite = "AES-256-GCM"
)

// nonceBudgetWarnThreshold is a conservative, coarse checkpoint on the number of
// Encrypt/EncryptWithAAD calls made under a single DEK, logged as a one-time loud
// warning to nudge an operator toward a routine `keyorix encryption rotate` well
// before nonce-collision risk becomes material. Standard random 96-bit AES-GCM
// nonces only become a real birthday-bound collision risk near 2^32 encryptions
// under one key; this threshold (2^28, ~268M) sits far below that boundary, giving
// a wide safety margin. This is purely an observability nudge — not a hard limit,
// and encryption is never refused past this point.
const nonceBudgetWarnThreshold uint64 = 1 << 28

// EncryptionService handles all encryption/decryption operations
type EncryptionService struct {
	dek []byte // Data Encryption Key
	gcm cipher.AEAD

	// encryptCount is a coarse, non-durable (reset on process restart) tally of
	// Encrypt/EncryptWithAAD calls made under this DEK. It exists only to drive
	// the one-time nonceBudgetWarnThreshold warning below — not a security
	// control, and rotation is never enforced or blocked on it.
	encryptCount atomic.Uint64
	// nonceBudgetWarned latches once the nonce-budget warning has fired, so
	// sustained write volume past the threshold logs it exactly once rather
	// than on every subsequent call.
	nonceBudgetWarned atomic.Bool

	// wiped latches in WipeDEK. gcm holds its own expanded AES key schedule
	// (crypto/aes has no way to zero it), so zeroing dek alone left a wiped
	// service fully able to encrypt and decrypt under the superseded key; every
	// operation checks this first and returns ErrDEKWiped instead.
	wiped atomic.Bool
}

// checkNonceBudget increments the per-DEK encryption counter and, the first time it
// crosses nonceBudgetWarnThreshold, logs a loud one-time warning nudging the operator
// toward a routine DEK rotation (`keyorix encryption rotate --confirm`). See
// nonceBudgetWarnThreshold for why this threshold, not 2^32, is used.
func (es *EncryptionService) checkNonceBudget() {
	count := es.encryptCount.Add(1)
	if count >= nonceBudgetWarnThreshold && es.nonceBudgetWarned.CompareAndSwap(false, true) {
		log.Printf("[WARN] SECURITY: this DEK has performed %d encryptions, approaching the AES-GCM 96-bit random-nonce birthday bound — run `keyorix encryption rotate --confirm` to rotate to a fresh DEK", count)
	}
}

// ErrDEKWiped is returned by every operation on an EncryptionService after
// WipeDEK has run on it.
var ErrDEKWiped = errors.New("encryption service DEK has been wiped")

// WipeDEK overwrites this service's DEK copy with zeros. internal/encryption's
// service_rotation.go calls this on rotation (the old service is about to be
// discarded) and on Shutdown — see this package's doc.go for why a plain field
// zeroing loop became a method here. From then on every operation on es returns
// ErrDEKWiped (TestWipeDEK_ServiceRefusesUseAfterWipe): the GCM key schedule
// outlives the zeroed bytes, so the latch, not the zeroing, is what stops a
// lingering reference from using the old key.
func (es *EncryptionService) WipeDEK() {
	es.wiped.Store(true)
	for i := range es.dek {
		es.dek[i] = 0
	}
}

// IsDEKWiped reports whether every byte of this service's DEK copy is zero,
// i.e. whether WipeDEK has run on it. It exposes one bit, never key
// material: internal/encryption's G62 tests hold the *EncryptionService
// that Shutdown/rotation must wipe and check this on that same object.
func (es *EncryptionService) IsDEKWiped() bool {
	for _, b := range es.dek {
		if b != 0 {
			return false
		}
	}
	return true
}

// EncryptionMetadata contains metadata about encrypted data
type EncryptionMetadata struct {
	Algorithm   string    `json:"algorithm"`
	KeyVersion  string    `json:"key_version"`
	EncryptedAt time.Time `json:"encrypted_at"`
	Nonce       string    `json:"nonce"`
	Salt        string    `json:"salt,omitempty"`
	Iterations  int       `json:"iterations,omitempty"`
	ChunkIndex  int       `json:"chunk_index,omitempty"`
	TotalChunks int       `json:"total_chunks,omitempty"`
	// ChunkStreamID is a random per-encryption identifier shared by every chunk of one
	// chunked secret. With ChunkIndex/TotalChunks it is folded into each chunk's AAD
	// (chunkAAD), so a chunk cannot be reordered, dropped, or spliced in from another
	// chunked secret without failing the GCM tag check on decryption.
	ChunkStreamID string `json:"chunk_stream_id,omitempty"`
	AADVersion    string `json:"aad_version,omitempty"` // "v2" = secretID:projectID:versionNumber; absent = legacy (no AAD). ("v1" was the pre-migration secretID:namespaceID:versionNumber scheme; no longer produced.)
}

// EncryptedData represents encrypted content with metadata
type EncryptedData struct {
	Data     []byte             `json:"data"`
	Metadata EncryptionMetadata `json:"metadata"`
}

// NewEncryptionService creates a new encryption service with the given DEK.
func NewEncryptionService(kek []byte) (*EncryptionService, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("DEK must be 32 bytes, got %d", len(kek))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EncryptionService{
		dek: kek,
		gcm: gcm,
	}, nil
}

// GenerateRandomKey generates a cryptographically secure random key
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts data using AES-GCM with the KEK
func (es *EncryptionService) Encrypt(plaintext []byte, keyVersion string) (*EncryptedData, error) {
	if es.wiped.Load() {
		return nil, ErrDEKWiped
	}
	es.checkNonceBudget()

	nonce := make([]byte, es.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := es.gcm.Seal(nil, nonce, plaintext, nil)

	metadata := EncryptionMetadata{
		Algorithm:   AESCipherSuite,
		KeyVersion:  keyVersion,
		EncryptedAt: time.Now().UTC(),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
	}

	return &EncryptedData{
		Data:     ciphertext,
		Metadata: metadata,
	}, nil
}

// Decrypt decrypts data using AES-GCM with the KEK
func (es *EncryptionService) Decrypt(encryptedData *EncryptedData) ([]byte, error) {
	if es.wiped.Load() {
		return nil, ErrDEKWiped
	}
	if encryptedData.Metadata.Algorithm != AESCipherSuite { //nolint:goconst
		return nil, fmt.Errorf("unsupported algorithm: %s", encryptedData.Metadata.Algorithm)
	}

	nonce, err := base64.StdEncoding.DecodeString(encryptedData.Metadata.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	// gcm.Open PANICS on a wrong-length nonce rather than returning an error. The nonce
	// comes from stored metadata, so a corrupt/tampered row would otherwise crash the
	// request goroutine (caught by recovery middleware as a 500); guard it as an error.
	if len(nonce) != es.gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length %d", len(nonce))
	}

	plaintext, err := es.gcm.Open(nil, nonce, encryptedData.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// EncryptWithAAD encrypts data using AES-GCM with Additional Authenticated Data.
// The AAD is mixed into the GCM authentication tag — it is not stored in the
// ciphertext but must be supplied identically on decryption.
func (es *EncryptionService) EncryptWithAAD(plaintext []byte, keyVersion string, aad []byte) (*EncryptedData, error) {
	if es.wiped.Load() {
		return nil, ErrDEKWiped
	}
	es.checkNonceBudget()

	nonce := make([]byte, es.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := es.gcm.Seal(nil, nonce, plaintext, aad)

	metadata := EncryptionMetadata{
		Algorithm:   AESCipherSuite,
		KeyVersion:  keyVersion,
		EncryptedAt: time.Now().UTC(),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		AADVersion:  "v2",
	}

	return &EncryptedData{
		Data:     ciphertext,
		Metadata: metadata,
	}, nil
}

// DecryptWithAAD decrypts data encrypted with EncryptWithAAD.
// Returns an error if the AAD does not match — this catches ciphertext transplants.
func (es *EncryptionService) DecryptWithAAD(encryptedData *EncryptedData, aad []byte) ([]byte, error) {
	if es.wiped.Load() {
		return nil, ErrDEKWiped
	}
	if encryptedData.Metadata.Algorithm != AESCipherSuite {
		return nil, fmt.Errorf("unsupported algorithm: %s", encryptedData.Metadata.Algorithm)
	}

	nonce, err := base64.StdEncoding.DecodeString(encryptedData.Metadata.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	// gcm.Open panics on a wrong-length nonce; treat a corrupt stored nonce as an error.
	if len(nonce) != es.gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length %d", len(nonce))
	}

	plaintext, err := es.gcm.Open(nil, nonce, encryptedData.Data, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data (AAD mismatch or corruption): %w", err)
	}

	return plaintext, nil
}

// EncryptChunked encrypts large data by splitting it into chunks
func (es *EncryptionService) EncryptChunked(plaintext []byte, chunkSize int, keyVersion string) ([]*EncryptedData, error) {
	if es.wiped.Load() {
		return nil, ErrDEKWiped // also for empty plaintext, which encrypts no chunk
	}
	if chunkSize <= 0 {
		chunkSize = 64 * 1024 // Default 64KB chunks
	}

	// A random per-call stream ID binds every chunk to THIS encryption. Together with the
	// chunk index and total, folded into each chunk's AAD, it makes reorder, truncation,
	// and cross-stream splice all fail the GCM tag check on decryption — the chunk index
	// and total in the (unauthenticated) metadata alone could otherwise be edited freely.
	streamIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, streamIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate chunk stream id: %w", err)
	}
	streamID := hex.EncodeToString(streamIDBytes)

	var chunks []*EncryptedData
	totalChunks := (len(plaintext) + chunkSize - 1) / chunkSize

	for i := 0; i < len(plaintext); i += chunkSize {
		end := min(i+chunkSize, len(plaintext))

		idx := len(chunks)
		encryptedChunk, err := es.EncryptWithAAD(plaintext[i:end], keyVersion, chunkAAD(streamID, idx, totalChunks))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt chunk %d: %w", idx, err)
		}

		// Add chunk metadata. These values are also bound into the AAD above, so any
		// tampering with them is caught by DecryptWithAAD, not trusted blindly.
		encryptedChunk.Metadata.ChunkIndex = idx
		encryptedChunk.Metadata.TotalChunks = totalChunks
		encryptedChunk.Metadata.ChunkStreamID = streamID

		chunks = append(chunks, encryptedChunk)
	}

	return chunks, nil
}

// chunkAAD binds a chunk to its stream, position, and count. Reconstructed identically on
// decryption from the chunk's claimed metadata, so a reordered, truncated, or spliced-in
// chunk yields a different AAD than it was sealed with and fails the AES-GCM tag check.
func chunkAAD(streamID string, index, total int) []byte {
	return []byte(fmt.Sprintf("keyorix:chunk:v1:%s:%d:%d", streamID, index, total))
}

// DecryptChunked decrypts chunked data and reassembles it. Every chunk must belong to the
// same stream and agree on the total; the per-chunk AAD (stream+index+total) is the
// cryptographic backstop, so reorder, truncation, duplication, and cross-secret splice all
// fail closed rather than reassembling an attacker-chosen plaintext.
func (es *EncryptionService) DecryptChunked(chunks []*EncryptedData) ([]byte, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	if es.wiped.Load() {
		return nil, ErrDEKWiped
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks provided")
	}

	totalChunks := chunks[0].Metadata.TotalChunks
	streamID := chunks[0].Metadata.ChunkStreamID
	if len(chunks) != totalChunks {
		return nil, fmt.Errorf("expected %d chunks, got %d", totalChunks, len(chunks))
	}

	// Sort chunks by index (they may arrive out of order), rejecting any inconsistency
	// before decryption; the AAD check below re-verifies the same facts cryptographically.
	sortedChunks := make([]*EncryptedData, totalChunks)
	for _, chunk := range chunks {
		if chunk.Metadata.ChunkStreamID != streamID {
			return nil, fmt.Errorf("chunk stream id mismatch (chunk spliced from another secret?)")
		}
		if chunk.Metadata.TotalChunks != totalChunks {
			return nil, fmt.Errorf("inconsistent total chunks across the set")
		}
		if chunk.Metadata.ChunkIndex < 0 || chunk.Metadata.ChunkIndex >= totalChunks {
			return nil, fmt.Errorf("invalid chunk index %d", chunk.Metadata.ChunkIndex)
		}
		if sortedChunks[chunk.Metadata.ChunkIndex] != nil {
			return nil, fmt.Errorf("duplicate chunk index %d", chunk.Metadata.ChunkIndex)
		}
		sortedChunks[chunk.Metadata.ChunkIndex] = chunk
	}

	// Decrypt and reassemble, binding each chunk to its position via the AAD.
	var result []byte
	for i, chunk := range sortedChunks {
		if chunk == nil {
			return nil, fmt.Errorf("missing chunk at index %d", i)
		}

		decrypted, err := es.DecryptWithAAD(chunk, chunkAAD(streamID, i, totalChunks))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt chunk %d: %w", i, err)
		}

		result = append(result, decrypted...)
	}

	return result, nil
}

// SerializeEncryptedData converts EncryptedData to JSON bytes
func SerializeEncryptedData(data *EncryptedData) ([]byte, error) {
	return json.Marshal(data)
}

// DeserializeEncryptedData converts JSON bytes to EncryptedData
func DeserializeEncryptedData(data []byte) (*EncryptedData, error) {
	var encrypted EncryptedData
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}
	return &encrypted, nil
}
