// Package gcpkms implements crypto.KMSClient against Google Cloud KMS (ADR-041).
// Like the awskms package, it is the only place the GCP KMS SDK is imported, so
// internal/crypto stays cloud-SDK-free. Credentials come from Application Default
// Credentials (GOOGLE_APPLICATION_CREDENTIALS / workload identity), never from
// Keyorix config. GCP KMS decrypts with the named crypto key, so the key is
// inherently pinned (the ciphertext cannot select a different key).
package gcpkms

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"log"
	"sort"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// gcpKMSAPI is the slice of the KMS client the provider uses — an interface seam so
// the SDK stays contained here and the AAD fallback is unit-testable.
type gcpKMSAPI interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

// AuditSink is a minimal audit-write hook, matching storage.Storage's
// LogAuditEvent method signature exactly (the identically-shaped type in
// internal/encryption/key_provider_downgrade.go is the precedent this mirrors) so
// a caller can pass that method value directly (e.g. after converting it, see
// encryption.Service.wireKMSAuditSink) without this package importing the full
// storage.Storage interface — internal/crypto sits below internal/storage in the
// dependency graph, so importing it here would be a cycle. Only
// internal/storage/models (plain structs, no storage-layer imports) is safe to
// depend on.
type AuditSink func(ctx context.Context, event *models.AuditEvent) error

// EventGCPKMSAADFallback is the audit event type recorded when
// kms_allow_context_fallback lets a context-bound Decrypt fall back to, and
// succeed against, an unbound (or differently-bound) ciphertext. This is a
// meaningful security-relevant event — the decrypted blob is not proven to
// belong to this install — so it is worth more than a process log line; see
// SetAuditSink.
const EventGCPKMSAADFallback = "crypto.gcpkms_aad_fallback" // #nosec G101 -- audit event type, not a credential

type client struct {
	kms           gcpKMSAPI
	keyName       string // projects/P/locations/L/keyRings/R/cryptoKeys/K
	aad           []byte // AdditionalAuthenticatedData binding the wrapped KEK (nil = none)
	allowFallback bool   // #123: opt-in, see KMSAllowContextFallback's doc comment
	// auditSink optionally records the AAD-fallback event (see
	// EventGCPKMSAADFallback) as a queryable audit event, in addition to the
	// unconditional log.Printf. Guarded by its own mutex since SetAuditSink may be
	// called concurrently with Decrypt (e.g. wired asynchronously after
	// construction).
	auditSink   AuditSink
	auditSinkMu sync.RWMutex
}

// SetAuditSink wires the audit sink this client uses to record the AAD-fallback
// security event (EventGCPKMSAADFallback) as more than a log line. Optional and
// safe to leave unset: the event is still always reported via the loud
// "gcp-kms:" log line Decrypt emits on a successful fallback either way. Safe to
// call concurrently with Decrypt.
func (c *client) SetAuditSink(sink AuditSink) {
	c.auditSinkMu.Lock()
	defer c.auditSinkMu.Unlock()
	c.auditSink = sink
}

// New builds a GCP-KMS-backed crypto.KMSClient for the given crypto-key resource
// name (projects/.../cryptoKeys/...). encContext, when non-empty, is bound to the
// wrapped KEK as AdditionalAuthenticatedData so a different install sharing the same
// key cannot unwrap it — UNLESS allowFallback is also set, in which case an
// AAD-bound Decrypt failure retries once without any AAD (see
// config.KeyProviderConfig.KMSAllowContextFallback for the full rationale; default
// false = the binding is strictly enforced).
func New(ctx context.Context, keyName string, encContext map[string]string, allowFallback bool) (keyorixcrypto.KMSClient, error) {
	if keyName == "" {
		return nil, fmt.Errorf("gcp-kms: kms_key_id (crypto key resource name) is required")
	}
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: create client: %w", err)
	}
	return &client{kms: c, keyName: keyName, aad: encContextAAD(encContext), allowFallback: allowFallback}, nil
}

// encContextAAD canonicalises an encryption-context map into deterministic,
// unambiguous bytes for use as GCP AdditionalAuthenticatedData. Returns nil for an
// empty map so the no-binding path is byte-identical to the prior behaviour.
//
// Each sorted (key, value) pair is written as a length-prefixed field
// (uvarint(len(s)) || s) with no separator byte between fields, so the encoding is
// injective over the sequence of strings: unlike a "key=value\n" join, no key or
// value content (including literal '=' or '\n' bytes) can shift a byte to look
// like it belongs to a neighbouring field, so two structurally different maps can
// never serialise to the same bytes. See TestEncContextAAD_NoCollisionOnAdversarialInput.
func encContextAAD(m map[string]string) []byte {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Upper bound: 2 fields per entry, each up to binary.MaxVarintLen64 prefix
	// bytes plus its content.
	size := 0
	for _, k := range keys {
		size += binary.MaxVarintLen64 + len(k) + binary.MaxVarintLen64 + len(m[k])
	}
	buf := make([]byte, 0, size)
	var lenBuf [binary.MaxVarintLen64]byte
	writeField := func(s string) {
		n := binary.PutUvarint(lenBuf[:], uint64(len(s)))
		buf = append(buf, lenBuf[:n]...)
		buf = append(buf, s...)
	}
	for _, k := range keys {
		writeField(k)
		writeField(m[k])
	}
	return buf
}

// crc32cSum computes the CRC32C (Castagnoli) checksum GCP KMS's Encrypt/Decrypt
// API uses for request/response integrity verification.
func crc32cSum(b []byte) uint32 {
	return crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	req := &kmspb.EncryptRequest{
		Name:            c.keyName,
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32cSum(plaintext))),
	}
	if len(c.aad) > 0 {
		req.AdditionalAuthenticatedData = c.aad
		req.AdditionalAuthenticatedDataCrc32C = wrapperspb.Int64(int64(crc32cSum(c.aad)))
	}
	resp, err := c.kms.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: encrypt: %w", err)
	}
	// Per Google's Cloud KMS client guidance: a request checksum that KMS did not
	// report back as verified means the server either never received it correctly
	// or never used it, either of which is grounds to distrust this response rather
	// than silently trust plaintext that may have been corrupted in transit.
	if !resp.GetVerifiedPlaintextCrc32C() {
		return nil, fmt.Errorf("gcp-kms: encrypt: server did not report the plaintext checksum as verified (possible request corruption)")
	}
	if len(c.aad) > 0 && !resp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return nil, fmt.Errorf("gcp-kms: encrypt: server did not report the AAD checksum as verified (possible request corruption)")
	}
	ciphertext := resp.GetCiphertext()
	if got := resp.GetCiphertextCrc32C(); got == nil || int64(crc32cSum(ciphertext)) != got.GetValue() {
		return nil, fmt.Errorf("gcp-kms: encrypt: ciphertext checksum mismatch (possible response corruption)")
	}
	return ciphertext, nil
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	ciphertextCRC := wrapperspb.Int64(int64(crc32cSum(ciphertext)))
	req := &kmspb.DecryptRequest{Name: c.keyName, Ciphertext: ciphertext, CiphertextCrc32C: ciphertextCRC}
	if len(c.aad) > 0 {
		req.AdditionalAuthenticatedData = c.aad
		req.AdditionalAuthenticatedDataCrc32C = wrapperspb.Int64(int64(crc32cSum(c.aad)))
	}
	resp, err := c.kms.Decrypt(ctx, req)
	// #123: the no-AAD retry is now OPT-IN (allowFallback) rather than automatic on any
	// failure — see awskms.Decrypt's comment for the full rationale (identical here: an
	// unconditional fallback makes the AAD binding advisory, since a blob an attacker
	// planted with no AAD at all always succeeds on the fallback attempt).
	fellBack := false
	if err != nil && len(c.aad) > 0 && c.allowFallback {
		resp, err = c.kms.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:             c.keyName,
			Ciphertext:       ciphertext,
			CiphertextCrc32C: ciphertextCRC,
		})
		fellBack = err == nil
	}
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: decrypt: %w", err)
	}
	plaintext := resp.GetPlaintext()
	if got := resp.GetPlaintextCrc32C(); got == nil || int64(crc32cSum(plaintext)) != got.GetValue() {
		return nil, fmt.Errorf("gcp-kms: decrypt: plaintext checksum mismatch (possible response corruption)")
	}
	if fellBack {
		msg := "gcp-kms: decrypted a wrapped KEK WITHOUT its configured AAD (insecure_allow_kms_context_fallback is on) — this blob is not bound to this install; re-wrap it under the context via 'keyorix encryption migrate-provider --to-kms-encryption-context=...' and disable insecure_allow_kms_context_fallback"
		log.Printf("%s", msg)
		c.emitFallbackAudit(ctx, msg)
	}
	return plaintext, nil
}

// emitFallbackAudit records the AAD-fallback event (see EventGCPKMSAADFallback)
// through the wired audit sink, if any. Best-effort: a sink write failure is
// logged but never propagated — the decrypt it's reporting on already succeeded
// by the time this runs and must not be undone by an audit-logging failure.
func (c *client) emitFallbackAudit(ctx context.Context, description string) {
	c.auditSinkMu.RLock()
	sink := c.auditSink
	c.auditSinkMu.RUnlock()
	if sink == nil {
		return
	}
	failed := false // the event itself reports a security-negative condition, not a success
	event := &models.AuditEvent{
		EventType:   EventGCPKMSAADFallback,
		Description: description,
		Success:     &failed,
		ActorType:   "system",
		EventTime:   time.Now(),
	}
	if err := sink(ctx, event); err != nil {
		log.Printf("gcp-kms: SECURITY: AAD fallback: failed to write audit event: %v", err)
	}
}
