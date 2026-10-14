// Package trust holds the asymmetric (ed25519) verification foundation for Keyorix's
// air-gapped update bundles and offline licenses (ADR-062, Phase 0). It is deliberately
// verify-only: it knows a set of *trusted public keys*, pinned at build time, and never
// holds a private key. Keyorix signs bundles/licenses out-of-band with the matching
// private keys (which never ship); a deployment verifies against the embedded public key
// for the signature's key-id — so trust follows a pinned chain, not a self-described
// signature.
//
// This package has no callers in the running server/CLI paths yet; the bundle/license
// phases (ADR-062 Phases 1–2) build on it.
package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Purpose scopes a key to one use, so an update-signing key can never validate a license
// (independent blast radii). This is enforced, not just a naming convention: Add refuses to
// register the same raw public key under two different purposes (see Add below) — because an
// ed25519 signature carries no purpose tag of its own, a key shared across purposes would
// otherwise let a signature valid for one purpose (e.g. an update manifest) verify as valid
// for the other (e.g. a license), defeating the independent-blast-radii guarantee entirely.
type Purpose string

const (
	PurposeUpdate  Purpose = "update"
	PurposeLicense Purpose = "license"
)

var (
	// ErrNoKeys means no trusted key is configured for the purpose — a release build
	// embeds them; a plain `go build` has none, so verification fails closed.
	ErrNoKeys = errors.New("trust: no trusted keys configured for purpose")
	// ErrUnknownKey means the signature names a key-id not in the trusted set.
	ErrUnknownKey = errors.New("trust: no trusted key for key-id")
	// ErrBadSignature means the signature did not verify against the trusted key.
	ErrBadSignature = errors.New("trust: signature verification failed")
	// ErrKeyReusedAcrossPurposes means Add was asked to register a public key that is
	// already trusted under a different purpose. Refused: see the Purpose doc comment.
	ErrKeyReusedAcrossPurposes = errors.New("trust: public key is already trusted for a different purpose")
)

// KeyRegistry holds trusted public keys keyed by purpose and key-id.
//
// #G63: mu guards keys. This package has no caller in the current live
// request path (see the package doc above), but Add is an exported mutator
// on a plain map with no synchronization of its own — a future runtime
// key-rotation caller (ADR-062 Phases 1-2 build on this package) racing a
// concurrent Verify/KeyIDs read would be a real, unsynchronized map access,
// not just a theoretical one.
type KeyRegistry struct {
	mu   sync.RWMutex
	keys map[Purpose]map[string]ed25519.PublicKey
}

// NewRegistry returns an empty registry.
func NewRegistry() *KeyRegistry {
	return &KeyRegistry{keys: make(map[Purpose]map[string]ed25519.PublicKey)}
}

// Add trusts pub for (purpose, keyID). It rejects a key of the wrong size, and — this is the
// enforcement point for the Purpose doc comment's "independent blast radii" guarantee — it
// refuses to register a public key that is already trusted under a DIFFERENT purpose.
//
// Without this check, the purpose scoping is purely a naming/registration convention: an
// ed25519 signature carries no domain/purpose tag of its own, so if the SAME key were ever
// registered under both PurposeUpdate and PurposeLicense (by operator mistake, or a build
// misconfiguration that embeds the same key material for both -X vars), a signature produced
// for one purpose would trivially verify as valid for the other too. Catching the reuse here,
// at registration time, means the mistake fails the whole registry construction (e.g.
// DefaultRegistry() at process startup) instead of silently weakening trust at verify time.
//
// A re-Add of the SAME key under the SAME purpose (e.g. under a different key-id, for
// rotation) is unaffected — only cross-purpose reuse is refused.
func (r *KeyRegistry) Add(purpose Purpose, keyID string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("trust: bad public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return fmt.Errorf("trust: key-id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for otherPurpose, ids := range r.keys {
		if otherPurpose == purpose {
			continue
		}
		for otherKeyID, otherPub := range ids {
			if bytes.Equal(otherPub, pub) {
				return fmt.Errorf("%w: key-id %q (purpose %q) is the same public key already trusted as key-id %q for purpose %q",
					ErrKeyReusedAcrossPurposes, keyID, purpose, otherKeyID, otherPurpose)
			}
		}
	}
	if r.keys[purpose] == nil {
		r.keys[purpose] = make(map[string]ed25519.PublicKey)
	}
	r.keys[purpose][keyID] = pub
	return nil
}

// Verify checks that sig is a valid ed25519 signature over message by the trusted key
// for (purpose, keyID). It fails closed: an unconfigured purpose, an unknown key-id, or a
// bad signature all return an error.
func (r *KeyRegistry) Verify(purpose Purpose, keyID string, message, sig []byte) error {
	r.mu.RLock()
	pub, ok := r.keys[purpose][keyID]
	noKeysForPurpose := len(r.keys[purpose]) == 0
	r.mu.RUnlock()
	if noKeysForPurpose {
		return fmt.Errorf("%w (%s)", ErrNoKeys, purpose)
	}
	if !ok {
		return fmt.Errorf("%w (%s/%s)", ErrUnknownKey, purpose, keyID)
	}
	if !ed25519.Verify(pub, message, sig) {
		return ErrBadSignature
	}
	return nil
}

// KeyIDs lists the trusted key-ids for a purpose, sorted (for logging/diagnostics).
func (r *KeyRegistry) KeyIDs(purpose Purpose) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.keys[purpose]))
	for id := range r.keys[purpose] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// GenerateKey mints a fresh ed25519 keypair (used by `keyorix trust keygen`). The private
// key is the signing secret — it must be stored offline and never shipped.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodePublicKeyBase64 renders a public key as standard base64 — the form embedded at
// build time (see keys.go) and printed by keygen.
func EncodePublicKeyBase64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// parseKeySpec parses a comma-separated "keyID=base64pub" spec (the build-time embedding
// format) into a key-id → public-key map. An empty spec yields an empty map (no trust).
func parseKeySpec(spec string) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey)
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
			return nil, fmt.Errorf("trust: bad key spec %q (want keyID=base64)", part)
		}
		keyID := strings.TrimSpace(kv[0])
		if _, dup := out[keyID]; dup {
			return nil, fmt.Errorf("trust: duplicate key-id %q in spec", keyID)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(kv[1]))
		if err != nil {
			return nil, fmt.Errorf("trust: key %q: decode: %w", keyID, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trust: key %q: bad size %d", keyID, len(raw))
		}
		out[keyID] = ed25519.PublicKey(raw)
	}
	return out, nil
}
