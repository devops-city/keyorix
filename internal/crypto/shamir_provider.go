package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// kekShareMagic frames a KEK before splitting so a reconstruction can be checked:
// it precedes the embedded threshold and the KEK bytes in the split payload. A
// reconstruction from too-few/wrong shares yields garbage whose first bytes will
// not equal the magic, so combineKEK rejects it — making sub-threshold unseal
// fail closed even on a FRESH install (where there is no existing wrapped DEK to
// fail against). The byte after the magic carries the threshold K so the provider
// can enforce that at least K shares were actually supplied.
//
// #429: this magic is NOT a cryptographic integrity check and must never be relied
// on as one. Because each byte of the split payload is the constant term of an
// INDEPENDENT Lagrange polynomial evaluated at the same set of share x-coordinates,
// an attacker holding threshold-1 genuine shares can forge one additional share by
// picking any x-coordinate and solving, independently per output byte, for the
// y-value that makes the interpolation land on a chosen byte — including the magic
// bytes AND every KEK byte simultaneously. Embedding a bigger/stronger check INSIDE
// the split payload (e.g. a hash of the KEK next to it) would not help: it is just
// as forgeable, one byte at a time, as the 4-byte magic is. Real protection has to
// come from a value that is NOT itself reconstructed via interpolation — see
// kekCommitment below, verified against a value stored outside the Shamir shares.
const kekShareMagic = "KXK1"

// kekFrameLen is the framed-payload length: magic + 1 threshold byte + KEK.
const kekFrameLen = len(kekShareMagic) + 1 + KEKSize

// kekCommitmentContext domain-separates the KEK integrity commitment (#429) from any
// other HMAC/hash use of the same KEK bytes elsewhere in the codebase — it is a
// fixed, public label, not a secret.
const kekCommitmentContext = "keyorix-shamir-kek-commitment-v1"

// CommitKEK computes a public, one-way HMAC-SHA256 commitment to kek. Unlike
// kekShareMagic (embedded IN the Shamir-split payload and therefore forgeable — see
// its doc comment), this commitment is computed ONCE at split time from the real
// original KEK and must be stored OUTSIDE the Shamir shares (e.g. in the server's
// own config, alongside — not as part of — the share files/env vars). At
// reconstruction time, ShamirKeyProvider recomputes this same commitment over the
// RECONSTRUCTED KEK and compares it (constant-time) against the stored value: an
// attacker who forges a share fully controls the interpolated KEK bytes, but cannot
// make them hash to a commitment they never see and cannot influence, since it isn't
// part of the interpolation at all. The commitment is safe to store in the clear —
// it is one-way and reveals nothing about the KEK — so it can live right next to the
// shares' own metadata/config without weakening anything.
func CommitKEK(kek []byte) []byte {
	mac := hmac.New(sha256.New, []byte(kekCommitmentContext))
	mac.Write(kek)
	return mac.Sum(nil)
}

// SplitKEK frames a 32-byte KEK (magic ‖ threshold ‖ KEK) and Shamir-splits it into
// parts shares with the given threshold. Reconstructing with combineKEK then both
// recovers the KEK and verifies enough correct shares were combined. Callers should
// also persist CommitKEK(kek) (see its doc comment) so combineKEK can be given a
// real cryptographic commitment to verify against, not just the forgeable magic.
func SplitKEK(kek []byte, parts, threshold int) ([][]byte, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("shamir: KEK must be %d bytes, got %d", KEKSize, len(kek))
	}
	if threshold < 2 || threshold > 255 {
		return nil, fmt.Errorf("shamir: threshold must be between 2 and 255, got %d", threshold)
	}
	payload := make([]byte, 0, kekFrameLen)
	payload = append(payload, kekShareMagic...)
	payload = append(payload, byte(threshold))
	payload = append(payload, kek...)
	return Split(payload, parts, threshold)
}

// combineKEK reconstructs a KEK from shares produced by SplitKEK. It fails closed
// when the magic does not match (too few or incorrect shares were combined) or when
// fewer than the embedded threshold shares were supplied. If commitment is non-empty
// (the operator configured shamir_commitment — see CommitKEK), it ALSO verifies the
// reconstructed KEK against that commitment in constant time and rejects a mismatch;
// this is the real cryptographic defense against the share-forgery attack (#429) —
// the magic check alone cannot catch it. An empty commitment is accepted for
// backward compatibility with key material split before this check existed; the
// caller is responsible for warning loudly about the reduced verification strength
// in that case.
func combineKEK(shares [][]byte, commitment []byte) ([]byte, error) {
	payload, err := Combine(shares)
	if err != nil {
		return nil, err
	}
	if len(payload) != kekFrameLen || string(payload[:len(kekShareMagic)]) != kekShareMagic {
		return nil, fmt.Errorf("shamir: insufficient or incorrect shares — the reconstructed key failed its integrity check (supply at least the threshold many correct shares)")
	}
	threshold := int(payload[len(kekShareMagic)])
	if len(shares) < threshold {
		return nil, fmt.Errorf("shamir: %d shares supplied but the split requires %d (threshold)", len(shares), threshold)
	}
	kek, err := validateKEK(payload[len(kekShareMagic)+1:], "shamir")
	if err != nil {
		return nil, err
	}
	if len(commitment) > 0 {
		if !hmac.Equal(CommitKEK(kek), commitment) {
			return nil, fmt.Errorf("shamir: reconstructed KEK failed its commitment check (shamir_commitment mismatch) — this indicates a forged/incorrect share, refusing to unseal")
		}
	}
	return kek, nil
}

// ShamirKeyProvider reconstructs the KEK from K-of-N Shamir shares (ADR-038): no
// single custodian holds the key. Each configured source — a file path or an
// environment variable — carries one share (hex or base64 of the raw share bytes,
// as emitted by `keyorix encryption shamir-split`). At KEK() time it reads the
// supplied shares (the operator provides at least the threshold many) and combines
// them; the result must be exactly KEKSize bytes or the unseal fails closed (too
// few / wrong shares reconstruct garbage rather than the real key).
//
// commitmentHex, if set (shamir_commitment in config, also printed by
// `keyorix encryption shamir-split`), is the hex-encoded CommitKEK output computed
// at split time; KEK() verifies the reconstructed key against it (#429) — real
// cryptographic protection against a forged share, unlike the magic-byte framing
// check alone. Left empty for key material split before this existed; KEK() then
// logs a loud warning rather than hard-failing an existing legitimate deployment.
type ShamirKeyProvider struct {
	shareFiles    []string
	shareEnv      []string
	commitmentHex string
}

// NewShamirKeyProvider builds a provider from share file paths and/or env var names,
// and an optional hex-encoded KEK commitment (shamir_commitment; empty = not
// configured, see the ShamirKeyProvider doc comment for the security implication).
func NewShamirKeyProvider(shareFiles, shareEnv []string, commitmentHex string) *ShamirKeyProvider {
	return &ShamirKeyProvider{shareFiles: shareFiles, shareEnv: shareEnv, commitmentHex: commitmentHex}
}

func (p *ShamirKeyProvider) Name() string { return "shamir" }

func (p *ShamirKeyProvider) KEK() ([]byte, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	var shares [][]byte
	for _, path := range p.shareFiles {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path) // #nosec G304 -- operator-configured trusted share path
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: read share %s: %w", path, err)
		}
		share, err := decodeShare(bytes.TrimSpace(data))
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: share %s: %w", path, err)
		}
		shares = append(shares, share)
	}
	for _, envVar := range p.shareEnv {
		if envVar == "" {
			continue
		}
		val, found, err := secretenv.LookupChecked(envVar) // also honours <env var>_FILE; a too-open file is refused (share = key material)
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: %w", err)
		}
		if !found {
			return nil, fmt.Errorf("shamir key provider: env var %s is not set or empty", envVar)
		}
		share, err := decodeShare([]byte(val))
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: env var %s: %w", envVar, err)
		}
		shares = append(shares, share)
	}

	if len(shares) < 2 {
		return nil, fmt.Errorf("shamir key provider: need at least 2 shares, got %d", len(shares))
	}

	var commitment []byte
	if p.commitmentHex != "" {
		var err error
		commitment, err = hex.DecodeString(strings.TrimSpace(p.commitmentHex))
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: shamir_commitment is not valid hex: %w", err)
		}
	} else {
		// #429: without a stored commitment, reconstruction is verified ONLY by the
		// 4-byte magic framing check, which an attacker holding threshold-1 genuine
		// shares can forge (they fully control the interpolated bytes, magic included).
		// Not a hard failure — existing key material split before shamir_commitment
		// existed has no commitment to check — but this is a real reduction in
		// verification strength that every startup should surface loudly.
		//
		// #G61: this used to log.Fatalf (os.Exit) here, unlike every other
		// KeyProvider implementation, which returns an error and lets the caller
		// (MultiKeyProvider) fall back to another configured provider. A missing
		// shamir_commitment is a WEAKER verification posture, not an unrecoverable
		// condition — killing the whole process denied that fallback a chance to
		// run at all.
		log.Printf("WARNING: shamir key provider: no shamir_commitment configured — reconstruction relies solely on the forgeable magic-byte framing check, NOT a cryptographic integrity check (see issue #429); run `keyorix encryption shamir-split` again and set shamir_commitment to close this gap")
	}
	// combineKEK enforces the embedded threshold and verifies the framing magic, so
	// a sub-threshold or wrong set of shares fails closed here — including on a fresh
	// install, where there is no existing wrapped DEK for a wrong KEK to fail against.
	// When commitment is non-empty it also verifies the real cryptographic commitment
	// (#429), which the magic check alone cannot do.
	kek, err := combineKEK(shares, commitment)
	if err != nil {
		return nil, fmt.Errorf("shamir key provider: %w", err)
	}
	return kek, nil
}

// decodeShare accepts a Shamir share as raw bytes, hex, or base64 and returns the
// raw share bytes. Shares are KEKSize+1 bytes (a 1-byte x-coordinate), so unlike a
// KEK they are not a fixed-length match — decode by trying hex then base64, else
// treat the input as already-raw.
func decodeShare(material []byte) ([]byte, error) {
	s := strings.TrimSpace(string(material))
	if s == "" {
		return nil, fmt.Errorf("empty share")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) >= 2 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) >= 2 {
			return b, nil
		}
	}
	if len(material) >= 2 {
		return material, nil
	}
	return nil, fmt.Errorf("share must be raw bytes, hex, or base64 (at least 2 bytes)")
}
