package rules

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK parsing for OIDC federation and SSO: turns one JSON Web Key from an
// issuer's JWKS into a public key, with size and curve bounds. Moved from
// core/oidc_jwks.go (leaf package, see doc.go); the fetching, caching and
// egress rules stay in core.

// MaxRSABits caps the modulus size of an RSA key accepted from a JWKS. Without
// this, a compromised/malicious OIDC provider can serve an RSA key with an
// absurdly large modulus (tens of thousands of bits); modular exponentiation
// cost grows roughly cubically with modulus size, so a single oversized key
// makes every signature verification against it expensive. Worse, the key is
// cached for up to jwksCacheTTL and reused for every verification in that
// window, so the cost is paid repeatedly per request, not just once at fetch —
// a sustained DoS. 8192 bits comfortably exceeds any real-world RSA key size in
// production use (2048/3072/4096 are standard; NIST's own long-term guidance
// tops out at 15360) while still rejecting a maliciously oversized modulus.
//
// MinRSABits (#100) is the missing lower bound: without it, a compromised or
// MITM'd issuer could serve a trivially-weak key (e.g. 512 bits) that parses
// and caches fine but offers no real cryptographic assurance — the check above
// only ever guarded against a DoS-oversized key, never an undersized one. 2048
// is the practical minimum still considered acceptable for a signing key today.
const (
	MaxRSABits = 8192
	MinRSABits = 2048
)

// MaxRSAPublicExponent bounds the RSA public exponent accepted from a JWKS.
// Verification cost (modular exponentiation) grows with the bit length of the
// exponent, same as it does with the modulus — ParseJWK previously only
// checked that e was a positive int64 (i.e. anything up to ~63 bits), so a
// compromised/MITM'd issuer could pair an in-bounds [MinRSABits,MaxRSABits]
// modulus with a needlessly huge exponent and make every verification against
// that cached key several times more expensive than a normal e=65537 key —
// the same sustained-DoS shape MaxRSABits guards against, just via the other
// operand. 2^32 comfortably exceeds every exponent used in real-world
// deployments (3, 17, and 65537 are effectively universal; even unusual
// configurations don't approach this) while remaining far below the ~63-bit
// ceiling the int64 conversion otherwise allows.
const MaxRSAPublicExponent = 1 << 32

// JWK is one JSON Web Key (the subset of fields we verify with).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseJWK converts a JWK into an *rsa.PublicKey or *ecdsa.PublicKey.
func ParseJWK(k JWK) (any, error) { // NOSONAR -- cognitive complexity 17, suppress go:S3776
	switch k.Kty {
	case "RSA":
		n, err := b64uBigInt(k.N)
		if err != nil {
			return nil, err
		}
		if bits := n.BitLen(); bits < MinRSABits || bits > MaxRSABits {
			return nil, fmt.Errorf("rsa modulus size %d bits outside allowed range [%d,%d]", bits, MinRSABits, MaxRSABits)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("rsa e: %w", err)
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() <= 0 {
			return nil, fmt.Errorf("rsa e out of range")
		}
		if e.Int64() > MaxRSAPublicExponent {
			return nil, fmt.Errorf("rsa exponent %d exceeds allowed maximum %d", e.Int64(), int64(MaxRSAPublicExponent))
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err := b64uBigInt(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uBigInt(k.Y)
		if err != nil {
			return nil, err
		}
		// Explicit, independent bound-check on the raw coordinates, mirroring the
		// RSA modulus/exponent checks above: this file's own defense-in-depth
		// guarantee shouldn't rely solely on the underlying crypto/ecdsa (or
		// nistec) verification path rejecting an oversized or off-curve point —
		// that's an implementation detail of the Go toolchain in use, not a
		// contract ParseJWK controls. maxJWKSBytes bounds the whole JWKS response
		// but not an individual coordinate within it.
		fieldBits := curve.Params().BitSize
		if x.BitLen() > fieldBits || y.BitLen() > fieldBits {
			return nil, fmt.Errorf("ec coordinate size exceeds curve %q field size (%d bits)", k.Crv, fieldBits)
		}
		byteLen := (fieldBits + 7) / 8
		point := make([]byte, 1+2*byteLen)
		point[0] = 0x04
		x.FillBytes(point[1 : 1+byteLen])
		y.FillBytes(point[1+byteLen : 1+2*byteLen])
		// ParseUncompressedPublicKey both performs the on-curve check (replacing
		// the deprecated elliptic.Curve.IsOnCurve) and builds the *ecdsa.PublicKey
		// without directly writing its deprecated X/Y fields.
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("ec point is not on curve %q: %w", k.Crv, err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

func b64uBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}
