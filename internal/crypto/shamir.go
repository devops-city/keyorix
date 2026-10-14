// shamir.go — Shamir's Secret Sharing over GF(2^8) (Rijndael field, reducing
// polynomial 0x11b). Split a secret into N shares such that any K reconstruct it
// and any K-1 reveal nothing. Keyorix uses it to split the 32-byte KEK across
// custodians (ADR-038): no single party holds the key, and K-of-N must combine
// their shares to unseal — separation of duties for the master key.
//
// Dependency-free and byte-wise: each secret byte is the constant term of an
// independent degree-(K-1) polynomial; a share is the polynomial evaluations at a
// distinct non-zero x plus that x as the final byte. Reconstruction is Lagrange
// interpolation at x=0.
package crypto

import (
	"crypto/rand"
	"fmt"
	"slices"
)

// gfMul multiplies two GF(2^8) elements (Russian-peasant, reducing by 0x11b).
func gfMul(a, b byte) byte {
	var p byte
	for range 8 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // x^8 ≡ x^4+x^3+x+1 (the 0x11b reduction, low byte)
		}
		b >>= 1
	}
	return p
}

// gfPow raises a to the e-th power in GF(2^8) (square-and-multiply).
func gfPow(a byte, e int) byte {
	r := byte(1)
	base := a
	for e > 0 {
		if e&1 == 1 {
			r = gfMul(r, base)
		}
		base = gfMul(base, base)
		e >>= 1
	}
	return r
}

// gfInv returns the multiplicative inverse of a (a^254, since a^255 = 1 for a != 0).
// a must be non-zero (callers only invert differences of distinct x-coordinates).
func gfInv(a byte) byte { return gfPow(a, 254) }

// gfEval evaluates the polynomial with the given coefficients (constant term first)
// at x, via Horner's method in GF(2^8).
func gfEval(coeffs []byte, x byte) byte {
	var r byte
	for _, coeff := range slices.Backward(coeffs) {
		r = gfMul(r, x) ^ coeff
	}
	return r
}

// Split divides secret into parts shares, of which any threshold reconstruct it.
// 2 <= threshold <= parts <= 255. Each returned share is len(secret)+1 bytes: the
// secret-byte evaluations followed by the share's distinct x-coordinate.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("shamir: cannot split an empty secret")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("shamir: threshold must be at least 2, got %d", threshold)
	}
	if parts < threshold {
		return nil, fmt.Errorf("shamir: parts (%d) must be >= threshold (%d)", parts, threshold)
	}
	if parts > 255 {
		return nil, fmt.Errorf("shamir: parts must be <= 255, got %d", parts)
	}

	shares := make([][]byte, parts)
	for i := range shares {
		s := make([]byte, len(secret)+1)
		s[len(secret)] = byte(i + 1) // distinct non-zero x-coordinate (1..parts)
		shares[i] = s
	}

	// Each secret byte is the constant term of an independent random degree-(K-1)
	// polynomial; evaluate it at every share's x-coordinate.
	coeffs := make([]byte, threshold)
	for bi, sb := range secret {
		coeffs[0] = sb
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("shamir: read randomness: %w", err)
		}
		for _, s := range shares {
			s[bi] = gfEval(coeffs, s[len(secret)])
		}
	}
	return shares, nil
}

// Combine reconstructs the secret from shares (any threshold-many of the original
// shares). It requires >= 2 shares of equal length with distinct, non-zero
// x-coordinates. Supplying fewer than the original threshold returns a well-formed
// but incorrect secret (that is the security property — it reveals nothing), so the
// caller must validate the result (e.g. that the KEK round-trips).
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("shamir: need at least 2 shares, got %d", len(shares))
	}
	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, fmt.Errorf("shamir: shares must be at least 2 bytes")
	}
	secretLen := shareLen - 1

	xs := make([]byte, len(shares))
	seen := make(map[byte]bool, len(shares))
	for i, s := range shares {
		if len(s) != shareLen {
			return nil, fmt.Errorf("shamir: shares have mismatched lengths")
		}
		x := s[secretLen]
		if x == 0 {
			return nil, fmt.Errorf("shamir: share has invalid zero x-coordinate")
		}
		if seen[x] {
			return nil, fmt.Errorf("shamir: duplicate share x-coordinate %d", x)
		}
		seen[x] = true
		xs[i] = x
	}

	secret := make([]byte, secretLen)
	ys := make([]byte, len(shares))
	for bi := range secretLen {
		for i, s := range shares {
			ys[i] = s[bi]
		}
		secret[bi] = interpolateAtZero(xs, ys)
	}
	return secret, nil
}

// interpolateAtZero evaluates the Lagrange interpolation of the points (xs[i],ys[i])
// at x=0 in GF(2^8). In this field subtraction is XOR and negation is identity, so
// (0 - x_j) = x_j and (x_i - x_j) = x_i ^ x_j.
func interpolateAtZero(xs, ys []byte) byte {
	var result byte
	for i := range xs {
		num := byte(1)
		den := byte(1)
		for j := range xs {
			if i == j {
				continue
			}
			num = gfMul(num, xs[j])
			den = gfMul(den, xs[i]^xs[j])
		}
		result ^= gfMul(ys[i], gfMul(num, gfInv(den)))
	}
	return result
}
