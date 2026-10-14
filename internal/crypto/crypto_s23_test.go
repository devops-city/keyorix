package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// EnvKeyProvider — raw 32-byte key material in an env var
// ---------------------------------------------------------------------------

// TestEnvKeyProvider_S23_RawBytesInEnv verifies that when the env var contains
// exactly KEKSize raw bytes (not encoded), the provider passes them through
// decodeKeyMaterial's first branch (len(material) == KEKSize).
func TestEnvKeyProvider_S23_RawBytesInEnv(t *testing.T) {
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(i + 11)
	}
	// os.Setenv round-trips arbitrary bytes through the process environment on
	// Linux/macOS (NUL is the only forbidden byte in posix env values).
	t.Setenv("KX_S23_RAW", string(raw))
	got, err := NewEnvKeyProvider("KX_S23_RAW").KEK()
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

// ---------------------------------------------------------------------------
// FileKeyProvider — empty path error message
// ---------------------------------------------------------------------------

// TestFileKeyProvider_S23_EmptyPathErrorText checks that the error returned for
// an empty file_path includes the expected diagnostic text.
func TestFileKeyProvider_S23_EmptyPathErrorText(t *testing.T) {
	_, err := NewFileKeyProvider("").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file_path is required")
}

// ---------------------------------------------------------------------------
// decodeKeyMaterial — raw-32-byte path exercised directly
// ---------------------------------------------------------------------------

// TestDecodeKeyMaterial_S23_Raw32BytePassThrough verifies that a 32-byte slice
// that is non-zero goes through the "already raw" fast path and is returned as-is.
func TestDecodeKeyMaterial_S23_Raw32BytePassThrough(t *testing.T) {
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(255 - i)
	}
	got, err := decodeKeyMaterial(raw, "test")
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

// TestDecodeKeyMaterial_S23_Raw32ByteAllZeroRejected checks that the all-zero
// guard is applied even on the raw-32-byte fast path.
func TestDecodeKeyMaterial_S23_Raw32ByteAllZeroRejected(t *testing.T) {
	_, err := decodeKeyMaterial(make([]byte, KEKSize), "raw-test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all-zero")
}

// ---------------------------------------------------------------------------
// combineKEK — reconstructed KEK fails validateKEK (all-zero payload KEK)
// ---------------------------------------------------------------------------

// TestCombineKEK_S23_AllZeroKEKInPayloadRejected crafts a split payload where the
// KEK portion is all-zero bytes (valid magic + threshold framing, but the KEK
// itself is the forbidden all-zero value) and confirms that combineKEK rejects it
// via validateKEK rather than returning zero key material.
func TestCombineKEK_S23_AllZeroKEKInPayloadRejected(t *testing.T) {
	// Build a framed payload with the magic, a threshold of 2, and an all-zero KEK.
	zeroKEK := make([]byte, KEKSize)
	payload := make([]byte, 0, kekFrameLen)
	payload = append(payload, kekShareMagic...)
	payload = append(payload, byte(2)) // threshold=2
	payload = append(payload, zeroKEK...)

	// Split the crafted payload (not a real KEK) into 2 shares with threshold 2.
	shares, err := Split(payload, 2, 2)
	require.NoError(t, err)

	_, err = combineKEK(shares, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all-zero")
}

// ---------------------------------------------------------------------------
// ShamirKeyProvider — minimum 2-of-2 split
// ---------------------------------------------------------------------------

// TestShamirKeyProvider_S23_TwoOfTwoSplit verifies that the ShamirKeyProvider
// correctly combines a 2-of-2 split (the minimum threshold) from two share files.
func TestShamirKeyProvider_S23_TwoOfTwoSplit(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 2, 2)
	require.NoError(t, err)

	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	commitmentHex := hex.EncodeToString(CommitKEK(kek))
	got, err := NewShamirKeyProvider([]string{f1, f2}, nil, commitmentHex).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

// TestShamirKeyProvider_S23_TwoSharesViaEnvOnly verifies that two env-var shares
// (no file shares) satisfy the minimum threshold of 2.
func TestShamirKeyProvider_S23_TwoSharesViaEnvOnly(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 2, 2)
	require.NoError(t, err)

	t.Setenv("KX_S23_ENVSHARE1", base64.StdEncoding.EncodeToString(shares[0]))
	t.Setenv("KX_S23_ENVSHARE2", base64.StdEncoding.EncodeToString(shares[1]))

	commitmentHex := hex.EncodeToString(CommitKEK(kek))
	got, err := NewShamirKeyProvider(nil, []string{"KX_S23_ENVSHARE1", "KX_S23_ENVSHARE2"}, commitmentHex).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

// ---------------------------------------------------------------------------
// decodeShare — base64 URL-safe input
// ---------------------------------------------------------------------------

// TestDecodeShare_S23_URLSafeBase64 exercises the URLEncoding and RawURLEncoding
// branches of decodeShare (not reachable from the existing share file/env tests
// which only use hex and StdEncoding).
func TestDecodeShare_S23_URLSafeBase64(t *testing.T) {
	// A 33-byte share (KEKSize + 1 x-coordinate byte).
	raw := make([]byte, KEKSize+1)
	for i := range raw {
		raw[i] = byte(i + 1)
	}

	for name, enc := range map[string]*base64.Encoding{
		"url-padded":   base64.URLEncoding,
		"url-unpadded": base64.RawURLEncoding,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeShare([]byte(enc.EncodeToString(raw)))
			require.NoError(t, err)
			assert.Equal(t, raw, got)
		})
	}
}

// ---------------------------------------------------------------------------
// gfInv — direct coverage
// ---------------------------------------------------------------------------

// TestGFInv_S23_InverseProperty verifies the multiplicative inverse property for
// every non-zero GF(2^8) element: a * a^-1 == 1.
func TestGFInv_S23_InverseProperty(t *testing.T) {
	for a := 1; a < 256; a++ {
		x := byte(a)
		assert.Equal(t, byte(1), gfMul(x, gfInv(x)), "a*gfInv(a)==1 for a=%d", a)
	}
}

// TestGFInv_S23_OneIsItsOwnInverse checks that gfInv(1) == 1 (the multiplicative
// identity is its own inverse).
func TestGFInv_S23_OneIsItsOwnInverse(t *testing.T) {
	assert.Equal(t, byte(1), gfInv(1))
}

// ---------------------------------------------------------------------------
// gfMul — zero operand branches
// ---------------------------------------------------------------------------

// TestGFMul_S23_ZeroOperand verifies that multiplying anything by zero in GF(2^8)
// always yields zero (the zero element is an absorbing element for multiplication).
func TestGFMul_S23_ZeroOperand(t *testing.T) {
	for a := range 256 {
		assert.Equal(t, byte(0), gfMul(byte(a), 0), "a*0==0 for a=%d", a)
		assert.Equal(t, byte(0), gfMul(0, byte(a)), "0*a==0 for a=%d", a)
	}
}

// ---------------------------------------------------------------------------
// stderrHint — boundary: exactly 200 bytes
// ---------------------------------------------------------------------------

// TestStderrHint_S23_ExactlyAtLimit checks that a 200-byte stderr payload is
// NOT truncated (the truncation triggers at > 200 bytes, not at exactly 200).
func TestStderrHint_S23_ExactlyAtLimit(t *testing.T) {
	exactly200 := bytes.Repeat([]byte("x"), 200)
	hint := stderrHint(exactly200)
	assert.NotContains(t, hint, "…", "exactly-200-byte stderr must not be truncated")
	assert.Contains(t, hint, string(exactly200))
}

// ---------------------------------------------------------------------------
// KMSKeyProvider — KMS returns all-zero KEK on decrypt
// ---------------------------------------------------------------------------

// TestKMSKeyProvider_S23_DecryptReturnsAllZeroKEK verifies that when the KMS
// decrypts a wrapped blob but returns all-zero bytes (a misconfigured or
// misbehaving KMS), validateKEK rejects the result rather than returning zero
// key material to the caller.
func TestKMSKeyProvider_S23_DecryptReturnsAllZeroKEK(t *testing.T) {
	dir := t.TempDir()
	// Persist a dummy wrapped blob so KEK() takes the decrypt (not generate) path.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "k.kms"), []byte("wrapped"), 0600))

	p := NewKMSKeyProvider(&zeroKMS{}, "test-kms", dir, "k.kms")
	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all-zero")
}

// zeroKMS always "decrypts" to a 32-byte all-zero slice.
type zeroKMS struct{}

func (zeroKMS) Encrypt(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (zeroKMS) Decrypt(_ context.Context, _ []byte) ([]byte, error) {
	return make([]byte, KEKSize), nil
}

// ---------------------------------------------------------------------------
// PasswordKeyProvider — empty passphrase error text
// ---------------------------------------------------------------------------

// TestPasswordKeyProvider_S23_EmptyPassphraseErrorText checks the exact error
// text returned when an empty passphrase is passed to KEK(). The outer check in
// keyprovider_test.go only asserts require.Error; this one asserts the message.
func TestPasswordKeyProvider_S23_EmptyPassphraseErrorText(t *testing.T) {
	_, err := NewPasswordKeyProvider("", t.TempDir(), "kek.salt").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passphrase must not be empty")
}

// ---------------------------------------------------------------------------
// ShamirKeyProvider — commitment hex with surrounding whitespace trimmed
// ---------------------------------------------------------------------------

// TestShamirKeyProvider_S23_CommitmentHexWithWhitespace verifies that
// commitmentHex values with leading/trailing whitespace (e.g. a config file
// with a trailing newline) are trimmed before hex.DecodeString so the
// verification still succeeds.
func TestShamirKeyProvider_S23_CommitmentHexWithWhitespace(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)

	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	// Commitment hex with leading/trailing whitespace.
	commitmentHex := "  " + hex.EncodeToString(CommitKEK(kek)) + "\n"

	got, err := NewShamirKeyProvider([]string{f1, f2}, nil, commitmentHex).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

// ---------------------------------------------------------------------------
// Split — parts == threshold (exact-coverage split)
// ---------------------------------------------------------------------------

// TestSplit_S23_PartsEqualsThreshold verifies the edge case where parts == threshold:
// every single share must be required for reconstruction.
func TestSplit_S23_PartsEqualsThreshold(t *testing.T) {
	secret := testKEK()
	shares, err := Split(secret, 3, 3)
	require.NoError(t, err)
	require.Len(t, shares, 3)

	got, err := Combine(shares)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

// ---------------------------------------------------------------------------
// Combine — mismatched lengths where second share is shorter
// ---------------------------------------------------------------------------

// TestCombine_S23_SecondShareShorterThanFirst exercises the mismatched-length
// branch in Combine when a later share is shorter than the first share. The
// existing mismatched-length test in shamir_test.go uses a longer second share;
// this covers the symmetric case.
func TestCombine_S23_SecondShareShorterThanFirst(t *testing.T) {
	s1 := []byte{0x01, 0x02, 0x03} // 3 bytes
	s2 := []byte{0x04, 0x05}       // 2 bytes (shorter)
	_, err := Combine([][]byte{s1, s2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mismatched")
}
