package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// decodeKeyMaterial — URL-safe base64 branches and error paths
// ---------------------------------------------------------------------------

// TestDecodeKeyMaterial_S22_URLBase64 verifies that decodeKeyMaterial accepts
// URL-safe base64 (both padded and raw/unpadded forms), since those branches
// are never exercised by the FileKeyProvider or EnvKeyProvider existing tests
// (which only test StdEncoding and RawStdEncoding).
func TestDecodeKeyMaterial_S22_URLBase64(t *testing.T) {
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(255 - i)
	}

	cases := map[string]string{
		"url-padded":   base64.URLEncoding.EncodeToString(raw),
		"url-unpadded": base64.RawURLEncoding.EncodeToString(raw),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := decodeKeyMaterial([]byte(encoded), "test")
			require.NoError(t, err)
			assert.Equal(t, raw, got)
		})
	}
}

// TestDecodeKeyMaterial_S22_RejectsGarbage covers the final error return of
// decodeKeyMaterial when the input is neither raw 32 bytes, valid hex, nor any
// base64 variant.
func TestDecodeKeyMaterial_S22_RejectsGarbage(t *testing.T) {
	_, err := decodeKeyMaterial([]byte("this-is-not-valid-key-material"), "myp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "myp key provider")
}

// TestDecodeKeyMaterial_S22_RejectsShortHex exercises the path where hex
// decoding succeeds but the decoded length is not KEKSize (e.g. 20-byte hex).
// A 16-byte input would itself be 32 chars which hits the raw-bytes path, so
// we use 20 bytes (40 hex chars) — a syntactically valid hex string that
// decodes to 20 bytes (not 32) and is not itself 32 bytes.
func TestDecodeKeyMaterial_S22_RejectsShortHex(t *testing.T) {
	short := hex.EncodeToString(make([]byte, 20)) // 40-char hex decoding to 20 bytes, not 32
	_, err := decodeKeyMaterial([]byte(short), "test")
	require.Error(t, err)
}

// TestDecodeKeyMaterial_S22_RejectsValidBase64ThatDecodesShort checks that a
// well-formed base64 string whose decoded length ≠ KEKSize is rejected.
func TestDecodeKeyMaterial_S22_RejectsValidBase64ThatDecodesShort(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 8))
	_, err := decodeKeyMaterial([]byte(short), "test")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// SplitKEK validation paths
// ---------------------------------------------------------------------------

// TestSplitKEK_S22_Validations exercises the guard checks inside SplitKEK
// itself — wrong KEK size, threshold < 2, threshold > 255 — which are distinct
// from the inner Split() validations already tested in shamir_test.go.
func TestSplitKEK_S22_WrongKEKSize(t *testing.T) {
	_, err := SplitKEK(make([]byte, 16), 3, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestSplitKEK_S22_ThresholdTooLow(t *testing.T) {
	kek := make([]byte, KEKSize)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	_, err := SplitKEK(kek, 3, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold")
}

func TestSplitKEK_S22_ThresholdTooHigh(t *testing.T) {
	kek := make([]byte, KEKSize)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	_, err := SplitKEK(kek, 3, 256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold")
}

// ---------------------------------------------------------------------------
// CommitKEK determinism and domain separation
// ---------------------------------------------------------------------------

// TestCommitKEK_S22_Deterministic verifies that CommitKEK returns the same
// 32-byte HMAC digest on every call for the same input.
func TestCommitKEK_S22_Deterministic(t *testing.T) {
	kek := testKEK()
	c1 := CommitKEK(kek)
	c2 := CommitKEK(kek)
	require.Len(t, c1, 32)
	assert.Equal(t, c1, c2)
}

// TestCommitKEK_S22_DifferentKEKsDifferentCommitments ensures two distinct KEKs
// produce distinct commitments (collision resistance at the unit level).
func TestCommitKEK_S22_DifferentKEKsDifferentCommitments(t *testing.T) {
	k1 := make([]byte, KEKSize)
	k2 := make([]byte, KEKSize)
	for i := range k1 {
		k1[i] = byte(i + 1)
		k2[i] = byte(255 - i)
	}
	assert.NotEqual(t, CommitKEK(k1), CommitKEK(k2))
}

// ---------------------------------------------------------------------------
// decodeShare — raw-bytes fallback path and short-input rejection
// ---------------------------------------------------------------------------

// TestDecodeShare_S22_RawBytesPassthrough verifies that when the input is
// already raw binary (not valid hex or base64), decodeShare returns it as-is
// provided it is at least 2 bytes long.
func TestDecodeShare_S22_RawBytesPassthrough(t *testing.T) {
	// A 33-byte blob whose contents are NOT valid hex or base64.
	raw := make([]byte, 33)
	for i := range raw {
		raw[i] = byte(i) | 0x80 // high-bit set prevents valid UTF-8 hex
	}
	got, err := decodeShare(raw)
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

// TestDecodeShare_S22_OneByteTooShort exercises the final rejection in
// decodeShare when the input is 1 byte (not hex, not base64, and < 2 bytes raw).
func TestDecodeShare_S22_OneByteTooShort(t *testing.T) {
	_, err := decodeShare([]byte{0xff})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2 bytes")
}

// TestDecodeShare_S22_EmptyString exercises the empty-string guard at the top
// of decodeShare.
func TestDecodeShare_S22_EmptyString(t *testing.T) {
	_, err := decodeShare([]byte(""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty share")
}

// TestDecodeShare_S22_WhitespaceOnlyIsEmpty exercises the whitespace-only input
// path (trimming leaves an empty string).
func TestDecodeShare_S22_WhitespaceOnlyIsEmpty(t *testing.T) {
	_, err := decodeShare([]byte("   \n\t  "))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty share")
}

// ---------------------------------------------------------------------------
// ShamirKeyProvider — empty-path skipping, empty-env skipping,
// invalid commitment hex, env-based provider errors
// ---------------------------------------------------------------------------

// TestShamirKeyProvider_S22_EmptyPathsSkipped checks that nil/empty strings in
// shareFiles are silently skipped (the `if path == "" { continue }` branch).
func TestShamirKeyProvider_S22_EmptyPathsSkipped(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)

	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	commitmentHex := hex.EncodeToString(CommitKEK(kek))
	// Include empty-string paths that must be silently skipped.
	got, err := NewShamirKeyProvider([]string{"", f1, "", f2, ""}, nil, commitmentHex).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

// TestShamirKeyProvider_S22_EmptyEnvVarsSkipped checks that empty strings in
// shareEnv are silently skipped (the `if envVar == "" { continue }` branch).
func TestShamirKeyProvider_S22_EmptyEnvVarsSkipped(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)

	f1 := filepath.Join(dir, "s1")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	t.Setenv("KX_S22_SHARE2", base64.StdEncoding.EncodeToString(shares[1]))

	commitmentHex := hex.EncodeToString(CommitKEK(kek))
	// One empty env-var name that must be skipped; the non-empty one carries the share.
	got, err := NewShamirKeyProvider([]string{f1}, []string{"", "KX_S22_SHARE2", ""}, commitmentHex).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

// TestShamirKeyProvider_S22_InvalidCommitmentHex verifies that a commitmentHex
// that is not valid hex is rejected (the hex.DecodeString error branch inside KEK()).
func TestShamirKeyProvider_S22_InvalidCommitmentHex(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)

	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	_, err = NewShamirKeyProvider([]string{f1, f2}, nil, "not-valid-hex!!").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shamir_commitment is not valid hex")
}

// TestShamirKeyProvider_S22_EnvShareGarbage exercises the path where an env var
// is set but its value is garbage that decodeShare rejects.
func TestShamirKeyProvider_S22_EnvShareGarbage(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := SplitKEK(kek, 3, 2)
	require.NoError(t, err)

	f1 := filepath.Join(dir, "s1")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	t.Setenv("KX_S22_GARBAGE_SHARE", "!") // single byte → decodeShare fails

	_, err = NewShamirKeyProvider([]string{f1}, []string{"KX_S22_GARBAGE_SHARE"}, "").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shamir key provider")
}

// ---------------------------------------------------------------------------
// Combine — zero x-coordinate and too-short share
// ---------------------------------------------------------------------------

// TestCombine_S22_ZeroXCoordinate exercises the `share has invalid zero
// x-coordinate` guard in Combine.
func TestCombine_S22_ZeroXCoordinate(t *testing.T) {
	// Build two syntactically valid 2-byte shares but give one an x=0.
	s1 := []byte{0x01, 0x01} // y=0x01, x=0x01 (valid)
	s2 := []byte{0x02, 0x00} // y=0x02, x=0x00 (invalid — zero x)
	_, err := Combine([][]byte{s1, s2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero x-coordinate")
}

// TestCombine_S22_ShareTooShort exercises the `shares must be at least 2 bytes`
// guard (shareLen < 2) in Combine.
func TestCombine_S22_ShareTooShort(t *testing.T) {
	_, err := Combine([][]byte{{0x01}, {0x02}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2 bytes")
}

// ---------------------------------------------------------------------------
// gfPow — zero exponent and identity
// ---------------------------------------------------------------------------

// TestGFPow_S22_ZeroExponent verifies that gfPow(a, 0) == 1 for any non-zero a
// (multiplicative identity: a^0 = 1 in GF(2^8)).
func TestGFPow_S22_ZeroExponent(t *testing.T) {
	for a := 1; a < 256; a++ {
		assert.Equal(t, byte(1), gfPow(byte(a), 0), "gfPow(%d, 0) must be 1", a)
	}
}

// TestGFPow_S22_ExponentOne verifies gfPow(a, 1) == a (trivial: squaring once
// then multiplying by identity == a).
func TestGFPow_S22_ExponentOne(t *testing.T) {
	for a := 1; a < 256; a++ {
		assert.Equal(t, byte(a), gfPow(byte(a), 1), "gfPow(%d, 1) must be %d", a, a)
	}
}

// ---------------------------------------------------------------------------
// gfEval — constant polynomial and zero-x evaluation
// ---------------------------------------------------------------------------

// TestGFEval_S22_ConstantPolynomial verifies that a single-coefficient (degree 0)
// polynomial evaluates to its constant term for any x.
func TestGFEval_S22_ConstantPolynomial(t *testing.T) {
	for c := range 256 {
		for x := 1; x < 16; x++ {
			assert.Equal(t, byte(c), gfEval([]byte{byte(c)}, byte(x)),
				"constant poly [%d] at x=%d", c, x)
		}
	}
}

// TestGFEval_S22_LinearPolynomial spot-checks a degree-1 polynomial: p(x)=a0+a1*x
// evaluated at x using GF(2^8) arithmetic.
func TestGFEval_S22_LinearPolynomial(t *testing.T) {
	// p(x) = 3 + 5*x in GF(2^8); p(2) = 3 XOR gfMul(5,2)
	a0, a1, x := byte(3), byte(5), byte(2)
	want := a0 ^ gfMul(a1, x)
	assert.Equal(t, want, gfEval([]byte{a0, a1}, x))
}

// ---------------------------------------------------------------------------
// PasswordKeyProvider — corrupt/wrong-size salt on disk
// ---------------------------------------------------------------------------

// TestPasswordKeyProvider_S22_WrongSaltSizeOnDisk exercises the
// `invalid salt size` branch in ensureSalt when the salt file exists but
// contains fewer than saltSize bytes.
func TestPasswordKeyProvider_S22_WrongSaltSizeOnDisk(t *testing.T) {
	dir := t.TempDir()
	// Write a salt file with the wrong size.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kek.salt"), make([]byte, 8), 0600))

	_, err := NewPasswordKeyProvider("passphrase", dir, "kek.salt").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid salt size")
}

// TestPasswordKeyProvider_S22_DifferentPassphraseDifferentKEK verifies that two
// providers sharing the same salt but different passphrases derive different KEKs.
func TestPasswordKeyProvider_S22_DifferentPassphraseDifferentKEK(t *testing.T) {
	dir := t.TempDir()
	k1, err := NewPasswordKeyProvider("hunter2", dir, "kek.salt").KEK()
	require.NoError(t, err)

	k2, err := NewPasswordKeyProvider("correcthorsebatterystaple", dir, "kek.salt").KEK()
	require.NoError(t, err)

	assert.NotEqual(t, k1, k2, "different passphrases must derive different KEKs")
}

// ---------------------------------------------------------------------------
// EnvKeyProvider — URL-safe base64 in env var
// ---------------------------------------------------------------------------

// TestEnvKeyProvider_S22_URLBase64 verifies that the env provider accepts
// URL-safe base64 key material (those branches in decodeKeyMaterial are only
// exercised here at the provider level).
func TestEnvKeyProvider_S22_URLBase64(t *testing.T) {
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(i + 7)
	}
	t.Setenv("KX_S22_URL_B64", base64.URLEncoding.EncodeToString(raw))
	got, err := NewEnvKeyProvider("KX_S22_URL_B64").KEK()
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

// TestEnvKeyProvider_S22_AllZeroHexRejected ensures the all-zero guard is not
// skippable by supplying a zero KEK via the env var (a rendered/unset secret
// can arrive as hex-encoded zeros).
func TestEnvKeyProvider_S22_AllZeroHexRejected(t *testing.T) {
	t.Setenv("KX_S22_ZERO_HEX", hex.EncodeToString(make([]byte, KEKSize)))
	_, err := NewEnvKeyProvider("KX_S22_ZERO_HEX").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all-zero")
}

// ---------------------------------------------------------------------------
// FileKeyProvider — CRLF trimming for encoded forms
// ---------------------------------------------------------------------------

// TestFileKeyProvider_S22_CRLFTrimmed verifies that a hex-encoded key file with
// a CRLF line ending (Windows-style) is decoded correctly (the bytes.TrimRight
// "\r\n" branch in FileKeyProvider.KEK()).
func TestFileKeyProvider_S22_CRLFTrimmed(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(i + 3)
	}
	content := []byte(hex.EncodeToString(raw) + "\r\n")
	path := filepath.Join(dir, "crlf.key")
	require.NoError(t, os.WriteFile(path, content, 0600))

	got, err := NewFileKeyProvider(path).KEK()
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}
