package encryption

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const compatPass = "correct horse battery staple"

// fakeKMS is an in-memory envelope cipher for the KMS-provider round-trip test.
type fakeKMS struct{}

func (fakeKMS) Encrypt(_ context.Context, pt []byte) ([]byte, error) {
	return append([]byte("wrapped|"), pt...), nil
}
func (fakeKMS) Decrypt(_ context.Context, ct []byte) ([]byte, error) {
	return ct[len("wrapped|"):], nil
}

// TestKeyProvider_PasswordIsBackwardCompatible is the load-bearing guarantee of
// ADR-038: a KeyManager using the new PasswordKeyProvider must unwrap a DEK that
// was created by the LEGACY passphrase+salt path — i.e. the KEK derivation is
// byte-identical, so existing encrypted deployments are unaffected.
func TestKeyProvider_PasswordIsBackwardCompatible(t *testing.T) {
	dir := t.TempDir()

	// Legacy path: no provider set → ensureSaltExists + GenerateKEK(600000).
	legacy := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, legacy.Initialize(compatPass))
	legacyDEK := append([]byte(nil), legacy.GetDEK()...)
	require.Len(t, legacyDEK, 32)

	// New path over the SAME files: PasswordKeyProvider derives the KEK and must
	// unwrap the identical DEK (passphrase arg ignored by the provider branch).
	viaProvider := NewKeyManager(dir, "dek.key", "kek.salt")
	viaProvider.SetKeyProvider(crypto.NewPasswordKeyProvider(compatPass, dir, "kek.salt"))
	require.NoError(t, viaProvider.Initialize(""))
	assert.Equal(t, legacyDEK, viaProvider.GetDEK(),
		"the password provider must unwrap a DEK created by the legacy derivation")

	// A wrong passphrase must fail to unwrap (the GCM auth check).
	wrong := NewKeyManager(dir, "dek.key", "kek.salt")
	wrong.SetKeyProvider(crypto.NewPasswordKeyProvider("not-the-passphrase", dir, "kek.salt"))
	require.Error(t, wrong.Initialize(""))
}

// roundTrip initialises a KeyManager with the given provider, captures its DEK,
// then re-initialises a fresh KeyManager over the same files and asserts the DEK
// unwraps identically — i.e. the provider's KEK is stable and the wrapped DEK
// persists correctly.
func roundTrip(t *testing.T, dir string, mk func() crypto.KeyProvider) {
	t.Helper()
	km1 := NewKeyManager(dir, "dek.key", "kek.salt")
	km1.SetKeyProvider(mk())
	require.NoError(t, km1.Initialize(""))
	dek1 := append([]byte(nil), km1.GetDEK()...)
	require.Len(t, dek1, 32)

	km2 := NewKeyManager(dir, "dek.key", "kek.salt")
	km2.SetKeyProvider(mk())
	require.NoError(t, km2.Initialize(""))
	assert.Equal(t, dek1, km2.GetDEK(), "the same provider must unwrap the same DEK across restarts")
}

func TestKeyProvider_FileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek.bin")
	raw := bytes.Repeat([]byte{0xAB}, 32)
	require.NoError(t, os.WriteFile(keyPath, raw, 0600))
	roundTrip(t, dir, func() crypto.KeyProvider { return crypto.NewFileKeyProvider(keyPath) })
}

func TestKeyProvider_EnvRoundTrip(t *testing.T) {
	dir := t.TempDir()
	raw := bytes.Repeat([]byte{0x5C}, 32)
	t.Setenv("KX_COMPAT_KEK", base64.StdEncoding.EncodeToString(raw))
	roundTrip(t, dir, func() crypto.KeyProvider { return crypto.NewEnvKeyProvider("KX_COMPAT_KEK") })
}

// TestKeyProvider_ShamirRoundTrip proves a Shamir-reconstructed KEK wraps/unwraps
// the DEK end-to-end: a KEK is split into shares written to disk, and a KeyManager
// using K of those shares unwraps the identical DEK across restarts.
func TestKeyProvider_ShamirRoundTrip(t *testing.T) {
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0x3D}, 32)
	shares, err := crypto.SplitKEK(kek, 5, 3)
	require.NoError(t, err)
	var files []string
	for i := range 3 { // write the threshold-many shares
		p := filepath.Join(dir, "share-"+string(rune('a'+i)))
		require.NoError(t, os.WriteFile(p, []byte(hex.EncodeToString(shares[i])), 0600))
		files = append(files, p)
	}
	commitmentHex := hex.EncodeToString(crypto.CommitKEK(kek))
	roundTrip(t, dir, func() crypto.KeyProvider { return crypto.NewShamirKeyProvider(files, nil, commitmentHex) })
}

// TestKeyProvider_KMSRoundTrip proves a KMS-envelope KEK wraps/unwraps the DEK
// end-to-end: the KEK is generated and KMS-wrapped on first init, and a fresh
// KeyManager over the same wrapped-blob + KMS unwraps the identical DEK.
func TestKeyProvider_KMSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	roundTrip(t, dir, func() crypto.KeyProvider {
		return crypto.NewKMSKeyProvider(fakeKMS{}, "aws-kms", dir, "kek.kms")
	})
}

// TestKeyProvider_DEKRotationUnderProvider verifies that rotating the DEK while a
// file provider sources the KEK re-wraps the NEW DEK with that same KEK, so a
// fresh KeyManager reads the rotated DEK back.
func TestKeyProvider_DEKRotationUnderProvider(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek.bin")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x11}, 32), 0600))

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(crypto.NewFileKeyProvider(keyPath))
	require.NoError(t, km.Initialize(""))
	before := append([]byte(nil), km.GetDEK()...)

	require.NoError(t, km.RotateDEKWithSweep("", func(_, _ *EncryptionService, _ string) error {
		return nil
	})) // exercises re-wrap under a provider
	after := km.GetDEK()
	assert.NotEqual(t, before, after, "rotation must produce a new DEK")

	// A fresh manager with the same KEK source unwraps the rotated DEK.
	km2 := NewKeyManager(dir, "dek.key", "kek.salt")
	km2.SetKeyProvider(crypto.NewFileKeyProvider(keyPath))
	require.NoError(t, km2.Initialize(""))
	assert.Equal(t, after, km2.GetDEK(), "the rotated DEK must unwrap with the provider KEK")
}

// TestService_FileProviderEndToEnd exercises the full Service path: a file-provider
// KEK encrypts a secret, and a fresh Service over the same files decrypts it.
func TestService_FileProviderEndToEnd(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek.bin")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0600))
	cfg := &config.EncryptionConfig{
		Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt",
		KeyProvider: config.KeyProviderConfig{Type: "file", FilePath: keyPath},
	}

	s1 := NewService(cfg, dir)
	require.NoError(t, s1.Initialize("")) // no passphrase needed for the file provider
	ct, _, err := s1.EncryptSecret([]byte("super-secret-value"))
	require.NoError(t, err)

	s2 := NewService(cfg, dir)
	require.NoError(t, s2.Initialize(""))
	pt, err := s2.DecryptSecret(ct)
	require.NoError(t, err)
	assert.Equal(t, "super-secret-value", string(pt))
}
