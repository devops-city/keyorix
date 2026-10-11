package crypto

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func secretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestResolvePassphrase_EnvFileVariant(t *testing.T) {
	t.Setenv("KX_PASS_FILE", secretFile(t, "s3cret pass\n"))
	got, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
	require.NoError(t, err)
	assert.Equal(t, "s3cret pass", string(got))
}

func TestResolvePassphrase_BothEnvAndFileRefuses(t *testing.T) {
	t.Setenv("KX_PASS", "from-env")
	t.Setenv("KX_PASS_FILE", secretFile(t, "from-file\n"))
	got, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "KX_PASS_FILE")
	assert.NotContains(t, err.Error(), "from-env")
	assert.NotContains(t, err.Error(), "from-file")
}

func TestResolvePassphrase_EnvFileUnreadableRefuses(t *testing.T) {
	t.Setenv("KX_PASS_FILE", filepath.Join(t.TempDir(), "missing"))
	_, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
	require.Error(t, err)
}

func TestEnvKeyProvider_FileVariant(t *testing.T) {
	kek := testKEK()
	t.Setenv("KX_KEK_FILE", secretFile(t, hex.EncodeToString(kek)+"\n"))
	got, err := NewEnvKeyProvider("KX_KEK").KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

func TestEnvKeyProvider_BothSetRefuses(t *testing.T) {
	kek := testKEK()
	t.Setenv("KX_KEK", hex.EncodeToString(kek))
	t.Setenv("KX_KEK_FILE", secretFile(t, hex.EncodeToString(kek)))
	_, err := NewEnvKeyProvider("KX_KEK").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KX_KEK_FILE")
}

func TestShamirKeyProvider_EnvShareFileVariant(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)
	f1 := secretFile(t, hex.EncodeToString(shares[0]))
	f2 := secretFile(t, hex.EncodeToString(shares[1]))
	t.Setenv("KX_SH_FILE_SHARE3_FILE", secretFile(t, hex.EncodeToString(shares[2])+"\n"))
	commitment := hex.EncodeToString(CommitKEK(kek))
	got, err := NewShamirKeyProvider([]string{f1, f2}, []string{"KX_SH_FILE_SHARE3"}, commitment).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

func secretFileMode(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := secretFile(t, content)
	require.NoError(t, os.Chmod(p, mode))
	return p
}

// Key material (master password, KEK, Shamir share) supplied via NAME_FILE is
// refused when the file is more open than 0600/0400 -- on every path that
// resolves it, with no override and no warn-only mode.
func TestKeyMaterialFiles_TooOpenRefused(t *testing.T) {
	kek := testKEK()
	shares, err := SplitKEK(kek, 5, 3)
	require.NoError(t, err)
	f1 := secretFile(t, hex.EncodeToString(shares[0]))
	f2 := secretFile(t, hex.EncodeToString(shares[1]))
	commitment := hex.EncodeToString(CommitKEK(kek))

	for _, mode := range []os.FileMode{0o640, 0o440, 0o644, 0o660, 0o604} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Setenv("KX_PASS_FILE", secretFileMode(t, "TOPSECRETPASS\n", mode))
			got, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
			require.Error(t, err, "master password")
			assert.Nil(t, got)
			assert.NotContains(t, err.Error(), "TOPSECRETPASS")

			t.Setenv("KX_KEK_FILE", secretFileMode(t, hex.EncodeToString(kek), mode))
			_, err = NewEnvKeyProvider("KX_KEK").KEK()
			require.Error(t, err, "env KEK")

			t.Setenv("KX_SH3_FILE", secretFileMode(t, hex.EncodeToString(shares[2]), mode))
			_, err = NewShamirKeyProvider([]string{f1, f2}, []string{"KX_SH3"}, commitment).KEK()
			require.Error(t, err, "shamir share")
		})
	}
}

func TestKeyMaterialFiles_StrictModesAccepted(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		t.Setenv("KX_PASS_FILE", secretFileMode(t, "pass\n", mode))
		got, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
		require.NoError(t, err, mode.String())
		assert.Equal(t, "pass", string(got))
	}
}

// The file source strips exactly one trailing newline and nothing else -- the
// same bytes --passphrase-file yields, so both derive the same KEK. (The plain
// environment variable keeps its historical whitespace trim.)
func TestResolvePassphrase_FileTrimsExactlyOneNewlineLikePassphraseFile(t *testing.T) {
	for _, content := range []string{"  pa ss  \n", "pass\r\n", "pass\n\n", "pass\r", "pass\n\r", "pass\r\r\n"} {
		p := secretFile(t, content)
		t.Setenv("KX_PASS_FILE", p)
		fromEnvFile, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
		require.NoError(t, err)
		fromFlag, err := ResolvePassphrase(PassphraseSource{FilePath: p}, "KX_PASS")
		require.NoError(t, err)
		assert.Equal(t, string(fromFlag), string(fromEnvFile), "content %q", content)
	}
	t.Setenv("KX_PASS_FILE", secretFile(t, "  pa ss  \n"))
	got, err := ResolvePassphrase(PassphraseSource{}, "KX_PASS")
	require.NoError(t, err)
	assert.Equal(t, "  pa ss  ", string(got), "surrounding spaces are part of the passphrase")
}
