package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// #3410: --passphrase-file is key material, so the file must be owned by the
// running user or root (the #3393 rule), whatever its mode. The test cannot
// chown a file to a third account, so it uses secretenv's ownership hook: the
// file reports owner fileUID and the process runs as uid 1001.
func TestReadPassphraseFile_Owner(t *testing.T) {
	cases := []struct {
		name    string
		fileUID int
		refuse  bool
	}{
		{"owned by a third uid", 1000, true},
		{"owned by the running user", 1001, false},
		{"owned by root", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []os.FileMode{0o600, 0o400} {
				p := filepath.Join(t.TempDir(), "master-password")
				require.NoError(t, os.WriteFile(p, []byte("TOPSECRET\n"), 0o600))
				require.NoError(t, os.Chmod(p, mode))
				restore := secretenv.OverrideOwnershipForTest(tc.fileUID, 1001)
				got, err := ResolvePassphrase(PassphraseSource{FilePath: p}, "KX_UNUSED")
				restore()
				if !tc.refuse {
					require.NoError(t, err, "mode %04o", mode)
					assert.Equal(t, "TOPSECRET", string(got))
					continue
				}
				require.Error(t, err, "a %04o --passphrase-file owned by uid 1000 (not the process, not root) must be refused", mode)
				assert.Nil(t, got)
				msg := err.Error()
				assert.Contains(t, msg, "--passphrase-file")
				assert.Contains(t, msg, p, "names the file")
				assert.Contains(t, msg, "uid 1000", "names the owner")
				assert.Contains(t, msg, "uid 1001", "names the running user")
				assert.NotContains(t, msg, "TOPSECRET")
			}
		})
	}
}

// The file KEK provider (storage.encryption.key_provider: file) is the same
// class: its mode was judged on the descriptor, its owner was not.
func TestFileKeyProvider_Owner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kek.key")
	require.NoError(t, os.WriteFile(p, testKEK(), 0o600))
	for _, tc := range []struct {
		fileUID int
		refuse  bool
	}{{1000, true}, {1001, false}, {0, false}} {
		restore := secretenv.OverrideOwnershipForTest(tc.fileUID, 1001)
		kek, err := NewFileKeyProvider(p).KEK()
		restore()
		if !tc.refuse {
			require.NoError(t, err, "owner uid %d", tc.fileUID)
			assert.Equal(t, testKEK(), kek)
			continue
		}
		require.Error(t, err, "a 0600 KEK file owned by uid 1000 (not the process, not root) must be refused")
		assert.Nil(t, kek)
		assert.Contains(t, err.Error(), p)
		assert.Contains(t, err.Error(), "uid 1000")
		assert.Contains(t, err.Error(), "uid 1001")
	}
}
