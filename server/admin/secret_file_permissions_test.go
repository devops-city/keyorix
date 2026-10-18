package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// QUICKSTART-2 item 2: the server refuses to start with a *_FILE secret that is
// readable beyond its owner (server/main.go enforceSecretFilePermissions), so an
// admin command must refuse the same file with the same message, before it
// touches the database. Otherwise `admin migrate` succeeds and the server then
// fails on the identical input.

func secretFileWithMode(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(p, []byte("value\n"), 0o600))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

func TestLoadConfig_RefusesTooOpenSecretFile(t *testing.T) {
	dir := t.TempDir()
	orig := configPathFlag
	t.Cleanup(func() { configPathFlag = orig })
	configPathFlag = writeBackupRestoreTestConfig(t, dir, filepath.Join(dir, "secrets.db"))

	t.Run("0644 DB password file is refused with the path and the mode", func(t *testing.T) {
		p := secretFileWithMode(t, 0o644)
		t.Setenv("KEYORIX_DB_PASSWORD_FILE", p)
		_, err := loadConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), p)
		assert.Contains(t, err.Error(), "0644")
		assert.Contains(t, err.Error(), "refused until the file is fixed")
		assert.NotContains(t, err.Error(), "value")
	})
	t.Run("0600 file is accepted", func(t *testing.T) {
		t.Setenv("KEYORIX_DB_PASSWORD_FILE", secretFileWithMode(t, 0o600))
		_, err := loadConfig()
		require.NoError(t, err)
	})
	t.Run("no secret files is accepted", func(t *testing.T) {
		_, err := loadConfig()
		require.NoError(t, err)
	})
}
