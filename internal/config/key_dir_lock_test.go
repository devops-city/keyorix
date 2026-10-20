package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidate_KeyDirLock: storage.encryption.key_dir_lock: database needs
// PostgreSQL; flock (or unset) is valid everywhere; anything else is refused.
func TestValidate_KeyDirLock(t *testing.T) {
	pg := func(mode string) *Config {
		c := &Config{}
		c.Storage.Type = "postgres"
		c.Storage.Database.DSN = "host=db user=keyorix dbname=keyorix sslmode=require"
		c.Storage.Encryption.KeyDirLock = mode
		return c
	}
	sq := func(mode string) *Config {
		c := &Config{}
		c.Storage.Type = "local"
		c.Storage.Database.Path = "/tmp/x.db"
		c.Storage.Encryption.KeyDirLock = mode
		return c
	}
	for _, mode := range []string{"", KeyDirLockFlock, KeyDirLockDatabase} {
		require.NoError(t, pg(mode).Validate(), "postgres + %q", mode)
	}
	require.NoError(t, sq("").Validate())
	require.NoError(t, sq(KeyDirLockFlock).Validate())
	require.ErrorContains(t, sq(KeyDirLockDatabase).Validate(), "key_dir_lock: database needs storage.type postgres")
	require.ErrorContains(t, pg("nfs").Validate(), `unknown value "nfs"`)
	require.True(t, pg(KeyDirLockDatabase).Storage.Encryption.KeyDirLockIsDatabase())
	require.False(t, pg("").Storage.Encryption.KeyDirLockIsDatabase())
}
