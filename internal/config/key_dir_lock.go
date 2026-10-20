package config

import "fmt"

// KeyDirLockModeMetadataKey is the system_metadata row a server running with
// storage.encryption.key_dir_lock: database writes at boot (value
// KeyDirLockDatabase). server/admin reads it to decide whether --force may
// override a held database lock: that decision must come from what the
// database records about its replicas, not from the admin command's own config,
// which can lack the setting while database-mode replicas are running. Only
// database-mode servers write it, and nothing removes it automatically, so a
// stale row fails closed (an operator who went back to flock deletes it).
const KeyDirLockModeMetadataKey = "key_dir_lock.mode"

// validateKeyDirLock checks storage.encryption.key_dir_lock
// (docs/multi-replica-keys.md). "database" replaces the key-directory flock
// with PostgreSQL advisory locks, so it needs PostgreSQL: SQLite and remote
// storage have no shared database to lock in, and keep the flock.
func validateKeyDirLock(c *Config) error {
	switch c.Storage.Encryption.KeyDirLock {
	case "", KeyDirLockFlock:
		return nil
	case KeyDirLockDatabase:
		switch c.Storage.Type {
		case "postgres", "postgresql":
			return nil
		default:
			return fmt.Errorf("storage.encryption.key_dir_lock: database needs storage.type postgres (got %q): the key-directory lock moves into PostgreSQL advisory locks; use flock (the default) with SQLite", c.Storage.Type)
		}
	default:
		return fmt.Errorf("storage.encryption.key_dir_lock: unknown value %q (want flock or database)", c.Storage.Encryption.KeyDirLock)
	}
}
