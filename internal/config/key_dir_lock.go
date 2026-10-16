package config

import "fmt"

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
