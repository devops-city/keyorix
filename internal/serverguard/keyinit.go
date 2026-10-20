package serverguard

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// keyInitLockKey is the PostgreSQL advisory-lock key a server takes, with
// storage.encryption.key_dir_lock: database, around the start-up steps that may
// write key files: DEK-rotation crash recovery and first-boot key generation
// (docs/multi-replica-keys.md). Distinct from serverPresenceLockKey (872342)
// and postgresMigrationLockKey (872341).
const keyInitLockKey = 872343

// keyInitPollInterval is how often WithKeyInitLock retries a held lock.
const keyInitPollInterval = 200 * time.Millisecond

// WithKeyInitLock runs fn while holding the key-initialisation advisory lock
// on cfg's PostgreSQL database, waiting up to wait for another holder (a
// sibling replica generating or recovering the shared key files) to finish.
// It replaces, for key_dir_lock: database, the exclusive flock(2) a server
// otherwise holds on dek.lock across the same steps: two replicas booting on
// one fresh key directory serialise here instead of on the filesystem, and
// the second then loads the key files the first wrote rather than generating
// its own.
//
// The lock is released when fn returns. It is not held for the server's
// lifetime: the shared server-presence lock (AcquirePresence) is what keeps
// key-changing admin commands out while a server runs.
//
// PostgreSQL only; any other storage type is an error (config validation
// already refuses key_dir_lock: database there). Under a transaction-mode
// pooler the lock is transaction-scoped inside a pinned transaction, like the
// presence lock (pgLockSQL).
func WithKeyInitLock(cfg *config.Config, wait time.Duration, fn func() error) error {
	switch cfg.Storage.Type {
	case "postgres", "postgresql":
	default:
		return fmt.Errorf("key-initialisation lock needs PostgreSQL storage (storage.type %q)", cfg.Storage.Type)
	}
	sqlDB, conn, err := pgConn(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = sqlDB.Close() }()
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	xact := cfg.Storage.Database.TransactionPooling()
	if xact {
		if err := beginPinnedLockTx(ctx, conn); err != nil {
			return fmt.Errorf("acquire key-initialisation advisory lock: %w", err)
		}
	}
	tryLock := pgLockSQL("pg_try_advisory_lock", xact)
	for {
		var acquired bool
		if err := conn.QueryRowContext(ctx, tryLock, keyInitLockArgs(xact)...).Scan(&acquired); err != nil {
			return fmt.Errorf("acquire key-initialisation advisory lock: %w", err)
		}
		if acquired {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("another replica has held the key-initialisation lock (postgres advisory lock %d) for more than %s; it is generating or recovering the shared key files -- retry when it has started", keyInitLockKey, wait)
		case <-time.After(keyInitPollInterval):
		}
	}
	defer func() {
		relCtx, relCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer relCancel()
		if xact {
			endPinnedLockTx(relCtx, conn)
			return
		}
		// A failed unlock is still released when conn closes (deferred above).
		_, _ = conn.ExecContext(relCtx, "SELECT pg_advisory_unlock($1)", keyInitLockKey)
	}()
	return fn()
}

// keyInitLockArgs is pgLockArgs with keyInitLockKey in place of the presence key.
func keyInitLockArgs(xact bool) []any {
	args := pgLockArgs(xact)
	args[len(args)-1] = keyInitLockKey
	return args
}
