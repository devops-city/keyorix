// audit_retention_anchor_trigger.go — refuses to replace a v2 audit retention
// anchor with an older layout (#3359).
//
// The v2 anchor (#3258) carries the signed cumulative purged-event count that
// checkpoints, the high-water check and `admin audit verify` add back to the
// chained count. A binary from before #3258 (an N-1 replica during a rolling
// upgrade) cannot parse it, and its retention purge writes a v1 anchor in the
// same transaction as the delete. The count is then lost for good: verify
// reports the chain truncated and checkpoints answer 409 until as many new
// events have been written.
//
// A BEFORE UPDATE trigger on system_metadata raises when the
// audit_retention_anchor row holds a v2 value and the update writes anything
// else. The older binary's purge transaction then rolls back whole, delete
// included: nothing is purged, nothing is lost, and the purge request fails.
//
// Limit: the trigger fires on UPDATE only. A DELETE of the row followed by an
// INSERT of a v1 value bypasses it; the trigger guards the older purge's
// update, not a writer that deletes the row first.
// The schema-epoch floor (minCompatibleSchemaEpoch 3) keeps older binaries
// from starting once this binary has migrated; the trigger covers the ones
// still running until the rollout replaces them.
//
// PostgreSQL only (SQLite is one process). The key and layout prefix mirror
// internal/core's auditRetentionAnchorKey and auditRetentionAnchorValueV2.
package store

import (
	"fmt"

	"gorm.io/gorm"
)

// AuditRetentionAnchorTrigger is the trigger's name, exported for tests.
const AuditRetentionAnchorTrigger = "trg_system_metadata_retention_anchor_v2"

const auditRetentionAnchorFunc = "keyorix_keep_retention_anchor_v2"

// postgresRetentionAnchorLockKey serialises concurrent installers. "KEYARANC".
const postgresRetentionAnchorLockKey = 0x4B455941_52414E43

// EnsureAuditRetentionAnchorTrigger installs the trigger on PostgreSQL.
// Idempotent; never drops an existing trigger. A no-op on SQLite and until
// system_metadata exists.
func EnsureAuditRetentionAnchorTrigger(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" || !storeTableExists(db, "system_metadata") {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(postgresRetentionAnchorLockKey)).Error; err != nil {
			return fmt.Errorf("acquire retention-anchor trigger advisory lock: %w", err)
		}
		if err := tx.Exec(`CREATE OR REPLACE FUNCTION ` + auditRetentionAnchorFunc + `() RETURNS trigger
LANGUAGE plpgsql AS $keyorix$
BEGIN
  IF left(OLD.value, 3) = 'v2' || chr(31) AND left(NEW.value, 3) IS DISTINCT FROM 'v2' || chr(31) THEN
    RAISE EXCEPTION 'refusing to replace the v2 audit retention anchor with an older layout: a Keyorix binary older than this database''s schema ran a retention purge (#3359); run it on an upgraded replica'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$keyorix$`).Error; err != nil {
			return fmt.Errorf("failed to create %s(): %w", auditRetentionAnchorFunc, err)
		}
		var n int64
		if err := tx.Raw("SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'system_metadata'::regclass AND tgname = ?",
			AuditRetentionAnchorTrigger).Scan(&n).Error; err != nil {
			return fmt.Errorf("failed to read %s: %w", AuditRetentionAnchorTrigger, err)
		}
		if n > 0 {
			return nil
		}
		if err := tx.Exec(`CREATE TRIGGER ` + AuditRetentionAnchorTrigger + `
BEFORE UPDATE ON system_metadata FOR EACH ROW
WHEN (OLD.key = 'audit_retention_anchor')
EXECUTE FUNCTION ` + auditRetentionAnchorFunc + `()`).Error; err != nil {
			return fmt.Errorf("failed to create %s: %w", AuditRetentionAnchorTrigger, err)
		}
		if err := tx.Exec(`ALTER TABLE system_metadata ENABLE ALWAYS TRIGGER ` + AuditRetentionAnchorTrigger).Error; err != nil {
			return fmt.Errorf("failed to enable %s: %w", AuditRetentionAnchorTrigger, err)
		}
		return nil
	})
}
