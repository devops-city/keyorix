// secret_suspend_marker_trigger.go — keeps secret_nodes.suspend_clear_synced_copies
// false on every secret that is not suspended, whoever writes the row (#3362).
//
// The marker (#3215) belongs to one suspension: set by the suspend that asked
// for "also clear the synced Kubernetes copies", cleared by the resume. A
// binary from before #3215 (an N-1 replica during a rolling upgrade) writes
// only status and updated_at, so its resume left the marker set on an active
// secret, and its next plain suspend then carried it: the operator and
// k8s-sync emptied the synced copies although that suspend never asked for it.
//
// A BEFORE UPDATE trigger clears the marker whenever status moves to anything
// but suspended, in the writer's own statement, so an old binary's resume
// clears it too. The schema-epoch floor (minCompatibleSchemaEpoch 3) stops old
// binaries from starting once this binary has migrated; the trigger covers the
// old replicas still running until the rollout replaces them.
//
// PostgreSQL only: SQLite is one process, so no older binary writes beside
// this one, and this binary's own resume already clears the marker.
package store

import (
	"fmt"

	"gorm.io/gorm"
)

// SecretSuspendMarkerTrigger is the trigger's name, exported for tests.
const SecretSuspendMarkerTrigger = "trg_secret_nodes_suspend_marker" // #nosec G101 -- trigger name, not a credential

const secretSuspendMarkerFunc = "keyorix_clear_suspend_marker" // #nosec G101 -- function name, not a credential

// postgresSuspendMarkerLockKey serialises concurrent installers (CREATE OR
// REPLACE FUNCTION races on the pg_proc tuple). "KEYASUSP".
const postgresSuspendMarkerLockKey = 0x4B455941_53555350

// EnsureSecretSuspendMarkerTrigger installs the trigger on PostgreSQL.
// Idempotent; it never drops a trigger that exists (a drop-then-create on boot
// would leave a window other replicas write through). A no-op on SQLite and
// until secret_nodes has the column. Also clears markers already left set on
// secrets that are not suspended.
func EnsureSecretSuspendMarkerTrigger(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" || !storeTableExists(db, "secret_nodes") ||
		!db.Migrator().HasColumn("secret_nodes", "suspend_clear_synced_copies") {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(postgresSuspendMarkerLockKey)).Error; err != nil {
			return fmt.Errorf("acquire suspend-marker trigger advisory lock: %w", err)
		}
		if err := tx.Exec(`CREATE OR REPLACE FUNCTION ` + secretSuspendMarkerFunc + `() RETURNS trigger
LANGUAGE plpgsql AS $keyorix$
BEGIN
  NEW.suspend_clear_synced_copies := false;
  RETURN NEW;
END;
$keyorix$`).Error; err != nil {
			return fmt.Errorf("failed to create %s(): %w", secretSuspendMarkerFunc, err)
		}
		// Rows an older binary already left stale (resumed with the marker set).
		if err := tx.Exec("UPDATE secret_nodes SET suspend_clear_synced_copies = false WHERE suspend_clear_synced_copies AND status IS DISTINCT FROM 'suspended'").Error; err != nil {
			return fmt.Errorf("failed to clear stale suspend markers: %w", err)
		}
		var n int64
		if err := tx.Raw("SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'secret_nodes'::regclass AND tgname = ?",
			SecretSuspendMarkerTrigger).Scan(&n).Error; err != nil {
			return fmt.Errorf("failed to read %s: %w", SecretSuspendMarkerTrigger, err)
		}
		if n > 0 {
			return nil
		}
		// ENABLE ALWAYS: fires in a session_replication_role = replica session too.
		if err := tx.Exec(`CREATE TRIGGER ` + SecretSuspendMarkerTrigger + `
BEFORE UPDATE OF status ON secret_nodes FOR EACH ROW
WHEN (NEW.status IS DISTINCT FROM 'suspended' AND NEW.suspend_clear_synced_copies)
EXECUTE FUNCTION ` + secretSuspendMarkerFunc + `()`).Error; err != nil {
			return fmt.Errorf("failed to create %s: %w", SecretSuspendMarkerTrigger, err)
		}
		if err := tx.Exec(`ALTER TABLE secret_nodes ENABLE ALWAYS TRIGGER ` + SecretSuspendMarkerTrigger).Error; err != nil {
			return fmt.Errorf("failed to enable %s: %w", SecretSuspendMarkerTrigger, err)
		}
		return nil
	})
}
