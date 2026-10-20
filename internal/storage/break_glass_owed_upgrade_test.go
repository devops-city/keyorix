package storage

// BREAKGLASS-OWED-1 (schema epoch 5): an install migrated by an epoch-3/4 binary
// already has break_glass_activations and pending_audit_events without the new
// columns. migrateDatabase must add them (and the owed-row index), or the
// degraded break-glass commit fails on every upgraded install and emergency
// access is refused exactly while the audit log is down.
// TestMigrateDatabase_EveryModelGetsATable_UpgradedInstall cannot see the
// pending_audit_events half: its v0.95.0 fixture predates that table.

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestMigrateDatabase_AddsBreakGlassOwedColumnsOnUpgrade(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "epoch4.db"))
	require.NoError(t, err)
	// The epoch-4 shape of both tables (columns as an epoch-4 binary created them).
	require.NoError(t, db.Exec(`CREATE TABLE break_glass_activations (
		id integer PRIMARY KEY AUTOINCREMENT, project_id integer, user_id integer, role_id integer,
		role_name text, justification text, state text, expires_at datetime, created_at datetime,
		revoked_by integer, revoked_by_machine_identity_id integer, revoked_at datetime,
		reviewed_by integer, reviewed_at datetime, review_note text)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE pending_audit_events (
		id integer PRIMARY KEY AUTOINCREMENT, event_type varchar(100) NOT NULL, event text NOT NULL,
		last_error text, attempts integer NOT NULL DEFAULT 0, created_at datetime, updated_at datetime)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO pending_audit_events (event_type, event) VALUES ('secret.suspended', '{}')`).Error)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	m := db.Migrator()
	for _, col := range []string{"Degraded", "AuditSettledAt"} {
		require.True(t, m.HasColumn(&models.BreakGlassActivation{}, col), "break_glass_activations.%s", col)
	}
	require.True(t, m.HasColumn(&models.PendingAuditEvent{}, "BreakGlassActivationID"))
	require.True(t, m.HasIndex(&models.PendingAuditEvent{}, "BreakGlassActivationID"))

	// The row an epoch-4 suspend left behind reads as "not owed by break-glass".
	var p models.PendingAuditEvent
	require.NoError(t, db.First(&p).Error)
	require.Zero(t, p.BreakGlassActivationID)

	// A degraded activation and its owed row can now be written.
	a := &models.BreakGlassActivation{ProjectID: 1, UserID: 2, RoleID: 3, State: "active", Degraded: true}
	require.NoError(t, db.Create(a).Error)
	require.NoError(t, db.Create(&models.PendingAuditEvent{EventType: "break_glass.activated", Event: "{}", BreakGlassActivationID: a.ID}).Error)

	// Re-running is a no-op.
	require.NoError(t, f.migrateDatabase(db))
}
