// audit_durability_test.go — ADR-112 Amendment 3's start-up reporting: one
// INFO line per start with the effective storage.database.audit_durability,
// and a level change between two starts audited by the start-to-start
// settings diff (old/new), replacing Amendment 1's per-start WARNING and
// admin.audit_durable_sync_skipped_at_startup event.
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func auditDurabilityTestConfig(storageType, level string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = storageType
	cfg.Storage.Database.AuditDurability = level
	return cfg
}

// TestLogAuditDurability_StartupInfoLine pins the line every start logs: INFO,
// never WARNING, with the effective level and its meaning.
func TestLogAuditDurability_StartupInfoLine(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"postgres default", auditDurabilityTestConfig("postgres", ""),
			"INFO: audit durability: standard (PostgreSQL default; committed before every disclosure; up to ~600 ms " +
				"of entries can be lost to an OS crash or power loss; set audit_durability: strict to wait for the disk sync)"},
		{"postgres strict", auditDurabilityTestConfig("postgres", "strict"),
			"INFO: audit durability: strict (committed and synced to disk before every disclosure; no audit entry " +
				"is lost to any crash or power loss)"},
		{"sqlite", auditDurabilityTestConfig("local", ""),
			"INFO: audit durability: strict (committed and synced to disk before every disclosure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLogs(func() { logAuditDurability(tc.cfg) })
			assert.Contains(t, logged, tc.want)
			assert.Equal(t, 1, strings.Count(logged, "audit durability:"), "exactly one line per start")
			assert.NotContains(t, logged, "WARNING")
			assert.NotContains(t, logged, "insecure_audit_skip_durable_sync")
		})
	}
}

// postureChanges returns the settings-diff events for setting, in order.
func postureChanges(t *testing.T, db *gorm.DB, setting string) []map[string]string {
	t.Helper()
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", core.EventSecurityPostureSettingChanged).Order("id").Find(&events).Error)
	var out []map[string]string
	for _, e := range events {
		var ch map[string]string
		require.NoError(t, json.Unmarshal([]byte(e.Diff), &ch))
		if ch["setting"] == setting {
			out = append(out, ch)
		}
	}
	return out
}

// TestSecurityPostureSnapshot_AuditsAuditDurabilityLevelChange: a level change
// between two starts is one settings-diff audit event carrying the old and new
// level, on a real store; an unchanged level writes nothing. Also the upgrade
// from a release that recorded the old insecure_ key: the move to standard is
// on the record.
func TestSecurityPostureSnapshot_AuditsAuditDurabilityLevelChange(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SystemMetadata{}))
	ctx := context.Background()
	st := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(st)

	// The previous start ran a build from before Amendment 3, whose snapshot
	// had the insecure_ key and no audit_durability.
	require.NoError(t, st.SetSystemMetadata(ctx, "security_posture_settings_snapshot",
		`{"storage.database.insecure_audit_skip_durable_sync":"false"}`))

	boot := func(cfg *config.Config) {
		coreService.ReconcileSecurityPostureSnapshot(ctx, securityPostureSnapshot(cfg))
	}

	boot(auditDurabilityTestConfig("postgres", "")) // upgrade, neither key set: standard
	boot(auditDurabilityTestConfig("postgres", "")) // unchanged
	boot(auditDurabilityTestConfig("postgres", "strict"))

	got := postureChanges(t, db, config.AuditDurabilitySettingName)
	require.Len(t, got, 2, "one event for the upgrade, one for the edit, none for the unchanged start: %v", got)
	assert.Equal(t, "", got[0]["old_value"])
	assert.Equal(t, "standard", got[0]["new_value"], "the upgrade's move to standard must be on the record")
	assert.Equal(t, "standard", got[1]["old_value"])
	assert.Equal(t, "strict", got[1]["new_value"])

	var startupEvents int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", "admin.audit_durable_sync_skipped_at_startup").Count(&startupEvents).Error)
	assert.Zero(t, startupEvents, "the per-start event is replaced by the settings diff")
}
