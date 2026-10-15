package main

// audit_skip_reads_integration_test.go — ADR-112 Amendment 4
// (storage.database.insecure_audit_skip_reads) driven the way an operator
// drives it: the real built binary, a one-line config file edit, real starts
// and real `admin` commands. Covers the start-up surfaces: the WARNING at
// every start, the admin.audit_reads_skipped_at_startup event at every start,
// the settings-diff event, `admin validate` and `admin validate --posture`,
// and a chain that still verifies. The read path itself is covered against
// the real router (server/http/audit_skip_reads_test.go) and over gRPC.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func auditEventsOfType(t *testing.T, dbPath, eventType string) []models.AuditEvent {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	var events []models.AuditEvent
	if err := db.Where("event_type = ?", eventType).Find(&events).Error; err != nil {
		t.Fatalf("query %s audit events: %v", eventType, err)
	}
	return events
}

func TestInsecureAuditSkipReads_EndToEnd(t *testing.T) {
	bin := buildServerBinary(t)
	for _, on := range []bool{false, true} {
		name := "default"
		if on {
			name = "insecure_audit_skip_reads=true"
		}
		t.Run(name, func(t *testing.T) {
			runSkipReadsEndToEnd(t, bin, on)
		})
	}
}

func runSkipReadsEndToEnd(t *testing.T, bin string, on bool) {
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-audit-skip-reads")
	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if on {
		addDatabaseLineToConfig(t, filepath.Join(dir, "keyorix.yaml"), "insecure_audit_skip_reads: true")
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	// Start 1 (bootstraps the admin), then start 2: both must warn and both
	// must write the start-up event.
	bootstrapAdminViaHTTP(t, bin, dir, env, "8080", "skipreadsadmin", "skip-reads@example.com", "InitialPassw0rd!")
	firstLog, err := os.ReadFile(filepath.Join(dir, "bootstrap-server.log")) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatalf("read server log: %v", err)
	}
	secondLog := runServerExpectingItToStayUp(t, bin, dir, append(append([]string{}, env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml"), "8080")

	const warning = "WARNING: storage.database.insecure_audit_skip_reads is in effect (true; config: " +
		"storage.database.insecure_audit_skip_reads) — secret reads are NOT audited"
	for i, l := range []string{string(firstLog), secondLog} {
		if got := strings.Contains(l, warning); got != on {
			t.Errorf("start %d: WARNING present=%v, want %v. Server log:\n%s", i+1, got, on, l)
		}
	}

	dbPath := filepath.Join(dir, "keyorix.db")
	wantStartupEvents := 0
	if on {
		wantStartupEvents = 2
	}
	if n := len(auditEventsOfType(t, dbPath, "admin.audit_reads_skipped_at_startup")); n != wantStartupEvents {
		t.Errorf("admin.audit_reads_skipped_at_startup events after two starts = %d, want %d", n, wantStartupEvents)
	}
	diffNamesSetting := false
	for _, e := range auditEventsOfType(t, dbPath, "security.posture_setting_changed") {
		if strings.Contains(e.Description+e.Diff, "storage.database.insecure_audit_skip_reads") {
			diffNamesSetting = true
		}
	}
	if diffNamesSetting != on {
		t.Errorf("settings-diff event naming insecure_audit_skip_reads present=%v, want %v", diffNamesSetting, on)
	}

	validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
	}
	if got := strings.Contains(validateOut, "Secret reads are NOT audited (storage.database.insecure_audit_skip_reads)"); got != on {
		t.Errorf("`admin validate` deviation line present=%v, want %v. Output:\n%s", got, on, validateOut)
	}
	postureOut, _ := runAdmin(t, bin, dir, env, "validate", "--posture", "--config", "./keyorix.yaml")
	if got := strings.Contains(postureOut, "storage.database.insecure_audit_skip_reads is in effect (true)"); got != on {
		t.Errorf("`admin validate --posture` deviation present=%v, want %v. Output:\n%s", got, on, postureOut)
	}

	verifyOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil || !strings.Contains(verifyOut, "VALID") {
		t.Fatalf("`admin verify-audit` must report VALID: %v\n%s", err, verifyOut)
	}
}
