package main

// admin_clear_login_lockout_integration_test.go drives `keyorix-server admin
// clear-login-lockout` (#2936) the way an operator does: the real binary, a
// real config written by `admin init`, a real SQLite database file.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

func TestAdminClearLoginLockout_RealBinary_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-sqlite")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}

	// The state #2936 reports: a full per-IP budget, as LoginMaxAttempts
	// counted attempts from the demo machine.
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "keyorix.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	for i := 0; i < core.LoginMaxAttempts; i++ {
		if err := db.Create(&models.LoginAttempt{IP: "127.0.0.1", AttemptedAt: time.Now()}).Error; err != nil {
			t.Fatalf("seed attempt: %v", err)
		}
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	out, err := runAdmin(t, bin, dir, env, "clear-login-lockout", "--config", "./keyorix.yaml", "--ip", "127.0.0.1")
	if err != nil {
		t.Fatalf("clear-login-lockout failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "cleared 10 counted login attempt(s) for IP 127.0.0.1") {
		t.Errorf("unexpected output:\n%s", out)
	}

	db, err = gorm.Open(sqlite.Open(filepath.Join(dir, "keyorix.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	var left int64
	if err := db.Model(&models.LoginAttempt{}).Where("ip = ?", "127.0.0.1").Count(&left).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if left != 0 {
		t.Errorf("expected the IP's budget to be cleared, %d attempt(s) left", left)
	}
	var ev models.AuditEvent
	if err := db.Where("event_type = ?", "admin.login_lockout_cleared").First(&ev).Error; err != nil {
		t.Fatalf("expected an admin.login_lockout_cleared audit event: %v", err)
	}
	if ev.ActorType != "admin_cli" {
		t.Errorf("audit actor_type = %q, want admin_cli", ev.ActorType)
	}

	// Neither flag: refused, nothing done.
	if out, err := runAdmin(t, bin, dir, env, "clear-login-lockout", "--config", "./keyorix.yaml"); err == nil {
		t.Errorf("expected clear-login-lockout with no --ip/--user to fail, got:\n%s", out)
	}
}
