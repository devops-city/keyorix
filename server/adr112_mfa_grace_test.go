// adr112_mfa_grace_test.go -- the boot half of #2923: the require_mfa upgrade
// grace start is recorded durably by the first graced boot and kept by every
// later one, the 30-day deadline is measured from it, and a clock set back
// since the last boot does not extend it. SQLite always; PostgreSQL when
// KEYORIX_TEST_PG_DSN is set.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var mfaGracePGSchemaN atomic.Int64

// runMFAGraceBackends runs fn with a config pointing at an empty database: a
// SQLite file, and (KEYORIX_TEST_PG_DSN) a fresh PostgreSQL schema.
func runMFAGraceBackends(t *testing.T, fn func(t *testing.T, newCfg func() *config.Config)) {
	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keyorix.db")
		fn(t, func() *config.Config {
			cfg := adr112MFAConfig(t)
			cfg.Storage.Database.Path = path
			return cfg
		})
	})
	t.Run("postgres", func(t *testing.T) {
		base := os.Getenv("KEYORIX_TEST_PG_DSN")
		if base == "" {
			t.Skip("KEYORIX_TEST_PG_DSN not set")
		}
		schema := fmt.Sprintf("mfa_grace_%d_%d", os.Getpid(), mfaGracePGSchemaN.Add(1))
		admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE; CREATE SCHEMA " + schema).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
			closeGormDB(admin)
		})
		dsn := pgdsn.PGSearchPathDSN(base, schema)
		fn(t, func() *config.Config {
			cfg := adr112MFAConfig(t)
			cfg.Storage = config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}
			return cfg
		})
	})
}

func readMetadata(t *testing.T, cfg *config.Config, key string) (string, bool) {
	t.Helper()
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeGormDB(db)
	var row models.SystemMetadata
	if err := db.Where("key = ?", key).Take(&row).Error; err != nil {
		return "", false
	}
	return row.Value, true
}

func writeMetadata(t *testing.T, cfg *config.Config, key, value string) {
	t.Helper()
	db, err := appstorage.OpenGormDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeGormDB(db)
	if err := db.Save(&models.SystemMetadata{Key: key, Value: value, UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
}

// bootMFAGrace runs the boot decision with the wall clock at now.
func bootMFAGrace(cfg *config.Config, now time.Time) {
	adr112MFAWindow = core.MFAUpgradeGraceWindow{}
	adr112Now = func() time.Time { return now }
	defer func() { adr112Now = func() time.Time { return time.Now().Round(0) } }()
	applyADR112UpgradeGrace(cfg)
}

func resetMFAGraceGlobals() {
	adr112MFAReason, adr112MFAWindow = "", core.MFAUpgradeGraceWindow{}
}

// The first graced boot records the grace start; a later boot keeps it, so the
// window is measured from the upgrade, not from whenever the server last
// started.
func TestADR112MFAGrace_StartIsDurable(t *testing.T) {
	t.Cleanup(resetMFAGraceGlobals)
	runMFAGraceBackends(t, func(t *testing.T, newCfg func() *config.Config) {
		first := newCfg()
		migrateADR112DB(t, first, 1)
		t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

		bootMFAGrace(first, t0)
		if !first.Security.RequireMFAUpgradeGrace {
			t.Fatalf("first boot after the upgrade must be in the grace period: %s", adr112MFAReason)
		}
		if !first.Security.RequireMFA {
			t.Fatal("RequireMFA must stay true during the grace period: the running server subtracts the grace period itself")
		}
		if got, _ := readMetadata(t, first, config.ADR112RequireMFAGraceStartedKey); got != t0.Format(time.RFC3339) {
			t.Fatalf("grace start = %q, want %q", got, t0.Format(time.RFC3339))
		}
		if !adr112MFAWindow.Deadline.Equal(t0.Add(30 * 24 * time.Hour)) {
			t.Fatalf("deadline = %v, want start + 30 days", adr112MFAWindow.Deadline)
		}

		second := newCfg()
		bootMFAGrace(second, t0.Add(10*24*time.Hour))
		if !second.Security.RequireMFAUpgradeGrace {
			t.Fatalf("day 10 is still inside the window: %s", adr112MFAReason)
		}
		if got, _ := readMetadata(t, second, config.ADR112RequireMFAGraceStartedKey); got != t0.Format(time.RFC3339) {
			t.Fatalf("a later boot must keep the first grace start, got %q", got)
		}
		if !adr112MFAWindow.Start.Equal(t0) {
			t.Fatalf("window start = %v, want the recorded %v", adr112MFAWindow.Start, t0)
		}
	})
}

// 30 days after the recorded start the grace period is over at boot, and the
// boot ratchets the deployment to enforced.
func TestADR112MFAGrace_DeadlinePassedAtBoot(t *testing.T) {
	t.Cleanup(resetMFAGraceGlobals)
	runMFAGraceBackends(t, func(t *testing.T, newCfg func() *config.Config) {
		cfg := newCfg()
		migrateADR112DB(t, cfg, 1)
		t0 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
		bootMFAGrace(cfg, t0)

		late := newCfg()
		bootMFAGrace(late, t0.Add(30*24*time.Hour))
		if late.Security.RequireMFAUpgradeGrace || !late.Security.RequireMFA {
			t.Fatalf("day 30 must be enforced: grace=%v RequireMFA=%v (%s)", late.Security.RequireMFAUpgradeGrace, late.Security.RequireMFA, adr112MFAReason)
		}
		if !strings.Contains(adr112MFAReason, "30-day grace period ended") {
			t.Errorf("reason should name the deadline: %q", adr112MFAReason)
		}
		recordADR112Markers(late)
		if _, found := readMetadata(t, late, config.ADR112RequireMFAEnforcedMarker); !found {
			t.Fatal("a boot past the deadline must write the enforcement marker")
		}
	})
}

// A clock set back since the last boot does not reopen or lengthen the
// window: the boot counts from the recorded clock.
func TestADR112MFAGrace_BackwardClockAtBootDoesNotExtend(t *testing.T) {
	t.Cleanup(resetMFAGraceGlobals)
	runMFAGraceBackends(t, func(t *testing.T, newCfg func() *config.Config) {
		cfg := newCfg()
		migrateADR112DB(t, cfg, 1)
		t0 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
		bootMFAGrace(cfg, t0)
		bootMFAGrace(newCfg(), t0.Add(29*24*time.Hour)) // records the clock at day 29

		back := newCfg()
		logged := captureLogs(func() { bootMFAGrace(back, t0.Add(2*24*time.Hour)) })
		if !back.Security.RequireMFAUpgradeGrace {
			t.Fatalf("still inside the window by the recorded clock: %s", adr112MFAReason)
		}
		if !adr112MFAWindow.Floor.Equal(t0.Add(29 * 24 * time.Hour)) {
			t.Fatalf("floor = %v, want the recorded day-29 clock", adr112MFAWindow.Floor)
		}
		if !strings.Contains(logged, "does not extend it") {
			t.Errorf("a backward clock must be logged: %q", logged)
		}

		// The recorded clock past the deadline ends it even with the wall clock
		// back inside the window.
		writeMetadata(t, cfg, config.ADR112RequireMFAGraceClockKey, t0.Add(31*24*time.Hour).Format(time.RFC3339))
		again := newCfg()
		bootMFAGrace(again, t0.Add(3*24*time.Hour))
		if again.Security.RequireMFAUpgradeGrace {
			t.Fatal("a recorded clock past the deadline must end the grace period whatever the wall clock says")
		}
	})
}

// Unparseable facts fail closed (enforced), they are not read as absent.
func TestADR112MFAGrace_CorruptFactsFailClosed(t *testing.T) {
	t.Cleanup(resetMFAGraceGlobals)
	for _, key := range []string{config.ADR112RequireMFAGraceStartedKey, config.ADR112RequireMFAGraceClockKey} {
		t.Run(key, func(t *testing.T) {
			runMFAGraceBackends(t, func(t *testing.T, newCfg func() *config.Config) {
				cfg := newCfg()
				migrateADR112DB(t, cfg, 1)
				writeMetadata(t, cfg, key, "not a time")
				bootMFAGrace(cfg, time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))
				if cfg.Security.RequireMFAUpgradeGrace || !cfg.Security.RequireMFA {
					t.Fatalf("a corrupt %s must fail closed (enforced): %s", key, adr112MFAReason)
				}
				if !strings.Contains(adr112MFAReason, "failing closed") {
					t.Errorf("reason should say it failed closed: %q", adr112MFAReason)
				}
			})
		})
	}
}
