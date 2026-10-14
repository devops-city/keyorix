package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// BenchmarkAnomalySweep measures one anomaly-detection pass (C-PERF-FIXES,
// Detected-by: PERF-2) over a deployment-shaped dataset: benchSweepSecrets secrets
// with 30 days of history, benchSweepActive of them read in the live window by a
// principal outside their baseline (so every pass re-runs CreateAnomalyAlert's
// dedup count for each), and benchSweepAlerts historical alerts in anomaly_alerts.
//
//	before:       full sweep, without the three new indexes (the pre-fix shape)
//	indexes-only: full sweep, with the indexes (attributes the win between the two parts)
//	after:        incremental sweep, with the indexes
//
// Run: go test ./internal/core -run '^$' -bench BenchmarkAnomalySweep -benchtime 5x
// Postgres legs run only with KEYORIX_TEST_PG_DSN set.
func BenchmarkAnomalySweep(b *testing.B) {
	for _, dialect := range []string{"sqlite", "postgres"} {
		for _, mode := range []string{"before", "indexes-only", "after"} {
			b.Run(dialect+"/"+mode, func(b *testing.B) {
				db := benchSweepDB(b, dialect)
				if mode == "before" {
					for _, idx := range []string{"idx_anomaly_alerts_dedup", "idx_secret_access_logs_secret_time", "idx_secret_access_logs_access_time"} {
						if err := db.Exec("DROP INDEX " + idx).Error; err != nil {
							b.Fatal(err)
						}
					}
				}
				secrets := benchSweepSeed(b, db)
				if dialect == "postgres" {
					db.Exec("ANALYZE")
				}
				d := NewAnomalyDetector(store.NewLocalStorage(db))
				d.fullSweep = mode != "after"
				ctx := context.Background()
				// Warm-up pass: records the live-window alerts, so the timed passes
				// measure the steady state (every candidate alert hits the dedup count).
				if err := d.RunDetection(ctx, secrets); err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := d.RunDetection(ctx, secrets); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

const (
	benchSweepSecrets    = 3000
	benchSweepHistory    = 20 // access-log rows per secret over the last 30 days
	benchSweepActive     = 150
	benchSweepLiveReads  = 4
	benchSweepAlerts     = 60000
	benchSweepPGSchema   = "anomaly_sweep_bench"
	benchSweepSQLiteOpts = "?_busy_timeout=10000&_journal_mode=WAL"
)

func benchSweepDB(b *testing.B, dialect string) *gorm.DB {
	b.Helper()
	cfg := &gorm.Config{Logger: logger.Discard}
	var db *gorm.DB
	var err error
	switch dialect {
	case "sqlite":
		db, err = gorm.Open(sqlite.Open("file:"+filepath.Join(b.TempDir(), "sweep.db")+benchSweepSQLiteOpts), cfg)
	case "postgres":
		dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
		if dsn == "" {
			b.Skip("KEYORIX_TEST_PG_DSN not set")
		}
		admin, aerr := gorm.Open(postgres.Open(dsn), cfg)
		if aerr != nil {
			b.Fatal(aerr)
		}
		admin.Exec("DROP SCHEMA IF EXISTS " + benchSweepPGSchema + " CASCADE")
		admin.Exec("CREATE SCHEMA " + benchSweepPGSchema)
		b.Cleanup(func() { admin.Exec("DROP SCHEMA IF EXISTS " + benchSweepPGSchema + " CASCADE") })
		db, err = gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, benchSweepPGSchema)), cfg)
	}
	if err != nil {
		b.Fatal(err)
	}
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretAccessLog{}, &models.AnomalyAlert{},
		&models.AuditEvent{}, &models.SystemMetadata{}); err != nil {
		b.Fatal(err)
	}
	return db
}

func benchSweepSeed(b *testing.B, db *gorm.DB) []models.SecretNode {
	b.Helper()
	now := time.Now().UTC()
	secrets := make([]models.SecretNode, 0, benchSweepSecrets)
	logs := make([]models.SecretAccessLog, 0, benchSweepSecrets*benchSweepHistory)
	for i := 1; i <= benchSweepSecrets; i++ {
		id := uint(i)
		secrets = append(secrets, models.SecretNode{ID: id, ProjectID: 1, Name: fmt.Sprintf("s-%d", i), Status: "active", IsSecret: true})
		for h := range benchSweepHistory {
			at := now.Add(-2*24*time.Hour - time.Duration(h)*30*time.Hour)
			logs = append(logs, models.SecretAccessLog{SecretNodeID: id, AccessedBy: "svc", IPAddress: "10.0.0.1", Action: "read", AccessTime: at})
		}
		if i <= benchSweepActive {
			for r := range benchSweepLiveReads {
				logs = append(logs, models.SecretAccessLog{SecretNodeID: id, AccessedBy: "loadgen", IPAddress: "10.9.9.9",
					Action: "read", AccessTime: now.Add(-time.Duration(r+1) * time.Minute)})
			}
		}
	}
	alerts := make([]models.AnomalyAlert, 0, benchSweepAlerts)
	for i := range benchSweepAlerts {
		alerts = append(alerts, models.AnomalyAlert{SecretNodeID: uint(i%benchSweepSecrets + 1), AlertType: "new_user",
			AccessedBy: fmt.Sprintf("old-%d", i), IPAddress: "10.0.0.2", DetectedAt: now.Add(-time.Duration(i) * time.Minute)})
	}
	for _, err := range []error{
		db.CreateInBatches(&secrets, 1000).Error,
		db.CreateInBatches(&logs, 1000).Error,
		db.CreateInBatches(&alerts, 1000).Error,
	} {
		if err != nil {
			b.Fatal(err)
		}
	}
	return secrets
}
