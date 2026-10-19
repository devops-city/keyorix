package core

// last_used_bench_postgres_test.go — OPT-LASTUSED-1 before/after benchmark: the
// last-used stamp an authenticated request pays, many concurrent clients of ONE
// machine credential, on real Postgres (KEYORIX_TEST_PG_DSN).
//
//   - steady: real clock. Before, every call ran the conditional UPDATE (it
//     matches no row while the stored value is younger than 30 s).
//   - rollover: every call lands in a new 30 s window (the clock advances 31 s
//     per call), the worst case before: every call really writes, so the
//     clients queue on the row lock and each one's commit.
//
// Uses only API that exists before and after the change, so the same file
// runs against main for the comparison.

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var lastUsedBenchSchemaCounter atomic.Int64

func BenchmarkLastUsedTouch_Postgres(b *testing.B) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		b.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	for _, mode := range []string{"steady", "rollover"} {
		b.Run(mode, func(b *testing.B) {
			schema := fmt.Sprintf("lastused_bench_%d_%d", os.Getpid(), lastUsedBenchSchemaCounter.Add(1))
			admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				b.Fatal(err)
			}
			adminSQL, _ := admin.DB()
			defer func() { _ = adminSQL.Close() }()
			if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
				b.Fatal(err)
			}
			defer func() { _ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error }()

			db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(base, schema)), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				b.Fatal(err)
			}
			sqlDB, _ := db.DB()
			sqlDB.SetMaxOpenConns(32)
			sqlDB.SetMaxIdleConns(32)
			defer func() { _ = sqlDB.Close() }()
			if err := db.AutoMigrate(&models.MachineIdentityCredential{}); err != nil {
				b.Fatal(err)
			}
			if err := db.Create(&models.MachineIdentityCredential{ID: 1, MachineIdentityID: 1, Name: "c", TokenHash: "h"}).Error; err != nil {
				b.Fatal(err)
			}

			c := NewKeyorixCore(store.NewLocalStorage(db))
			if mode == "rollover" {
				var mu sync.Mutex
				clock := time.Now()
				c.now = func() time.Time {
					mu.Lock()
					defer mu.Unlock()
					clock = clock.Add(31 * time.Second)
					return clock
				}
			}
			ctx := b.Context()
			b.SetParallelism(4) // 4 × GOMAXPROCS concurrent clients of one credential
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					c.TouchMachineTokenLastUsed(ctx, 1)
				}
			})
		})
	}
}
