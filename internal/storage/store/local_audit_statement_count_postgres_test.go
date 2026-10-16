// local_audit_statement_count_postgres_test.go — OPT-AUDIT-RT-1: how many SQL
// statements the audit write adds to each audited request on Postgres, counted
// on the connection itself (a pgx tracer sees every statement, pipelined or
// not). pg-gated (KEYORIX_TEST_PG_DSN).
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// statementTracer records every statement a pgx connection runs: each one
// sent on its own and each one queued in a pipelined batch.
type statementTracer struct {
	mu    sync.Mutex
	stmts []string
}

func (s *statementTracer) add(sql string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stmts = append(s.stmts, sql)
}

func (s *statementTracer) since(n int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.stmts[n:]...)
}

func (s *statementTracer) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.stmts)
}

func (s *statementTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	s.add(data.SQL)
	return ctx
}

func (s *statementTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (s *statementTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}

func (s *statementTracer) TraceBatchQuery(_ context.Context, _ *pgx.Conn, data pgx.TraceBatchQueryData) {
	s.add(data.SQL)
}

func (s *statementTracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

// statementCountingPGStore is pipelinePGStore with a statementTracer on its
// one connection instead of a write counter.
func statementCountingPGStore(t testing.TB) (*LocalStorage, *statementTracer) {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	var suffix [6]byte
	_, err := rand.Read(suffix[:])
	require.NoError(t, err)
	schema := "audit_stmts_" + hex.EncodeToString(suffix[:])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if a, e := admin.DB(); e == nil {
			_ = a.Close()
		}
	})
	cc, err := pgx.ParseConfig(pgdsn.PGSearchPathDSN(dsn, schema))
	require.NoError(t, err)
	tracer := &statementTracer{}
	cc.Tracer = tracer
	sqlDB := stdlib.OpenDB(*cc)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	return NewLocalStorage(db), tracer
}

// Each audited request's audit write, in the steady state (the flusher's
// chain-head cache armed, the connection's statement cache warm), runs
// BEGIN, [the standard level's SET LOCAL], the KEYAUDIT lock, ONE statement
// that inserts the events and checks the chain head and the links, [the
// access-log INSERT for a read], and COMMIT. Before OPT-AUDIT-RT-1 the head
// check and the link check were statements of their own (a read cost 7
// statements at the strict level, a write 6).
func TestAuditStatementsPerRequest_Postgres(t *testing.T) {
	for _, standard := range []bool{false, true} {
		level := map[bool]string{false: "strict", true: "standard"}[standard]
		t.Run(level, func(t *testing.T) {
			ls, tracer := statementCountingPGStore(t)
			ls.SetAuditSkipDurableSync(standard)
			ctx := context.Background()
			n := 0
			read := func() error {
				n++
				node := uint(1000 + n)
				return ls.LogAuditEventWithAccessLog(ctx,
					&models.AuditEvent{EventType: "secret.read", SecretNodeID: &node, Description: fmt.Sprintf("read %d", n), EventTime: time.Now()},
					&models.SecretAccessLog{SecretNodeID: node, Action: "read", AccessTime: time.Now()})
			}
			write := func() error {
				n++
				return ls.LogAuditEvent(ctx, &models.AuditEvent{EventType: "secret.update", Description: fmt.Sprintf("write %d", n), EventTime: time.Now()})
			}
			for range 3 {
				require.NoError(t, read())
				require.NoError(t, write())
			}
			require.True(t, armedHead(ls))

			extra := map[bool]int{false: 0, true: 1}[standard]
			for _, tc := range []struct {
				name string
				call func() error
				want int
			}{
				{"audited read", read, 5 + extra},
				{"audited write", write, 4 + extra},
			} {
				before := tracer.len()
				require.NoError(t, tc.call())
				got := tracer.since(before)
				assert.Len(t, got, tc.want, "%s at the %s level ran: %q", tc.name, level, got)
			}
			assert.Zero(t, ls.auditHead.oneFlightMisses.Load())
			v, err := ls.VerifyAuditChain(ctx, nil)
			require.NoError(t, err)
			assert.True(t, v.Valid, v.Reason)
		})
	}
}

// BenchmarkAuditedRead_Postgres measures the audit write of an audited read
// (LogAuditEventWithAccessLog through the flusher) with c concurrent callers:
// ns/op is the inverse of throughput, p99-µs the callers' 99th percentile.
// For before/after comparisons on one machine, not a gate.
func BenchmarkAuditedRead_Postgres(b *testing.B) {
	for _, standard := range []bool{false, true} {
		for _, c := range []int{1, 50} {
			b.Run(fmt.Sprintf("%s/c=%d", map[bool]string{false: "strict", true: "standard"}[standard], c), func(b *testing.B) {
				ls, _ := statementCountingPGStore(b)
				ls.SetAuditSkipDurableSync(standard)
				ctx := context.Background()
				var seq atomic.Int64
				read := func() error {
					n := seq.Add(1)
					node := uint(1000 + n%97)
					return ls.LogAuditEventWithAccessLog(ctx,
						&models.AuditEvent{EventType: "secret.read", SecretNodeID: &node, Description: fmt.Sprintf("read %d", n), EventTime: time.Now()},
						&models.SecretAccessLog{SecretNodeID: node, Action: "read", AccessTime: time.Now()})
				}
				for range 2 * c {
					require.NoError(b, read())
				}
				var (
					next  atomic.Int64
					mu    sync.Mutex
					lat   []time.Duration
					wg    sync.WaitGroup
					fails atomic.Int64
				)
				b.ResetTimer()
				for range c {
					wg.Go(func() {
						var mine []time.Duration
						for next.Add(1) <= int64(b.N) {
							start := time.Now()
							if err := read(); err != nil {
								fails.Add(1)
							}
							mine = append(mine, time.Since(start))
						}
						mu.Lock()
						lat = append(lat, mine...)
						mu.Unlock()
					})
				}
				wg.Wait()
				b.StopTimer()
				require.Zero(b, fails.Load())
				slices.Sort(lat)
				b.ReportMetric(float64(lat[min(len(lat)-1, len(lat)*99/100)].Microseconds()), "p99-µs")
			})
		}
	}
}
