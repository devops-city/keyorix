// auth_budget_record_keyed_test.go — #2837 shape 2 (FIX-2837B): the
// outcome-agnostic budget writes (RecordPasswordResetAttempt,
// RecordSSOBeginAttempt, RecordFailedLogin -> budgetRecord) used one plain
// RecordLoginAttempt. One transient write error sent the attempt to the
// per-process fallback: no stored row, an auth.rate_limit_error audit event,
// and an attempt the other replicas never count. FuzzStorageFaultOperations
// found it on REST POST /auth/password-reset (RecordLoginAttempt#1/error,
// oracle (a) [LoginAttempt AuditEvent]). A write that landed but reported an
// error was worse: stored AND counted again in memory.
//
// budgetRecord now uses the login reservation's keyed, once-retried write
// (#3050, budgetWriteKeyed). These tests fault the FIRST login_attempts write
// whatever method it goes through, so they are red on the old code too.
package core

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// firstWriteFaultStub faults login_attempts writes (RecordLoginAttempt or
// ReserveLoginAttempt) while faults > 0, one per write. effect makes a faulted
// write land before it reports the error (a lost acknowledgement).
type firstWriteFaultStub struct {
	faults int
	effect bool
}

func (s *firstWriteFaultStub) fault() bool {
	if s.faults <= 0 {
		return false
	}
	s.faults--
	return true
}

func (s *firstWriteFaultStub) RecordLoginAttempt(next corestorage.Storage, ctx context.Context, ip string, at time.Time) error {
	if !s.fault() {
		return next.RecordLoginAttempt(ctx, ip, at)
	}
	if s.effect {
		_ = next.RecordLoginAttempt(ctx, ip, at)
	}
	return errLoginAttemptsDown
}

func (s *firstWriteFaultStub) ReserveLoginAttempt(next corestorage.Storage, ctx context.Context, ip string, at time.Time, key string) (uint, error) {
	if !s.fault() {
		return next.ReserveLoginAttempt(ctx, ip, at, key)
	}
	if s.effect {
		_, _ = next.ReserveLoginAttempt(ctx, ip, at, key)
	}
	return 0, errLoginAttemptsDown
}

// wrap returns inner decorated with firstWriteFaultStub's overrides.
func (s *firstWriteFaultStub) wrap(inner corestorage.Storage) corestorage.Storage {
	return hooked(inner, &storeHooks{
		RecordLoginAttempt:  s.RecordLoginAttempt,
		ReserveLoginAttempt: s.ReserveLoginAttempt,
	})
}

func newFirstWriteFaultCore(t *testing.T) (*KeyorixCore, *firstWriteFaultStub, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	if sqlDB, derr := db.DB(); derr == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}, &models.AuditEvent{}))
	stub := &firstWriteFaultStub{}
	now := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: stub.wrap(store.NewLocalStorage(db)), now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	return c, stub, db
}

type recordBudgetCase struct {
	name    string
	budget  authBudget
	record  func(*KeyorixCore, string)
	limited func(*KeyorixCore, string) bool
}

func recordBudgetCases() []recordBudgetCase {
	ctx := context.Background()
	return []recordBudgetCase{
		{"password_reset", passwordResetBudget,
			func(c *KeyorixCore, ip string) { c.RecordPasswordResetAttempt(ctx, ip) },
			func(c *KeyorixCore, ip string) bool { return c.IsPasswordResetRateLimited(ctx, ip) }},
		{"sso_begin", ssoBeginBudget,
			func(c *KeyorixCore, ip string) { c.RecordSSOBeginAttempt(ctx, ip) },
			func(c *KeyorixCore, ip string) bool { return c.IsSSOBeginRateLimited(ctx, ip) }},
		{"login/record", loginBudget,
			func(c *KeyorixCore, ip string) { c.RecordFailedLogin(ctx, ip) },
			func(c *KeyorixCore, ip string) bool { return c.IsLoginRateLimited(ctx, ip) }},
	}
}

func rateLimitErrorEvents(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventAuthRateLimitError).Count(&n).Error)
	return n
}

func storedAttempts(t *testing.T, db *gorm.DB, b authBudget, ip string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Where("ip = ?", b.prefix+ip).Count(&n).Error)
	return n
}

// TestBudgetRecord_OneFaultedWriteIsStoredExactlyOnce: a single failed write,
// with or without its effect landing, leaves exactly one stored row, nothing in
// the in-memory fallback, no auth.rate_limit_error event and the budget not
// degraded: the same state as a fault-free attempt.
func TestBudgetRecord_OneFaultedWriteIsStoredExactlyOnce(t *testing.T) {
	for _, tc := range recordBudgetCases() {
		for _, effect := range []bool{false, true} {
			name := tc.name + "/error"
			if effect {
				name = tc.name + "/effect-then-error"
			}
			t.Run(name, func(t *testing.T) {
				c, stub, db := newFirstWriteFaultCore(t)
				const ip = "198.51.100.21"
				stub.faults, stub.effect = 1, effect
				tc.record(c, ip)
				require.Zero(t, stub.faults, "calibration: the fault did not fire, so this proves nothing")

				assert.EqualValues(t, 1, storedAttempts(t, db, tc.budget, ip), "the attempt must be stored exactly once")
				assert.Zero(t, c.authBudgetFallback(tc.budget).count(ip, c.now().Add(-tc.budget.window), true),
					"the attempt went to the per-process fallback (stored=%d): other replicas do not see it",
					storedAttempts(t, db, tc.budget, ip))
				assert.Zero(t, rateLimitErrorEvents(t, db), "a write the retry recovered must not audit a fallback")
				assert.False(t, c.budgetDegraded(tc.budget), "a write the retry recovered must not degrade the budget")
			})
		}
	}
}

// TestBudgetRecord_FaultedWritesStillBindAtTheLimit: the security property.
// An attacker who can provoke one write error per request neither escapes the
// budget nor gets it charged twice: with every request's first write faulted
// (error, or effect-then-error), exactly limit requests are admitted.
func TestBudgetRecord_FaultedWritesStillBindAtTheLimit(t *testing.T) {
	for _, tc := range recordBudgetCases() {
		for _, effect := range []bool{false, true} {
			name := tc.name + "/error"
			if effect {
				name = tc.name + "/effect-then-error"
			}
			t.Run(name, func(t *testing.T) {
				c, stub, db := newFirstWriteFaultCore(t)
				const ip = "198.51.100.22"
				admitted := 0
				for i := 0; i < 3*tc.budget.limit; i++ {
					if tc.limited(c, ip) {
						continue
					}
					admitted++
					stub.faults, stub.effect = 1, effect
					tc.record(c, ip)
					require.Zero(t, stub.faults, "calibration: the fault did not fire")
				}
				assert.Equal(t, tc.budget.limit, admitted, "admitted %d requests against a limit of %d", admitted, tc.budget.limit)
				assert.EqualValues(t, tc.budget.limit, storedAttempts(t, db, tc.budget, ip))
			})
		}
	}
}

// TestBudgetRecord_WriteFailingTwiceStillFallsBack: the retry is one retry.
// A write that fails both times is counted in memory and audited, exactly as
// before (INV-CORE-auth-budgets-never-fail-open): never fail open.
func TestBudgetRecord_WriteFailingTwiceStillFallsBack(t *testing.T) {
	for _, tc := range recordBudgetCases() {
		t.Run(tc.name, func(t *testing.T) {
			c, stub, db := newFirstWriteFaultCore(t)
			const ip = "198.51.100.23"
			stub.faults = 2
			tc.record(c, ip)
			require.Zero(t, stub.faults, "calibration: both writes must have been attempted and faulted")
			assert.Zero(t, storedAttempts(t, db, tc.budget, ip))
			assert.Equal(t, 1, c.authBudgetFallback(tc.budget).count(ip, c.now().Add(-tc.budget.window), true),
				"a write that failed twice must still be counted (in memory)")
			assert.EqualValues(t, 1, rateLimitErrorEvents(t, db), "the fallback must be audited")
		})
	}
}

// TestAuthBudget_EveryStoredWriteIsKeyed is the class guard: no budget write in
// auth_budget.go may use the non-idempotent RecordLoginAttempt, which can be
// neither retried (a lost acknowledgement would count twice) nor left
// unretried (one transient error moves the attempt off the shared table). Every
// stored write goes through budgetWriteKeyed; ReserveLoginAttempt is called
// from nowhere else in the file. RecordLoginAttemptRelay (rate_limit.go) is not
// a budget write: it returns the storage error to its caller.
func TestAuthBudget_EveryStoredWriteIsKeyed(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "auth_budget.go", nil, 0)
	require.NoError(t, err)
	reserveCallers := map[string]int{}
	var unkeyed []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !isStorageValue(sel.X) {
				return true
			}
			switch sel.Sel.Name {
			case "RecordLoginAttempt":
				unkeyed = append(unkeyed, fset.Position(call.Pos()).String()+" "+fd.Name.Name)
			case "ReserveLoginAttempt":
				reserveCallers[fd.Name.Name]++
			}
			return true
		})
	}
	assert.Empty(t, unkeyed, "auth_budget.go writes login_attempts through the non-idempotent RecordLoginAttempt: use budgetWriteKeyed")
	assert.Equal(t, map[string]int{"budgetWriteKeyed": 2}, reserveCallers,
		"ReserveLoginAttempt must be called only by budgetWriteKeyed (the write and its one same-key retry); "+
			"a zero here means this guard no longer recognises the write and would pass vacuously")
}
