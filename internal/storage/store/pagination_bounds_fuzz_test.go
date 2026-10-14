package store

import (
	"context"
	"fmt"
	"math"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// FuzzPaginationBounds is the value-as-bound / bounded-work invariant for the
// LocalStorage pagination guard (#G44, #r124-M). Page and PageSize are attacker-
// controlled request fields (a hostile or buggy caller that skips the ≤100 clamp
// every current handler applies), and they become an in-band SQL bound:
//
//	pageSize := clampPageSize(filter.PageSize)   // Limit(pageSize)
//	page     := clampPage(filter.Page)           // (page-1)*pageSize -> Offset
//	offset   := (page - 1) * pageSize
//
// A number field that reaches Limit()/Offset() unclamped is the classic
// value-as-bound DoS: a negative PageSize makes GORM's Limit(-1) DROP the LIMIT
// clause entirely (unbounded full-table scan), and an unbounded Page forces a
// huge OFFSET the database must scan-and-discard. The existing table tests pin
// specific values of each field independently and only ever run end-to-end with
// Page=1 (offset always 0); this fuzzer sweeps the COMBINED (page, pageSize)
// space — including the (page-1)*pageSize multiplication that no existing test
// exercises for overflow — and checks the invariant end-to-end against a real
// (in-memory) query.
//
// Invariants (all hold for correct code, so no false positives; each is
// red-proofable by loosening a clamp or raising a ceiling):
//   - clampPageSize(x) in [0, maxStoragePageSize]; never negative (negative =>
//     Limit(-1) => unbounded query, the #G44 bug).
//   - clampPage(x) in [1, maxStoragePage].
//   - offset = (clampPage(page)-1)*clampPageSize(pageSize) is non-negative and
//     did not overflow (equals the int64 computation, and stays within the
//     clamp-implied ceiling). A raised ceiling that let the product overflow int
//     would wrap negative and be caught here.
//   - end-to-end: ListSecrets with those Page/PageSize returns without error,
//     never more than maxStoragePageSize rows, never more than the true total,
//     and 0 rows exactly when pageSize clamps to 0 — i.e. no (page, pageSize)
//     combination removes the LIMIT or yields a negative OFFSET.
func FuzzPaginationBounds(f *testing.F) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		f.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&models.SecretNode{}, &models.Environment{}); err != nil {
		f.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error; err != nil {
		f.Fatalf("seed env: %v", err)
	}
	const seededRows = 7
	for i := range seededRows {
		if err := db.Create(&models.SecretNode{
			ProjectID: 1, EnvironmentID: 1, Name: fmt.Sprintf("secret-%d", i),
			IsSecret: true, Type: "api_key", Status: "active",
		}).Error; err != nil {
			f.Fatalf("seed secret: %v", err)
		}
	}
	ls := NewLocalStorage(db)
	ctx := context.Background()

	// Boundary pairs around every clamp edge and the multiplication's danger zone.
	seeds := []struct{ page, pageSize int }{
		{1, 20}, {1, -1}, {1, 0}, {1, maxStoragePageSize}, {1, maxStoragePageSize + 1},
		{0, 0}, {-5, -5}, {maxStoragePage, maxStoragePageSize}, {maxStoragePage + 1, maxStoragePageSize + 1},
		{math.MaxInt32, math.MaxInt32}, {math.MinInt32, math.MinInt32},
		{math.MaxInt, math.MaxInt}, {math.MinInt, math.MinInt}, {math.MaxInt, -1},
	}
	for _, s := range seeds {
		f.Add(s.page, s.pageSize)
	}

	f.Fuzz(func(t *testing.T, page, pageSize int) {
		// --- clamp invariants ---
		cps := clampPageSize(pageSize)
		if cps < 0 || cps > maxStoragePageSize {
			t.Fatalf("clampPageSize(%d)=%d escaped [0,%d] — a negative reaches Limit() as unbounded (#G44)", pageSize, cps, maxStoragePageSize)
		}
		cp := clampPage(page)
		if cp < 1 || cp > maxStoragePage {
			t.Fatalf("clampPage(%d)=%d escaped [1,%d]", page, cp, maxStoragePage)
		}

		// --- offset arithmetic: non-negative and no integer overflow ---
		// offset is computed in int exactly as production does; detect wrap with the
		// canonical division test (a*b overflowed iff a!=0 && (a*b)/a != b), which is
		// correct at any int width — comparing against an int64 recomputation would be
		// useless where int IS int64 (both wrap identically).
		a := cp - 1
		offset := a * cps
		if a != 0 && offset/a != cps {
			t.Fatalf("OFFSET OVERFLOW: (clampPage(%d)-1)*clampPageSize(%d) wrapped (a=%d cps=%d offset=%d) — a raised ceiling let the OFFSET bound overflow", page, pageSize, a, cps, offset)
		}
		if offset < 0 {
			t.Fatalf("NEGATIVE OFFSET: (clampPage(%d)-1)*clampPageSize(%d)=%d — a negative OFFSET is caller-controlled bound corruption", page, pageSize, offset)
		}

		// --- end-to-end: the real query must stay bounded and fail closed ---
		secrets, total, err := ls.ListSecrets(ctx, &storage.SecretFilter{Page: page, PageSize: pageSize})
		if err != nil {
			t.Fatalf("ListSecrets(page=%d,pageSize=%d) errored on a bound it must clamp, not reject: %v", page, pageSize, err)
		}
		if len(secrets) > maxStoragePageSize {
			t.Fatalf("UNBOUNDED RESULT: ListSecrets(page=%d,pageSize=%d) returned %d rows > ceiling %d — the LIMIT clause was dropped (#G44)", page, pageSize, len(secrets), maxStoragePageSize)
		}
		if int64(len(secrets)) > total {
			t.Fatalf("ListSecrets returned %d rows but reported total=%d", len(secrets), total)
		}
		if cps == 0 && len(secrets) != 0 {
			t.Fatalf("pageSize clamped to 0 but ListSecrets(page=%d,pageSize=%d) still returned %d rows — Limit(0) must yield no rows, not every row", page, pageSize, len(secrets))
		}
	})
}
