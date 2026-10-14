package faultstorage

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newFaultTestReal builds a fresh in-memory SQLite-backed storage.Storage, plus
// the raw *gorm.DB so tests can assert on real row state directly rather than
// through the interface under test. Each test gets its own DB — a fresh world
// per test rather than a shared+reset one (unlike the fuzzers built on
// internal/testutil/fuzzworld, which reuse one world per testing.F).
func newFaultTestReal(t *testing.T) (storage.Storage, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return store.NewLocalStorage(db), db
}

var errRedProof = errors.New("faultstorage red-proof sentinel")

// TestFaultyStorage_PassThroughWhenNoFaultArmed is the green control: with spec
// nil, every call must behave exactly like calling real directly.
func TestFaultyStorage_PassThroughWhenNoFaultArmed(t *testing.T) {
	ctx := context.Background()
	real, _ := newFaultTestReal(t)
	w := NewFaultyStorage(real, nil)

	created, err := w.CreateProject(ctx, &models.Project{Name: "p1"})
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	got, err := w.GetProject(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if got.Name != "p1" {
		t.Fatalf("got project name %q, want p1", got.Name)
	}
	if w.Fired() {
		t.Fatalf("Fired() = true with no fault armed")
	}
}

// TestFaultyStorage_KindError_FiresOnNthCallOnlyAndSkipsTheRealCall is the
// red-proof for KindError: it must fire on exactly the Nth call to the named
// method, an EARLIER call to the same method must pass through untouched, and a
// fired KindError call must never reach the real storage (no effect at all).
func TestFaultyStorage_KindError_FiresOnNthCallOnlyAndSkipsTheRealCall(t *testing.T) {
	ctx := context.Background()
	real, db := newFaultTestReal(t)
	w := NewFaultyStorage(real, &FaultSpec{Method: "CreateProject", NthCall: 2, Kind: KindError, Err: errRedProof})

	// 1st call: fault targets the 2nd call, so this one must pass through.
	first, err := w.CreateProject(ctx, &models.Project{Name: "first"})
	if err != nil {
		t.Fatalf("1st CreateProject unexpectedly faulted: %v", err)
	}
	if w.Fired() {
		t.Fatalf("Fired() = true after the 1st call, fault targets the 2nd")
	}

	// 2nd call: must fire.
	second, err := w.CreateProject(ctx, &models.Project{Name: "second"})
	if !errors.Is(err, errRedProof) {
		t.Fatalf("2nd CreateProject error = %v, want errRedProof", err)
	}
	if second != nil {
		t.Fatalf("2nd CreateProject returned non-nil result %v alongside an error", second)
	}
	if !w.Fired() {
		t.Fatalf("Fired() = false after the 2nd call, fault should have fired")
	}

	// The real storage must show exactly the 1st project — KindError never
	// invokes the real method, so the 2nd project must not exist at all.
	var count int64
	if err := db.Model(&models.Project{}).Count(&count).Error; err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if count != 1 {
		t.Fatalf("project count = %d, want 1 (only %q, the 2nd must never have been written)", count, first.Name)
	}
}

// TestFaultyStorage_KindPanic_PropagatesTheInjectedValue is the red-proof for
// KindPanic: the goroutine must panic with exactly the armed Err, not a generic
// runtime panic and not a swallowed one.
func TestFaultyStorage_KindPanic_PropagatesTheInjectedValue(t *testing.T) {
	ctx := context.Background()
	real, _ := newFaultTestReal(t)
	w := NewFaultyStorage(real, &FaultSpec{Method: "CreateProject", NthCall: 1, Kind: KindPanic, Err: errRedProof})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("CreateProject did not panic")
		}
		if !errors.Is(r.(error), errRedProof) {
			t.Fatalf("panic value = %v, want errRedProof", r)
		}
	}()
	_, _ = w.CreateProject(ctx, &models.Project{Name: "boom"})
	t.Fatalf("unreachable: panic should have unwound the stack")
}

// TestFaultyStorage_KindEffectThenError_RealEffectHappensDespiteTheReturnedError
// is the red-proof for KindEffectThenError (goal oracle (d)'s fault class): the
// real write must actually land even though the caller sees an error — proving
// the wrapper models "committed, then the caller found out late," not a clean
// no-op failure.
func TestFaultyStorage_KindEffectThenError_RealEffectHappensDespiteTheReturnedError(t *testing.T) {
	ctx := context.Background()
	real, db := newFaultTestReal(t)
	w := NewFaultyStorage(real, &FaultSpec{Method: "CreateProject", NthCall: 1, Kind: KindEffectThenError, Err: errRedProof})

	_, err := w.CreateProject(ctx, &models.Project{Name: "ghost"})
	if !errors.Is(err, errRedProof) {
		t.Fatalf("CreateProject error = %v, want errRedProof", err)
	}
	var count int64
	if err := db.Model(&models.Project{}).Where("name = ?", "ghost").Count(&count).Error; err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if count != 1 {
		t.Fatalf("project row count for %q = %d, want 1 (the real effect must have happened despite the returned error)", "ghost", count)
	}
}

// TestFaultyStorage_WithTransaction_FaultInsideCallbackRollsBackTheWholeTransaction
// red-proofs the WithTransaction re-wrap: a fault armed for a method called only
// inside the transaction callback must both fire there AND cause the surrounding
// transaction to roll back when the caller correctly propagates the error — the
// call-count state must be shared between the parent wrapper and the
// transaction-scoped child the callback receives.
func TestFaultyStorage_WithTransaction_FaultInsideCallbackRollsBackTheWholeTransaction(t *testing.T) {
	ctx := context.Background()
	real, db := newFaultTestReal(t)
	w := NewFaultyStorage(real, &FaultSpec{Method: "CreateProject", NthCall: 1, Kind: KindError, Err: errRedProof})

	txErr := w.WithTransaction(ctx, func(tx storage.Storage) error {
		_, err := tx.CreateProject(ctx, &models.Project{Name: "in-tx"})
		return err
	})
	if !errors.Is(txErr, errRedProof) {
		t.Fatalf("WithTransaction error = %v, want errRedProof", txErr)
	}
	if !w.Fired() {
		t.Fatalf("Fired() = false, fault armed inside the transaction callback should have fired")
	}
	var count int64
	if err := db.Model(&models.Project{}).Count(&count).Error; err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if count != 0 {
		t.Fatalf("project count = %d, want 0 (the transaction must have rolled back)", count)
	}
}

// TestFaultyStorage_CallLog_RecordsEveryCallInOrderWithFiredFlag is a red-proof
// that the call log (used by the fuzz harness's readable trace) actually reflects
// which call fired and which didn't, not just a running total.
func TestFaultyStorage_CallLog_RecordsEveryCallInOrderWithFiredFlag(t *testing.T) {
	ctx := context.Background()
	real, _ := newFaultTestReal(t)
	w := NewFaultyStorage(real, &FaultSpec{Method: "CreateProject", NthCall: 2, Kind: KindError, Err: errRedProof})

	_, _ = w.CreateProject(ctx, &models.Project{Name: "a"})
	_, _ = w.GetProject(ctx, 1)
	_, _ = w.CreateProject(ctx, &models.Project{Name: "b"})

	calls := w.Calls()
	if len(calls) != 3 {
		t.Fatalf("call log length = %d, want 3", len(calls))
	}
	if calls[0].Method != "CreateProject" || calls[0].Fired {
		t.Fatalf("call 0 = %+v, want CreateProject/not-fired", calls[0])
	}
	if calls[1].Method != "GetProject" || calls[1].Fired {
		t.Fatalf("call 1 = %+v, want GetProject/not-fired", calls[1])
	}
	if calls[2].Method != "CreateProject" || !calls[2].Fired || calls[2].Kind != KindError {
		t.Fatalf("call 2 = %+v, want CreateProject/fired/KindError", calls[2])
	}
}

// TestFaultyStorage_Arm_ResetsCountsSoNthCallStartsFromTheArmPoint red-proofs
// Arm: a caller that makes N unfaulted "prefix" calls to a method, then Arms a
// fault targeting NthCall=1 of that SAME method, must see it fire on the VERY
// NEXT call — not on call N+1 overall (which prefix calls would already have
// consumed if the counter carried over untouched).
func TestFaultyStorage_Arm_ResetsCountsSoNthCallStartsFromTheArmPoint(t *testing.T) {
	ctx := context.Background()
	real, _ := newFaultTestReal(t)
	w := NewFaultyStorage(real, nil)

	// Unfaulted prefix: three CreateProject calls with no fault armed.
	for i := range 3 {
		if _, err := w.CreateProject(ctx, &models.Project{Name: "prefix"}); err != nil {
			t.Fatalf("prefix CreateProject %d: %v", i, err)
		}
	}
	if w.Fired() {
		t.Fatalf("Fired() = true after an unfaulted prefix")
	}

	w.Arm(&FaultSpec{Method: "CreateProject", NthCall: 1, Kind: KindError, Err: errRedProof})

	_, err := w.CreateProject(ctx, &models.Project{Name: "post-arm"})
	if !errors.Is(err, errRedProof) {
		t.Fatalf("first CreateProject after Arm(NthCall:1) error = %v, want errRedProof — counter did not reset", err)
	}
	if !w.Fired() {
		t.Fatalf("Fired() = false after the armed call should have fired")
	}
}
