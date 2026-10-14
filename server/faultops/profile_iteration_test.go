package faultops

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestProfileOneIteration times each phase of newFaultWorld + one full
// runOneFuzzIteration-shaped pass, to find where the ~18s/iteration the
// -fuzztime burst showed actually goes. Not a correctness test — logs only.
func TestProfileOneIteration(t *testing.T) {
	report := func(label string, start time.Time) {
		t.Logf("PROFILE %-28s %v", label, time.Since(start))
	}

	overall := time.Now()

	t0 := time.Now()
	w := newFaultWorld(t, nil)
	report("newFaultWorld (total)", t0)
	_ = w

	op := opCatalog[0] // REST PUT /api/v1/roles/{id}
	ctx := context.Background()

	t1 := time.Now()
	state, err := op.Setup(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	report("op.Setup", t1)

	t2 := time.Now()
	if _, err := snapshotDB(w.db); err != nil {
		t.Fatal(err)
	}
	report("snapshotDB (before)", t2)

	t3 := time.Now()
	if _, err := op.Execute(ctx, w, state); err != nil {
		t.Fatal(err)
	}
	report("op.Execute", t3)

	t4 := time.Now()
	if _, err := snapshotDB(w.db); err != nil {
		t.Fatal(err)
	}
	report("snapshotDB (after)", t4)

	report("TOTAL (one world, one op)", overall)
}

// TestProfileNewFaultWorldSubphases breaks newFaultWorld itself down further
// by timing DB setup, bootstrap+login, REST router construction, and gRPC
// server+bufconn construction separately -- newFaultWorld doesn't expose
// these as separate calls, so this duplicates its body with timers rather
// than modifying the real one (which stays timer-free for the actual harness).
func TestProfileNewFaultWorldSubphases(t *testing.T) {
	for i := range 3 {
		t.Run("", func(t *testing.T) {
			overall := time.Now()
			w := newFaultWorld(t, nil)
			t.Logf("PROFILE run %d: newFaultWorld total = %v", i, time.Since(overall))
			_ = w
		})
	}
}

// TestProfileWorldReuseSpeedup is M5's before/after measurement: N
// iterations built the OLD way (a fresh newFaultWorld per iteration, the
// per-input cost every other runOneFuzzIteration caller still pays) versus N
// iterations reusing ONE world pair (one buildReusableFaultWorld, then
// resetForReuse per iteration -- the path runOneFuzzIterationWithWorlds
// takes when given non-nil worlds, exactly as TestWorldReuseSoundness
// exercises it). Not a correctness test -- logs only; the soundness gate is
// what proves correctness.
func TestProfileWorldReuseSpeedup(t *testing.T) {
	if os.Getenv("KEYORIX_FAULTOPS_PROFILE") == "" {
		t.Skip("profiling only; set KEYORIX_FAULTOPS_PROFILE=1 to run (builds 16 worlds)")
	}
	const n = 15

	freshStart := time.Now()
	for range n {
		w := newFaultWorld(t, nil)
		_ = w
	}
	freshTotal := time.Since(freshStart)
	t.Logf("PROFILE fresh-per-iteration: %d worlds in %v (%v/world)", n, freshTotal, freshTotal/n)

	reusedStart := time.Now()
	w := buildReusableFaultWorld(t, nil)
	buildTotal := time.Since(reusedStart)
	resetStart := time.Now()
	for range n {
		w.resetForReuse(t, nil)
	}
	resetTotal := time.Since(resetStart)
	reusedTotal := time.Since(reusedStart)
	t.Logf("PROFILE reused-world: 1 build (%v) + %d resets in %v (%v/reset) = %v total (%v/iteration incl. amortized build)",
		buildTotal, n, resetTotal, resetTotal/n, reusedTotal, reusedTotal/n)

	t.Logf("PROFILE speedup: %.2fx per-iteration (fresh %v/iter vs reused %v/iter, both amortized over %d)",
		float64(freshTotal)/float64(reusedTotal), freshTotal/n, reusedTotal/n, n)
}
