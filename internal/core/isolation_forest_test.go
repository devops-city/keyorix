package core

import (
	"math"
	"math/rand"
	"testing"
)

func TestAvgPathLength(t *testing.T) {
	t.Parallel()
	// Documented anchor values: c(1)=0, c(2)=1; c(n) grows ~ln(n).
	if got := avgPathLength(1); got != 0 {
		t.Fatalf("c(1) = %v, want 0", got)
	}
	if got := avgPathLength(2); got != 1 {
		t.Fatalf("c(2) = %v, want 1", got)
	}
	if c10, c100 := avgPathLength(10), avgPathLength(100); !(c100 > c10 && c10 > 1) {
		t.Fatalf("expected monotone growth 1 < c(10) < c(100), got c(10)=%v c(100)=%v", c10, c100)
	}
}

// TestIsolationForestSeparatesOutlier is the core behavioural guarantee: a point far
// outside a tight normal cluster scores higher (more anomalous) than a point inside it.
func TestIsolationForestSeparatesOutlier(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(42))
	// 200 normal points clustered tightly around (10,10,10).
	data := make([][]float64, 0, 201)
	for range 200 {
		data = append(data, []float64{
			10 + rng.Float64(),
			10 + rng.Float64(),
			10 + rng.Float64(),
		})
	}
	forest := newIsolationForest(data, 100, 256, rand.New(rand.NewSource(7)))
	if forest == nil {
		t.Fatal("expected a trained forest")
	}

	normal := forest.score([]float64{10.5, 10.5, 10.5})
	outlier := forest.score([]float64{100, 100, 100})
	if outlier <= normal {
		t.Fatalf("expected outlier score > normal score, got outlier=%.3f normal=%.3f", outlier, normal)
	}
	if outlier < 0.6 {
		t.Errorf("a clear outlier should score well above 0.5, got %.3f", outlier)
	}
	if normal > 0.6 {
		t.Errorf("an in-cluster point should score near 0.5, got %.3f", normal)
	}
}

// TestIsolationForestDeterministic verifies the seed makes scoring reproducible — the
// property the rest of the system relies on for stable, testable alerts.
func TestIsolationForestDeterministic(t *testing.T) {
	t.Parallel()
	data := make([][]float64, 100)
	for i := range data {
		data[i] = []float64{float64(i % 24), float64(i % 5), float64(i % 7)}
	}
	x := []float64{3, 0, 0}
	a := newIsolationForest(data, 50, 64, rand.New(rand.NewSource(99))).score(x)
	b := newIsolationForest(data, 50, 64, rand.New(rand.NewSource(99))).score(x)
	if math.Abs(a-b) > 1e-12 {
		t.Fatalf("same seed must give identical scores, got %v vs %v", a, b)
	}
}

func TestIsolationForestTooLittleData(t *testing.T) {
	t.Parallel()
	if newIsolationForest([][]float64{{1, 2, 3}}, 100, 256, rand.New(rand.NewSource(1))) != nil {
		t.Fatal("a single-row dataset should yield no forest")
	}
	if newIsolationForest(nil, 100, 256, rand.New(rand.NewSource(1))) != nil {
		t.Fatal("empty data should yield no forest")
	}
}

func TestIsolationForestConstantFeatures(t *testing.T) {
	t.Parallel()
	// All-identical points: no split can separate them, so every score collapses to
	// the neutral 0.5 — nothing is flagged. Must not panic or diverge.
	data := make([][]float64, 50)
	for i := range data {
		data[i] = []float64{5, 5, 5}
	}
	forest := newIsolationForest(data, 50, 32, rand.New(rand.NewSource(3)))
	if forest == nil {
		t.Fatal("expected a forest even on constant data")
	}
	if s := forest.score([]float64{5, 5, 5}); math.Abs(s-0.5) > 0.2 {
		t.Errorf("constant data should score ~0.5, got %v", s)
	}
}
