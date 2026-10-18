package fuzzutil

import "testing"

var benchSink int

// pureFn stands in for a cheap pure function under fuzz: the benchmark measures
// Guard's per-call overhead, so fn must be nearly free.
func pureFn() { benchSink++ }

func BenchmarkGuard(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Guard(b.Fatalf, "bench", pureFn)
	}
}

func BenchmarkGuardParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Guard(b.Fatalf, "bench", func() {})
		}
	})
}
