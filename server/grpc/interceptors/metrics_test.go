package interceptors

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// TestMetricsInterceptor_CountsSuccessAndError verifies that the metrics interceptor
// correctly increments success and error counters, and records total duration.
//
// #1504: bound to a fresh, test-local *Metrics via metricsInterceptorFor rather
// than the shared package-level grpcMetrics singleton (MetricsInterceptor()) —
// this test previously computed a before/after delta on that global with no
// isolation contract against prometheus_test.go's two tests, which hard-reset
// the same global. A per-test instance removes the shared state entirely
// instead of coping with it, so no delta arithmetic is needed: every count
// asserted below is this call's own, absolute total.
func TestMetricsInterceptor_CountsSuccessAndError(t *testing.T) {
	target := &Metrics{}
	interceptor := metricsInterceptorFor(target)
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	// A successful call.
	_, err := interceptor(context.Background(), nil, info,
		func(_ context.Context, _ any) (any, error) {
			time.Sleep(time.Millisecond) // #2927: keep duration above clock resolution
			return "ok", nil
		})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// A failing call.
	_, err = interceptor(context.Background(), nil, info,
		func(_ context.Context, _ any) (any, error) {
			return nil, errors.New("fail")
		})
	if err == nil {
		t.Fatal("expected an error from the interceptor, got nil")
	}

	if target.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", target.TotalRequests)
	}
	if target.SuccessRequests != 1 {
		t.Errorf("SuccessRequests = %d, want 1", target.SuccessRequests)
	}
	if target.ErrorRequests != 1 {
		t.Errorf("ErrorRequests = %d, want 1", target.ErrorRequests)
	}
	if target.TotalDuration <= 0 {
		t.Errorf("TotalDuration should be positive, got %d", target.TotalDuration)
	}
}

// TestMetricsInterceptor_UsesSharedGlobalSingleton verifies that the production
// entrypoints — MetricsInterceptor() and GetGRPCMetrics() — are actually wired to
// the same package-level grpcMetrics singleton, not merely that metricsInterceptorFor
// and loadMetrics work in isolation (already covered by the test above and by
// TestGRPCPrometheusCollector). Uses a before/after delta on the shared global
// rather than resetting it (the global is process-wide and other tests never
// write to it directly, only through this same pair of functions), so the
// assertion holds regardless of test execution order.
func TestMetricsInterceptor_UsesSharedGlobalSingleton(t *testing.T) {
	before := GetGRPCMetrics()

	interceptor := MetricsInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	// #2927: the handlers must take measurable time. A no-op handler can finish
	// within the clock's resolution, so time.Since reports 0ns and TotalDuration
	// legitimately does not move (~1.6% of runs) — a flaw in the test's input, not
	// in the interceptor, and not shared state: the delta arithmetic here is
	// already immune to other tests' writes.
	_, err := interceptor(context.Background(), nil, info,
		func(_ context.Context, _ any) (any, error) {
			time.Sleep(time.Millisecond)
			return "ok", nil
		})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	_, err = interceptor(context.Background(), nil, info,
		func(_ context.Context, _ any) (any, error) {
			time.Sleep(time.Millisecond)
			return nil, errors.New("fail")
		})
	if err == nil {
		t.Fatal("expected an error from the interceptor, got nil")
	}

	after := GetGRPCMetrics()

	if after.TotalRequests != before.TotalRequests+2 {
		t.Errorf("TotalRequests delta = %d, want 2 (MetricsInterceptor must record into the same singleton GetGRPCMetrics reads)", after.TotalRequests-before.TotalRequests)
	}
	if after.SuccessRequests != before.SuccessRequests+1 {
		t.Errorf("SuccessRequests delta = %d, want 1", after.SuccessRequests-before.SuccessRequests)
	}
	if after.ErrorRequests != before.ErrorRequests+1 {
		t.Errorf("ErrorRequests delta = %d, want 1", after.ErrorRequests-before.ErrorRequests)
	}
	if after.TotalDuration <= before.TotalDuration {
		t.Errorf("TotalDuration should have increased, before=%d after=%d", before.TotalDuration, after.TotalDuration)
	}
}

// TestMetrics_AverageResponseTime verifies the helper returns 0 when no requests have
// been recorded.
func TestMetrics_AverageResponseTime(t *testing.T) {
	m := &Metrics{}
	if got := m.GetAverageResponseTime(); got != 0 {
		t.Errorf("GetAverageResponseTime on empty Metrics = %v, want 0", got)
	}
}

// TestMetrics_SuccessAndErrorRateOnEmpty verifies helper functions return 0 for an empty
// Metrics struct (no division by zero).
func TestMetrics_SuccessAndErrorRateOnEmpty(t *testing.T) {
	m := &Metrics{}
	if got := m.GetSuccessRate(); got != 0 {
		t.Errorf("GetSuccessRate on empty Metrics = %v, want 0", got)
	}
	if got := m.GetErrorRate(); got != 0 {
		t.Errorf("GetErrorRate on empty Metrics = %v, want 0", got)
	}
}

// TestMetrics_Rates verifies computed rates for a known distribution.
func TestMetrics_Rates(t *testing.T) {
	m := &Metrics{
		TotalRequests:   10,
		SuccessRequests: 8,
		ErrorRequests:   2,
		TotalDuration:   int64(10e9), // 10 seconds total → 1000ms avg
	}
	if got := m.GetSuccessRate(); got != 80.0 {
		t.Errorf("GetSuccessRate = %v, want 80", got)
	}
	if got := m.GetErrorRate(); got != 20.0 {
		t.Errorf("GetErrorRate = %v, want 20", got)
	}
	if got := m.GetAverageResponseTime(); got != 1000.0 {
		t.Errorf("GetAverageResponseTime = %v, want 1000", got)
	}
}
