package interceptors

import (
	"context"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
)

// Metrics holds gRPC server metrics
type Metrics struct {
	TotalRequests   int64
	SuccessRequests int64
	ErrorRequests   int64
	TotalDuration   int64 // in nanoseconds
}

// grpcMetrics is the process-wide metrics singleton: exactly one gRPC server
// runs per process, so one shared counter set is correct in production.
// MetricsInterceptor and GetGRPCMetrics always operate on this global.
var grpcMetrics = &Metrics{}

// MetricsInterceptor returns a unary server interceptor for collecting metrics
// into the shared, process-wide grpcMetrics singleton.
func MetricsInterceptor() grpc.UnaryServerInterceptor {
	return metricsInterceptorFor(grpcMetrics)
}

// metricsInterceptorFor returns a unary server interceptor that records into
// target instead of the package-level grpcMetrics singleton — the injection
// seam #1504 added so tests can construct a fully isolated interceptor bound
// to its own *Metrics instance, rather than three tests racing to reset/read/
// assert on shared process-wide state with no isolation contract between
// them. Production code always goes through MetricsInterceptor above, which
// fixes target to grpcMetrics; this unexported variant exists for tests only
// and changes no production behavior.
func metricsInterceptorFor(target *Metrics) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()

		// Increment total requests
		atomic.AddInt64(&target.TotalRequests, 1)

		// Call the handler
		resp, err := handler(ctx, req)

		// Record duration
		duration := time.Since(start)
		atomic.AddInt64(&target.TotalDuration, duration.Nanoseconds())

		// Record success/error
		if err != nil {
			atomic.AddInt64(&target.ErrorRequests, 1)
		} else {
			atomic.AddInt64(&target.SuccessRequests, 1)
		}

		return resp, err
	}
}

// loadMetrics returns an atomic point-in-time snapshot of m's four counters.
func loadMetrics(m *Metrics) *Metrics {
	return &Metrics{
		TotalRequests:   atomic.LoadInt64(&m.TotalRequests),
		SuccessRequests: atomic.LoadInt64(&m.SuccessRequests),
		ErrorRequests:   atomic.LoadInt64(&m.ErrorRequests),
		TotalDuration:   atomic.LoadInt64(&m.TotalDuration),
	}
}

// GetGRPCMetrics returns a snapshot of the current process-wide gRPC metrics.
func GetGRPCMetrics() *Metrics {
	return loadMetrics(grpcMetrics)
}

// GetAverageResponseTime returns the average response time in milliseconds
func (m *Metrics) GetAverageResponseTime() float64 {
	if m.TotalRequests == 0 {
		return 0
	}
	return float64(m.TotalDuration) / float64(m.TotalRequests) / 1e6 // Convert to milliseconds
}

// GetSuccessRate returns the success rate as a percentage
func (m *Metrics) GetSuccessRate() float64 {
	if m.TotalRequests == 0 {
		return 0
	}
	return float64(m.SuccessRequests) / float64(m.TotalRequests) * 100
}

// GetErrorRate returns the error rate as a percentage
func (m *Metrics) GetErrorRate() float64 {
	if m.TotalRequests == 0 {
		return 0
	}
	return float64(m.ErrorRequests) / float64(m.TotalRequests) * 100
}
