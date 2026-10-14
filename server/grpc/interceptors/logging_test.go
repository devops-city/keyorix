package interceptors

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// captureLog redirects the standard logger's output for the duration of fn and
// returns what it wrote — the only way to observe LoggingInterceptor's status
// ("OK"/"ERROR") and slow-request line, both local to the closure and never
// part of the interceptor's return value.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// TestLoggingInterceptor_SuccessPath ensures the logging interceptor passes through
// the handler's result without modifying it on a successful call.
func TestLoggingInterceptor_SuccessPath(t *testing.T) {
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	resp, err := interceptor(context.Background(), "req", info,
		func(_ context.Context, req any) (any, error) {
			return "resp-value", nil
		})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp != "resp-value" {
		t.Fatalf("expected resp-value, got %v", resp)
	}
}

// TestLoggingInterceptor_ErrorPath ensures the logging interceptor propagates handler
// errors without swallowing them.
func TestLoggingInterceptor_ErrorPath(t *testing.T) {
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}
	handlerErr := errors.New("something went wrong")

	resp, err := interceptor(context.Background(), nil, info,
		func(_ context.Context, _ any) (any, error) {
			return nil, handlerErr
		})
	if err == nil {
		t.Fatal("expected an error from the interceptor, got nil")
	}
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected the original error to propagate, got %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on error, got %v", resp)
	}
}

// The logged status line reports "OK" or "ERROR" matching the handler's actual
// outcome -- previously unverified: the earlier success/error-path tests above
// only checked the interceptor's return value, which doesn't depend on the
// local "status" variable used purely for the log line (found by mutation
// testing: negating "if err != nil" survived with no test noticing).
func TestLoggingInterceptor_LogsStatusMatchingOutcome(t *testing.T) {
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	okLog := captureLog(t, func() {
		_, _ = interceptor(context.Background(), nil, info,
			func(_ context.Context, _ any) (any, error) { return "ok", nil })
	})
	if !strings.Contains(okLog, " OK ") || strings.Contains(okLog, "ERROR") {
		t.Fatalf("expected a status of OK, not ERROR, got log line: %q", okLog)
	}

	errLog := captureLog(t, func() {
		_, _ = interceptor(context.Background(), nil, info,
			func(_ context.Context, _ any) (any, error) { return nil, errors.New("boom") })
	})
	if !strings.Contains(errLog, " ERROR ") || strings.Contains(errLog, " OK ") {
		t.Fatalf("expected a status of ERROR, not OK, got log line: %q", errLog)
	}
}

// StreamLoggingInterceptor's status line has the same OK/ERROR split as the
// unary path, on its own local "status" variable and its own "if err != nil"
// (a separate LIVED mutant from the unary one above).
func TestStreamLoggingInterceptor_LogsStatusMatchingOutcome(t *testing.T) {
	interceptor := StreamLoggingInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.SecretService/ListSecrets"}
	stream := &fakeServerStream{ctx: context.Background()}

	okLog := captureLog(t, func() {
		_ = interceptor(nil, stream, info, func(any, grpc.ServerStream) error { return nil })
	})
	if !strings.Contains(okLog, " OK ") || strings.Contains(okLog, "ERROR") {
		t.Fatalf("expected a status of OK, not ERROR, got log line: %q", okLog)
	}

	errLog := captureLog(t, func() {
		_ = interceptor(nil, stream, info, func(any, grpc.ServerStream) error { return errors.New("boom") })
	})
	if !strings.Contains(errLog, " ERROR ") || strings.Contains(errLog, " OK ") {
		t.Fatalf("expected a status of ERROR, not OK, got log line: %q", errLog)
	}
}

// isSlowRequest's boundary is tested directly against synthetic durations,
// not through a real sleep timed against wall-clock precision -- exact at
// the 1-second threshold itself (not-slow at exactly 1s, slow just past it),
// which a real-sleep test structurally can't assert without flakiness.
// Kills the CONDITIONALS_BOUNDARY (">" vs ">=") and ARITHMETIC_BASE
// (slowRequestThreshold's own definition) mutants a real-sleep version of
// this test left LIVED: a >=100ms-off sleep can't distinguish the original
// 1-second threshold from nearby mutations of it, only an exact synthetic
// duration can.
func TestIsSlowRequest(t *testing.T) {
	cases := []struct {
		name     string
		duration time.Duration
		want     bool
	}{
		{"well under threshold", 100 * time.Millisecond, false},
		{"exactly at threshold", 1 * time.Second, false},
		{"just past threshold", 1*time.Second + time.Millisecond, true},
		{"well past threshold", 5 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSlowRequest(tc.duration); got != tc.want {
				t.Errorf("isSlowRequest(%v) = %v, want %v", tc.duration, got, tc.want)
			}
		})
	}
}

// The interceptor actually wires isSlowRequest's result into the log line —
// checked end to end (not just the predicate in isolation) with a real, fast
// call that must not be reported as slow.
func TestLoggingInterceptor_FastRequestNotLoggedAsSlow(t *testing.T) {
	interceptor := LoggingInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	fastLog := captureLog(t, func() {
		_, _ = interceptor(context.Background(), nil, info,
			func(_ context.Context, _ any) (any, error) { return "ok", nil })
	})
	if strings.Contains(fastLog, "SLOW gRPC REQUEST") {
		t.Fatalf("a fast handler must not be logged as slow, got: %q", fastLog)
	}
}

// fakeServerStream is a minimal grpc.ServerStream for exercising
// StreamLoggingInterceptor directly, without a real gRPC connection.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

// TestGetErrorMessage verifies the helper returns the error string or empty for nil.
func TestGetErrorMessage(t *testing.T) {
	if got := getErrorMessage(nil); got != "" {
		t.Errorf("getErrorMessage(nil) = %q, want empty string", got)
	}
	e := errors.New("test error")
	if got := getErrorMessage(e); got != e.Error() {
		t.Errorf("getErrorMessage(err) = %q, want %q", got, e.Error())
	}
}
