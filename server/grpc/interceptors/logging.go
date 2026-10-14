package interceptors

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// LoggingInterceptor returns a unary server interceptor for logging
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()

		// Get client info
		clientIP := "unknown"
		if p, ok := peer.FromContext(ctx); ok {
			clientIP = p.Addr.String()
		}

		// Call the handler
		resp, err := handler(ctx, req)

		// Log the request
		duration := time.Since(start)
		status := "OK"
		if err != nil {
			status = "ERROR"
		}

		log.Printf(
			"gRPC [%s] %s - %s - %v - %s",
			info.FullMethod,
			status,
			duration,
			clientIP,
			getErrorMessage(err),
		)

		// Log slow requests
		if isSlowRequest(duration) {
			log.Printf("SLOW gRPC REQUEST: %s took %v", info.FullMethod, duration)
		}

		return resp, err
	}
}

// slowRequestThreshold is the handler duration past which a request is logged
// as slow. A named constant (rather than the literal inline) so
// isSlowRequest's boundary is exercisable by a unit test with a synthetic
// duration, not only by a real sleep timed against wall-clock precision.
const slowRequestThreshold = 1 * time.Second

func isSlowRequest(duration time.Duration) bool {
	return duration > slowRequestThreshold
}

// StreamLoggingInterceptor returns a stream server interceptor for logging
func StreamLoggingInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()

		// Get client info
		clientIP := "unknown"
		if p, ok := peer.FromContext(stream.Context()); ok {
			clientIP = p.Addr.String()
		}

		// Call the handler
		err := handler(srv, stream)

		// Log the stream
		duration := time.Since(start)
		status := "OK"
		if err != nil {
			status = "ERROR"
		}

		log.Printf(
			"gRPC STREAM [%s] %s - %v - %s - %s",
			info.FullMethod,
			status,
			duration,
			clientIP,
			getErrorMessage(err),
		)

		return err
	}
}

// getErrorMessage extracts error message safely
func getErrorMessage(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
