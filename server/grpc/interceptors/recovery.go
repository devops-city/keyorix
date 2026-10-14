package interceptors

import (
	"context"
	"log"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryInterceptor returns a unary server interceptor for panic recovery
func RecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				// Log the panic with stack trace
				log.Printf("gRPC PANIC in %s: %v\n%s", info.FullMethod, r, debug.Stack())

				// Return internal server error
				err = status.Errorf(codes.Internal, "Internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// StreamRecoveryInterceptor returns a stream server interceptor for panic recovery
func StreamRecoveryInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				// Log the panic with stack trace
				log.Printf("gRPC STREAM PANIC in %s: %v\n%s", info.FullMethod, r, debug.Stack())

				// Return internal server error
				err = status.Errorf(codes.Internal, "Internal server error")
			}
		}()

		return handler(srv, stream)
	}
}
