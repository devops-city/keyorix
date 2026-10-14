package interceptors

import (
	"context"
	"time"

	"google.golang.org/grpc"
)

// TimeoutInterceptor returns a unary server interceptor that caps each RPC's
// duration at d, mirroring the HTTP API's request-timeout middleware
// (middleware.Timeout) so a slow or hung handler cannot tie up server resources
// indefinitely over gRPC when it would be bounded over HTTP.
//
// It is unary-only by design: streaming RPCs (e.g. StreamAuditLogs) are
// legitimately long-lived and must not be cut off, so the stream chain carries no
// timeout. context.WithTimeout only ever shortens the deadline, so a client that
// already set a tighter deadline keeps it; one that set none (or a longer one) is
// capped at d. On expiry the handler's context is cancelled and the RPC returns
// DeadlineExceeded.
func TimeoutInterceptor(d time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return handler(ctx, req)
	}
}
