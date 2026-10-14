package interceptors

import (
	"context"
	"log"
	"strconv"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// WriteContentionRetryAfterSeconds mirrors the HTTP API's Retry-After for the
// same condition (server/middleware.WriteContentionRetryAfterSeconds); gRPC
// carries it as the "retry-after" trailer.
const WriteContentionRetryAfterSeconds = 5

const writeContentionMessage = "The service is temporarily busy. Please retry shortly."

// WriteContentionInterceptor maps "the SQLite write gate timed out" to
// codes.Unavailable with a fixed message and a retry-after trailer, the gRPC
// counterpart of server/middleware.WriteContention.
//
// Like the HTTP side it only converts an answer that is already an internal
// failure (codes.Internal / codes.Unknown), or a bare gate sentinel that escaped
// unwrapped; any other status a service chose (NotFound, FailedPrecondition,
// PermissionDenied, ...) is left alone. gRPC exposes no login/credential RPC, so
// there is no credential surface to exempt.
func WriteContentionInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, sig := corestorage.WithContentionSignal(ctx)
		resp, err := handler(ctx, req)
		if err == nil {
			return resp, nil
		}
		if !corestorage.IsWriteContention(err) {
			if c := status.Code(err); !(sig.Hit() && (c == codes.Internal || c == codes.Unknown)) {
				return resp, err
			}
		}
		log.Printf("write gate contention: %s answered Unavailable (retry-after %ds)", info.FullMethod, WriteContentionRetryAfterSeconds)
		_ = grpc.SetTrailer(ctx, metadata.Pairs("retry-after", strconv.Itoa(WriteContentionRetryAfterSeconds)))
		return nil, status.Error(codes.Unavailable, writeContentionMessage)
	}
}
