package interceptors

import (
	"context"

	"google.golang.org/grpc"

	"github.com/keyorixhq/keyorix/internal/core"
)

// ShareElevationAuditInterceptor gives every unary RPC a core.ShareElevationRecorder
// and writes the share_access_elevated rows it collected only when the RPC returns
// without error — the gRPC counterpart of the HTTP share-aware gate's 2xx commit
// (#3001 follow-up: audit an elevated action when it is PERFORMED, never on a refusal
// or a failure). Without a recorder on the context, core refuses a write-share
// elevation outright, so leaving this out of the chain fails closed.
func ShareElevationAuditInterceptor(cs *core.KeyorixCore) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx, rec := core.WithShareElevationRecorder(ctx)
		resp, err := handler(ctx, req)
		if err == nil {
			cs.CommitShareElevations(core.DetachedAuditContext(ctx), rec)
		}
		return resp, err
	}
}
