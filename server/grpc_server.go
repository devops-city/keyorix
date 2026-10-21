package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/grpc"
)

func startGRPCServer(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) error {
	// Create gRPC server
	grpcServer, err := grpc.NewServer(cfg, coreService)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}

	// Create listener
	lis, err := bindListener(cfg.Server.GRPC)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port: %w", err)
	}

	log.Printf("gRPC server listening on %s%s", lis.Addr().String(), bindScopeNote(cfg.Server.GRPC.BindHost()))

	// Start server
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	log.Println("Shutting down gRPC server...")
	stopGRPCServerWithTimeout(grpcServer, grpcShutdownTimeout)
	return nil
}

// grpcShutdownTimeout bounds how long startGRPCServer waits for
// grpcServer.GracefulStop() to drain in-flight RPCs before falling back to
// the forceful grpcServer.Stop(). Matches the HTTP listener's shutdownCtx
// timeout (see startHTTPServer) so neither transport can block shutdown past
// 10s on its own — main()'s outer 30s select/time.After backstop only forces
// process exit; it never calls grpcServer.Stop() or otherwise interrupts a
// goroutine still blocked inside GracefulStop(), so without this the abandoned
// goroutine (and any in-flight RPC/cleanup inside it) would just be leaked
// rather than drained deterministically.
const grpcShutdownTimeout = 10 * time.Second

// grpcGracefulStopper is the subset of *grpc.Server's shutdown surface that
// stopGRPCServerWithTimeout needs. Extracted as an interface (rather than
// depending on *grpc.Server directly) so a test can exercise the
// timeout/fallback branch with a fake whose GracefulStop() blocks
// indefinitely, without standing up a real gRPC listener or an actual
// long-lived RPC.
type grpcGracefulStopper interface {
	GracefulStop()
	Stop()
}

// stopGRPCServerWithTimeout runs gs.GracefulStop() in a goroutine and waits
// up to timeout for it to finish draining in-flight RPCs. A client that opens
// a long-lived or slow streaming RPC (e.g. StreamAuditLogs) and never closes
// it would otherwise block GracefulStop() forever; if timeout fires first,
// this calls gs.Stop() to forcibly cancel every outstanding RPC immediately
// instead of leaving that goroutine — and whatever RPC/cleanup it's still
// waiting on — abandoned mid-flight when main() eventually gives up.
func stopGRPCServerWithTimeout(gs grpcGracefulStopper, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		gs.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		log.Println("gRPC graceful shutdown timeout exceeded, forcing stop")
		gs.Stop()
	}
}
