package grpc

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// serveNewServer starts NewServer(cfg) on a loopback listener and returns its address.
func serveNewServer(t *testing.T, cfg *config.Config) string {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	srv, err := NewServer(cfg, h.CoreService)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String()
}

// TestNewServer_HandshakeTimeoutClosesSilentConnection: a client that opens TCP
// and never sends the HTTP/2 preface is disconnected after
// server.grpc.keepalive.handshake_timeout. grpc-go's own default would hold the
// connection for 120s.
func TestNewServer_HandshakeTimeoutClosesSilentConnection(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.Keepalive.HandshakeTimeout = "300ms"
	addr := serveNewServer(t, cfg)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	// The server writes its own SETTINGS preface first; drain until it hangs up.
	_, err = io.Copy(io.Discard, conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("silent connection still open after %v: handshake timeout not applied", time.Since(start))
	}
	// err == nil is EOF (server closed); a reset is a close too.
	t.Logf("server closed the silent connection after %v (err=%v)", time.Since(start), err)
}

// TestNewServer_MaxConnectionIdleReclaimsIdleConnection: after one RPC, a
// connection with nothing in flight gets GOAWAY after
// server.grpc.keepalive.max_connection_idle and the client drops to IDLE. Without
// MaxConnectionIdle the connection stays READY forever (the client acks pings).
func TestNewServer_MaxConnectionIdleReclaimsIdleConnection(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.Keepalive.MaxConnectionIdle = "300ms"
	addr := serveNewServer(t, cfg)

	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := pb.NewSystemServiceClient(cc).HealthCheck(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if s := cc.GetState(); s != connectivity.Ready {
		t.Fatalf("state after RPC = %v, want READY", s)
	}
	for s := cc.GetState(); s == connectivity.Ready; s = cc.GetState() {
		if !cc.WaitForStateChange(ctx, s) {
			t.Fatal("idle connection still READY after 10s: max_connection_idle not applied")
		}
	}
}

// TestNewServer_AdvertisesStreamAndHeaderLimits reads the server's HTTP/2 SETTINGS
// frame off the wire: it must advertise MAX_CONCURRENT_STREAMS and
// MAX_HEADER_LIST_SIZE. grpc-go sends neither by default (unlimited streams per
// connection, 16 MiB of headers).
func TestNewServer_AdvertisesStreamAndHeaderLimits(t *testing.T) {
	addr := serveNewServer(t, &config.Config{})

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("reading server SETTINGS: %v", err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		streams, ok := sf.Value(http2.SettingMaxConcurrentStreams)
		if !ok || streams != grpcMaxConcurrentStreams {
			t.Errorf("SETTINGS_MAX_CONCURRENT_STREAMS = %d (sent=%v), want %d", streams, ok, grpcMaxConcurrentStreams)
		}
		hdr, ok := sf.Value(http2.SettingMaxHeaderListSize)
		if !ok || hdr != grpcMaxHeaderListSize {
			t.Errorf("SETTINGS_MAX_HEADER_LIST_SIZE = %d (sent=%v), want %d", hdr, ok, grpcMaxHeaderListSize)
		}
		return
	}
}

// TestGRPCConnectionLimitDefaults pins the defaults the matrix documents.
func TestGRPCConnectionLimitDefaults(t *testing.T) {
	var ka config.GRPCKeepaliveConfig
	if got := ka.GetHandshakeTimeout(); got != 10*time.Second {
		t.Errorf("default handshake_timeout = %v, want 10s", got)
	}
	if got := ka.GetMaxConnectionIdle(); got != 15*time.Minute {
		t.Errorf("default max_connection_idle = %v, want 15m", got)
	}
	if got := ka.GetMaxConnectionAge(); got != time.Hour {
		t.Errorf("default max_connection_age = %v, want 1h", got)
	}
	// An operator cannot switch the bounds off with 0 or a negative value.
	ka = config.GRPCKeepaliveConfig{HandshakeTimeout: "0s", MaxConnectionIdle: "-1s"}
	if ka.GetHandshakeTimeout() <= 0 || ka.GetMaxConnectionIdle() <= 0 {
		t.Error("a zero/negative handshake_timeout or max_connection_idle must fall back to the default")
	}
	if grpcMaxConcurrentStreams <= 0 || grpcMaxConcurrentStreams > 1024 {
		t.Errorf("grpcMaxConcurrentStreams = %d", grpcMaxConcurrentStreams)
	}
}
