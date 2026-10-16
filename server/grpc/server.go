package grpc

import (
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

// grpcUnaryTimeout caps each unary RPC's duration, matching the HTTP API's 60s
// request-timeout middleware (server/http/router.go) so the bound is the same on
// both transports. Streaming RPCs are exempt (see TimeoutInterceptor).
const grpcUnaryTimeout = 60 * time.Second

// grpcMaxConcurrentStreams caps in-flight RPCs per connection. StreamAuditLogs
// additionally caps held-open streams per principal (acquireStreamSlot).
const grpcMaxConcurrentStreams = 128

// grpcMaxHeaderListSize caps a request's metadata (HTTP/2 header list), matching
// the HTTP listener's 64 KiB MaxHeaderBytes.
const grpcMaxHeaderListSize = 64 << 10

// NewServer creates a new gRPC server. The auth interceptor validates session
// tokens against the shared core service. Service registration is wired in a
// later phase; until then the server runs with interceptors only.
func NewServer(cfg *config.Config, coreService *core.KeyorixCore) (*grpc.Server, error) {
	// Surface the gRPC interceptor metrics on the shared Prometheus /metrics endpoint.
	interceptors.RegisterPrometheusMetrics()

	// Create server options
	opts := []grpc.ServerOption{
		// Consistent with the HTTP API's secret-write-route body limit
		// (server/http/router.go's secretBodyLimit) — both are derived from the
		// same secrets.limits.max_secret_size via config.DeriveMaxRequestBodySize,
		// so a caller cannot bypass the HTTP transport's tighter limit by
		// switching to gRPC. gRPC's default MaxRecvMsgSize (4 MiB) would
		// otherwise silently let a request through this transport that the HTTP
		// API already rejects at the wire level for the same secret.
		grpc.MaxRecvMsgSize(int(config.DeriveMaxRequestBodySize(cfg.Secrets.Limits.MaxSecretSize))),
		// grpc.ChainUnaryInterceptor/ChainStreamInterceptor run interceptors in the
		// order listed: the first is OUTERMOST (executes first on the way in, last on
		// the way out), wrapping every interceptor listed after it. RecoveryInterceptor
		// / StreamRecoveryInterceptor are listed FIRST so a panic in ANY later
		// interceptor — metrics, logging, timeout, auth, or the handler itself — is
		// caught, instead of only panics inside the handler. A panic that unwound past
		// an inner (non-outermost) recovery interceptor would otherwise crash the
		// request with none of Recovery's clean INTERNAL status + logged stack trace.
		//
		// MetricsInterceptor is listed SECOND — inside Recovery but wrapping everything
		// after it, including AuthInterceptor — for parity with the HTTP API, where
		// PrometheusMiddleware is registered before the Authentication middleware
		// (server/http/router.go) and so records every request regardless of auth
		// outcome. Metrics used to run last, after Auth, so an auth-rejected gRPC call
		// (bad/expired token, IP-allowlist miss, MFA required) never reached it and was
		// invisible to keyorix_grpc_requests_total — a credential-stuffing campaign
		// against the gRPC endpoint produced zero movement in Prometheus-based
		// alerting, even though LoggingInterceptor (also outermost) still logged every
		// attempt. Metrics sits just inside Recovery (not outside it) so a panic is
		// still caught and turned into a clean INTERNAL status before Metrics' own
		// deferred bookkeeping runs on the way out.
		grpc.ChainUnaryInterceptor(
			interceptors.RecoveryInterceptor(),
			interceptors.MetricsInterceptor(),
			interceptors.LoggingInterceptor(),
			// Cap each unary RPC at the same 60s the HTTP API's Timeout middleware
			// enforces, so a hung handler can't tie up resources over gRPC when it would
			// be bounded over HTTP. Streams are intentionally exempt (StreamAuditLogs is
			// long-lived), so the stream chain carries no timeout.
			interceptors.TimeoutInterceptor(grpcUnaryTimeout),
			// RESIL-1 (#2637 follow-up): a handler whose write timed out on the SQLite
			// write gate answers codes.Unavailable + retry-after instead of Internal.
			// Inside Timeout (sees the handlers' context), outside Auth so it needs no
			// principal; Metrics/Logging above record the converted status.
			interceptors.WriteContentionInterceptor(),
			interceptors.AuthInterceptor(coreService, cfg.Security.RequireMFA),
			// Per-principal token-bucket rate limit mirroring the HTTP PrincipalRateLimit
			// middleware so an authenticated caller cannot bypass the rate limit by
			// switching transports (GRPC-009). Runs inside Auth so only authenticated
			// principals are counted; unauthenticated requests are rejected by Auth first.
			//
			// This deliberately still runs AFTER Auth, not before (G41 member 2): it is
			// keyed by grpcRateLimitKey, which resolves principal identity (user/machine
			// ID) from context Auth itself sets, so running it earlier wouldn't add
			// coverage — it would silently degrade every authenticated caller's budget to
			// a shared per-IP one (NAT/proxy collisions) since the principal identity it
			// keys on wouldn't exist yet. The actual gap this left — an attacker hammering
			// bad credentials was never throttled, since a failed Auth call never reaches
			// this interceptor — is closed separately and independently of chain order: a
			// per-IP failed-auth budget (recordGRPCTokenAuthFailure /
			// grpcTokenAuthFailureBurst, see interceptors/rate_limit.go) is checked inline
			// inside authenticateRequest itself, the function both AuthInterceptor and
			// StreamAuthInterceptor call — mirroring the HTTP stack's own split between
			// PrincipalRateLimit (post-auth, per-principal) and the inline per-IP
			// token-failure budget in its auth middleware (server/middleware/auth.go).
			interceptors.GRPCRateLimitInterceptor(cfg.Server.GRPC.RateLimit),
			// Innermost: a per-RPC recorder for share elevations, committed to the audit
			// log only when the handler succeeds (an elevated action is audited when
			// performed). Without it core refuses write-share elevation, so it must stay.
			interceptors.ShareElevationAuditInterceptor(coreService),
		),
		// The stream chain intentionally carries no metrics interceptor: MetricsInterceptor
		// (and the keyorix_grpc_requests_total / _duration_seconds_total series it feeds)
		// times a single request/response round trip, and grpcMetrics.TotalDuration backs
		// an average-latency figure. A streaming call's "handler" blocks for the entire
		// life of the stream (StreamAuditLogs can run for hours), so folding stream call
		// establishment into the same counters/duration total would both misrepresent unary
		// latency (one long-lived stream would dominate the average) and conflate two
		// different things under one metric name. Auth-rejected stream opens are still
		// visible via StreamLoggingInterceptor (also outermost here). A correct fix — a
		// separate, stream-specific metric — is tracked as its own follow-up rather than
		// folded into this reordering.
		grpc.ChainStreamInterceptor(
			interceptors.StreamRecoveryInterceptor(),
			interceptors.StreamLoggingInterceptor(),
			interceptors.StreamAuthInterceptor(coreService, cfg.Security.RequireMFA),
			// Per-principal token-bucket rate limit on stream OPEN, the streaming
			// counterpart to the unary GRPCRateLimitInterceptor above (G41 member 1/3).
			// StreamAuditLogs was the server's only streaming RPC and, until this, was
			// entirely exempt from rate limiting: the existing per-principal
			// CONCURRENCY cap inside it (AuditGRPCService.acquireStreamSlot, max 3
			// held-open streams) bounds how many streams a principal holds open at
			// once, but not the RATE at which new ones can be opened — an attacker
			// could open+close+reopen as fast as the network allowed, each open cheap
			// (auth plus a couple of DB reads) before the stream settles into its
			// long-lived tail. Runs after StreamAuthInterceptor for the same reason the
			// unary rate limiter runs after Auth (see the comment above it); the
			// failed-auth-hammering gap for streams is closed the same way too, via the
			// shared authenticateRequest per-IP budget both auth interceptors call.
			//
			// Deliberately NOT added here: a stream-side TimeoutInterceptor equivalent.
			// TimeoutInterceptor's own doc comment and the KeepaliveParams comment below
			// both already establish, as a considered product decision (not an
			// oversight), that StreamAuditLogs is legitimately long-lived and must not
			// be cut off by a blanket per-call duration cap — an operator tailing the
			// audit log for hours is the intended use, not an anomaly to bound. Giving
			// it a 60s (or any fixed) timeout would break that feature outright. The
			// resource-exhaustion concern TimeoutInterceptor exists to address for
			// unary calls (a hung handler tying up resources indefinitely) is instead
			// already covered for streams by mechanisms suited to a long-lived call:
			// the per-principal concurrency cap above, the dedicated re-authorization
			// ticker inside StreamAuditLogs (revoked credentials can't ride a stream
			// forever), and the connection-level MaxConnectionAge/MaxConnectionAgeGrace
			// keepalive below (forces periodic reconnection, so even a stream itself
			// can't outlive one connection's age indefinitely).
			interceptors.StreamRateLimitInterceptor(cfg.Server.GRPC.RateLimit),
		),
	}

	// Honor the configured request-size cap on gRPC too. HTTP enforces it via the
	// MaxBodyBytes middleware (max_request_body_bytes) to mitigate memory-exhaustion
	// DoS; without this gRPC silently kept grpc-go's own 4 MiB default and ignored the
	// operator's server.grpc setting, so the cap was bypassable by switching transport.
	// Bounds the inbound message; clamp to MaxInt32 so the int64→int conversion is safe
	// on every platform (a >2 GiB request cap is nonsensical anyway).
	//
	// The same value also bounds the OUTBOUND response (#173 residual). grpc-go's
	// server-side default for MaxSendMsgSize is math.MaxInt32 (~2 GiB) — far larger
	// than the 4 MiB it defaults to for MaxRecvMsgSize — so leaving it unset meant the
	// send direction was effectively uncapped while the recv direction was explicitly
	// bounded. Lower risk than the inbound case (an oversized response generally means
	// the server already did the expensive work to build it), but still worth closing
	// for defense-in-depth against endpoints that return large aggregated data (bulk
	// secret listings, audit log streams). No separate response-size config field
	// exists (nor is one warranted): server.grpc.max_request_body_bytes is documented
	// as "the max gRPC message size" without a request/response distinction, so the
	// same configured/defaulted value applies to both directions.
	maxMsg := min(cfg.Server.GRPC.EffectiveMaxRequestBodyBytes(), math.MaxInt32)
	opts = append(opts,
		grpc.MaxRecvMsgSize(int(maxMsg)),
		grpc.MaxSendMsgSize(int(maxMsg)),
	)

	// Detect and reclaim idle/abandoned connections (#222/#435). Without server-side
	// keepalive, a valid audit.read (or any other) credential holder can open many
	// long-lived, mostly-idle connections that the server can never detect as dead —
	// a slow-drip goroutine/fd exhaustion surface distinct from the per-principal
	// concurrency cap already applied to StreamAuditLogs (which only bounds "many
	// streams from one principal", not "idle connections nobody ever closes").
	ka := cfg.Server.GRPC.Keepalive
	opts = append(opts,
		grpc.KeepaliveParams(keepalive.ServerParameters{
			// Ping an idle connection after this long to check it's still alive.
			Time: ka.GetTime(),
			// Close the connection if the ping isn't ack'd within this long.
			Timeout: ka.GetTimeout(),
			// Force periodic reconnection so stale transport-layer auth (e.g. revoked
			// mTLS cert, rotated machine token) is re-evaluated on the new connection's
			// handshake (GRPC-008). Without this a token revoked after connection
			// establishment stays valid for the entire connection lifetime.
			MaxConnectionAge:      ka.GetMaxConnectionAge(),
			MaxConnectionAgeGrace: ka.GetMaxConnectionAgeGrace(),
			// Close a connection with no RPC in flight: a live client acks the
			// keepalive pings above, so pings alone never reclaim an idle connection.
			MaxConnectionIdle: ka.GetMaxConnectionIdle(),
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			// Reject a client that pings more often than this as abusive (GOAWAY
			// ENHANCE_YOUR_CALM) rather than let ping frequency itself become a DoS
			// vector.
			MinTime: ka.GetMinTime(),
			// No client here legitimately pings with zero active RPCs/streams — even
			// StreamAuditLogs keeps its stream open for as long as it needs pings — so
			// streamless pings are rejected outright rather than tolerated.
			PermitWithoutStream: ka.PermitWithoutStream,
		}),
		// grpc-go waits 120s by default for a new connection's TLS handshake and
		// HTTP/2 preface: a client that opens TCP and sends nothing holds a
		// connection (and goroutine) that long.
		grpc.ConnectionTimeout(ka.GetHandshakeTimeout()),
		// grpc-go's default is unlimited concurrent streams per connection; one
		// connection could otherwise open any number of in-flight RPCs, each with
		// its own handler goroutine.
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		// grpc-go's default header-list cap is 16 MiB; metadata here is an
		// authorization token and a few short keys.
		grpc.MaxHeaderListSize(grpcMaxHeaderListSize),
	)

	// Add TLS if enabled
	if cfg.Server.GRPC.TLS.Enabled {
		tlsConfig, err := createGRPCTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC TLS config: %w", err)
		}
		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
	}

	// Create server
	server := grpc.NewServer(opts...)

	// Register services. The remaining services are migrated to the generated
	// pb.*ServiceServer interfaces in subsequent phases:
	pb.RegisterSecretServiceServer(server, services.NewSecretService(coreService))
	pb.RegisterShareServiceServer(server, services.NewShareService(coreService))
	pb.RegisterUserServiceServer(server, services.NewUserService(coreService))
	pb.RegisterRoleServiceServer(server, services.NewRoleService(coreService))
	pb.RegisterAuditServiceServer(server, services.NewAuditService(coreService))
	pb.RegisterSystemServiceServer(server, services.NewSystemService(coreService, cfg))
	pb.RegisterProjectServiceServer(server, services.NewProjectService(coreService))
	pb.RegisterMachineIdentityServiceServer(server, services.NewMachineIdentityService(coreService))
	pb.RegisterDynamicSecretServiceServer(server, services.NewDynamicSecretService(coreService))
	pb.RegisterComplianceServiceServer(server, services.NewComplianceService(coreService))
	pb.RegisterConnectServiceServer(server, services.NewConnectService(coreService))
	pb.RegisterBreakGlassServiceServer(server, services.NewBreakGlassService(coreService))
	pb.RegisterGroupServiceServer(server, services.NewGroupService(coreService))

	// Enable reflection for development
	if cfg.Server.GRPC.ReflectionEnabled {
		reflection.Register(server)
		log.Println("gRPC reflection enabled")
	}

	log.Println("gRPC server configured (all 13 services registered)")
	return server, nil
}

// hardenedCipherSuites is the explicit AEAD-only cipher suite allowlist applied to
// every gRPC TLS listener, regardless of how its certificate is sourced, UNLESS the
// operator has explicitly configured tls.allowed_ciphers (#333) — in which case that
// configured list is honored instead (see applyTLSHardening).
var hardenedCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// applyTLSHardening layers the hardened MinVersion/CipherSuites onto tlsConfig in
// place. The protocol-version floor and cipher-suite allowlist are independent of how
// the certificate itself is sourced, so this must be applied uniformly on both the
// AutoCert and non-AutoCert paths below — AutoCert should only supply the certificate,
// not silently determine the rest of the TLS posture too (#172).
//
// CipherSuites is resolved from tlsCfg.AllowedCiphers (#333): unset means the hardcoded
// hardenedCipherSuites default above applies unchanged (no regression for existing
// deployments); set means the operator's configured suite list is honored instead,
// validated against config.SecureCipherSuiteNames so a weak/deprecated/misspelled
// suite name fails closed rather than being silently ignored or accepted. MinVersion
// stays fixed at TLS 1.2 UNLESS mode is config.TLSModeStrict (ADR-112 §3,
// "tls_mode: strict"), in which case Min/MaxVersion are both pinned to TLS 1.3 and
// CipherSuites is left untouched — TLS 1.3 negotiates its own, always-AEAD suite
// set, so there is nothing for allowed_ciphers to configure under either mode.
func applyTLSHardening(tlsConfig *tls.Config, tlsCfg config.TLSConfig, mode string) error {
	if mode == config.TLSModeStrict {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
		return nil
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	suites, err := tlsCfg.ResolveCipherSuites(hardenedCipherSuites)
	if err != nil {
		return fmt.Errorf("invalid gRPC TLS configuration: %w", err)
	}
	tlsConfig.CipherSuites = suites
	return nil
}

// createGRPCTLSConfig creates TLS configuration for gRPC server
func createGRPCTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.GRPC.TLS.AutoCert {
		// For gRPC, autocert (certificate acquisition) is more complex and typically
		// not wired up here — but the hardened MinVersion/CipherSuites below must
		// still apply, matching the non-AutoCert path's posture (#172).
		tlsConfig := &tls.Config{} // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion -- applyTLSHardening below sets MinVersion unconditionally on every path (TLS 1.3 in strict mode, TLS 1.2 otherwise) before this config is ever used
		if err := applyTLSHardening(tlsConfig, cfg.Server.GRPC.TLS, cfg.Server.GRPC.TLSMode); err != nil {
			return nil, err
		}
		return tlsConfig, nil
	}

	// Load certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.Server.GRPC.TLS.CertFile, cfg.Server.GRPC.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load gRPC TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}} // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion -- applyTLSHardening below sets MinVersion unconditionally on every path, same as createGRPCTLSConfig's AutoCert branch above
	if err := applyTLSHardening(tlsConfig, cfg.Server.GRPC.TLS, cfg.Server.GRPC.TLSMode); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}
