package interceptors

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/ratelimitmetrics"
)

// GRPCRateLimitInterceptor returns a unary server interceptor that enforces a
// per-principal token-bucket request budget over the gRPC transport, mirroring
// the HTTP PrincipalRateLimit middleware so an authenticated caller cannot bypass
// the rate limit by switching transports (GRPC-009).
//
// Keyed by the same principal identity as the HTTP middleware (user ID, machine
// identity ID, or source IP as fallback). Disabled when cfg.Enabled == false,
// matching the HTTP middleware's zero-value behaviour.
func GRPCRateLimitInterceptor(cfg config.RateLimitConfig) grpc.UnaryServerInterceptor {
	if !cfg.Enabled || cfg.RequestsPerSecond <= 0 {
		log.Printf("Keyorix: GRPCRateLimitInterceptor is disabled (server.grpc.ratelimit.enabled=false) — no per-principal gRPC rate limit is active; enable in production")
		return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.RequestsPerSecond
	}
	rl := &grpcRateLimiter{
		rps:      rate.Limit(cfg.RequestsPerSecond),
		burst:    burst,
		limiters: make(map[string]*grpcPrincipalBucket),
	}
	return rl.intercept
}

const (
	grpcPrincipalLimiterIdleTTL    = 10 * time.Minute
	grpcPrincipalLimiterSweepEvery = 1000
)

type grpcPrincipalBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type grpcRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*grpcPrincipalBucket
	rps      rate.Limit
	burst    int
	requests uint64
}

func (rl *grpcRateLimiter) intercept(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !rl.allow(grpcRateLimitKey(ctx)) {
		ratelimitmetrics.Reject(ratelimitmetrics.GRPCPrincipal)
		return nil, status.Error(codes.ResourceExhausted, "too many requests; slow down")
	}
	return handler(ctx, req)
}

func (rl *grpcRateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests++
	if rl.requests%grpcPrincipalLimiterSweepEvery == 0 {
		rl.sweepLocked()
	}
	b, ok := rl.limiters[key]
	if !ok {
		b = &grpcPrincipalBucket{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[key] = b
	}
	b.lastSeen = time.Now()
	return b.limiter.Allow()
}

func (rl *grpcRateLimiter) sweepLocked() {
	cutoff := time.Now().Add(-grpcPrincipalLimiterIdleTTL)
	for k, b := range rl.limiters {
		if b.lastSeen.Before(cutoff) {
			delete(rl.limiters, k)
		}
	}
}

// grpcRateLimitKey identifies the request's budget bucket, mirroring the HTTP
// rateLimitKey: authenticated user or machine identity first, source IP as fallback.
//
// #G20: p.Addr.String() previously went straight into the key INCLUDING the
// ephemeral client TCP port — every new connection from the same unauthenticated
// caller (a trivial, free action for any real client) got a fresh port and
// therefore a fresh bucket, defeating the fallback IP budget entirely instead
// of merely being imprecise. core.CanonicalIP strips the port and normalizes
// the remaining IP to one canonical textual form, matching the HTTP-side fix
// in internal/core/rate_limit.go and server/http/handlers' clientIP.
func grpcRateLimitKey(ctx context.Context) string {
	if u := GetUserFromGRPCContext(ctx); u != nil {
		if u.MachineIdentityID != 0 {
			return "machine:" + strconv.FormatUint(uint64(u.MachineIdentityID), 10)
		}
		if u.UserID != 0 {
			return "user:" + strconv.FormatUint(uint64(u.UserID), 10)
		}
	}
	if p, ok := peer.FromContext(ctx); ok {
		return fmt.Sprintf("ip:%s", core.CanonicalIP(p.Addr.String()))
	}
	return "ip:unknown"
}

// StreamRateLimitInterceptor returns a stream server interceptor enforcing a
// per-principal token-bucket budget on stream OPEN, the streaming counterpart to
// GRPCRateLimitInterceptor (G41 member 1/3). StreamAuditLogs is the server's only
// streaming RPC, and until this it was entirely exempt from rate limiting: the
// per-principal CONCURRENCY cap already applied inside it
// (AuditGRPCService.acquireStreamSlot, capped at 3 held-open streams) bounds how
// many streams a principal may hold open at once, but does nothing to bound the
// RATE of open+close+reopen churn — each open is itself cheap (auth plus a couple
// of DB reads before the stream settles into its long-lived tail), so a caller
// could open new streams as fast as the network allowed. Keyed the same way as
// the unary limiter (grpcRateLimitKey) but backed by its OWN token bucket instance
// — deliberately a separate budget from GRPCRateLimitInterceptor's, not shared —
// so a burst of stream opens cannot starve a principal's unary-call budget or vice
// versa; both are still configured from the same server.grpc.ratelimit settings.
func StreamRateLimitInterceptor(cfg config.RateLimitConfig) grpc.StreamServerInterceptor {
	if !cfg.Enabled || cfg.RequestsPerSecond <= 0 {
		log.Printf("Keyorix: StreamRateLimitInterceptor is disabled (server.grpc.ratelimit.enabled=false) — no per-principal gRPC stream rate limit is active; enable in production")
		return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			return handler(srv, stream)
		}
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.RequestsPerSecond
	}
	rl := &grpcRateLimiter{
		rps:      rate.Limit(cfg.RequestsPerSecond),
		burst:    burst,
		limiters: make(map[string]*grpcPrincipalBucket),
	}
	return rl.interceptStream
}

func (rl *grpcRateLimiter) interceptStream(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !rl.allow(grpcRateLimitKey(stream.Context())) {
		ratelimitmetrics.Reject(ratelimitmetrics.GRPCPrincipal)
		return status.Error(codes.ResourceExhausted, "too many requests; slow down")
	}
	return handler(srv, stream)
}

// grpcTokenAuthFailureBurst and globalGRPCTokenAuthFailureLimiter mirror the HTTP
// stack's ipFailureLimiter (server/middleware/rate_limit.go, PAT-003): a per-IP
// budget on FAILED gRPC token-validation attempts, independent of the
// per-PRINCIPAL budgets GRPCRateLimitInterceptor and StreamRateLimitInterceptor
// enforce (G41 member 2).
//
// Those per-principal limiters run AFTER AuthInterceptor/StreamAuthInterceptor
// succeed (grpcRateLimitKey resolves identity from context AuthInterceptor sets),
// so a caller hammering either RPC style with invalid credentials never reaches
// them and was previously unthrottled — an attacker could flood bad tokens at
// unlimited rate. Reordering the per-principal limiter ahead of Auth was
// considered and rejected: doing so would not add coverage, it would silently
// DEGRADE every authenticated caller's per-principal budget to a shared per-IP
// budget (colliding behind the same NAT/proxy), since the limiter would run
// before the principal identity it keys on even exists. A dedicated, IP-only,
// failure-only limiter — checked inline inside authenticateRequest, the function
// both AuthInterceptor and StreamAuthInterceptor call — closes the gap for both
// RPC styles from one place without touching the per-principal limiters' chain
// position at all, exactly mirroring how the HTTP stack keeps PrincipalRateLimit
// (post-auth, per-principal) and the token-failure budget (inline in the auth
// middleware itself, per-IP) as two separate, independently-scoped controls.
const grpcTokenAuthFailureBurst = 10

type grpcIPFailureLimiter struct {
	mu       sync.Mutex
	limiters map[string]*grpcPrincipalBucket
	requests uint64
}

var globalGRPCTokenAuthFailureLimiter = &grpcIPFailureLimiter{
	limiters: make(map[string]*grpcPrincipalBucket),
}

// recordGRPCTokenAuthFailure records a failed gRPC token-validation attempt for
// the given source IP, returning false once the IP has exceeded its failure
// budget (grpcTokenAuthFailureBurst, refilling at 1/s — same shape as HTTP's
// tokenAuthFailureLimiter).
func recordGRPCTokenAuthFailure(ip string) bool {
	return globalGRPCTokenAuthFailureLimiter.allow(ip)
}

// #3429: allow() runs on every failed gRPC token validation and used to call
// sweepLocked() every time, a full scan of the map under the one mutex, so a
// flood from many source IPs (the case this limiter exists for) made the limiter
// itself the bottleneck. Amortized like grpcRateLimiter.allow above and the HTTP
// twin (ipFailureLimiter.allow, #G19): one sweep every
// grpcPrincipalLimiterSweepEvery calls.
func (l *grpcIPFailureLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests++
	if l.requests%grpcPrincipalLimiterSweepEvery == 0 {
		l.sweepLocked()
	}
	b, ok := l.limiters[ip]
	if !ok {
		b = &grpcPrincipalBucket{limiter: rate.NewLimiter(rate.Limit(1), grpcTokenAuthFailureBurst)}
		l.limiters[ip] = b
	}
	b.lastSeen = time.Now()
	return b.limiter.Allow()
}

func (l *grpcIPFailureLimiter) sweepLocked() {
	cutoff := time.Now().Add(-grpcPrincipalLimiterIdleTTL)
	for k, b := range l.limiters {
		if b.lastSeen.Before(cutoff) {
			delete(l.limiters, k)
		}
	}
}
