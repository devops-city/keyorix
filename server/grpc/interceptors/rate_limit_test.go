package interceptors

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// grpcCtxForUser attaches a UserContext the same way AuthInterceptor does, for
// tests that exercise GRPCRateLimitInterceptor directly without a real token.
func grpcCtxForUser(userID, machineID uint) context.Context {
	return context.WithValue(context.Background(), GetUserContextKey(), &UserContext{
		UserID:            userID,
		MachineIdentityID: machineID,
	})
}

// grpcCtxForIP attaches a gRPC peer with the given source IP and no UserContext,
// exercising the unauthenticated IP-fallback path.
func grpcCtxForIP(ip string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 5555}})
}

func rlHandler() grpc.UnaryHandler {
	return func(_ context.Context, _ any) (any, error) { return "ok", nil }
}

// Disabled (the config zero value, or an explicit Enabled: false) is a
// transparent no-op — GRPCRateLimitInterceptor returns a pass-through
// interceptor, not a limiter with an effectively-infinite budget. Also covers
// RequestsPerSecond <= 0 while Enabled is true, the OTHER half of the
// disabling condition.
func TestGRPCRateLimitInterceptor_DisabledIsNoOp(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.RateLimitConfig
	}{
		{"zero value", config.RateLimitConfig{}},
		{"explicitly disabled", config.RateLimitConfig{Enabled: false, RequestsPerSecond: 100}},
		{"enabled but non-positive rps", config.RateLimitConfig{Enabled: true, RequestsPerSecond: 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interceptor := GRPCRateLimitInterceptor(tc.cfg)
			for i := range 50 {
				_, err := interceptor(grpcCtxForUser(1, 0), nil, nil, rlHandler())
				require.NoError(t, err, "request %d must pass through unlimited", i)
			}
		})
	}
}

// A principal exceeding their burst gets ResourceExhausted; a DIFFERENT
// principal is unaffected — budgets are per-principal, not shared. Also
// confirms the enabled path is actually reached (the inverse of the
// disabled-is-no-op case above).
func TestGRPCRateLimitInterceptor_EnforcesPerPrincipalBudget(t *testing.T) {
	interceptor := GRPCRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 3})

	for i := range 3 {
		_, err := interceptor(grpcCtxForUser(1, 0), nil, nil, rlHandler())
		require.NoError(t, err, "request %d within burst must pass", i)
	}
	_, err := interceptor(grpcCtxForUser(1, 0), nil, nil, rlHandler())
	require.Error(t, err, "the 4th request within the same instant must be limited")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	_, err = interceptor(grpcCtxForUser(2, 0), nil, nil, rlHandler())
	assert.NoError(t, err, "a different principal must have an independent budget")
}

// Burst defaults to RequestsPerSecond when unset (Burst <= 0) — the token
// bucket accepts exactly RequestsPerSecond requests up front, not 0 (which
// would deny every request outright) and not unlimited.
func TestGRPCRateLimitInterceptor_BurstDefaultsToRequestsPerSecond(t *testing.T) {
	interceptor := GRPCRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 3})

	for i := range 3 {
		_, err := interceptor(grpcCtxForUser(1, 0), nil, nil, rlHandler())
		require.NoError(t, err, "request %d within the defaulted burst of 3 must pass", i)
	}
	_, err := interceptor(grpcCtxForUser(1, 0), nil, nil, rlHandler())
	assert.Error(t, err, "the 4th request must be limited once the defaulted burst is exhausted")
}

// A machine-identity principal is keyed by machine ID, ahead of any user ID on
// the same UserContext (mirrors AuthInterceptor's convention that a machine
// request never carries a UserID) -- and independently of a same-numbered user.
func TestGRPCRateLimitInterceptor_MachineIdentityKeyedSeparatelyFromUser(t *testing.T) {
	interceptor := GRPCRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})

	_, err := interceptor(grpcCtxForUser(0, 7), nil, nil, rlHandler())
	require.NoError(t, err, "machine 7's first request must pass")
	_, err = interceptor(grpcCtxForUser(0, 7), nil, nil, rlHandler())
	assert.Error(t, err, "machine 7's second request within burst=1 must be limited")

	// A user whose numeric ID happens to equal the machine ID has an
	// independent budget -- the key must be "machine:7" vs "user:7", not the
	// same bucket by coincidence of numeric value.
	_, err = interceptor(grpcCtxForUser(7, 0), nil, nil, rlHandler())
	assert.NoError(t, err, "user 7 must not share machine 7's exhausted budget")
}

// An unauthenticated request (no UserContext, e.g. a public method) falls back
// to an IP-keyed budget rather than panicking or bypassing the limiter. A
// request with no resolvable peer at all still gets a (shared) "ip:unknown"
// budget rather than crashing.
func TestGRPCRateLimitInterceptor_FallsBackToIPForUnauthenticated(t *testing.T) {
	interceptor := GRPCRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})

	ctx := grpcCtxForIP("203.0.113.5")
	_, err := interceptor(ctx, nil, nil, rlHandler())
	require.NoError(t, err)
	_, err = interceptor(ctx, nil, nil, rlHandler())
	assert.Error(t, err, "a second request from the same IP within burst=1 must be limited")

	_, err = interceptor(context.Background(), nil, nil, rlHandler())
	assert.NoError(t, err, "no UserContext and no peer must still resolve to a real key (\"ip:unknown\"), not panic")
}

// TestGRPCRateLimitInterceptor_IPFallbackIgnoresEphemeralPort is #G20:
// grpcRateLimitKey previously keyed the unauthenticated IP-fallback bucket on
// peer.Addr.String() directly, which INCLUDES the ephemeral client TCP port.
// Reconnecting — a free, trivial action for any real caller — got a fresh
// port and therefore a fresh bucket every time, defeating the fallback budget
// entirely rather than merely being imprecise about it.
func TestGRPCRateLimitInterceptor_IPFallbackIgnoresEphemeralPort(t *testing.T) {
	interceptor := GRPCRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})

	firstConn := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 5555}})
	_, err := interceptor(firstConn, nil, nil, rlHandler())
	require.NoError(t, err, "the first connection's request must pass")

	// A "reconnect" from the SAME IP but a DIFFERENT ephemeral port must share
	// the same bucket, not get a fresh burst.
	reconnected := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 60001}})
	_, err = interceptor(reconnected, nil, nil, rlHandler())
	assert.Error(t, err, "a reconnect from the same IP on a new ephemeral port must still be limited")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

// sweepLocked evicts only entries idle past grpcPrincipalLimiterIdleTTL (10
// minutes), not everything and not nothing -- constructed directly against
// the unexported type (white-box) since driving real 10-minute idleness
// through the public API isn't practical. Deliberately asserts against
// hardcoded 9m/11m offsets, not the constant itself, so a mutation to the
// constant's own definition (an ARITHMETIC_BASE flip of "10 * time.Minute",
// or an INVERT_NEGATIVES flip of the cutoff's leading "-") changes the
// asserted behavior instead of silently reading back its own mutated value.
func TestGRPCRateLimiter_SweepEvictsOnlyIdleEntries(t *testing.T) {
	rl := &grpcRateLimiter{limiters: make(map[string]*grpcPrincipalBucket)}
	rl.limiters["stale"] = &grpcPrincipalBucket{lastSeen: time.Now().Add(-11 * time.Minute)}
	rl.limiters["fresh"] = &grpcPrincipalBucket{lastSeen: time.Now().Add(-9 * time.Minute)}

	rl.sweepLocked()

	_, staleStillPresent := rl.limiters["stale"]
	_, freshStillPresent := rl.limiters["fresh"]
	assert.False(t, staleStillPresent, "an entry idle past the 10-minute TTL must be evicted")
	assert.True(t, freshStillPresent, "an entry within the 10-minute TTL must survive")
}

// The sweep runs every grpcPrincipalLimiterSweepEvery (1000) requests, not on
// every request and not never -- verified by observing its side effect (a
// stale entry's eventual eviction) rather than the private counter directly,
// so an INCREMENT_DECREMENT mutant on "rl.requests++" (which would make the
// modulo check never land on exactly 0 starting from 0) or a mutant on the
// modulo condition itself is caught by the sweep visibly failing to run.
func TestGRPCRateLimiter_SweepsEveryNRequests(t *testing.T) {
	rl := &grpcRateLimiter{
		rps:      rate.Limit(1000),
		burst:    1000,
		limiters: make(map[string]*grpcPrincipalBucket),
	}
	rl.limiters["stale"] = &grpcPrincipalBucket{lastSeen: time.Now().Add(-11 * time.Minute)}

	for range grpcPrincipalLimiterSweepEvery - 1 {
		rl.allow("churn")
	}
	rl.mu.Lock()
	_, stillPresentBeforeSweep := rl.limiters["stale"]
	rl.mu.Unlock()
	require.True(t, stillPresentBeforeSweep, "the sweep must not run before the Nth request")

	rl.allow("churn") // the Nth request
	rl.mu.Lock()
	_, presentAfterSweep := rl.limiters["stale"]
	rl.mu.Unlock()
	assert.False(t, presentAfterSweep, "the sweep must run on exactly the Nth request and evict the stale entry")
}

// grpcIPFailureLimiter.sweepLocked (the per-IP token-auth-failure budget's own
// sweep, distinct from grpcRateLimiter.sweepLocked above) evicts only entries
// idle past the TTL, not everything and not nothing. allow() always sets
// lastSeen to time.Now() for the entry it just touched before sweeping, so
// driving this through the public recordGRPCTokenAuthFailure API can never
// produce a stale entry for the sweep to evict; constructed directly against
// the unexported type (white-box), same rationale as
// TestGRPCRateLimiter_SweepEvictsOnlyIdleEntries.
func TestGRPCIPFailureLimiter_SweepEvictsOnlyIdleEntries(t *testing.T) {
	l := &grpcIPFailureLimiter{limiters: make(map[string]*grpcPrincipalBucket)}
	l.limiters["stale"] = &grpcPrincipalBucket{lastSeen: time.Now().Add(-11 * time.Minute)}
	l.limiters["fresh"] = &grpcPrincipalBucket{lastSeen: time.Now().Add(-9 * time.Minute)}

	l.sweepLocked()

	_, staleStillPresent := l.limiters["stale"]
	_, freshStillPresent := l.limiters["fresh"]
	assert.False(t, staleStillPresent, "an entry idle past the 10-minute TTL must be evicted")
	assert.True(t, freshStillPresent, "an entry within the 10-minute TTL must survive")
}

// TestGRPCIPFailureLimiter_SweepAmortized is #3429, the gRPC twin of
// TestIPFailureLimiter_SweepAmortized (#G19): allow() runs on every failed
// token validation, and it used to scan the whole map under the one mutex
// every time, so a flood from many source IPs made the limiter itself the
// bottleneck. The sweeps are counted by their effect: an idle sentinel is
// re-planted before every call, and each call that removes it ran a sweep.
func TestGRPCIPFailureLimiter_SweepAmortized(t *testing.T) {
	l := &grpcIPFailureLimiter{limiters: make(map[string]*grpcPrincipalBucket)}
	const calls = 3 * grpcPrincipalLimiterSweepEvery
	sweeps := 0
	for i := range calls {
		l.mu.Lock()
		l.limiters["203.0.113.9"] = &grpcPrincipalBucket{lastSeen: time.Now().Add(-2 * grpcPrincipalLimiterIdleTTL)}
		l.mu.Unlock()
		l.allow(fmt.Sprintf("10.0.%d.%d", i/256%256, i%256))
		l.mu.Lock()
		if _, ok := l.limiters["203.0.113.9"]; !ok {
			sweeps++
		}
		l.mu.Unlock()
	}
	assert.Equal(t, calls/grpcPrincipalLimiterSweepEvery, sweeps,
		"one sweep per %d failed validations, not one per call", grpcPrincipalLimiterSweepEvery)
}

// ---------------------------------------------------------------------------
// StreamRateLimitInterceptor — G41: the streaming counterpart to
// GRPCRateLimitInterceptor above. Before G41, StreamAuditLogs (the server's
// only streaming RPC) carried no rate limiting on stream OPEN at all: opening
// streams as fast as the network allowed was entirely unthrottled, unlike the
// unary surface. These tests are the detection idea from the G41 writeup —
// "open N StreamAuditLogs connections... assert throttled like their
// authenticated-unary counterparts" — applied directly at the interceptor
// (the same level TestGRPCRateLimitInterceptor_* above tests the unary side).
// ---------------------------------------------------------------------------

func streamRLHandler() grpc.StreamHandler {
	return func(_ any, _ grpc.ServerStream) error { return nil }
}

// Mirrors TestGRPCRateLimitInterceptor_DisabledIsNoOp: disabled config is a
// transparent no-op stream interceptor, not an infinite-budget limiter.
func TestStreamRateLimitInterceptor_DisabledIsNoOp(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.RateLimitConfig
	}{
		{"zero value", config.RateLimitConfig{}},
		{"explicitly disabled", config.RateLimitConfig{Enabled: false, RequestsPerSecond: 100}},
		{"enabled but non-positive rps", config.RateLimitConfig{Enabled: true, RequestsPerSecond: 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interceptor := StreamRateLimitInterceptor(tc.cfg)
			for i := range 50 {
				stream := &fakeStream{ctx: grpcCtxForUser(1, 0)}
				err := interceptor(nil, stream, nil, streamRLHandler())
				require.NoError(t, err, "stream open %d must pass through unlimited", i)
			}
		})
	}
}

// Opening N StreamAuditLogs connections rapidly (as the G41 detection idea
// describes) is throttled once a principal exceeds its burst, exactly like the
// unary case in TestGRPCRateLimitInterceptor_EnforcesPerPrincipalBudget. A
// different principal opening streams is unaffected — budgets are
// per-principal, not global.
func TestStreamRateLimitInterceptor_EnforcesPerPrincipalBudget(t *testing.T) {
	interceptor := StreamRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 3})

	for i := range 3 {
		stream := &fakeStream{ctx: grpcCtxForUser(1, 0)}
		err := interceptor(nil, stream, nil, streamRLHandler())
		require.NoError(t, err, "stream open %d within burst must pass", i)
	}
	blocked := &fakeStream{ctx: grpcCtxForUser(1, 0)}
	err := interceptor(nil, blocked, nil, streamRLHandler())
	require.Error(t, err, "the 4th stream open within the same instant must be limited")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	other := &fakeStream{ctx: grpcCtxForUser(2, 0)}
	err = interceptor(nil, other, nil, streamRLHandler())
	assert.NoError(t, err, "a different principal opening a stream must have an independent budget")
}

// Mirrors TestGRPCRateLimitInterceptor_BurstDefaultsToRequestsPerSecond: Burst
// defaults to RequestsPerSecond when unset (Burst <= 0) on the stream side too —
// the token bucket accepts exactly RequestsPerSecond stream opens up front.
func TestStreamRateLimitInterceptor_BurstDefaultsToRequestsPerSecond(t *testing.T) {
	interceptor := StreamRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 3})

	for i := range 3 {
		stream := &fakeStream{ctx: grpcCtxForUser(1, 0)}
		err := interceptor(nil, stream, nil, streamRLHandler())
		require.NoError(t, err, "stream open %d within the defaulted burst of 3 must pass", i)
	}
	blocked := &fakeStream{ctx: grpcCtxForUser(1, 0)}
	err := interceptor(nil, blocked, nil, streamRLHandler())
	assert.Error(t, err, "the 4th stream open must be limited once the defaulted burst is exhausted")
}

// An unauthenticated stream open (no UserContext — StreamAuthInterceptor
// rejects those before this interceptor ever runs in the real chain, but the
// interceptor itself must still behave sanely if reached) falls back to an
// IP-keyed budget, mirroring the unary fallback.
func TestStreamRateLimitInterceptor_FallsBackToIPForUnauthenticated(t *testing.T) {
	interceptor := StreamRateLimitInterceptor(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})

	ctx := grpcCtxForIP("203.0.113.77")
	stream := &fakeStream{ctx: ctx}
	err := interceptor(nil, stream, nil, streamRLHandler())
	require.NoError(t, err)

	stream2 := &fakeStream{ctx: ctx}
	err = interceptor(nil, stream2, nil, streamRLHandler())
	assert.Error(t, err, "a second stream open from the same IP within burst=1 must be limited")
}

// StreamRateLimitInterceptor and GRPCRateLimitInterceptor are built from
// independent grpcRateLimiter instances (deliberately NOT a shared budget —
// see the doc comment on StreamRateLimitInterceptor): exhausting one surface's
// budget for a principal must not affect the other surface's budget for the
// same principal.
func TestStreamRateLimitInterceptor_IndependentBudgetFromUnary(t *testing.T) {
	cfg := config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1}
	unary := GRPCRateLimitInterceptor(cfg)
	stream := StreamRateLimitInterceptor(cfg)

	// Exhaust the unary budget for principal 5.
	_, err := unary(grpcCtxForUser(5, 0), nil, nil, rlHandler())
	require.NoError(t, err)
	_, err = unary(grpcCtxForUser(5, 0), nil, nil, rlHandler())
	require.Error(t, err, "unary budget for principal 5 must now be exhausted")

	// The same principal's stream-open budget is untouched.
	err = stream(nil, &fakeStream{ctx: grpcCtxForUser(5, 0)}, nil, streamRLHandler())
	assert.NoError(t, err, "stream-open budget must be independent of the exhausted unary budget")
}
