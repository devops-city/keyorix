package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/ratelimitmetrics"
)

// PrincipalRateLimit enforces a general per-authenticated-principal request budget
// across the whole authenticated API surface (#163). Before this, only login had
// any rate limiting; a handful of system.read-gated endpoints (compliance posture,
// deployment-wide secrets-inventory export) walk the entire deployment per call, so
// a broadly-privileged system.read holder could drive up their own deployment's DB
// load with repeated calls. This is a nuisance backstop, not an authorization
// boundary: every route it guards is already permission-gated, so the intent is
// bounding how hard one already-authorized principal can hammer expensive
// endpoints, not preventing access.
//
// Token-bucket per principal (falling back to source IP for the rare request that
// reaches this middleware unauthenticated), in-memory and per-process — unlike the
// DB-backed cluster-wide login limiter (rate_limit.go), a self-inflicted-cost
// nuisance control doesn't need cross-replica coordination, and keeping it
// in-memory avoids adding DB load to a middleware whose whole point is reducing
// DB load. Must run AFTER Authentication so the principal is resolved. Disabled by
// default (cfg.Enabled == false, the config zero value), matching the config
// schema already documented in server/config/production.yaml and
// docs/CONFIGURATION.md.
func PrincipalRateLimit(cfg config.RateLimitConfig) func(http.Handler) http.Handler {
	if !cfg.Enabled || cfg.RequestsPerSecond <= 0 {
		log.Printf("Keyorix: PrincipalRateLimit is disabled (server.http.ratelimit.enabled=false) — no per-principal API rate limit is active; enable in production")
		return func(next http.Handler) http.Handler { return next }
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = cfg.RequestsPerSecond
	}
	rl := &principalRateLimiter{
		rps:      rate.Limit(cfg.RequestsPerSecond),
		burst:    burst,
		limiters: make(map[string]*principalBucket),
	}
	return rl.middleware
}

// principalLimiterIdleTTL is how long an idle principal's bucket is kept before a
// sweep evicts it, bounding memory growth from a long-running process seeing many
// distinct principals/IPs over time.
const principalLimiterIdleTTL = 10 * time.Minute

// principalLimiterSweepEvery amortizes the idle-eviction sweep cost by running it
// only every Nth request rather than on every single one.
const principalLimiterSweepEvery = 1000

// principalBucket pairs a token-bucket limiter with the time it was last used.
type principalBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type principalRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*principalBucket
	rps      rate.Limit
	burst    int
	requests uint64
}

func (rl *principalRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(rateLimitKey(r)) {
			ratelimitmetrics.Reject(ratelimitmetrics.Principal)
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "RateLimited",
				"message": "too many requests; slow down",
				"code":    http.StatusTooManyRequests,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *principalRateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests++
	if rl.requests%principalLimiterSweepEvery == 0 {
		rl.sweepLocked()
	}
	b, ok := rl.limiters[key]
	if !ok {
		b = &principalBucket{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[key] = b
	}
	b.lastSeen = time.Now()
	return b.limiter.Allow()
}

// sweepLocked evicts buckets idle longer than principalLimiterIdleTTL. Caller must
// hold rl.mu.
func (rl *principalRateLimiter) sweepLocked() {
	cutoff := time.Now().Add(-principalLimiterIdleTTL)
	for k, b := range rl.limiters {
		if b.lastSeen.Before(cutoff) {
			delete(rl.limiters, k)
		}
	}
}

// rateLimitKey identifies the request's budget bucket: the authenticated user or
// machine identity when present (the overwhelmingly common case on /api/v1, since
// this middleware runs after Authentication), falling back to the client IP for
// the rare unauthenticated request that reaches it.
func rateLimitKey(r *http.Request) string {
	if uc := GetUserFromContext(r.Context()); uc != nil {
		if uc.MachineIdentityID != nil {
			return "machine:" + strconv.FormatUint(uint64(*uc.MachineIdentityID), 10)
		}
		if uc.UserID != 0 {
			return "user:" + strconv.FormatUint(uint64(uc.UserID), 10)
		}
	}
	return "ip:" + hostOnly(r.RemoteAddr)
}

// tokenAuthFailureLimiter enforces a per-IP rate limit on failed token
// authentication attempts — PAT, machine, and session tokens alike. Prevents an
// attacker from flooding auth with invalid tokens without bound. Each IP is
// allowed a burst of tokenAuthFailureBurst failures, refilling at 1/s. The limiter
// is in-process and not cluster-coordinated (same trade-off as PrincipalRateLimit).
const tokenAuthFailureBurst = 10

type ipFailureLimiter struct {
	mu       sync.Mutex
	limiters map[string]*principalBucket
	requests uint64
}

var globalTokenAuthFailureLimiter = &ipFailureLimiter{
	limiters: make(map[string]*principalBucket),
}

// recordTokenAuthFailure records a failed auth attempt for the given source IP,
// returning false when the IP has exceeded its failure budget. Caller should
// respond with 429 in that case.
func recordTokenAuthFailure(ip string) bool {
	ok := globalTokenAuthFailureLimiter.allow(ip)
	if !ok {
		ratelimitmetrics.Reject(ratelimitmetrics.FailedAuthIP)
	}
	return ok
}

// #G19: allow() previously called sweepLocked() on EVERY invocation — a full O(n)
// scan of the limiter map under the shared mutex on every single failed-auth
// attempt, unlike principalRateLimiter.allow (above), which explicitly amortizes
// the identical sweep to once every principalLimiterSweepEvery calls. Under a
// sustained token-brute-forcing flood (the exact scenario this limiter exists to
// bound) that made the O(n) sweep run at full request rate, scaling cost with the
// number of distinct attacking IPs instead of bounding it.
func (l *ipFailureLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests++
	if l.requests%principalLimiterSweepEvery == 0 {
		l.sweepLocked()
	}
	b, ok := l.limiters[ip]
	if !ok {
		b = &principalBucket{limiter: rate.NewLimiter(rate.Limit(1), tokenAuthFailureBurst)}
		l.limiters[ip] = b
	}
	b.lastSeen = time.Now()
	return b.limiter.Allow()
}

func (l *ipFailureLimiter) sweepLocked() {
	cutoff := time.Now().Add(-principalLimiterIdleTTL)
	for k, b := range l.limiters {
		if b.lastSeen.Before(cutoff) {
			delete(l.limiters, k)
		}
	}
}
