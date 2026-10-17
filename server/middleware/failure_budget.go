package middleware

import (
	"net/http"
	"slices"
	"sync"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// FailureBudget bounds credential guessing on a public route that checks a
// static secret (the bootstrap token on POST /system/init, the metrics token on
// GET /metrics) and has no per-account lockout to lean on. Per client IP (the
// address ClientIP resolved, so trusted-proxy aware), a response whose status is
// one of failStatuses spends one unit of a budget of burst units refilling at one
// per refill; once the budget is spent the route answers 429 without running the
// handler. Successful responses cost nothing, so a healthy caller (a probe, a
// Prometheus scrape, an idempotent init call) is never throttled.
//
// The unit is reserved BEFORE the handler runs and handed back when the response
// is not a failure, so a concurrent burst from one IP cannot all observe an unspent
// budget and run the credential check past it (the race INV-HTTP-19 closes for the
// login budget). In-process and per replica, like the other in-memory limiters.
func FailureBudget(burst int, refill time.Duration, failStatuses ...int) func(http.Handler) http.Handler {
	b := &failureBudget{burst: float64(burst), refill: refill, buckets: map[string]*failureBucket{}}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := hostOnly(r.RemoteAddr)
			if !b.take(ip) {
				tooManyRequestsResponse(w, "too many failed attempts")
				return
			}
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			if !slices.Contains(failStatuses, ww.Status()) {
				b.giveBack(ip)
			}
		})
	}
}

// failureBudget is a per-IP token bucket whose units can be handed back: x/time/rate's
// Reservation.Cancel restores nothing once the reservation's time has passed, which
// is always the case after the handler has run.
type failureBudget struct {
	burst    float64
	refill   time.Duration
	mu       sync.Mutex
	buckets  map[string]*failureBucket
	requests uint64
}

type failureBucket struct {
	tokens float64
	last   time.Time
}

// take spends one unit for ip, refilling first; false when none is left.
func (b *failureBudget) take(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.requests++
	if b.requests%principalLimiterSweepEvery == 0 {
		cutoff := now.Add(-principalLimiterIdleTTL)
		for k, v := range b.buckets {
			if v.last.Before(cutoff) {
				delete(b.buckets, k)
			}
		}
	}
	bk, ok := b.buckets[ip]
	if !ok {
		bk = &failureBucket{tokens: b.burst, last: now}
		b.buckets[ip] = bk
	}
	bk.tokens = min(b.burst, bk.tokens+float64(now.Sub(bk.last))/float64(b.refill))
	bk.last = now
	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}

// giveBack returns the unit take spent, for a response that was not a failure.
func (b *failureBudget) giveBack(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bk, ok := b.buckets[ip]; ok {
		bk.tokens = min(b.burst, bk.tokens+1)
	}
}
