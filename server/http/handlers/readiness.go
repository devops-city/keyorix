// readiness.go — ReadinessCheck: a real readiness probe that verifies the server can
// actually serve traffic by pinging its database (core.HealthCheck → SELECT 1). It
// returns 200 when ready and 503 when a dependency is down, so a Kubernetes readiness
// probe stops routing traffic to a replica whose database is unreachable. This is
// distinct from /health (HealthCheck), which is a lightweight liveness signal that must
// NOT depend on the database — a transient DB blip should not restart the pod.
package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
)

// readinessCacheTTL bounds how often GET /readyz actually pings the database
// (#G82): unlike the login/SSO endpoints, an unauthenticated flood here can't
// be rejected outright with a rate-limit error — a readiness probe that starts
// reporting "too many requests" instead of the real DB status would make
// Kubernetes wrongly conclude a healthy replica is unready, a self-inflicted
// outage strictly worse than the DB-load DoS this closes. Caching the last
// real result for a short window instead means a flood reuses that result
// (bounding DB round trips) while still reflecting reality well within any
// realistic orchestrator probe interval (Kubernetes' own default is 10s).
// Overridable by tests.
var readinessCacheTTL = time.Second

// readinessNow is time.Now, overridable by tests so they can force the cache
// to expire without a real sleep.
var readinessNow = time.Now

// readinessCache is the last real HealthCheck result and when it was taken.
type readinessCache struct {
	mu       sync.Mutex
	checked  time.Time
	notReady bool
}

// ReadinessCheck returns a handler for GET /readyz that reports whether the server is
// ready to serve traffic (database reachable). 200 = ready, 503 = not ready. The error
// detail is intentionally generic so internals aren't leaked on an unauthenticated route.
func ReadinessCheck(svc *core.KeyorixCore) http.HandlerFunc {
	cache := &readinessCache{}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")

		cache.mu.Lock()
		fresh := readinessNow().Sub(cache.checked) < readinessCacheTTL
		notReady := cache.notReady
		cache.mu.Unlock()

		if !fresh {
			notReady = svc.HealthCheck(r.Context()) != nil
			cache.mu.Lock()
			cache.checked = readinessNow()
			cache.notReady = notReady
			cache.mu.Unlock()
		}

		if notReady {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = encodeJSONResponse(w, map[string]string{"status": "not_ready", "reason": "database unreachable"})
			return
		}
		_ = encodeJSONResponse(w, map[string]string{"status": "ready"})
	}
}
