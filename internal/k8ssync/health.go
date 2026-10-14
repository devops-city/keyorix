package k8ssync

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Status tracks the outcome of the most recent reconcile pass — plus cumulative
// totals across all passes — so the agent can serve Kubernetes liveness/readiness
// probes and Prometheus metrics. Safe for concurrent use: the reconcile loop records
// results while the HTTP handlers read them.
type Status struct {
	mu      sync.Mutex
	ran     bool
	lastRun time.Time
	last    Result
	passes  int64
	// Cumulative target-Secret outcomes across all passes (monotonic counters).
	totCreated, totUpdated, totUnchanged, totFailed, totDeleted, totRevoked, totSuspected int64
	// Targets observed with a suspended / expired / soon-to-expire source (FIX-3175B).
	totSourceSuspended, totSourceExpired, totSourceExpiring int64
	// Targets skipped on a 401 from Keyorix; their Secrets were kept.
	totAuthFailed int64
	// Targets skipped because Keyorix was unreachable, timed out or answered 5xx; kept.
	totKeyorixUnreachable int64
	now                   func() time.Time
}

// NewStatus returns a Status with a real clock.
func NewStatus() *Status {
	return &Status{now: time.Now}
}

// Record stores the result of a completed reconcile pass and folds it into the
// cumulative totals.
func (s *Status) Record(res Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ran = true
	s.lastRun = s.now()
	s.last = res
	s.passes++
	s.totCreated += int64(res.Created)
	s.totUpdated += int64(res.Updated)
	s.totUnchanged += int64(res.Unchanged)
	s.totFailed += int64(res.Failed)
	s.totDeleted += int64(res.Deleted)
	s.totRevoked += int64(res.Revoked)
	s.totSuspected += int64(res.Suspected)
	s.totSourceSuspended += int64(res.SourceSuspended)
	s.totSourceExpired += int64(res.SourceExpired)
	s.totSourceExpiring += int64(res.SourceExpiring)
	s.totAuthFailed += int64(res.AuthFailed)
	s.totKeyorixUnreachable += int64(res.KeyorixUnreachable)
}

func (s *Status) snapshot() (bool, time.Time, Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ran, s.lastRun, s.last
}

// Handler serves the agent's probe + status endpoints with /metrics left
// unauthenticated. See HandlerWithToken to require a bearer token on /metrics
// specifically (e.g. for an internet-facing deployment without NetworkPolicy
// support) while keeping the probe endpoints open for Kubernetes.
func (s *Status) Handler() http.Handler {
	return s.HandlerWithToken("")
}

// HandlerWithToken serves the same endpoints as Handler:
//   - GET /healthz — liveness: always 200 while the process is responsive.
//   - GET /readyz  — readiness: 200 once at least one reconcile pass has completed,
//     503 before that (so traffic/rollout waits for the first sync).
//   - GET /status  — JSON of the last pass (counts + timestamp), for observability.
//   - GET /metrics — Prometheus text exposition of the counters above.
//
// /healthz, /readyz, and /status are deliberately never gated by token: they carry no
// secret values (only counts, a timestamp, and an error count) and Kubernetes' own
// kubelet must be able to reach them unauthenticated to run liveness/readiness probes.
// When token is non-empty, /metrics additionally requires a matching
// "Authorization: Bearer <token>" header — mirrors server/http/router.go's
// cfg.Server.HTTP.MetricsToken gate and operator/cmd/main.go's own
// -metrics-bearer-token gate on this repo's other two Prometheus-scraped endpoints.
// When token is empty, /metrics is left unauthenticated, same as Handler.
func (s *Status) HandlerWithToken(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		ran, _, _ := s.snapshot()
		if !ran {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("no reconcile completed yet"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		ran, lastRun, last := s.snapshot()
		body := map[string]any{
			"ran":                 ran,
			"created":             last.Created,
			"updated":             last.Updated,
			"unchanged":           last.Unchanged,
			"failed":              last.Failed,
			"deleted":             last.Deleted,
			"revoked":             last.Revoked,
			"suspected":           last.Suspected,
			"auth_failed":         last.AuthFailed,
			"keyorix_unreachable": last.KeyorixUnreachable,
			"errors":              len(last.Errors),
		}
		if ran {
			body["last_run"] = lastRun.UTC().Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	var metricsHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		// s.metrics() is a hand-built Prometheus text-exposition body assembled from this
		// process's own internal counters -- no request- or user-derived data reaches it, and
		// the response is served as text/plain, not HTML, so there is no XSS sink here.
		_, _ = w.Write([]byte(s.metrics()))
	})
	if token != "" {
		inner := metricsHandler
		metricsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if len(auth) < 8 || auth[:7] != "Bearer " || subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(token)) != 1 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}
	mux.Handle("/metrics", metricsHandler)
	return mux
}

// metrics renders the agent's state in the Prometheus text exposition format. Written
// by hand to avoid a client-library dependency (the metric set is small and stable).
func (s *Status) metrics() string {
	s.mu.Lock()
	ran := s.ran
	lastRun := s.lastRun
	last := s.last
	passes := s.passes
	c, u, n, f, d, rv, sp := s.totCreated, s.totUpdated, s.totUnchanged, s.totFailed, s.totDeleted, s.totRevoked, s.totSuspected
	ss, se, sx, af := s.totSourceSuspended, s.totSourceExpired, s.totSourceExpiring, s.totAuthFailed
	ku := s.totKeyorixUnreachable
	s.mu.Unlock()

	var lastTS int64
	if ran {
		lastTS = lastRun.Unix()
	}
	return fmt.Sprintf(`# HELP keyorix_k8s_sync_reconcile_passes_total Reconcile passes completed.
# TYPE keyorix_k8s_sync_reconcile_passes_total counter
keyorix_k8s_sync_reconcile_passes_total %d
# HELP keyorix_k8s_sync_secrets_total Cumulative target-Secret outcomes across all passes.
# TYPE keyorix_k8s_sync_secrets_total counter
keyorix_k8s_sync_secrets_total{outcome="created"} %d
keyorix_k8s_sync_secrets_total{outcome="updated"} %d
keyorix_k8s_sync_secrets_total{outcome="unchanged"} %d
keyorix_k8s_sync_secrets_total{outcome="failed"} %d
keyorix_k8s_sync_secrets_total{outcome="deleted"} %d
keyorix_k8s_sync_secrets_total{outcome="revoked"} %d
keyorix_k8s_sync_secrets_total{outcome="mass_revocation_suspected"} %d
keyorix_k8s_sync_secrets_total{outcome="source_suspended"} %d
keyorix_k8s_sync_secrets_total{outcome="source_expired"} %d
keyorix_k8s_sync_secrets_total{outcome="source_expiring"} %d
keyorix_k8s_sync_secrets_total{outcome="auth_failed"} %d
keyorix_k8s_sync_secrets_total{outcome="keyorix_unreachable"} %d
# HELP keyorix_k8s_sync_last_run_timestamp_seconds Unix time of the last completed reconcile (0 if none).
# TYPE keyorix_k8s_sync_last_run_timestamp_seconds gauge
keyorix_k8s_sync_last_run_timestamp_seconds %d
# HELP keyorix_k8s_sync_last_failed Target Secrets that failed in the most recent reconcile.
# TYPE keyorix_k8s_sync_last_failed gauge
keyorix_k8s_sync_last_failed %d
`, passes, c, u, n, f, d, rv, sp, ss, se, sx, af, ku, lastTS, last.Failed)
}
