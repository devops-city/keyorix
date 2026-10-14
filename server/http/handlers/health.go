package handlers

import (
	"net/http"
	"os"
	"time"
)

// processStart is captured when the package loads (≈ server start) so /health can report
// a real uptime.
var processStart = time.Now()

// instanceNonce is empty in every real deployment. The e2e journey harness
// (scripts/e2e/harness) sets KEYORIX_E2E_INSTANCE_NONCE to a random value per
// server boot and this echoes it back, so the harness can prove the process
// answering a health check is the exact child it started -- not another
// journey's server that won the FreeTCPPort race (#2459, see
// harness.WaitHealthy). Omitted from the response entirely when unset, so
// this changes nothing about /health's real-deployment shape or its
// deliberate omission of version/commit info below.
var instanceNonce = os.Getenv("KEYORIX_E2E_INSTANCE_NONCE")

// HealthCheck handles GET /health — a lightweight liveness signal: it reports that the
// process is up and responsive. It deliberately does NOT check the database or other
// dependencies (that is /readyz's job) — a transient dependency outage should not cause
// the liveness probe to fail and restart the pod.
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeHealth(w, nil)
}

// HealthCheckWithAuthRateLimit is HealthCheck plus an "auth_rate_limit" field:
// "degraded" while authRateLimitDegraded reports that an auth rate limit is
// enforcing from its in-memory storage fallback
// (core.KeyorixCore.AuthRateLimitDegraded, AUTH-AUDIT-1 item 5), else "ok".
// The probe reads process memory only, so this still never touches the
// database. Liveness is unaffected, and the field never says which budget, key
// or address.
func HealthCheckWithAuthRateLimit(authRateLimitDegraded func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeHealth(w, authRateLimitDegraded)
	}
}

func writeHealth(w http.ResponseWriter, authRateLimitDegraded func() bool) {
	// Deliberately omit version/commit: /health is unauthenticated, and disclosing the
	// exact build aids CVE targeting. The precise version is available on the
	// system.read-gated /api/v1/system/info instead.
	health := map[string]any{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"uptime":    time.Since(processStart).String(),
	}
	if instanceNonce != "" {
		health["instance_nonce"] = instanceNonce
	}
	if authRateLimitDegraded != nil {
		state := "ok"
		if authRateLimitDegraded() {
			state = "degraded"
		}
		health["auth_rate_limit"] = state
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	if err := encodeJSONResponse(w, health); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
