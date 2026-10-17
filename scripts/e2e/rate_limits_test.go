//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestRateLimits_SQLite drives the brute-force bounds against a real keyorix-server
// binary (docs/security/production-hardening-matrix.d/rate-limits.md):
//   - guessing bearer tokens on the API is answered 429 after the failed-token budget;
//   - on an initialised system, POST /system/init is the idempotent 200 every time,
//     so the bootstrap-token failure budget never throttles automation that calls it
//     (Helm hooks, compose health checks).
func TestRateLimits_SQLite(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	srv := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite", NoMFAReason: "no login needed: only unauthenticated and bad-credential requests are sent"})
	t.Cleanup(srv.Close)
	client := &http.Client{}

	for i := range 20 {
		req, err := http.NewRequest(http.MethodPost, srv.BaseURL+"/system/init", strings.NewReader(`{"bootstrap_token":"anything"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("idempotent /system/init call %d on an initialised system: status %d, want 200", i+1, resp.StatusCode)
		}
	}

	throttled := false
	for i := range 50 {
		req, err := http.NewRequest(http.MethodGet, srv.BaseURL+"/api/v1/secrets", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer guess-"+strings.Repeat("y", i+1))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			throttled = true
			break
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bad bearer token %d: status %d, want 401 or 429", i+1, resp.StatusCode)
		}
	}
	if !throttled {
		t.Fatal("50 wrong bearer tokens were never throttled by the real server")
	}
}
