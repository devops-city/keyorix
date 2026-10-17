//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestResponseHygiene_SQLite checks error responses from a real keyorix-server
// binary (docs/security/production-hardening-matrix.d/response-hygiene.md): an
// unauthenticated API call (401), an unknown backend path (404), a wrong method
// (405) and a missing static asset (404) each carry the baseline security headers,
// Cache-Control: no-store and the JSON error body.
func TestResponseHygiene_SQLite(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	srv := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite", NoMFAReason: "no login needed: only unauthenticated error responses are checked"})
	t.Cleanup(srv.Close)
	client := &http.Client{}

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/secrets", http.StatusUnauthorized},
		{http.MethodGet, "/api/v2/nothing-here", http.StatusNotFound},
		{http.MethodDelete, "/health", http.StatusMethodNotAllowed},
		{http.MethodGet, "/assets/no-such-file.js", http.StatusNotFound},
	} {
		req, err := http.NewRequest(tc.method, srv.BaseURL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		where := tc.method + " " + tc.path
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", where, resp.StatusCode, tc.want)
			continue
		}
		for h, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
			"Cache-Control":          "no-store",
		} {
			if got := resp.Header.Get(h); got != want {
				t.Errorf("%s: %s = %q, want %q", where, h, got, want)
			}
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: CSP %q lacks frame-ancestors 'none'", where, resp.Header.Get("Content-Security-Policy"))
		}
		var env struct {
			Error string `json:"error"`
			Code  int    `json:"code"`
		}
		if err := json.Unmarshal(body, &env); err != nil || env.Error == "" || env.Code != tc.want {
			t.Errorf("%s: body %q is not the JSON error body", where, body)
		}
	}
}
