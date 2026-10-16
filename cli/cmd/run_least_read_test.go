package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// runReadServer serves one project environment holding secrets a, b and c, and records the
// ids whose VALUE was read (GET /api/v1/secrets/{id}?include_value=true). Every such read is
// an audited secret.read on the real server.
func runReadServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var reads []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/environments"):
			_, _ = fmt.Fprint(w, `{"data":{"environments":[{"id":7,"name":"development"}]}}`)
		case r.URL.Path == "/api/v1/secrets" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"secrets":[{"id":1,"name":"a"},{"id":2,"name":"b"},{"id":3,"name":"c"}]}}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/secrets/") && r.URL.Query().Get("include_value") == "true":
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
			mu.Lock()
			reads = append(reads, id)
			mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"data":{"id":%s,"value":"v%s"}}`, id, id)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	setRequestCreds(t, srv)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), reads...)
	}
}

// TestFetchRunSecrets_VarReadsOnlyTheNamedSecrets: `keyorix run --var X=b` must read the
// value of b and of nothing else. Before this fix it read every secret in the environment,
// so a CI identity injecting one secret looked (audit log + anomaly detector's
// principal_breadth rule) like it had read the whole project.
func TestFetchRunSecrets_VarReadsOnlyTheNamedSecrets(t *testing.T) {
	_, reads := runReadServer(t)
	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	got, err := fetchRunSecrets(context.Background(), client, 1, "p", "development", wantedRunSecrets([]string{"X=b"}, false))
	if err != nil {
		t.Fatalf("fetchRunSecrets: %v", err)
	}
	if len(got) != 1 || got["b"] != "v2" {
		t.Fatalf("fetched %v, want only b=v2", got)
	}
	if r := reads(); len(r) != 1 || r[0] != "2" {
		t.Fatalf("value reads = %v, want exactly [2]", r)
	}
}

// TestFetchRunSecrets_DeriveNamesStillReadsEverything: the deprecated --derive-names path
// injects the whole environment by design; the fix must not narrow it.
func TestFetchRunSecrets_DeriveNamesStillReadsEverything(t *testing.T) {
	_, reads := runReadServer(t)
	client, err := apiClientWithSkewCheck(context.Background())
	if err != nil {
		t.Fatalf("apiClientWithSkewCheck: %v", err)
	}
	got, err := fetchRunSecrets(context.Background(), client, 1, "p", "development", wantedRunSecrets(nil, true))
	if err != nil {
		t.Fatalf("fetchRunSecrets: %v", err)
	}
	if len(got) != 3 || len(reads()) != 3 {
		t.Fatalf("fetched %v with %d reads, want all 3", got, len(reads()))
	}
}

func TestWantedRunSecrets(t *testing.T) {
	if w := wantedRunSecrets([]string{"A=x", "B=y=z", "bad", "C="}, false); len(w) != 2 || !w["x"] || !w["y=z"] {
		t.Fatalf("wantedRunSecrets = %v, want {x, y=z} (malformed mappings ignored here, rejected later)", w)
	}
	if w := wantedRunSecrets([]string{"A=x"}, true); w != nil {
		t.Fatalf("--derive-names must mean every secret (nil), got %v", w)
	}
	if w := wantedRunSecrets(nil, false); w != nil {
		t.Fatalf("no mappings => nil, got %v", w)
	}
}
