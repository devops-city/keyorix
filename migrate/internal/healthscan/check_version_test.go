package healthscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeServer(t *testing.T, handlers map[string]string) (*Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range handlers {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{addr: srv.URL, token: "t", hc: srv.Client()}, srv
}

// newCanaryMux builds a *Client backed by an httptest server that serves handlers normally but
// fails the test immediately if any request path has forbiddenPrefix — used by checks that must
// never touch a KV *data* path to prove they structurally can't, not just that a given fixture
// didn't happen to trigger it.
func newCanaryMux(t *testing.T, handlers map[string]string, forbiddenPrefix string) *Client {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range handlers {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, forbiddenPrefix) {
				t.Fatalf("forbidden path requested: %s", r.URL.Path)
			}
			_, _ = w.Write([]byte(body))
		})
	}
	mux.HandleFunc(forbiddenPrefix, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("forbidden path requested: %s", r.URL.Path)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{addr: srv.URL, token: "t", hc: srv.Client()}
}

func fakeServerStatus(t *testing.T, path string, status int, body string) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{addr: srv.URL, token: "t", hc: srv.Client()}
}

func TestCheckVersionEOL_CurrentVault(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/health": `{"version":"1.17.6"}`})
	res := checkVersionEOL(context.Background(), c)
	if res.Finding == nil {
		t.Fatalf("expected a finding, got %+v", res)
	}
	if res.Finding.Severity != SeverityInfo {
		t.Errorf("current version severity = %s, want info", res.Finding.Severity)
	}
	if !strings.Contains(res.Finding.Evidence, "Vault") || !strings.Contains(res.Finding.Evidence, "BSL-1.1") {
		t.Errorf("evidence = %q, want it to name Vault and BSL-1.1", res.Finding.Evidence)
	}
}

func TestCheckVersionEOL_EOLVault(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/health": `{"version":"1.10.3"}`})
	res := checkVersionEOL(context.Background(), c)
	if res.Finding == nil {
		t.Fatalf("expected a finding, got %+v", res)
	}
	if res.Finding.Severity != SeverityMedium {
		t.Errorf("EOL vault severity = %s, want medium", res.Finding.Severity)
	}
	if !strings.Contains(res.Finding.Evidence, "MPL-2.0") {
		t.Errorf("pre-1.14 vault should be MPL-2.0, evidence = %q", res.Finding.Evidence)
	}
}

func TestCheckVersionEOL_OpenBao(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{"/v1/sys/health": `{"version":"2.1.0"}`})
	res := checkVersionEOL(context.Background(), c)
	if res.Finding == nil {
		t.Fatalf("expected a finding, got %+v", res)
	}
	if !strings.Contains(res.Finding.Evidence, "OpenBao") || !strings.Contains(res.Finding.Evidence, "MPL-2.0") {
		t.Errorf("evidence = %q, want it to name OpenBao and MPL-2.0", res.Finding.Evidence)
	}
}

func TestCheckVersionEOL_PermissionDenied(t *testing.T) {
	c := fakeServerStatus(t, "/v1/sys/health", http.StatusForbidden, `{"errors":["permission denied"]}`)
	res := checkVersionEOL(context.Background(), c)
	if res.NotChecked == nil {
		t.Fatalf("expected NotChecked, got %+v", res)
	}
	if res.NotChecked.PolicyLine == "" {
		t.Error("expected a PolicyLine naming the missing grant")
	}
}

func TestCheckEnterpriseLicense_CommunityEdition(t *testing.T) {
	c := fakeServerStatus(t, "/v1/sys/license/status", http.StatusNotFound, `{"errors":[]}`)
	res := checkEnterpriseLicense(context.Background(), c)
	if res.Finding == nil || !strings.Contains(res.Finding.Evidence, "Community") {
		t.Fatalf("expected a Community Edition finding, got %+v", res)
	}
}

func TestCheckEnterpriseLicense_Enterprise(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/license/status": `{"data":{"autoloaded":{"state":"autoloaded","expiration_time":"2027-01-01T00:00:00Z"}}}`,
	})
	res := checkEnterpriseLicense(context.Background(), c)
	if res.Finding == nil || !strings.Contains(res.Finding.Evidence, "Enterprise") {
		t.Fatalf("expected an Enterprise finding, got %+v", res)
	}
}

func TestParseVaultVersion_RejectsGarbage(t *testing.T) {
	if _, err := parseVaultVersion("not-a-version"); err == nil {
		t.Fatal("expected an error for an unparseable version string")
	}
}

func TestParseVaultVersion_StripsEnterpriseSuffix(t *testing.T) {
	dv, err := parseVaultVersion("1.17.6+ent")
	if err != nil {
		t.Fatalf("parseVaultVersion: %v", err)
	}
	if dv.Major != 1 || dv.Minor != 17 {
		t.Errorf("got major=%d minor=%d, want 1.17", dv.Major, dv.Minor)
	}
}
