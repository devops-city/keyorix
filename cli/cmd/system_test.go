package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setSystemCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunSystemInfo_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 10's own test requirement) against
// internal/cli/system/info.go's infoCmd.
func TestRunSystemInfo_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/system/info" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"version":"v1.2.3","git_commit":"abc123","go_version":"go1.24","os":"linux","arch":"amd64","uptime":"3h","environment":"production","features":{"airgap_updates":true},"database":{"type":"postgres","connected":true},"security":{"tls_enabled":true,"auth_enabled":true,"encryption_method":"aes256","audit_enabled":true}}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	out := captureStdout(t, func() {
		if err := systemInfoCmd.RunE(systemInfoCmd, nil); err != nil {
			t.Fatalf("system info: %v", err)
		}
	})
	if !containsAll(out, "Version:     v1.2.3", "Commit:      abc123", "Platform:    linux/amd64",
		"Database:    postgres (connected=true)", "Security:    tls=true auth=true audit=true encryption=aes256",
		"Features:    airgap_updates=true") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunSystemRoleExpiryCheck_MatchesOldCLIOutputShape(t *testing.T) {
	var calledPath, calledMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath, calledMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"warnings":3,"criticals":1}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	out := captureStdout(t, func() {
		if err := systemRoleExpiryCheckCmd.RunE(systemRoleExpiryCheckCmd, nil); err != nil {
			t.Fatalf("system role-expiry-check: %v", err)
		}
	})
	if calledPath != "/api/v1/admin/jobs/role-expiry-check" || calledMethod != http.MethodPost {
		t.Fatalf("called = %s %s", calledMethod, calledPath)
	}
	if !containsAll(out, "Role-expiry check complete: 3 warning(s), 1 critical(s)") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunSystemTokenExpiryCheck_MatchesOldCLIOutputShape(t *testing.T) {
	var calledPath, calledMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		calledPath, calledMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"pat_warnings":2,"pat_criticals":0,"machine_warnings":1,"machine_criticals":1}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	out := captureStdout(t, func() {
		if err := systemTokenExpiryCheckCmd.RunE(systemTokenExpiryCheckCmd, nil); err != nil {
			t.Fatalf("system token-expiry-check: %v", err)
		}
	})
	if calledPath != "/api/v1/admin/jobs/token-expiry-check" || calledMethod != http.MethodPost {
		t.Fatalf("called = %s %s", calledMethod, calledPath)
	}
	if !containsAll(out, "Token expiry check complete: 2 PAT warning(s), 0 PAT critical(s), 1 machine warning(s), 1 machine critical(s)") {
		t.Fatalf("output = %q", out)
	}
}

// An unstamped server (dev/none/unknown/empty) must never print as raw values, and the CLI's
// own build is always shown (#3143).
func TestRunSystemInfo_UnstampedBuildIsNotPrintedRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"version":"dev","git_commit":"none","build_time":"","go_version":"go1.24","os":"linux","arch":"amd64","uptime":"3h","environment":"demo","database":{"type":"sqlite","connected":true},"security":{}}}`)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)

	out := captureStdout(t, func() {
		if err := systemInfoCmd.RunE(systemInfoCmd, nil); err != nil {
			t.Fatalf("system info: %v", err)
		}
	})
	if !containsAll(out, "Version:     dev (not stamped)", "Commit:      n/a (not stamped)", "Built:       n/a", "CLI:         ") {
		t.Fatalf("unstamped build not rendered as expected: %q", out)
	}
	for _, raw := range []string{"Commit:      none", "Version:     dev\n", "Built:       \n"} {
		if strings.Contains(out, raw) {
			t.Fatalf("raw unstamped value %q leaked into output: %q", raw, out)
		}
	}
}
