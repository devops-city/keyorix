package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/credstore"
)

// #3026: the bundled web tier (nginx on :8088) answers /health itself with a
// plain-text "healthy". status must report that as reachable, not as
// "unreachable or unexpected response (HTTP 200)".
func TestStatus_AcceptsPlainTextProxyHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "healthy\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	out := captureStdout(t, func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})
	if strings.Contains(out, "unreachable") {
		t.Fatalf("plain-text proxy /health reported as unreachable:\n%s", out)
	}
	if !strings.Contains(out, "Health: ok (web proxy") {
		t.Fatalf("expected proxy health line, got:\n%s", out)
	}
}

// A 200 with an unrecognised body is still flagged, so the fix does not turn
// every HTTP 200 into "healthy".
func TestStatus_UnknownHealthBodyStillFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "<html>captive portal</html>")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	out := captureStdout(t, func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})
	if !strings.Contains(out, "unreachable or unexpected response (HTTP 200)") {
		t.Fatalf("unexpected body must stay flagged, got:\n%s", out)
	}
}

// F6 (INSTALL-CLEANROOM-1): the credential file is per OS user and shared by every install on
// the account, so status names it, also when no server is configured yet.
func TestStatus_PrintsCredentialFilePath(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_TOKEN_FILE", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	want, err := credstore.DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	out := captureStdout(t, func() {
		if err := runStatus(statusCmd, nil); err == nil {
			t.Fatalf("runStatus with no server configured should fail")
		}
	})
	if !strings.Contains(out, "Credentials file: "+want+"\n") {
		t.Fatalf("status output must name %q, got:\n%s", want, out)
	}
}

func TestStatus_HelpNamesCredentialFileAndXDG(t *testing.T) {
	for _, s := range []string{"credentials.yaml", "XDG_CONFIG_HOME", "~/.config", "Application Support"} {
		if !strings.Contains(statusCmd.Long, s) {
			t.Errorf("status --help must mention %q", s)
		}
	}
}
