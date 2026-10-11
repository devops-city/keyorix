package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
