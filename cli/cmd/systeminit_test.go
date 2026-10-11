package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// resetSystemInitFlagChanged clears the .Changed bit on every systemInitCmd flag --
// needed because systemInitCmd is a package-level singleton shared across the whole
// test binary, and pflag.FlagSet.Parse only ever sets Changed to true, never back to
// false for a later call that omits the flag (see share_test.go's resetFlagChanged in
// PR #2082, which this duplicates in miniature -- kept independent since these two
// follow-up PRs aren't guaranteed to land in either order).
func resetSystemInitFlagChanged() {
	systemInitCmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
}

// resetSystemInitFlags clears every package-level system-init flag var between tests.
func resetSystemInitFlags() {
	systemInitServer = ""
	systemInitAdminUsername = "admin"
	systemInitAdminPassword = ""
	systemInitAdminEmail = "admin@localhost"
	systemInitBootstrapToken = ""
	resetSystemInitFlagChanged()
}

func TestSystemInitCmd_RequiresServer(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()

	if err := systemInitCmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags(nil): %v", err)
	}
	if err := systemInitCmd.ValidateRequiredFlags(); err == nil {
		t.Fatal("expected an error when --server is not provided")
	}

	resetSystemInitFlagChanged()
	if err := systemInitCmd.ParseFlags([]string{"--server", "http://localhost:8080"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := systemInitCmd.ValidateRequiredFlags(); err != nil {
		t.Fatalf("unexpected error with --server provided: %v", err)
	}
}

func TestEndpointIsSecure(t *testing.T) {
	cases := []struct {
		endpoint string
		want     bool
	}{
		{"https://vault.example.com", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://vault.example.com", false},
		{"http://10.0.0.5:8080", false},
		{"not a url at all \x7f", false},
	}
	for _, c := range cases {
		if got := endpointIsSecure(c.endpoint); got != c.want {
			t.Errorf("endpointIsSecure(%q) = %v, want %v", c.endpoint, got, c.want)
		}
	}
}

func TestWarnIfInsecureEndpoint_WarnsOnlyForNonHTTPSNonLoopback(t *testing.T) {
	out := captureStderr(t, func() { warnIfInsecureEndpoint("http://vault.example.com") })
	if !containsAll(out, "not HTTPS", "vault.example.com") {
		t.Fatalf("expected an insecure-endpoint warning, got: %q", out)
	}

	out = captureStderr(t, func() { warnIfInsecureEndpoint("https://vault.example.com") })
	if out != "" {
		t.Fatalf("expected no warning for an HTTPS endpoint, got: %q", out)
	}

	out = captureStderr(t, func() { warnIfInsecureEndpoint("http://localhost:8080") })
	if out != "" {
		t.Fatalf("expected no warning for a loopback endpoint, got: %q", out)
	}
}

func TestResolveSystemInitAdminPassword_FlagTakesPrecedenceAndWarns(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	if err := systemInitCmd.ParseFlags([]string{"--server", "http://localhost:8080", "--admin-password", "secret123"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}

	var got string
	var err error
	out := captureStderr(t, func() { got, err = resolveSystemInitAdminPassword(systemInitCmd) })
	if err != nil {
		t.Fatalf("resolveSystemInitAdminPassword: %v", err)
	}
	if got != "secret123" {
		t.Fatalf("got %q, want %q", got, "secret123")
	}
	if !containsAll(out, "insecure", "admin-password") {
		t.Fatalf("expected an insecure-flag warning, got: %q", out)
	}
}

func TestResolveSystemInitAdminPassword_EnvVarUsedWithoutWarning(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	if err := systemInitCmd.ParseFlags([]string{"--server", "http://localhost:8080"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "envpass456")

	var got string
	var err error
	out := captureStderr(t, func() { got, err = resolveSystemInitAdminPassword(systemInitCmd) })
	if err != nil {
		t.Fatalf("resolveSystemInitAdminPassword: %v", err)
	}
	if got != "envpass456" {
		t.Fatalf("got %q, want %q", got, "envpass456")
	}
	if out != "" {
		t.Fatalf("expected no warning when the password comes from the env var, got: %q", out)
	}
}

func TestResolveSystemInitBootstrapToken_FlagAndEnvPrecedence(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()

	if err := systemInitCmd.ParseFlags([]string{"--server", "http://localhost:8080"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "env-token-xyz")
	if got, err := resolveSystemInitBootstrapToken(systemInitCmd); err != nil || got != "env-token-xyz" {
		t.Fatalf("got %q, %v, want the env var value", got, err)
	}

	resetSystemInitFlagChanged()
	if err := systemInitCmd.ParseFlags([]string{"--server", "http://localhost:8080", "--bootstrap-token", "flag-token-abc"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	out := captureStderr(t, func() {
		if got, err := resolveSystemInitBootstrapToken(systemInitCmd); err != nil || got != "flag-token-abc" {
			t.Fatalf("got %q, %v, want the flag value", got, err)
		}
	})
	if !containsAll(out, "insecure", "bootstrap-token") {
		t.Fatalf("expected an insecure-flag warning for --bootstrap-token, got: %q", out)
	}
}

// KEYORIX_ADMIN_PASSWORD_FILE / KEYORIX_BOOTSTRAP_TOKEN_FILE: read, one trailing
// newline stripped; a too-open file, an unreadable file, or X and X_FILE together
// are errors (never a prompt, never a silent fallback).
func TestSystemInit_SecretFiles(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	if err := systemInitCmd.ParseFlags([]string{"--server", "http://localhost:8080"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	write := func(content string, mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), "s")
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Setenv("KEYORIX_ADMIN_PASSWORD_FILE", write("filepass\n", 0o600))
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN_FILE", write("filetoken\n", 0o400))
	if got, err := resolveSystemInitAdminPassword(systemInitCmd); err != nil || got != "filepass" {
		t.Fatalf("admin password from file: %q, %v", got, err)
	}
	if got, err := resolveSystemInitBootstrapToken(systemInitCmd); err != nil || got != "filetoken" {
		t.Fatalf("bootstrap token from file: %q, %v", got, err)
	}

	t.Setenv("KEYORIX_ADMIN_PASSWORD_FILE", write("filepass\n", 0o644))
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN_FILE", write("filetoken\n", 0o644))
	if got, err := resolveSystemInitAdminPassword(systemInitCmd); err == nil || strings.Contains(err.Error(), "filepass") {
		t.Fatalf("a world-readable admin password file must be refused without echoing it: %q, %v", got, err)
	}
	if _, err := resolveSystemInitBootstrapToken(systemInitCmd); err == nil {
		t.Fatal("a world-readable bootstrap token file must be refused")
	}

	t.Setenv("KEYORIX_ADMIN_PASSWORD_FILE", write("filepass\n", 0o600))
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "both")
	if _, err := resolveSystemInitAdminPassword(systemInitCmd); err == nil {
		t.Fatal("X and X_FILE both set must be refused")
	}
}

func TestRunSystemInit_Success(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/system/init" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"already_initialized":false,"project":"default","environments":["development","staging","production"],"user":{"id":1,"username":"admin","email":"admin@localhost"}}}`)
	}))
	defer srv.Close()

	systemInitServer = srv.URL
	systemInitAdminUsername = "admin"
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "secret123")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "bootstrap-tok")

	out := captureStdout(t, func() {
		if err := runSystemInit(systemInitCmd, nil); err != nil {
			t.Fatalf("runSystemInit: %v", err)
		}
	})
	if !containsAll(out, "Keyorix initialised successfully", "Project: default",
		"development, staging, production", "Admin user: admin") {
		t.Fatalf("output missing expected fields: %q", out)
	}
	// #2940: the printed next step must be a command that works (`secret create`
	// takes --name; the bare positional form fails with "secret name is required").
	if !containsAll(out, "keyorix secret create --name my-first-secret") {
		t.Fatalf("next-step hint is not a working command: %q", out)
	}
}

func TestRunSystemInit_AlreadyInitialized(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"already_initialized":true}}`)
	}))
	defer srv.Close()

	systemInitServer = srv.URL
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "secret123")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "bootstrap-tok")

	stdout, stderr := captureStdoutAndStderr(t, func() {
		if err := runSystemInit(systemInitCmd, nil); err != nil {
			t.Fatalf("runSystemInit: %v", err)
		}
	})
	if stdout != "" {
		t.Fatalf("expected no stdout output, got: %q", stdout)
	}
	if !containsAll(stderr, "already initialised", "login") {
		t.Fatalf("expected the already-initialised message on stderr, got: %q", stderr)
	}
}

func TestRunSystemInit_NonOKStatusReturnsReadableError(t *testing.T) {
	resetSystemInitFlags()
	defer resetSystemInitFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"Forbidden","message":"invalid bootstrap token"}`)
	}))
	defer srv.Close()

	systemInitServer = srv.URL
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "secret123")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "wrong-token")

	err := runSystemInit(systemInitCmd, nil)
	if err == nil {
		t.Fatal("expected an error for a 403 response")
	}
	if !containsAll(err.Error(), "invalid bootstrap token", "403") {
		t.Fatalf("error missing expected detail: %v", err)
	}
}

// TestRunSystemInit_NeverLeaksAdminPasswordOrBootstrapToken mirrors secret_test.go's
// canary-value discipline: the admin password and bootstrap token this command sends
// must never appear in its own stdout or stderr, across the success, already-initialized,
// and error paths -- including inside the "insecure flag" warnings, which name the FLAG,
// never its VALUE.
func TestRunSystemInit_NeverLeaksAdminPasswordOrBootstrapToken(t *testing.T) {
	const canaryPassword = "CANARY-PASSWORD-do-not-leak-9f3e"
	const canaryToken = "CANARY-BOOTSTRAP-TOKEN-do-not-leak-7a2c"

	run := func(t *testing.T, handler http.HandlerFunc) (stdout, stderr string) {
		t.Helper()
		resetSystemInitFlags()
		defer resetSystemInitFlags()
		srv := httptest.NewServer(handler)
		defer srv.Close()

		systemInitServer = srv.URL
		if err := systemInitCmd.ParseFlags([]string{"--admin-password", canaryPassword, "--bootstrap-token", canaryToken}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		return captureStdoutAndStderr(t, func() {
			_ = runSystemInit(systemInitCmd, nil)
		})
	}

	assertNoLeak := func(t *testing.T, stdout, stderr string) {
		t.Helper()
		for _, s := range []string{stdout, stderr} {
			if containsAll(s, canaryPassword) {
				t.Fatalf("admin password leaked into output: %q", s)
			}
			if containsAll(s, canaryToken) {
				t.Fatalf("bootstrap token leaked into output: %q", s)
			}
		}
	}

	t.Run("success", func(t *testing.T) {
		stdout, stderr := run(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"already_initialized":false,"project":"default","environments":["development"],"user":{"id":1,"username":"admin","email":"admin@localhost"}}}`)
		})
		assertNoLeak(t, stdout, stderr)
	})

	t.Run("already initialized", func(t *testing.T) {
		stdout, stderr := run(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"already_initialized":true}}`)
		})
		assertNoLeak(t, stdout, stderr)
	})

	t.Run("forbidden", func(t *testing.T) {
		stdout, stderr := run(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":"Forbidden","message":"invalid bootstrap token"}`)
		})
		assertNoLeak(t, stdout, stderr)
	})
}
