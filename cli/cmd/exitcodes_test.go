package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func runCLIForTest(t *testing.T, args ...string) (code int, stderr string) {
	t.Helper()
	var buf bytes.Buffer
	code = Run(args, &buf)
	return code, buf.String()
}

func isolateCredentials(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("APPDATA", home)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
}

// TestExitCodesAreDocumented keeps the table in `keyorix --help` and the constants the
// code returns in step: every code appears in the help, and nothing else does.
func TestExitCodesAreDocumented(t *testing.T) {
	for _, code := range []int{exitOK, exitFailure, exitUsage, exitAuth, exitPermission, exitNotFound, exitUnreach} {
		line := fmt.Sprintf("\n  %d  ", code)
		if !strings.Contains("\n"+exitCodesHelp, line) {
			t.Errorf("exit code %d is not documented in exitCodesHelp", code)
		}
	}
	if got := strings.Count(exitCodesHelp, "\n  "); got != 7 {
		t.Errorf("exitCodesHelp documents %d codes, the constants define 7", got)
	}
	if !strings.Contains(exitCodesHelp, "doctor") {
		t.Error("exitCodesHelp must say that `keyorix doctor` exits 1 when a check fails")
	}
	if !strings.Contains(rootCmd.Long, exitCodesHelp) {
		t.Error("`keyorix --help` does not show the exit-code table")
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		reachedBody bool
		want        int
	}{
		{"nil", nil, true, exitOK},
		{"401", apiError("list projects", 401, []byte(`{"message":"Invalid or expired token"}`)), true, exitAuth},
		{"403", apiError("create project", 403, []byte(`{"message":"forbidden"}`)), true, exitPermission},
		{"404 without a body", apiError("get secret", 404, nil), true, exitNotFound},
		{"409", httpStatusError("create project", 409, []byte(`{"message":"exists"}`)), true, exitFailure},
		{"500", httpStatusError("create project", 500, nil), true, exitFailure},
		{"wrapped status error keeps its code", fmt.Errorf("outer: %w", apiError("x", 403, nil)), true, exitPermission},
		{"plain error before the body ran is a usage error", errors.New(`unknown flag: --bogus`), false, exitUsage},
		{"plain error after the body ran is a failure", errors.New("disk full"), true, exitFailure},
		{"usageErrorf", usageErrorf("--id is required"), true, exitUsage},
	}
	for _, c := range cases {
		if got, _ := classifyError(c.err, c.reachedBody); got != c.want {
			t.Errorf("%s: exit code %d, want %d", c.name, got, c.want)
		}
	}
}

func TestStatusHints(t *testing.T) {
	err := apiError("list projects", 401, []byte(`{"message":"Invalid or expired token"}`))
	if !strings.Contains(err.Error(), "keyorix login") || !strings.Contains(err.Error(), "(HTTP 401)") {
		t.Errorf("401 should say how to sign in again: %v", err)
	}
	// A wrong password is not fixed by logging in again.
	for _, action := range []string{"login", "second-factor verification", "change password", "MFA activation failed"} {
		if e := apiError(action, 401, []byte(`{"message":"Invalid credentials"}`)); strings.Contains(e.Error(), "Next step") {
			t.Errorf("%s: a 401 here must not tell the user to log in again: %v", action, e)
		}
	}
	if e := apiError("create project", 403, []byte(`{"message":"forbidden"}`)); !strings.Contains(e.Error(), "request access") {
		t.Errorf("403 should name how to get access: %v", e)
	}
	// The server's own error code still wins over the generic status hint.
	e := apiError("list projects", 403, []byte(`{"error":"MFAEnrollmentRequired","message":"mfa"}`))
	if !strings.Contains(e.Error(), "keyorix mfa enroll") || strings.Contains(e.Error(), "request access") {
		t.Errorf("MFA enrolment hint should replace the generic 403 hint: %v", e)
	}
	// No raw body, ever.
	e = apiError("get thing", 502, []byte("<html><body>Bad gateway from proxy 10.0.0.7</body></html>"))
	if strings.Contains(e.Error(), "html") || strings.Contains(e.Error(), "10.0.0.7") {
		t.Errorf("a non-JSON body must not reach the message: %v", e)
	}
}

func TestRun_NotLoggedIn(t *testing.T) {
	isolateCredentials(t)
	code, stderr := runCLIForTest(t, "project", "list")
	if code != exitAuth {
		t.Fatalf("exit code %d, want %d\n%s", code, exitAuth, stderr)
	}
	if !strings.Contains(stderr, "not logged in") || !strings.Contains(stderr, "keyorix login") {
		t.Errorf("want 'not logged in' and the login command, got: %q", stderr)
	}
	if strings.Contains(stderr, "lstat") || strings.Contains(stderr, "no such file") {
		t.Errorf("the missing credentials file is the normal case; don't print the OS error: %q", stderr)
	}
}

func TestRun_ServerUnreachable(t *testing.T) {
	isolateCredentials(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // now nothing listens there
	t.Setenv("KEYORIX_SERVER", url)
	t.Setenv("KEYORIX_TOKEN", "tok")

	code, stderr := runCLIForTest(t, "project", "list")
	if code != exitUnreach {
		t.Fatalf("exit code %d, want %d\n%s", code, exitUnreach, stderr)
	}
	if !strings.Contains(stderr, "cannot reach the Keyorix server at "+url) || !strings.Contains(stderr, "Next step") {
		t.Errorf("want a plain-language unreachable message with a next step, got: %q", stderr)
	}
	if strings.Contains(stderr, "version-skew") || strings.Contains(stderr, "dial tcp") {
		t.Errorf("Go-internal wording leaked: %q", stderr)
	}
}

func TestRun_StatusCodesMapToExitCodes(t *testing.T) {
	for status, want := range map[int]int{401: exitAuth, 403: exitPermission, 404: exitNotFound, 409: exitFailure} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			isolateCredentials(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/version" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"error":"X","message":"the server says no"}`)
			}))
			defer srv.Close()
			t.Setenv("KEYORIX_SERVER", srv.URL)
			t.Setenv("KEYORIX_TOKEN", "tok")
			code, stderr := runCLIForTest(t, "project", "list")
			if code != want {
				t.Fatalf("HTTP %d -> exit code %d, want %d\n%s", status, code, want, stderr)
			}
			if !strings.Contains(stderr, "the server says no") || !strings.Contains(stderr, fmt.Sprintf("HTTP %d", status)) {
				t.Errorf("the server's own message and status must be shown: %q", stderr)
			}
		})
	}
}

func TestRun_UsageErrorsExitTwo(t *testing.T) {
	isolateCredentials(t)
	for _, args := range [][]string{
		{"nosuchcommand"},
		{"secret", "nosuchsubcommand"},
		{"secret", "get", "--bogus"},
		{"billing", "report"},                // required flags --from/--to missing
		{"anomalies", "acknowledge"},         // wrong argument count
		{"secret", "create"},                 // "--name is required": checked in the command body
		{"project", "env", "list", "extra!"}, // unexpected argument
	} {
		code, stderr := runCLIForTest(t, args...)
		if code != exitUsage {
			t.Errorf("keyorix %s: exit code %d, want %d\n%s", strings.Join(args, " "), code, exitUsage, stderr)
		}
	}
	// And the failure on a group's typo says what was typed, with a way forward.
	_, stderr := runCLIForTest(t, "secret", "lst")
	if !strings.Contains(stderr, `unknown command "lst" for "keyorix secret"`) || !strings.Contains(stderr, "list") {
		t.Errorf("want the typo and a suggestion, got: %q", stderr)
	}
}

func TestRun_SuccessExitsZero(t *testing.T) {
	isolateCredentials(t)
	if code, stderr := runCLIForTest(t, "version"); code != exitOK {
		t.Fatalf("version: exit code %d\n%s", code, stderr)
	}
	// A group with no subcommand shows its help and succeeds, as before.
	if code, _ := runCLIForTest(t, "secret"); code != exitOK {
		t.Fatalf("`keyorix secret` should still print help and exit 0, got %d", code)
	}
}

// A panic must end as a one-line report, never a Go stack trace.
func TestRun_PanicIsReportedWithoutAStackTrace(t *testing.T) {
	boom := &cobra.Command{Use: "zz-boom", RunE: func(*cobra.Command, []string) error { panic("kaboom") }}
	rootCmd.AddCommand(boom)
	defer rootCmd.RemoveCommand(boom)

	t.Setenv("KEYORIX_DEBUG", "")
	code, stderr := runCLIForTest(t, "zz-boom")
	if code != exitFailure {
		t.Errorf("exit code %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr, "internal error: kaboom") || !strings.Contains(stderr, "KEYORIX_DEBUG=1") {
		t.Errorf("want a one-line internal-error report, got: %q", stderr)
	}
	if strings.Contains(stderr, "goroutine") || strings.Contains(stderr, ".go:") {
		t.Errorf("a stack trace leaked: %q", stderr)
	}

	t.Setenv("KEYORIX_DEBUG", "1")
	_, stderr = runCLIForTest(t, "zz-boom")
	if !strings.Contains(stderr, "goroutine") {
		t.Errorf("KEYORIX_DEBUG=1 should add the stack trace: %q", stderr)
	}
}
