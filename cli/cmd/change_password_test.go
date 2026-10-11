package cmd

// #3024: when change-password is the last setup step of a setup-only session
// (recover-admin / one-time password under security.require_mfa), the server
// ends the session and says so with data.reauthentication_required; the CLI
// must tell the operator to log in again with a code instead of claiming the
// session lives on.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func runChangePasswordAgainst(t *testing.T, response string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/change-password" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	defer srv.Close()
	setProjectCreds(t, srv)
	changePasswordCurrent, changePasswordNew = "old-Passw0rd!x", "new-Passw0rd!y"
	t.Cleanup(func() { changePasswordCurrent, changePasswordNew = "", "" })
	return captureStdout(t, func() {
		if err := runChangePassword(changePasswordCmd, nil); err != nil {
			t.Fatalf("runChangePassword: %v", err)
		}
	})
}

func TestChangePassword_SetupCompleteTellsOperatorToLogInAgain(t *testing.T) {
	out := runChangePasswordAgainst(t, `{"success":true,"data":{"reauthentication_required":true},"message":"Password changed."}`)
	if !strings.Contains(out, "session has ended") || !strings.Contains(out, "keyorix login") {
		t.Fatalf("expected a log-in-again instruction, got:\n%s", out)
	}
}

func TestChangePassword_OrdinaryChangeKeepsSession(t *testing.T) {
	out := runChangePasswordAgainst(t, `{"success":true,"data":{"reauthentication_required":false},"message":"Password changed"}`)
	if strings.Contains(out, "session has ended") || !strings.Contains(out, "other active session") {
		t.Fatalf("expected the ordinary message, got:\n%s", out)
	}
}
