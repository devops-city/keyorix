package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REISSUE-1: `keyorix user reissue-one-time-password <user>`.

func reissueServer(t *testing.T, postStatus int, postBody string, posted *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/users/by-email" && r.URL.Query().Get("email") == "bob@example.com":
			_, _ = fmt.Fprint(w, `{"data":{"id":42,"username":"bob","email":"bob@example.com"}}`)
		case r.URL.Path == "/api/v1/users/42" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":42,"username":"bob","email":"bob@example.com"}}`)
		case r.URL.Path == "/api/v1/users/42/reissue-one-time-password" && r.Method == http.MethodPost:
			if posted != nil {
				*posted++
			}
			w.WriteHeader(postStatus)
			_, _ = fmt.Fprint(w, postBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	setUserCreds(t, srv)
	return srv
}

const reissueOKBody = `{"data":{"user_id":42,"one_time_password":{"email":"bob@example.com","one_time_password":"Zq7!kPm2-vXw9nRt4Bc6","expires_at":"2026-10-14T09:00:00Z"}}}`

// Golden output: the password appears exactly once, indented on its own line, with the
// expiry and what happened to the account.
const reissueGolden = "Reissuing one-time password for user 42 (bob@example.com)...\n" +
	"One-time password for bob@example.com (relay securely — it is shown only once and must be changed on first login; the user's existing sessions have ended):\n" +
	"  Zq7!kPm2-vXw9nRt4Bc6\n" +
	"Expires: 2026-10-14T09:00:00Z (UTC). After that, login with it is refused like a wrong password; reissue another with `keyorix user reissue-one-time-password`.\n"

func TestRunUserReissueOneTimePassword_ByID_Golden(t *testing.T) {
	reissueServer(t, http.StatusOK, reissueOKBody, nil)

	out := captureStdout(t, func() {
		if err := runUserReissueOneTimePassword(userReissueOneTimePasswordCmd, []string{"42"}); err != nil {
			t.Fatalf("reissue: %v", err)
		}
	})
	if out != reissueGolden {
		t.Fatalf("output mismatch.\n got: %q\nwant: %q", out, reissueGolden)
	}
	if n := strings.Count(out, "Zq7!kPm2-vXw9nRt4Bc6"); n != 1 {
		t.Fatalf("the password must be printed exactly once, got %d", n)
	}
}

func TestRunUserReissueOneTimePassword_ByEmail_Golden(t *testing.T) {
	reissueServer(t, http.StatusOK, reissueOKBody, nil)

	out := captureStdout(t, func() {
		if err := runUserReissueOneTimePassword(userReissueOneTimePasswordCmd, []string{"bob@example.com"}); err != nil {
			t.Fatalf("reissue: %v", err)
		}
	})
	if out != reissueGolden {
		t.Fatalf("output mismatch.\n got: %q\nwant: %q", out, reissueGolden)
	}
}

func TestRunUserReissueOneTimePassword_RejectsUnresolvableUserWithoutCalling(t *testing.T) {
	var posted int
	reissueServer(t, http.StatusOK, reissueOKBody, &posted)

	for _, arg := range []string{"bob", "0", "-3", ""} {
		err := runUserReissueOneTimePassword(userReissueOneTimePasswordCmd, []string{arg})
		if err == nil || !strings.Contains(err.Error(), "numeric user ID or an email") {
			t.Fatalf("arg %q: err = %v, want the usage error", arg, err)
		}
	}
	if posted != 0 {
		t.Fatalf("no reissue request may be sent for an unresolvable <user>, sent %d", posted)
	}
}

func TestRunUserReissueOneTimePassword_SurfacesRefusalsAndPrintsNoPassword(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"own account": {http.StatusBadRequest, `{"error":"Error","message":"Cannot reissue your own one-time password; use recover-admin"}`, "recover-admin"},
		"sso only":    {http.StatusConflict, `{"error":"Error","message":"this account is managed by an external identity provider"}`, "external identity provider"},
		"forbidden":   {http.StatusForbidden, `{"error":"Error","message":"insufficient admin authority"}`, "403"},
	} {
		t.Run(name, func(t *testing.T) {
			reissueServer(t, tc.status, tc.body, nil)
			var runErr error
			out := captureStdout(t, func() {
				runErr = runUserReissueOneTimePassword(userReissueOneTimePasswordCmd, []string{"42"})
			})
			if runErr == nil || !strings.Contains(runErr.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", runErr, tc.want)
			}
			if strings.Contains(out, "One-time password for") {
				t.Fatalf("a refused reissue must not print a password block: %q", out)
			}
		})
	}
}

func TestUserReissueOneTimePasswordCmd_IsRegisteredUnderUser(t *testing.T) {
	found := false
	for _, c := range userCmd.Commands() {
		if c == userReissueOneTimePasswordCmd {
			found = true
		}
	}
	if !found {
		t.Fatal("reissue-one-time-password is not registered under `user`")
	}
	if userReissueOneTimePasswordCmd.Args == nil {
		t.Fatal("the command must require exactly one <user> argument")
	}
}
