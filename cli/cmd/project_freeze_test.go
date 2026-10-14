package cmd

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestProjectSuspendSecrets_RequiresID(t *testing.T) {
	projectFreezeID = 0
	if err := projectSuspendSecretsCmd.RunE(projectSuspendSecretsCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
	projectThawID = 0
	if err := projectResumeSecretsCmd.RunE(projectResumeSecretsCmd, nil); err == nil {
		t.Fatal("expected an error when --id is omitted")
	}
}

// --clear-synced-copies puts clear_synced_copies:true in the project-wide request and
// tells the person to rotate; without it the body has no such member and the output does
// not mention synced copies.
func TestProjectSuspendSecrets_ClearSyncedCopiesFlag(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flag        bool
		wantInBody  bool
		wantInPrint []string
		notInPrint  string
	}{
		{"flag set", true, true, []string{"Project 5", "3 secret(s) suspended", "cleared on their next sync", "secret rotate"}, ""},
		{"flag unset", false, false, []string{"Project 5", "3 secret(s) suspended"}, "synced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody string
			srv := secretOpsServer(t, secretOpsRoute{http.MethodPost, "/api/v1/projects/5/secrets/suspend-all", func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"data":{"suspended":3}}`)
			}})
			setPATCreds(t, srv)
			projectFreezeID, projectFreezeReason, projectFreezeClearCopies = 5, "leaked", tc.flag
			defer func() { projectFreezeID, projectFreezeReason, projectFreezeClearCopies = 0, "", false }()

			out := captureStdout(t, func() {
				if err := projectSuspendSecretsCmd.RunE(projectSuspendSecretsCmd, nil); err != nil {
					t.Fatalf("projectSuspendSecretsCmd: %v", err)
				}
			})
			if has := strings.Contains(gotBody, `"clear_synced_copies":true`); has != tc.wantInBody {
				t.Fatalf("request body %q: clear_synced_copies present=%v, want %v", gotBody, has, tc.wantInBody)
			}
			if !strings.Contains(gotBody, `"reason":"leaked"`) {
				t.Fatalf("the reason must still be sent: %q", gotBody)
			}
			if !containsAll(out, tc.wantInPrint...) {
				t.Fatalf("output missing %v, got: %q", tc.wantInPrint, out)
			}
			if tc.notInPrint != "" && strings.Contains(out, tc.notInPrint) {
				t.Fatalf("output must not mention %q, got: %q", tc.notInPrint, out)
			}
		})
	}
}

// A caller without the permission gets the server's 403 as an error, and the command
// never claims a suspension.
func TestProjectSuspendSecrets_PermissionDenied(t *testing.T) {
	srv := secretOpsServer(t, secretOpsRoute{http.MethodPost, "/api/v1/projects/5/secrets/suspend-all", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"Forbidden","message":"missing secrets.write"}`)
	}})
	setPATCreds(t, srv)
	projectFreezeID, projectFreezeClearCopies = 5, true
	defer func() { projectFreezeID, projectFreezeClearCopies = 0, false }()

	var runErr error
	out := captureStdout(t, func() { runErr = projectSuspendSecretsCmd.RunE(projectSuspendSecretsCmd, nil) })
	if runErr == nil {
		t.Fatal("a 403 must be an error")
	}
	if strings.Contains(out, "suspended") {
		t.Fatalf("must not report a suspension on 403, got %q", out)
	}
}

func TestProjectResumeSecrets(t *testing.T) {
	srv := secretOpsServer(t, secretOpsRoute{http.MethodPost, "/api/v1/projects/5/secrets/resume-all", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"resumed":2}}`)
	}})
	setPATCreds(t, srv)
	projectThawID = 5
	defer func() { projectThawID = 0 }()
	out := captureStdout(t, func() {
		if err := projectResumeSecretsCmd.RunE(projectResumeSecretsCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !containsAll(out, "Project 5", "2 secret(s) resumed") {
		t.Fatalf("unexpected output %q", out)
	}
}
