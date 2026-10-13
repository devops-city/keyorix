package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setBGCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

func TestRunBGActivate_RequiresProjectIDAndJustification(t *testing.T) {
	bgProject, bgJustify = 0, ""
	err := runBGActivate(bgActivateCmd, nil)
	if err == nil || !containsAll(err.Error(), "--project-id is required") {
		t.Fatalf("err = %v, want the --project-id required error", err)
	}

	bgProject, bgJustify = 1, ""
	err = runBGActivate(bgActivateCmd, nil)
	if err == nil || !containsAll(err.Error(), "--justification is required") {
		t.Fatalf("err = %v, want the --justification required error", err)
	}
}

// TestRunBGActivate_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 1's own test requirement) against
// internal/cli/breakglass/breakglass.go's activateCmd.
func TestRunBGActivate_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/1/break-glass" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"activation":{"id":42,"project_id":1,"user_id":1,"role_name":"proj-dev","justification":"incident INC-1","state":"active","expires_at":"2026-01-02T00:00:00Z","created_at":"2026-01-01T20:00:00Z"}}}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject, bgJustify = 1, "incident INC-1"
	defer func() { bgProject, bgJustify = 0, "" }()

	out := captureStdout(t, func() {
		if err := runBGActivate(bgActivateCmd, nil); err != nil {
			t.Fatalf("runBGActivate: %v", err)
		}
	})
	// First line is the old CLI's, unchanged; #2981 adds the effect lines after it.
	want := "Emergency access activated (id=42): role \"proj-dev\" until 2026-01-02T00:00:00Z.\n"
	if !strings.HasPrefix(out, want) {
		t.Fatalf("output = %q, want it to start with %q", out, want)
	}
	if !containsAll(out, `"proj-dev" is now granted to you on project 1`, "revoke --project-id 1 --activation-id 42") {
		t.Fatalf("output lacks the effect lines: %q", out)
	}
}

func TestRunBGList_RequiresProjectID(t *testing.T) {
	bgProject = 0
	err := runBGList(bgListCmd, nil)
	if err == nil || !containsAll(err.Error(), "--project-id is required") {
		t.Fatalf("err = %v, want the --project-id required error", err)
	}
}

func TestRunBGList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/1/break-glass" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"activations":[{"id":42,"user_id":7,"role_name":"proj-dev","justification":"incident INC-1","state":"active","expires_at":"2026-01-02T00:00:00Z","created_at":"2026-01-01T20:00:00Z"}],"count":1}}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject = 1
	defer func() { bgProject = 0 }()

	out := captureStdout(t, func() {
		if err := runBGList(bgListCmd, nil); err != nil {
			t.Fatalf("runBGList: %v", err)
		}
	})
	if !containsAll(out, "Break-glass activations — project 1:", "ID", "USER", "STATE", "ROLE", "EXPIRES", "JUSTIFICATION",
		"42", "7", "active", "proj-dev", "incident INC-1") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunBGList_EmptyPrintsNoActivationsMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"activations":[],"count":0}}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject = 1
	defer func() { bgProject = 0 }()

	out := captureStdout(t, func() {
		if err := runBGList(bgListCmd, nil); err != nil {
			t.Fatalf("runBGList: %v", err)
		}
	})
	if out != "No break-glass activations for project 1.\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

func TestRunBGRevoke_RequiresProjectIDAndActivationID(t *testing.T) {
	bgProject, bgActivation = 0, 0
	err := runBGRevoke(bgRevokeCmd, nil)
	if err == nil || !containsAll(err.Error(), "--project-id and --activation-id are required") {
		t.Fatalf("err = %v, want the required-flags error", err)
	}
}

func TestRunBGRevoke_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/1/break-glass/42/revoke" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":null,"message":"Emergency access revoked"}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject, bgActivation = 1, 42
	defer func() { bgProject, bgActivation = 0, 0 }()

	out := captureStdout(t, func() {
		if err := runBGRevoke(bgRevokeCmd, nil); err != nil {
			t.Fatalf("runBGRevoke: %v", err)
		}
	})
	if out != "Revoked break-glass activation 42 in project 1.\n" {
		t.Fatalf("output = %q", out)
	}
}

// BREAKGLASS-OWN-1: a member without roles.read gets scope "own"; the CLI must say the
// list is theirs only, so neither the table nor "none" reads as the whole project.
func TestRunBGList_OwnScopeSaysOnlyYourOwn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"activations":[{"id":42,"user_id":7,"role_name":"proj-dev","justification":"incident INC-1","state":"active","expires_at":"2026-01-02T00:00:00Z","created_at":"2026-01-01T20:00:00Z"}],"count":1,"scope":"own"}}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject = 1
	defer func() { bgProject = 0 }()

	out := captureStdout(t, func() {
		if err := runBGList(bgListCmd, nil); err != nil {
			t.Fatalf("runBGList: %v", err)
		}
	})
	if !containsAll(out, "Your break-glass activations — project 1 (only your own", "42", "proj-dev", "incident INC-1") {
		t.Fatalf("output = %q, want the own-scope heading and the row", out)
	}
	if strings.Contains(out, "Break-glass activations — project 1:") {
		t.Fatalf("output = %q, must not use the whole-project heading for an own-scope list", out)
	}
}

func TestRunBGList_OwnScopeEmptySaysYouHaveNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"activations":[],"count":0,"scope":"own"}}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject = 1
	defer func() { bgProject = 0 }()

	out := captureStdout(t, func() {
		if err := runBGList(bgListCmd, nil); err != nil {
			t.Fatalf("runBGList: %v", err)
		}
	})
	if out != "You have no break-glass activations on project 1 (listing other users' activations needs roles.read).\n" {
		t.Fatalf("output = %q", out)
	}
}

// FIX-3184: the own view omits the reviewer's note and the reviewer/revoker ids on
// the server; the CLI must not print them either, even if a server (or a stale one)
// still sent them for scope "own".
func TestRunBGList_OwnScopeNeverPrintsReviewNoteOrAdminIdentities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"activations":[{"id":42,"user_id":7,"role_name":"proj-dev","justification":"incident INC-1","state":"revoked","expires_at":"2026-01-02T00:00:00Z","created_at":"2026-01-01T20:00:00Z","revoked_at":"2026-01-01T21:00:00Z","reviewed_at":"2026-01-02T09:00:00Z","revoked_by":991,"reviewed_by":992,"review_note":"SECRET-REVIEW-NOTE"}],"count":1,"scope":"own"}}`)
	}))
	defer srv.Close()
	setBGCreds(t, srv)
	bgProject = 1
	defer func() { bgProject = 0 }()

	out := captureStdout(t, func() {
		if err := runBGList(bgListCmd, nil); err != nil {
			t.Fatalf("runBGList: %v", err)
		}
	})
	if !containsAll(out, "revoked", "42", "incident INC-1") {
		t.Fatalf("output = %q, want the revoked row", out)
	}
	for _, leak := range []string{"SECRET-REVIEW-NOTE", "991", "992"} {
		if strings.Contains(out, leak) {
			t.Fatalf("output = %q, must not print %q for scope own", out, leak)
		}
	}
}
