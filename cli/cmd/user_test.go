package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setUserCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunUserList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 6's own test requirement) against
// internal/cli/user/list.go's runListRemote.
func TestRunUserList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"users":[{"id":1,"username":"alice","email":"alice@example.com","active":true}],"total":1}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userListPage, userListPageSize = 1, 20

	out := captureStdout(t, func() {
		if err := runUserList(userListCmd, nil); err != nil {
			t.Fatalf("runUserList: %v", err)
		}
	})
	if !containsAll(out, "Total: 1", "ID", "USERNAME", "EMAIL", "ACTIVE", "1", "alice", "alice@example.com", "true") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunUserGet_ByID matches internal/cli/user/get.go's printRemoteUser.
func TestRunUserGet_ByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/42" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":42,"username":"bob","email":"bob@example.com","display_name":"Bob","active":true,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userGetID, userGetEmail = 42, ""

	out := captureStdout(t, func() {
		if err := runUserGet(userGetCmd, nil); err != nil {
			t.Fatalf("runUserGet: %v", err)
		}
	})
	if !containsAll(out, "ID: 42", "Username: bob", "Email: bob@example.com", "Display: Bob", "Active: true") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunUserGet_ByEmail matches internal/cli/user/get.go's --email branch (GET
// /api/v1/users/by-email, added by this PR).
func TestRunUserGet_ByEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/by-email" || r.URL.Query().Get("email") != "bob@example.com" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":42,"username":"bob","email":"bob@example.com"}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userGetID, userGetEmail = 0, "bob@example.com"

	out := captureStdout(t, func() {
		if err := runUserGet(userGetCmd, nil); err != nil {
			t.Fatalf("runUserGet: %v", err)
		}
	})
	if !containsAll(out, "ID: 42", "Username: bob") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunUserGet_RequiresIDOrEmail(t *testing.T) {
	userGetID, userGetEmail = 0, ""
	if err := runUserGet(userGetCmd, nil); err == nil || !containsAll(err.Error(), "specify --id or --email") {
		t.Fatalf("err = %v, want the missing-id-or-email error", err)
	}
}

// TestRunUserUpdate_MatchesOldCLIOutputShape matches
// internal/cli/user/update.go's runUpdateRemote.
func TestRunUserUpdate_MatchesOldCLIOutputShape(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/9" || r.Method != http.MethodPut {
			http.NotFound(w, r)
			return
		}
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":9,"username":"renamed","email":"renamed@example.com"}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userUpdateID = 9
	userUpdateUsername = "renamed"
	userUpdateEmail, userUpdateDisplayName, userUpdateActiveStr = "", "", ""
	defer func() { userUpdateUsername = "" }()

	out := captureStdout(t, func() {
		if err := runUserUpdate(userUpdateCmd, nil); err != nil {
			t.Fatalf("runUserUpdate: %v", err)
		}
	})
	if !containsAll(out, "User updated: id=9 username=renamed email=renamed@example.com") {
		t.Fatalf("output = %q", out)
	}
	if !containsAll(gotBody, `"username":"renamed"`) {
		t.Fatalf("request body = %q", gotBody)
	}
}

func TestRunUserUpdate_RequiresAtLeastOneField(t *testing.T) {
	userUpdateID = 9
	userUpdateUsername, userUpdateEmail, userUpdateDisplayName, userUpdateActiveStr = "", "", "", ""
	err := runUserUpdate(userUpdateCmd, nil)
	if err == nil || !containsAll(err.Error(), "provide at least one of") {
		t.Fatalf("err = %v, want the missing-field error", err)
	}
}

// TestRunUserUpdate_SurfacesLastAdminRefusalReadably is the CLI-side half of this PR's
// server fix (server/http/handlers/users_crud.go's UpdateUser switch, and
// users_update_lastadmin_test.go): a 409 response with a real message must reach the
// operator as readable text, not a bare "HTTP 409".
func TestRunUserUpdate_SurfacesLastAdminRefusalReadably(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/1" || r.Method != http.MethodPut {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusConflict)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":false,"error":"Conflict","message":"refusing to deactivate the last install administrator"}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userUpdateID = 1
	userUpdateActiveStr = "false"
	userUpdateUsername, userUpdateEmail, userUpdateDisplayName = "", "", ""
	defer func() { userUpdateActiveStr = "" }()

	err := runUserUpdate(userUpdateCmd, nil)
	if err == nil || !containsAll(err.Error(), "refusing to deactivate the last install administrator") {
		t.Fatalf("err = %v, want the real server refusal reason surfaced", err)
	}
}

// TestRunUserDelete_ForceSkipsConfirm matches internal/cli/user/delete.go's
// runDeleteRemote.
func TestRunUserDelete_ForceSkipsConfirm(t *testing.T) {
	var deletedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/users/9" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":9,"email":"gone@example.com"}}`)
		case r.URL.Path == "/api/v1/users/9" && r.Method == http.MethodDelete:
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userDeleteID, userDeleteForce, userDeleteBy = 9, true, "admin@example.com"

	out := captureStdout(t, func() {
		if err := runUserDelete(userDeleteCmd, nil); err != nil {
			t.Fatalf("runUserDelete: %v", err)
		}
	})
	if deletedPath != "/api/v1/users/9" {
		t.Fatalf("deleted path = %q", deletedPath)
	}
	if !containsAll(out, "user 9 (gone@example.com)", "deleted") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunUserSuspend_MatchesOldCLIOutputShape matches
// internal/cli/user/lifecycle.go's runAccountStateRemote.
func TestRunUserSuspend_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/users/9" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":9,"email":"target@example.com"}}`)
		case r.URL.Path == "/api/v1/users/9/suspend" && r.Method == http.MethodPost:
			_, _ = fmt.Fprint(w, `{"data":null}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setUserCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runAccountStateChange(9, "suspend", "Suspending", "suspended"); err != nil {
			t.Fatalf("runAccountStateChange: %v", err)
		}
	})
	if !containsAll(out, "Suspending user 9 (target@example.com)", "user 9 (target@example.com) has been suspended.") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunUserRevokeSessions_ZeroCase matches
// internal/cli/user/lifecycle.go's runRevokeSessionsRemote zero-revoked branch.
func TestRunUserRevokeSessions_ZeroCase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/users/9" && r.Method == http.MethodGet:
			_, _ = fmt.Fprint(w, `{"data":{"id":9,"email":"target@example.com"}}`)
		case r.URL.Path == "/api/v1/users/9/revoke-sessions" && r.Method == http.MethodPost:
			_, _ = fmt.Fprint(w, `{"data":{"revoked":0}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userRevokeSessionsID, userRevokeSessionsBy = 9, "admin@example.com"

	out := captureStdout(t, func() {
		if err := userRevokeSessionsCmd.RunE(userRevokeSessionsCmd, nil); err != nil {
			t.Fatalf("revoke-sessions: %v", err)
		}
	})
	if !containsAll(out, "0 sessions revoked for user 9 (target@example.com) -- none were active.") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunUserSuspendInactive_DryRun matches
// internal/cli/user/inactivity_suspend.go's printSuspendResult dry-run branch.
func TestRunUserSuspendInactive_DryRun(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/jobs/suspend-inactive-users" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"suspended":[1,2],"skipped":1,"total":3}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userSuspendInactiveDays, userSuspendInactiveDryRun = 90, true
	defer func() { userSuspendInactiveDryRun = false }()

	out := captureStdout(t, func() {
		if err := runUserSuspendInactive(userSuspendInactiveCmd, nil); err != nil {
			t.Fatalf("runUserSuspendInactive: %v", err)
		}
	})
	if !containsAll(out, "[dry-run] Inactive users examined: 3", "[dry-run] Would suspend: 2", "[dry-run] Would suspend user IDs: 1, 2") {
		t.Fatalf("output = %q", out)
	}
	if !containsAll(gotBody, `"inactive_days":90`, `"dry_run":true`) {
		t.Fatalf("request body = %q", gotBody)
	}
}

func TestRunUserSuspendInactive_RequiresPositiveDays(t *testing.T) {
	userSuspendInactiveDays = 0
	if err := runUserSuspendInactive(userSuspendInactiveCmd, nil); err == nil || !containsAll(err.Error(), "--days must be greater than 0") {
		t.Fatalf("err = %v, want the missing-days error", err)
	}
}

// TestRunUserCreate_PasswordMode matches internal/cli/user/create.go's
// runCreateRemote classic-password branch.
func TestRunUserCreate_PasswordMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":5,"username":"newuser","email":"newuser@example.com"}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userCreateUsername = "newuser"
	userCreateEmail = "newuser@example.com"
	userCreateDisplayName = ""
	userCreateSetupLink, userCreateOneTimePassword = false, false
	userCreatePassword = "correct-horse-battery-staple-1"
	defer func() { userCreateUsername, userCreatePassword = "", "" }()

	out := captureStdout(t, func() {
		if err := runUserCreate(userCreateCmd, nil); err != nil {
			t.Fatalf("runUserCreate: %v", err)
		}
	})
	if !containsAll(out, "User created: id=5 username=newuser email=newuser@example.com") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunUserCreate_SetupLinkMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"user":{"id":6,"username":"setupuser","email":"setup@example.com"},"setup_link":{"email":"setup@example.com","channel":"out-of-band","delivered":false,"link_for_admin":"https://example.com/setup/abc"}}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userCreateUsername = "setupuser"
	userCreateEmail = "setup@example.com"
	userCreateSetupLink = true
	defer func() { userCreateUsername, userCreateSetupLink = "", false }()

	out := captureStdout(t, func() {
		if err := runUserCreate(userCreateCmd, nil); err != nil {
			t.Fatalf("runUserCreate: %v", err)
		}
	})
	if !containsAll(out, "User created: id=6 username=setupuser email=setup@example.com",
		"Setup link (relay this to setup@example.com securely", "https://example.com/setup/abc") {
		t.Fatalf("output = %q", out)
	}
}

// OTP-EXPIRY-1: the operator is told when the one-time password expires (UTC).
func TestRunUserCreate_OneTimePasswordMode_PrintsExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		// A non-UTC offset on the wire must still be printed as UTC.
		_, _ = fmt.Fprint(w, `{"data":{"user":{"id":7,"username":"otpuser","email":"otp@example.com"},"one_time_password":{"email":"otp@example.com","one_time_password":"Zx9#Temp-Pass","expires_at":"2026-10-13T14:00:00+02:00"}}}`)
	}))
	defer srv.Close()
	setUserCreds(t, srv)
	userCreateUsername = "otpuser"
	userCreateEmail = "otp@example.com"
	userCreateOneTimePassword = true
	defer func() { userCreateUsername, userCreateOneTimePassword = "", false }()

	out := captureStdout(t, func() {
		if err := runUserCreate(userCreateCmd, nil); err != nil {
			t.Fatalf("runUserCreate: %v", err)
		}
	})
	if !containsAll(out, "One-time password for otp@example.com", "Zx9#Temp-Pass", "Expires: 2026-10-13T12:00:00Z (UTC)") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunUserCreate_RequiresUsernameAndEmail(t *testing.T) {
	userCreateUsername, userCreateEmail = "", ""
	if err := runUserCreate(userCreateCmd, nil); err == nil || !containsAll(err.Error(), "username is required") {
		t.Fatalf("err = %v, want the missing-username error", err)
	}
}
