// secret_delete_test.go — 'secret delete': soft-delete wording, the dependents
// guard (ADR-052) and the non-interactive --format json mode.
package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// deletePurgeAt is the Keyorix-Purge-At header deleteServer sends on DELETE ("" = an
// older server that does not send it). Reset per test via setDeletePurgeAt.
var deletePurgeAt = "2026-11-09T12:00:00Z"

func setDeletePurgeAt(t *testing.T, v string) {
	t.Helper()
	orig := deletePurgeAt
	deletePurgeAt = v
	t.Cleanup(func() { deletePurgeAt = orig })
}

// deleteServer serves secret 5 ("db-pass", 2 versions) with the given
// dependents JSON array, and counts DELETE calls.
func deleteServer(t *testing.T, dependents string, deletes *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5":
			_, _ = fmt.Fprint(w, `{"data":{"id":5,"name":"db-pass"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5/versions":
			_, _ = fmt.Fprint(w, `{"data":{"versions":[{"version_number":1},{"version_number":2}]}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/5/dependencies":
			_, _ = fmt.Fprintf(w, `{"data":{"secret_id":5,"depends_on":[],"dependents":%s}}`, dependents)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/secrets/5":
			*deletes++
			if deletePurgeAt != "" {
				w.Header().Set("Keyorix-Purge-At", deletePurgeAt)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	setPATCreds(t, srv)
	return srv
}

func resetDeleteFlags(t *testing.T) {
	t.Helper()
	secretDeleteID, secretDeleteName, secretDeleteForce, secretDeleteFormat = 5, "", false, "text"
	t.Cleanup(func() {
		secretDeleteID, secretDeleteName, secretDeleteForce, secretDeleteFormat = 0, "", false, "text"
	})
}

const twoDependents = `[{"id":1,"secret_id":8,"secret_name":"app-conn"},{"id":2,"secret_id":9,"secret_name":"worker-conn"}]`

func TestSecretDelete_ForceSuccessSaysSoftDeletedAndRestorable(t *testing.T) {
	var deletes int
	deleteServer(t, `[]`, &deletes)
	resetDeleteFlags(t)
	secretDeleteForce = true

	out := captureStdout(t, func() {
		if err := runSecretDelete(secretDeleteCmd, nil); err != nil {
			t.Fatalf("runSecretDelete: %v", err)
		}
	})
	if deletes != 1 {
		t.Fatalf("DELETE calls = %d, want 1", deletes)
	}
	// RETENTION-1: the REAL purge date the server reported, not a guessed default.
	if !containsAll(out, "soft-delete", "keyorix secret restore --id 5", "Restorable until 2026-11-09T12:00:00Z (UTC)", "2 version(s) are kept") {
		t.Fatalf("success text missing soft-delete/restore wording or the real purge date: %q", out)
	}
	if strings.Contains(out, "30 days") {
		t.Fatalf("a guessed 'default 30 days' is printed again: %q", out)
	}
	if strings.Contains(out, "also deleted") {
		t.Fatalf("old misleading 'also deleted' wording still present: %q", out)
	}
}

// An older server sends no date. The CLI must say so, never invent one.
func TestSecretDelete_ServerWithoutPurgeDate_DoesNotGuess(t *testing.T) {
	var deletes int
	deleteServer(t, `[]`, &deletes)
	setDeletePurgeAt(t, "")
	resetDeleteFlags(t)
	secretDeleteForce = true

	out := captureStdout(t, func() {
		if err := runSecretDelete(secretDeleteCmd, nil); err != nil {
			t.Fatalf("runSecretDelete: %v", err)
		}
	})
	if !containsAll(out, "did not report the date") || strings.Contains(out, "30 days") {
		t.Fatalf("expected an honest 'not reported' line and no guessed window: %q", out)
	}
}

func TestSecretDelete_GarbagePurgeHeaderIsIgnored(t *testing.T) {
	var deletes int
	deleteServer(t, `[]`, &deletes)
	setDeletePurgeAt(t, "tomorrow-ish")
	resetDeleteFlags(t)
	secretDeleteForce = true

	out := captureStdout(t, func() {
		if err := runSecretDelete(secretDeleteCmd, nil); err != nil {
			t.Fatalf("runSecretDelete: %v", err)
		}
	})
	if strings.Contains(out, "tomorrow-ish") {
		t.Fatalf("an unparseable server value was echoed to the terminal: %q", out)
	}
}

func TestSecretDelete_DependentsRequireForce(t *testing.T) {
	var deletes int
	deleteServer(t, twoDependents, &deletes)
	resetDeleteFlags(t)

	var err error
	out := captureStdout(t, func() { err = runSecretDelete(secretDeleteCmd, nil) })
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v, want a refusal naming --force", err)
	}
	if deletes != 0 {
		t.Fatalf("DELETE was sent despite dependents and no --force")
	}
	if !containsAll(out, "2 dependent secret(s)", "app-conn (ID: 8)", "worker-conn (ID: 9)") {
		t.Fatalf("dependents not listed: %q", out)
	}
}

func TestSecretDelete_ForceDeletesDespiteDependents(t *testing.T) {
	var deletes int
	deleteServer(t, twoDependents, &deletes)
	resetDeleteFlags(t)
	secretDeleteForce = true

	out := captureStdout(t, func() {
		if err := runSecretDelete(secretDeleteCmd, nil); err != nil {
			t.Fatalf("runSecretDelete: %v", err)
		}
	})
	if deletes != 1 {
		t.Fatalf("DELETE calls = %d, want 1", deletes)
	}
	if !containsAll(out, "WARNING: 2 secret(s) depend on this one", "app-conn (ID: 8)") {
		t.Fatalf("forced delete did not warn about dependents: %q", out)
	}
}

func TestSecretDelete_InteractivePromptShowsRestoreWording(t *testing.T) {
	var deletes int
	deleteServer(t, `[]`, &deletes)
	resetDeleteFlags(t)

	r, w, _ := os.Pipe()
	_, _ = w.WriteString("db-pass\nno\n")
	_ = w.Close()
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	out := captureStdout(t, func() {
		if err := runSecretDelete(secretDeleteCmd, nil); err != nil {
			t.Fatalf("runSecretDelete: %v", err)
		}
	})
	if deletes != 0 {
		t.Fatalf("DELETE sent after answering 'no'")
	}
	if !containsAll(out, "keyorix secret restore --id 5", "retention", "Deletion cancelled") {
		t.Fatalf("prompt text missing restore wording: %q", out)
	}
}

func TestSecretDelete_JSONSuccessIsMachineReadable(t *testing.T) {
	var deletes int
	deleteServer(t, twoDependents, &deletes)
	resetDeleteFlags(t)
	secretDeleteForce, secretDeleteFormat = true, "json"

	out := captureStdout(t, func() {
		if err := runSecretDelete(secretDeleteCmd, nil); err != nil {
			t.Fatalf("runSecretDelete: %v", err)
		}
	})
	var got secretDeleteResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%q", err, out)
	}
	if !got.Deleted || !got.SoftDeleted || got.ID != 5 || got.Name != "db-pass" || got.Versions != 2 ||
		got.RestoreCommand != "keyorix secret restore --id 5" || len(got.Dependents) != 2 ||
		got.PurgeAt != "2026-11-09T12:00:00Z" {
		t.Fatalf("unexpected JSON result: %+v", got)
	}
}

func TestSecretDelete_JSONWithoutForceIsRefusedBeforeAnyRequest(t *testing.T) {
	var deletes int
	deleteServer(t, twoDependents, &deletes)
	resetDeleteFlags(t)
	secretDeleteFormat = "json"

	// json without --force is refused up front (no interactive prompt possible).
	if err := runSecretDelete(secretDeleteCmd, nil); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v, want --force required with --format json", err)
	}
	if deletes != 0 {
		t.Fatalf("DELETE sent without --force")
	}
}

func TestSecretDelete_RejectsUnknownFormat(t *testing.T) {
	var deletes int
	deleteServer(t, `[]`, &deletes)
	resetDeleteFlags(t)
	secretDeleteFormat = "yaml"
	if err := runSecretDelete(secretDeleteCmd, nil); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("err = %v, want unsupported format", err)
	}
}
