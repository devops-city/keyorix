package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ERRMAP-1: when a secret's own state refuses a value read the server answers
// 403 (schedule) or 409 (expired, suspended, max reads) with a stable code. The
// CLI must print the server's reason and the command that lifts it, never a
// bare status or "could not fetch value".

type readRefusal struct {
	status        int
	code, message string
	hint          []string // what the next-step hint must name
}

var readRefusals = []readRefusal{
	{403, "SecretAccessOutsideSchedule", "secret access is not permitted outside the configured time window",
		[]string{"`keyorix secret get-schedule <secret-id>`"}},
	{409, "SecretExpired", "secret has expired; its value can no longer be read",
		[]string{"`keyorix secret update --id <secret-id> --expires <RFC3339>`", "`--clear-expiration`"}},
	{409, "SecretSuspended", "secret is suspended; its value cannot be read until it is resumed",
		[]string{"`keyorix secret resume --id <secret-id>`"}},
	{409, "SecretMaxReadsExhausted", "secret has reached its maximum number of reads",
		[]string{"`keyorix secret update --id <secret-id> --max-reads <n>`"}},
}

func refusingServer(t *testing.T, rf readRefusal) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rf.status)
		_, _ = fmt.Fprintf(w, `{"success":false,"code":%d,"error":%q,"message":%q}`, rf.status, rf.code, rf.message)
	}))
	t.Cleanup(srv.Close)
	setBGCreds(t, srv)
	return srv
}

func TestSecretGet_ValueReadRefusalShowsReasonAndNextStep(t *testing.T) {
	for _, rf := range readRefusals {
		for name, set := range map[string]func(){
			"--id --show-value": func() { secretGetID, secretGetShowValue = 7, true },
			"--ref":             func() { secretGetRef = "proj/prod/db-password" },
		} {
			t.Run(rf.code+"/"+name, func(t *testing.T) {
				refusingServer(t, rf)
				oldID, oldShow, oldRef, oldName := secretGetID, secretGetShowValue, secretGetRef, secretGetName
				t.Cleanup(func() { secretGetID, secretGetShowValue, secretGetRef, secretGetName = oldID, oldShow, oldRef, oldName })
				secretGetID, secretGetShowValue, secretGetRef, secretGetName = 0, false, "", ""
				set()

				var err error
				out := captureStdout(t, func() { err = runSecretGet(secretGetCmd, nil) })
				if err == nil {
					t.Fatalf("want an error, got output %q", out)
				}
				want := append([]string{rf.message, fmt.Sprintf("(HTTP %d)", rf.status), "Next step:"}, rf.hint...)
				for _, w := range want {
					if !strings.Contains(err.Error(), w) {
						t.Fatalf("error %q does not contain %q", err, w)
					}
				}
			})
		}
	}
}

// keyorix secret export skips a refused secret; the warning must carry the reason.
func TestSecretExport_SkipWarningCarriesRefusalReason(t *testing.T) {
	for _, rf := range readRefusals {
		t.Run(rf.code, func(t *testing.T) {
			refusingServer(t, rf)
			client, err := secretAPIClient()
			if err != nil {
				t.Fatal(err)
			}
			var got []exportedSecret
			stderr := captureStderr(t, func() {
				got, err = fetchSecretValuesForExport(context.Background(), client, []struct {
					ID   int
					Name string
				}{{ID: 7, Name: "db-password"}})
			})
			if err != nil || len(got) != 0 {
				t.Fatalf("want the secret skipped without failing the export, got %v, %v", got, err)
			}
			for _, w := range []string{`skipping "db-password"`, rf.message, fmt.Sprintf("(HTTP %d)", rf.status)} {
				if !strings.Contains(stderr, w) {
					t.Fatalf("warning %q does not contain %q", stderr, w)
				}
			}
		})
	}
}

// Every command and flag a refusal hint names exists.
func TestValueReadRefusalHints_NameRealCommandsAndFlags(t *testing.T) {
	for _, c := range []struct {
		path  []string
		flags []string
	}{
		{[]string{"secret", "get-schedule"}, nil},
		{[]string{"secret", "update"}, []string{"id", "expires", "clear-expiration", "max-reads"}},
		{[]string{"secret", "resume"}, []string{"id"}},
	} {
		cmd, _, err := rootCmd.Find(c.path)
		if err != nil || cmd == nil || cmd.Name() != c.path[len(c.path)-1] {
			t.Fatalf("a hint names `keyorix %s`, which is not registered: %v", strings.Join(c.path, " "), err)
		}
		for _, f := range c.flags {
			if cmd.Flags().Lookup(f) == nil {
				t.Fatalf("a hint names `keyorix %s --%s`, which has no such flag", strings.Join(c.path, " "), f)
			}
		}
	}
}
