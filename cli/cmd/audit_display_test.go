package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #2942: display glitches on the audit and break-glass screens.

// The server's /audit/search returns the same redacted rows as /audit/logs
// (timestamp, actor, actor_type; never event_time or ip_address). The CLI used to
// decode event_time/ip_address, so TIME and IP printed blank for every row.
func TestRunAuditSearch_RendersTimeAndActorFromTheServerShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/search" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"events":[{"id":34,"event_type":"secret.read","actor":"alice","actor_type":"user","description":"read db-pass","timestamp":"2026-10-10T01:56:04Z"}],"total":1}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditSearchLimit = 100
	auditSearchActor, auditSearchAction = "alice", "secret.read"
	defer func() { auditSearchActor, auditSearchAction = "", "" }()

	out := captureStdout(t, func() {
		if err := runAuditSearch(auditSearchCmd, nil); err != nil {
			t.Fatalf("runAuditSearch: %v", err)
		}
	})
	if !containsAll(out, "2026-10-10 01:56:04", "alice", "secret.read", "TIME (UTC)") {
		t.Fatalf("search row is missing its time/actor: %q", out)
	}
}

func TestPrintAuditLogTable_NeverCutsEventNamesMidWord(t *testing.T) {
	long := "secret.auto_rotate_completed"
	out := captureStdout(t, func() {
		printAuditLogTable([]logEntry{
			{ID: 1, EventType: long, Actor: "system", ActorType: "system", Timestamp: "2026-10-10T01:56:04Z"},
			{ID: 2, EventType: "secret.read", Actor: "alice", ActorType: "user", Timestamp: "2026-10-10T01:57:04Z"},
		}, auditPageFooter{})
	})
	if !strings.Contains(out, long) || strings.Contains(out, "…") {
		t.Fatalf("event name was truncated:\n%s", out)
	}
}

func TestRunBGList_ShowsFullRoleAndUTCExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"activations":[{"id":42,"user_id":7,"role_name":"project_developer","justification":"incident INC-1","state":"active","expires_at":"2026-10-10T02:57:06.232161Z","created_at":"2026-10-10T00:57:06Z"}],"count":1}}`)
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
	if !containsAll(out, "project_developer", "2026-10-10 02:57:06") || strings.Contains(out, "…") || strings.Contains(out, "232161") {
		t.Fatalf("role truncated or expiry not normalised:\n%s", out)
	}
}

// Every human-readable timestamp is UTC (the audit log's zone), whatever the
// machine's local zone is.
func TestUTCTimeIgnoresLocalZone(t *testing.T) {
	if got := shortTime("2026-10-10T03:53:40+02:00"); got != "2026-10-10 01:53:40" {
		t.Fatalf("shortTime = %q, want the UTC wall clock", got)
	}
	if got := shortTime("2026-10-10T02:57:06.232161Z"); got != "2026-10-10 02:57:06" {
		t.Fatalf("shortTime(fractional) = %q", got)
	}
}
