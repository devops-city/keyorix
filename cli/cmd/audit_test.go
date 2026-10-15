package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setAuditCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// TestRunAuditVerify_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 7's own test requirement) against
// internal/cli/audit/audit.go's verifyCmd.
func TestRunAuditVerify_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/verify" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"valid":true,"chained_events":42,"unchained_events":0,"head_id":42,"head_hash":"abc123","checkpointed":true}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditVerifyJSON = false

	out := captureStdout(t, func() {
		if err := runAuditVerify(auditVerifyCmd, nil); err != nil {
			t.Fatalf("runAuditVerify: %v", err)
		}
	})
	if !containsAll(out, "Audit chain: VALID", "chained events:   42", "head id:          42", "head hash:        abc123",
		"checked against a signed in-DB checkpoint") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

func TestRunAuditVerify_BrokenChainReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"valid":false,"first_broken_id":7,"reason":"hash mismatch"}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditVerifyJSON = false

	err := runAuditVerify(auditVerifyCmd, nil)
	if err == nil || !containsAll(err.Error(), "FAILED", "hash mismatch") {
		t.Fatalf("err = %v, want a broken-chain error", err)
	}
}

// Incremental verification (docs/specs/audit-incremental-verification.md): a
// not_proven status prints NOT PROVEN with the reason and exits non-zero, and
// is not reported as a broken chain.
func TestRunAuditVerify_NotProvenIsNeitherValidNorBroken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"valid":false,"status":"not_proven","mode":"incremental","not_proven_reason":"no full verification has completed yet","chained_events":9,"head_id":9,"head_hash":"h","checkpointed":true,"coverage":{"checkpoint_id":2,"tail_from_id":5,"tail_through_id":9,"tail_complete":true},"last_full_verification_at":null}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditVerifyJSON, auditVerifyFull = false, false

	var err error
	out := captureStdout(t, func() { err = runAuditVerify(auditVerifyCmd, nil) })
	if !containsAll(out, "Audit chain: NOT PROVEN", "rows 6..9 after signed checkpoint #2", "full re-walk:     none completed yet", "no full verification has completed yet") {
		t.Fatalf("output missing expected fields: %q", out)
	}
	if err == nil || !containsAll(err.Error(), "NOT PROVEN") || containsAll(err.Error(), "FAILED") {
		t.Fatalf("err = %v, want a not-proven (not a broken-chain) error", err)
	}
}

// --full starts the server-side job (?full=true → 202) and polls its status
// until it finishes, then reports the job's result.
func TestRunAuditVerify_FullPollsTheJob(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/audit/verify" && r.URL.Query().Get("full") == "true":
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprint(w, `{"data":{"job_id":"j1","state":"running","status_url":"/api/v1/audit/verify/jobs/j1"}}`)
		case r.URL.Path == "/api/v1/audit/verify/jobs/j1":
			polls++
			if polls < 2 {
				_, _ = fmt.Fprint(w, `{"data":{"job_id":"j1","state":"running"}}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"data":{"job_id":"j1","state":"succeeded","result":{"valid":true,"status":"valid","mode":"full","chained_events":42,"head_id":42,"head_hash":"abc","checkpointed":true}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditVerifyJSON, auditVerifyFull, auditVerifyTimeout, auditVerifyPollInterval = false, true, time.Minute, time.Millisecond
	defer func() { auditVerifyFull = false }()

	out := captureStdout(t, func() {
		if err := runAuditVerify(auditVerifyCmd, nil); err != nil {
			t.Fatalf("runAuditVerify --full: %v", err)
		}
	})
	if polls < 2 || !containsAll(out, "Audit chain: VALID", "chained events:   42") {
		t.Fatalf("polls=%d output=%q", polls, out)
	}
}

// TestRunAuditLogs_MatchesOldCLIOutputShape matches internal/cli/audit/audit.go's
// printAuditLogTable.
func TestRunAuditLogs_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/logs" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"logs":[{"id":1,"event_type":"secret.read","actor":"alice","actor_type":"user","description":"read db-pass","timestamp":"2026-01-01T00:00:00Z"}],"total":1}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditLogLimit = 50
	auditLogEventType, auditLogUserID, auditLogProjectID, auditLogActorType, auditLogSince, auditLogUntil = "", 0, 0, "", "", ""

	out := captureStdout(t, func() {
		if err := runAuditLogs(auditLogsCmd, nil); err != nil {
			t.Fatalf("runAuditLogs: %v", err)
		}
	})
	if !containsAll(out, "ID", "TIME", "ACTOR", "secret.read", "alice", "read db-pass", "Showing 1 of 1 total event(s).") {
		t.Fatalf("output missing expected fields: %q", out)
	}
}

// TestRunAuditCheckpoint_MatchesOldCLIOutputShape matches audit.go's checkpointCmd.
func TestRunAuditCheckpoint_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/checkpoint" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"id":1,"chained_events":42,"head_id":42,"head_hash":"abc123"}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runAuditCheckpoint(auditCheckpointCmd, nil); err != nil {
			t.Fatalf("runAuditCheckpoint: %v", err)
		}
	})
	if !containsAll(out, "Audit checkpoint written:", "id:             1", "chained events: 42") {
		t.Fatalf("output = %q", out)
	}
}

// TestRunAuditMigrateChain_DryRunDefault matches audit.go's migrateChainCmd default
// (preview-only) behavior.
func TestRunAuditMigrateChain_DryRunDefault(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/migrate-chain-encoding" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"dry_run":true,"rows_migrated":10,"unchained_rows_skipped":2,"head_id":42,"head_hash":"abc123"}}`)
	}))
	defer srv.Close()
	setAuditCreds(t, srv)
	auditMigrateConfirm = false

	out := captureStdout(t, func() {
		if err := runAuditMigrateChain(auditMigrateChainCmd, nil); err != nil {
			t.Fatalf("runAuditMigrateChain: %v", err)
		}
	})
	if !containsAll(out, "DRY RUN — nothing was written.", "rows migrated:          10") {
		t.Fatalf("output = %q", out)
	}
	if !containsAll(gotQuery, "dry_run=true") {
		t.Fatalf("query = %q, want dry_run=true", gotQuery)
	}
}
