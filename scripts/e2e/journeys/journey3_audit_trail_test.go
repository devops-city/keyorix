//go:build e2e

package journeys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// waitForAuditEventsToSettle polls GET /api/v1/audit/search's total count
// until it stops growing for two consecutive polls, or a 5s deadline passes
// (whichever first) -- see the doc comment at this function's call site for
// why this is needed (async secret.read logging).
func waitForAuditEventsToSettle(t *testing.T, s *harness.Server, adminToken string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last := -1
	stableStreak := 0
	for time.Now().Before(deadline) {
		env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/audit/search?limit=1", nil, http.StatusOK)
		var data struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode audit search total: %v\nraw: %s", err, env.Data)
		}
		if data.Total == last {
			stableStreak++
			if stableStreak >= 2 {
				return
			}
		} else {
			stableStreak = 0
		}
		last = data.Total
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("audit event count never stabilized within 5s (last observed total: %d)", last)
}

// n3ExactEventCounts is every LOW-CARDINALITY, one-shot audit event type N1
// (appGetsSecret) + N2 (accessControl) together are expected to produce
// exactly this many of, against a completely fresh install (no other writes
// happen before this journey runs). Derived empirically (a discovery pass
// dumped the real histogram, then each count was hand-traced back to the
// exact N1/N2 call that produces it) rather than guessed, per this journey's
// own "assert the outcome" mandate. secret.read and auth.login are
// deliberately excluded here -- both are high-frequency, incidentally
// triggered by nearly every helper call in N1/N2 (including admin
// verification readbacks that aren't part of either journey's own
// narrative), so pinning one aggregate magic number for them would be
// fragile to unrelated changes elsewhere in N1/N2; both get their own
// narrower, still-exact assertions below instead (viewer's own read count,
// and total login count matching the exact number of adminLogin calls this
// test file's own call graph makes).
// #2394 (journey1 switched to keyorix-sdks/go v0.3.0) added SDK-only checks
// to N1 that this journey also runs: a second project + machine identity for
// the cross-project denial check (one extra project.created,
// machine_identity.created/role_granted/token_issued each), and 24 extra
// secrets that push one scope past the server's page_size=20 default for the
// ListSecretsScoped pagination check (secret.created 4 -> 28).
var n3ExactEventCounts = map[string]int{
	"secret.created":                 28,
	"secret.updated":                 1,
	"secret.rolled_back":             1,
	"machine_identity.created":       2,
	"machine_identity.role_granted":  2,
	"machine_identity.token_issued":  2,
	"machine_identity.token_revoked": 1,
	"role.assigned":                  3,
	"role.removed":                   1,
	"access_request.created":         1,
	"access_request.approved":        1,
	// project.created/user.created: 4 each, not 3 -- the 4th of each is
	// BootstrapSystem's OWN bootstrap-admin user + "default" project
	// (internal/core/auth_bootstrap.go's own doc comment: "default project
	// ('default')"), not an N1/N2 action. See n3StaleKnownGapNote below for
	// why these are asserted PRESENT here at all -- this was NOT true when
	// N3 was first written.
	"project.created": 5,
	"user.created":    4,
}

// project.created/user.created are asserted PRESENT (n3ExactEventCounts,
// above) even though server/faultops/audit_completeness_fuzz_test.go's
// knownUnauditedOperations still lists "REST POST /api/v1/projects" and
// "REST POST /api/v1/users/" as known gaps -- both are genuinely audited on
// current main (confirmed live via this journey's own histogram, not
// assumed). Not a new bug (behavior is correct) and not fixed here
// (server/faultops/*_test.go is outside this session's OWNS) -- filed as
// https://github.com/keyorixhq/keyorix/issues/2345 for whichever session
// owns that registry to remove the two now-stale entries.

func TestJourney_AuditTrail(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	// Backstop, not the primary teardown -- this function calls s.Close()
	// itself partway through (before the offline-verifier section, since
	// verify-audit needs the server stopped), but an earlier t.Fatal (in
	// appGetsSecret, accessControl, or any subtest above that point) would
	// otherwise skip straight past that explicit call and leak the server
	// process. s.Close() is safe to call twice -- the second call's
	// Kill()/Wait() on an already-reaped process just returns an ignored
	// error.
	t.Cleanup(s.Close)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)

	appGetsSecretAs(t, s, cliBin, adminToken)
	accessControl(t, s, cliBin, adminToken)

	// secret.read (and only secret.read -- every other event type this journey
	// asserts on is written synchronously, in the request's own goroutine,
	// before the handler responds) is logged via a DETACHED, fire-and-forget
	// goroutine (server/http/handlers/secrets_crud.go's `goSafe(func() {
	// ...LogSecretReadWithProject... })`, core.DetachedAuditContext) -- so a
	// read event can genuinely not exist yet the instant its triggering
	// request returns. Wait for the total event count to stop growing before
	// taking the histogram this journey's assertions depend on, rather than
	// assume synchronous consistency.
	waitForAuditEventsToSettle(t, s, adminToken)

	hist := auditEventTypeHistogram(t, s, adminToken)

	t.Run("histogram accounts for every event -- no silent truncation by server-side paging", func(t *testing.T) {
		// auditEventTypeHistogram itself paginates to exhaustion (loops until
		// a page comes back short), but this cross-checks its sum against the
		// server's own reported total (the same "total" field
		// waitForAuditEventsToSettle already polls) -- catches a paging bug
		// (off-by-one page-size boundary, a server-side cap this journey
		// isn't aware of) that a self-consistent-but-wrong histogram would
		// otherwise hide.
		env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/audit/search?limit=1", nil, http.StatusOK)
		var data struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode audit search total: %v\nraw: %s", err, env.Data)
		}
		var sum int
		for _, n := range hist {
			sum += n
		}
		if sum != data.Total {
			t.Fatalf("histogram sums to %d events, server reports total=%d -- histogram is missing or double-counting events", sum, data.Total)
		}
	})

	t.Run("every expected event type present, exact count, no duplicates", func(t *testing.T) {
		for evtType, want := range n3ExactEventCounts {
			if got := hist[evtType]; got != want {
				t.Errorf("event type %q: want exactly %d, got %d", evtType, want, got)
			}
		}
	})

	t.Run("viewer's reads are logged exactly 2 times and the delete preview's version listing once, attributed correctly", func(t *testing.T) {
		// N2's viewer subtest makes two direct value reads (REST + CLI `secret
		// get --ref`): exactly 2 secret.read. It ALSO attempts a denied `secret
		// delete`, and cli/cmd/secret_crud.go's runSecretDelete fetches the
		// secret's version list (to preview "Versions: N") BEFORE the delete
		// call itself, which is denied separately. That listing exposes no value,
		// so since AUDIT-UX-2 (#2951) GetSecretVersions audits it as
		// secret.versions_listed, not secret.read: exactly 1 of those. (Until
		// then this asserted 3 secret.read, the listing counted as a read.)
		//
		// Polls rather than trusting the single waitForAuditEventsToSettle
		// call above at face value -- that call settles the AGGREGATE total,
		// which stabilizing doesn't strictly guarantee this actor-filtered
		// count has ALSO reached its final value in the same instant (a
		// defensive poll here is cheap and removes the dependency on that
		// timing coincidence).
		for action, want := range map[string]int{"secret.read": 2, "secret.versions_listed": 1} {
			deadline := time.Now().Add(5 * time.Second)
			for {
				env := restExpect(t, s, adminToken, http.MethodGet,
					"/api/v1/audit/search?action="+action+"&actor="+n2ViewerU, nil, http.StatusOK)
				var data struct {
					Total int `json:"total"`
				}
				if err := json.Unmarshal(env.Data, &data); err != nil {
					t.Fatalf("decode audit search for viewer's %s: %v\nraw: %s", action, err, env.Data)
				}
				if data.Total == want {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("viewer's %s events: want exactly %d, got %d after 5s poll", action, want, data.Total)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	})

	t.Run("secret.read is present overall (not asserting an exact aggregate -- see n3ExactEventCounts doc comment)", func(t *testing.T) {
		if hist["secret.read"] == 0 {
			t.Fatal("expected at least one secret.read event across N1+N2, found none")
		}
	})

	// ── Offline verifier: stop the server, verify the clean chain, then
	// tamper two SEPARATE copies (a modified row, a deleted row) and confirm
	// the verifier catches both. verify-audit's exit code is part of its
	// documented contract (0 for VALID, non-zero for BROKEN -- operators
	// script on it), so every call below asserts BOTH the exit status and
	// the JSON verdict, not just the JSON. Requires sqlite3 on the runner's
	// PATH (tamperAuditRow/deleteAuditRow shell out to it) -- already fails
	// loudly (t.Fatalf) if missing, since exec.Command's own error surfaces
	// through cmd.CombinedOutput()'s non-nil err. ──

	rolledBackID := auditEventID(t, s, adminToken, "secret.rolled_back")
	tokenRevokedID := auditEventID(t, s, adminToken, "machine_identity.token_revoked")

	s.Close()

	dbPath := filepath.Join(s.Dir, "keyorix.db")
	// s.Close() kills the server (no graceful shutdown), and SQLite runs in
	// WAL mode (internal/storage/factory.go's sqliteDSN) -- a recently
	// written row can still be sitting only in keyorix.db-wal, never
	// checkpointed into keyorix.db itself. copyFile below copies only
	// keyorix.db, so without this, a row that exists only in the WAL
	// wouldn't exist in the tampered copy at all: the UPDATE/DELETE below
	// would silently affect zero rows, and verify-audit would report VALID
	// on a copy that's missing the exact row this test tampers with (#2459
	// item 4). Force everything into keyorix.db first so a single-file copy
	// is always complete.
	checkpointWAL(t, dbPath)
	verdict, verifyErr := runVerifyAudit(t, s, dbPath)
	if verifyErr != nil {
		t.Fatalf("verify-audit on the untampered chain: want exit 0, got error: %v", verifyErr)
	}
	if verdict.Verdict != "VALID" {
		t.Fatalf("verify-audit on the untampered chain: want VALID, got %+v", verdict)
	}

	// Case 1: a row's non-hash field is modified in place -- hash-chain
	// recomputation mismatch.
	modifiedPath := filepath.Join(s.Dir, "keyorix-tampered-modified.db")
	copyFile(t, dbPath, modifiedPath)
	tamperAuditRow(t, modifiedPath, rolledBackID)

	modifiedVerdict, modifiedErr := runVerifyAudit(t, s, modifiedPath)
	if modifiedErr == nil {
		t.Fatal("verify-audit on a modified-row copy: want non-zero exit for BROKEN, got exit 0")
	}
	if modifiedVerdict.Verdict != "BROKEN" {
		t.Fatalf("verify-audit on a modified-row copy: want BROKEN, got %+v", modifiedVerdict)
	}
	if modifiedVerdict.FirstBrokenID == nil || *modifiedVerdict.FirstBrokenID != uint64(rolledBackID) {
		t.Fatalf("verify-audit on a modified-row copy: want first_broken_id=%d, got %+v", rolledBackID, modifiedVerdict.FirstBrokenID)
	}

	// Case 2: a MIDDLE row (not the tail -- deleting the tail alone doesn't
	// break linkage, since a shorter self-consistent chain still verifies,
	// per verify-audit's own "what this run does NOT prove" output) is
	// deleted outright -- breaks the NEXT row's prev-hash linkage to it,
	// a different corruption shape than an in-place field edit.
	deletedPath := filepath.Join(s.Dir, "keyorix-tampered-deleted.db")
	copyFile(t, dbPath, deletedPath)
	deleteAuditRow(t, deletedPath, tokenRevokedID)

	deletedVerdict, deletedErr := runVerifyAudit(t, s, deletedPath)
	if deletedErr == nil {
		t.Fatal("verify-audit on a deleted-row copy: want non-zero exit for BROKEN, got exit 0")
	}
	if deletedVerdict.Verdict != "BROKEN" {
		t.Fatalf("verify-audit on a deleted-row copy: want BROKEN, got %+v", deletedVerdict)
	}
}

// auditEventTypeHistogram fetches every audit event (paginated) via GET
// /api/v1/audit/search and counts occurrences by event_type.
func auditEventTypeHistogram(t *testing.T, s *harness.Server, adminToken string) map[string]int {
	t.Helper()
	hist := map[string]int{}
	const pageSize = 200
	for offset := 0; ; offset += pageSize {
		path := fmt.Sprintf("/api/v1/audit/search?limit=%d&offset=%d", pageSize, offset)
		env := restExpect(t, s, adminToken, http.MethodGet, path, nil, http.StatusOK)
		var data struct {
			Events []struct {
				EventType string `json:"event_type"`
			} `json:"events"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode GET %s: %v\nraw: %s", path, err, env.Data)
		}
		for _, e := range data.Events {
			hist[e.EventType]++
		}
		if len(data.Events) < pageSize {
			break
		}
	}
	return hist
}

// auditEventID returns the ID of the single event of evtType this journey
// produces (fails the test if there isn't exactly one -- callers only use
// this for event types n3ExactEventCounts pins at 1).
func auditEventID(t *testing.T, s *harness.Server, adminToken, evtType string) int {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/audit/search?action="+evtType, nil, http.StatusOK)
	var data struct {
		Events []struct {
			ID int `json:"id"`
		} `json:"events"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode audit search for %q: %v\nraw: %s", evtType, err, env.Data)
	}
	if len(data.Events) != 1 {
		t.Fatalf("expected exactly 1 event of type %q, found %d", evtType, len(data.Events))
	}
	return data.Events[0].ID
}

// verifyAuditVerdict mirrors internal/auditverify.Result's wire shape --
// only the two fields this journey needs.
type verifyAuditVerdict struct {
	Verdict       string  `json:"verdict"`
	FirstBrokenID *uint64 `json:"first_broken_id,omitempty"`
}

// runVerifyAudit runs `keyorix-server admin verify-audit --json --db dbPath`
// (the server must already be stopped -- this opens the file directly, same
// as scripts/e2e's own verifyAuditChain, but against an arbitrary path so
// this journey can point it at a tampered COPY too). Returns cmd.Run()'s own
// error too -- verify-audit's exit code (0 for VALID, non-zero for BROKEN)
// is part of its documented CLI contract (operators script on it), so a
// caller that only checked the JSON verdict field would miss a regression
// that kept reporting the right verdict string but stopped setting a
// non-zero exit status.
func runVerifyAudit(t *testing.T, s *harness.Server, dbPath string) (verifyAuditVerdict, error) {
	t.Helper()
	cmd := exec.Command(s.Binary, "admin", "verify-audit", "--json", "--db", dbPath) // #nosec G204 -- s.Binary/dbPath are this test's own built binary and its own tempdir-derived paths, never attacker input nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e journey itself built, with the journey's own fixed arguments
	cmd.Env = s.Env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run() // non-zero exit is EXPECTED for a BROKEN verdict -- returned, not discarded, so callers can assert it; the JSON body (stdout only -- a non-VALID verdict also prints a plain-text "Error: ..." line to stderr, which must not be mixed into the JSON) is what determines the verdict struct
	var v verifyAuditVerdict
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil {
		t.Fatalf("decode verify-audit --json output: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return v, runErr
}

// checkpointWAL forces any content sitting in dbPath's -wal sidecar into
// dbPath itself (PRAGMA wal_checkpoint(TRUNCATE) also empties the -wal file
// afterward) -- see this function's call site for why that matters here.
func checkpointWAL(t *testing.T, dbPath string) {
	t.Helper()
	cmd := exec.Command("sqlite3", dbPath, "PRAGMA wal_checkpoint(TRUNCATE);") // #nosec G204 -- dbPath is this test's own tempdir-derived path, never attacker input
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 wal_checkpoint failed: %v\n%s", err, out)
	}
}

// copyFile copies a SQLite database file AND its -wal/-shm companions. The
// server is stopped with Kill (no clean shutdown), so the most recent
// committed rows can still live only in the -wal file; copying the main file
// alone silently drops them, and a tamper aimed at one of those rows then
// edits nothing, so the verifier correctly reports VALID and the journey's
// tamper assertion fails for the wrong reason (seen after #2394 grew N1's
// write volume).
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(src + suffix) // #nosec G304 -- src is this test's own harness-managed DB path
		if err != nil {
			if suffix != "" && os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", src+suffix, err)
		}
		if err := os.WriteFile(dst+suffix, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", dst+suffix, err)
		}
	}
}

// tamperAuditRow modifies one non-hash field of the given audit_events row
// directly via the sqlite3 CLI -- the same shape of mutation
// internal/auditverify/differential_test.go's own tamper matrix uses
// ("UPDATE audit_events SET description = 'tampered' WHERE id = ?"), so this
// journey's tamper-detection assertion is testing genuine hash-recomputation
// mismatch detection, not a hash-column edit the verifier would trivially
// catch a different way.
func tamperAuditRow(t *testing.T, dbPath string, id int) {
	t.Helper()
	stmt := fmt.Sprintf("UPDATE audit_events SET description = 'tampered-by-N3-journey' WHERE id = %d;", id)
	cmd := exec.Command("sqlite3", dbPath, stmt) // #nosec G204 -- dbPath is this test's own tempdir-derived copy, id is an int from this test's own prior query, never attacker input
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 tamper UPDATE failed: %v\n%s", err, out)
	}
}

// deleteAuditRow removes one audit_events row outright via the sqlite3 CLI
// -- a different corruption shape than tamperAuditRow's in-place edit: this
// breaks the NEXT row's prev-hash linkage to the now-missing row, rather
// than a hash-recomputation mismatch on the row itself. Requires sqlite3 on
// the runner's PATH, same as tamperAuditRow -- exec.Command's own error
// (binary not found) surfaces through CombinedOutput()'s non-nil err below,
// so a missing sqlite3 fails this test loudly rather than silently.
func deleteAuditRow(t *testing.T, dbPath string, id int) {
	t.Helper()
	stmt := fmt.Sprintf("DELETE FROM audit_events WHERE id = %d;", id)
	cmd := exec.Command("sqlite3", dbPath, stmt) // #nosec G204 -- dbPath is this test's own tempdir-derived copy, id is an int from this test's own prior query, never attacker input
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 tamper DELETE failed: %v\n%s", err, out)
	}
}
