//go:build e2e

package journeys

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_SecretReadRefusals is ERRMAP-1 as an operator meets it: a secret
// whose own state refuses a value read (max reads spent, suspended, expired,
// outside its access schedule) makes `keyorix secret get --show-value` (human
// session) and `keyorix secret get --ref` (machine token) say why, with the
// HTTP status the API documents (409, or 403 for the schedule) and the command
// that lifts it; running that command makes the next read succeed. Before
// ERRMAP-1 every one of these printed "Failed to get secret value (HTTP 500)".
func TestJourney_SecretReadRefusals(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projName    = "j23-read-refusals"
		envName     = "development"
		machineName = "j23-reader"
	)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projName)
	projID := projectID(t, s, adminToken, projName)
	envID := environmentID(t, s, adminToken, projID, envName)

	runCLI(t, cliBin, aEnv, "machine", "create", "--project", projName, "--name", machineName, "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", machineName, "--project", projName, "--role", "project_viewer")
	issueOut := runCLI(t, cliBin, aEnv, "machine", "token", "issue", machineName, "--project", projName, "--name", "j23-token")
	machToken, _ := parseIssuedToken(t, issueOut)
	mEnv := machineEnv(s, machToken)

	n := 0
	newSecret := func(extra ...string) (id int, ref, value string) {
		n++
		name := "j23-secret-" + strconv.Itoa(n)
		value = "j23-value-" + strconv.Itoa(n) + "-do-not-leak"
		args := append([]string{"secret", "create", "--name", name,
			"--project", strconv.Itoa(projID), "--environment", strconv.Itoa(envID), "--value", value}, extra...)
		runCLI(t, cliBin, aEnv, args...)
		return secretID(t, s, adminToken, projID, envID, name), projName + "/" + envName + "/" + name, value
	}
	// readOK reads the value both ways and checks it.
	readOK := func(step string, id int, ref, value string) {
		t.Helper()
		if out := runCLI(t, cliBin, aEnv, "secret", "get", "--id", strconv.Itoa(id), "--show-value"); !strings.Contains(out, value) {
			t.Fatalf("%s: human read did not return the value:\n%s", step, out)
		}
		if out := runCLI(t, cliBin, mEnv, "secret", "get", "--ref", ref); !strings.Contains(out, value) {
			t.Fatalf("%s: machine read did not return the value:\n%s", step, out)
		}
	}
	// refused checks one refused read's output: reason, status, next step, no value.
	refused := func(step, out, value string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Fatalf("%s: output does not contain %q:\n%s", step, w, out)
			}
		}
		for _, bad := range []string{value, "HTTP 500", "Failed to get secret value"} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s: output contains %q:\n%s", step, bad, out)
			}
		}
	}
	refusedBothWays := func(step string, id int, ref, value string, want ...string) {
		t.Helper()
		refused(step+" (human)", runCLIExpectErr(t, cliBin, aEnv, "secret", "get", "--id", strconv.Itoa(id), "--show-value"), value, want...)
		refused(step+" (machine)", runCLIExpectErr(t, cliBin, mEnv, "secret", "get", "--ref", ref), value, want...)
	}

	// ── Max reads: the one permitted read, then a 409 naming the limit ───────
	id, ref, value := newSecret("--max-reads", "1")
	if out := runCLI(t, cliBin, aEnv, "secret", "get", "--id", strconv.Itoa(id), "--show-value"); !strings.Contains(out, value) {
		t.Fatalf("max reads: the first read must succeed:\n%s", out)
	}
	refusedBothWays("max reads exhausted", id, ref, value,
		"maximum number of reads", "(HTTP 409)", "keyorix secret update --id <secret-id> --max-reads")
	// max_reads counts every read since creation; 5 leaves room for the two reads below.
	runCLI(t, cliBin, aEnv, "secret", "update", "--id", strconv.Itoa(id), "--max-reads", "5")
	readOK("max reads lifted", id, ref, value)

	// ── Suspended ─────────────────────────────────────────────────────────────
	id, ref, value = newSecret()
	readOK("before suspend", id, ref, value)
	runCLI(t, cliBin, aEnv, "secret", "suspend", "--id", strconv.Itoa(id))
	refusedBothWays("suspended", id, ref, value, "is suspended", "(HTTP 409)", "keyorix secret resume --id <secret-id>")
	runCLI(t, cliBin, aEnv, "secret", "resume", "--id", strconv.Itoa(id))
	readOK("resumed", id, ref, value)

	// ── Expired ───────────────────────────────────────────────────────────────
	expires := time.Now().UTC().Add(3 * time.Second).Format(time.RFC3339)
	id, ref, value = newSecret("--expires", expires)
	time.Sleep(4 * time.Second)
	refusedBothWays("expired", id, ref, value, "has expired", "(HTTP 409)", "--clear-expiration")
	runCLI(t, cliBin, aEnv, "secret", "update", "--id", strconv.Itoa(id), "--clear-expiration")
	readOK("expiration cleared", id, ref, value)

	// ── Outside the access schedule: 403, not a permission problem ────────────
	id, ref, value = newSecret()
	runCLI(t, cliBin, aEnv, "secret", "set-schedule", strconv.Itoa(id), "--days", notTodayOrTomorrowUTC(),
		"--start-hour", "0", "--end-hour", "24", "--timezone", "UTC")
	refusedBothWays("outside schedule", id, ref, value,
		"outside the configured time window", "(HTTP 403)", "keyorix secret get-schedule")
	// Open the window (an update in place). Not clear-schedule: it reports the
	// server's 200 as a failure (it expects the 204 the spec documents), a separate bug.
	runCLI(t, cliBin, aEnv, "secret", "set-schedule", strconv.Itoa(id), "--days", "*",
		"--start-hour", "0", "--end-hour", "24", "--timezone", "UTC")
	readOK("schedule opened", id, ref, value)
}

// notTodayOrTomorrowUTC lists the ISO weekdays other than today and tomorrow (UTC),
// so a schedule built from it is closed for the whole run even across midnight.
func notTodayOrTomorrowUTC() string {
	iso := func(d time.Weekday) int {
		if d == time.Sunday {
			return 7
		}
		return int(d)
	}
	now := time.Now().UTC()
	skip := map[int]bool{iso(now.Weekday()): true, iso(now.Add(24 * time.Hour).Weekday()): true}
	var days []string
	for d := 1; d <= 7; d++ {
		if !skip[d] {
			days = append(days, strconv.Itoa(d))
		}
	}
	return strings.Join(days, ",")
}
