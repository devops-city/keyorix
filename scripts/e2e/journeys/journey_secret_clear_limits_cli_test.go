//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_SecretClearLimitsCLI drives, with the real CLI against a real
// server, the two "remove a limit" commands that used to fail:
//
//   - #3172: `secret update --max-reads 0` was documented "0 = unlimited" but the
//     server answers 400 (max_reads has minimum 1). The contract stays; the CLI
//     now refuses 0 with a pointer to `--clear-max-reads`, which removes the limit.
//   - #3173: `secret clear-schedule` removed the schedule on the server (200) but
//     the CLI treated anything but 204 as an error and exited 1.
func TestJourney_SecretClearLimitsCLI(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		proj  = "j-clear-limits"
		name  = "j-clear-limits-secret"
		value = "j-clear-limits-value"
	)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", proj)
	pid := projectID(t, s, adminToken, proj)
	eid := environmentID(t, s, adminToken, pid, "development")
	runCLISecret(t, cliBin, aEnv, value, "secret", "create", "--name", name,
		"--project", strconv.Itoa(pid), "--environment", strconv.Itoa(eid), "--max-reads", "1")
	id := secretID(t, s, adminToken, pid, eid, name)
	idArg := strconv.Itoa(id)

	storedMaxReads := func() *int {
		env := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", id), nil, http.StatusOK)
		var d struct {
			MaxReads *int `json:"max_reads"`
		}
		if err := json.Unmarshal(env.Data, &d); err != nil {
			t.Fatalf("decode secret: %v\n%s", err, env.Data)
		}
		return d.MaxReads
	}

	t.Run("max-reads 0 is refused with a pointer to --clear-max-reads", func(t *testing.T) {
		out := runCLIExpectErr(t, cliBin, aEnv, "secret", "update", "--id", idArg, "--max-reads", "0")
		if !strings.Contains(out, "--clear-max-reads") {
			t.Fatalf("want a pointer to --clear-max-reads, got:\n%s", out)
		}
		if m := storedMaxReads(); m == nil || *m != 1 {
			t.Fatalf("a refused update must leave the limit at 1, got %v", m)
		}
	})

	t.Run("both flags together are refused", func(t *testing.T) {
		runCLIExpectErr(t, cliBin, aEnv, "secret", "update", "--id", idArg, "--max-reads", "5", "--clear-max-reads")
		if m := storedMaxReads(); m == nil || *m != 1 {
			t.Fatalf("limit must stay 1, got %v", m)
		}
	})

	t.Run("--clear-max-reads removes the limit", func(t *testing.T) {
		runCLI(t, cliBin, aEnv, "secret", "update", "--id", idArg, "--clear-max-reads")
		if m := storedMaxReads(); m != nil {
			t.Fatalf("limit must be cleared, got %d", *m)
		}
		// With the limit of 1 gone, repeated value reads keep working.
		for i := 0; i < 3; i++ {
			out := runCLI(t, cliBin, aEnv, "secret", "get", "--id", idArg, "--show-value")
			if !strings.Contains(out, value) {
				t.Fatalf("read %d: want value, got:\n%s", i+1, out)
			}
		}
	})

	t.Run("clear-schedule succeeds and exits 0", func(t *testing.T) {
		runCLI(t, cliBin, aEnv, "secret", "set-schedule", idArg, "--days", "*")
		out := runCLI(t, cliBin, aEnv, "secret", "clear-schedule", idArg)
		if !strings.Contains(out, "Schedule cleared") {
			t.Fatalf("want 'Schedule cleared', got:\n%s", out)
		}
		// Idempotent: clearing again still succeeds.
		runCLI(t, cliBin, aEnv, "secret", "clear-schedule", idArg)
	})
}
