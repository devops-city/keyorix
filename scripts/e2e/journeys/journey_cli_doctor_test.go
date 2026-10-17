//go:build e2e

package journeys

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_CLIDoctor runs `keyorix doctor` (CLI-UX-1 item 3) against a real server:
// a healthy setup passes every check it can run, and each way a setup goes wrong -- an
// expired session, a server that is down -- is a FAIL line with the next step and a
// non-zero exit.
func TestJourney_CLIDoctor(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	t.Run("a healthy setup passes", func(t *testing.T) {
		out := runCLI(t, cliBin, aEnv, "doctor")
		for _, w := range []string{"PASS  config", "PASS  reachable", "PASS  version", "PASS  clock", "PASS  auth", "smoketestadmin"} {
			if !strings.Contains(out, w) {
				t.Errorf("output lacks %q:\n%s", w, out)
			}
		}
		// The harness serves plain http on loopback: nothing to inspect, not a warning.
		if !strings.Contains(out, "SKIP  tls") {
			t.Errorf("tls on a loopback http server should be skipped:\n%s", out)
		}
		// The audit chain of a young server is valid, or not yet proven; never broken.
		if strings.Contains(out, "FAIL") {
			t.Errorf("a healthy setup must not fail anything:\n%s", out)
		}
		if !strings.Contains(out, "PASS  audit") && !strings.Contains(out, "WARN  audit") {
			t.Errorf("audit check missing:\n%s", out)
		}
	})

	t.Run("-o json is machine readable", func(t *testing.T) {
		out := runCLI(t, cliBin, aEnv, "doctor", "-o", "json")
		var rep struct {
			OK     bool `json:"ok"`
			Checks []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"checks"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if !rep.OK || len(rep.Checks) != 7 {
			t.Fatalf("want 7 checks and ok, got %+v", rep)
		}
	})

	t.Run("a rejected session fails auth with the fix", func(t *testing.T) {
		env := append(append([]string{}, s.CLIEnv()...), "KEYORIX_SERVER="+s.BaseURL, "KEYORIX_TOKEN=expired-token")
		out, err := runCLIRaw(cliBin, env, "doctor")
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("doctor must exit non-zero when a check fails:\n%s", out)
		}
		for _, w := range []string{"FAIL  auth", "HTTP 401", "Next step: run `keyorix login`", "PASS  reachable", "SKIP  audit"} {
			if !strings.Contains(out, w) {
				t.Errorf("output lacks %q:\n%s", w, out)
			}
		}
	})

	t.Run("a server that is down fails reachable and skips the rest", func(t *testing.T) {
		env := append(append([]string{}, s.CLIEnv()...), "KEYORIX_SERVER=http://127.0.0.1:1", "KEYORIX_TOKEN=x")
		out, err := runCLIRaw(cliBin, env, "doctor")
		if err == nil {
			t.Fatalf("doctor must exit non-zero:\n%s", out)
		}
		for _, w := range []string{"FAIL  reachable", "server is running", "SKIP  version", "SKIP  auth"} {
			if !strings.Contains(out, w) {
				t.Errorf("output lacks %q:\n%s", w, out)
			}
		}
	})

	t.Run("not logged in says so", func(t *testing.T) {
		out, err := runCLIRaw(cliBin, s.CLIEnv(), "doctor")
		if err == nil {
			t.Fatalf("doctor must exit non-zero:\n%s", out)
		}
		if !strings.Contains(out, "FAIL  config") || !strings.Contains(out, "keyorix login") {
			t.Errorf("want a config failure that names `keyorix login`:\n%s", out)
		}
	})
}
