package http

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// TestCanaryOracle_SeesAccessLogLines guards the canary log-leak oracle's input:
// buildCanaryWorld builds the router BEFORE it calls log.SetOutput(world buffer),
// so the access-log middleware must follow the std logger at write time. When it
// snapshotted the destination at construction (the #3231 regression) every access
// line went to the old output and the "log" channel never saw one, so a secret
// reaching the access log would have been invisible to FuzzCanarySecretLeakage and
// the faultops canary fuzzer.
//
// The in-process half asserts the access line (carrying a planted canary in an
// unredacted query value) lands in the world's log buffer. The subprocess half
// proves the oracle then FAILS on it, as TestScanCanaryLeaks_* do (a subtest that
// is supposed to fail cannot live in an always-green test).
func TestCanaryOracle_SeesAccessLogLines(t *testing.T) {
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev); i18n.ResetForTesting() })

	w := buildCanaryWorld(t)
	t.Cleanup(w.close)
	val := w.plant(deriveCanary("ACCESSLOG", []byte{7, 7, 7}))
	w.drainLog()
	w.adminReq("GET", "/api/v1/projects?x="+val, "")
	if got := string(w.drainLog()); !strings.Contains(got, "/api/v1/projects?x="+val) {
		t.Fatalf("the access-log line did not reach the canary world's log buffer (log = %q)", got)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestCanaryOracle_SeesAccessLogLines_Helper", "-test.v")
	cmd.Env = append(os.Environ(), "CANARY_ACCESSLOG_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected the oracle to flag a canary planted in an access-log line, but the helper exited 0:\n%s", out)
	}
	if !strings.Contains(string(out), "CANARY LEAK") {
		t.Fatalf("helper failed, but not with CANARY LEAK:\n%s", out)
	}
}

// TestCanaryOracle_SeesAccessLogLines_Helper only runs as the subprocess above.
func TestCanaryOracle_SeesAccessLogLines_Helper(t *testing.T) {
	if os.Getenv("CANARY_ACCESSLOG_HELPER") != "1" {
		t.Skip("only runs as a subprocess helper for TestCanaryOracle_SeesAccessLogLines")
	}
	w := buildCanaryWorld(t)
	defer w.close()
	val := w.plant(deriveCanary("ACCESSLOG", []byte{7, 7, 7}))
	rec := w.adminReq("GET", "/api/v1/projects?x="+val, "")
	w.scanOp(t, 0, "http", "admin", rec)
}
