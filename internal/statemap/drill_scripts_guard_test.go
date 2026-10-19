package statemap

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// TestDrillScripts_SelfTestAndNoEchoGrepQ runs scripts/drills/selftest.sh in the default `go test`.
// It guards the drill helpers against `echo "$x" | grep -q ...` under `set -o pipefail` (grep -q
// exits at the first match, echo dies of SIGPIPE, the pipeline returns 141 and a VALID verify-audit
// is reported as a failure at random), and against totp_fresh sharing one "last code" between accounts.
// It does NOT run the drills themselves (they need real binaries); it covers the helper functions and
// a static scan of scripts/drills/*.sh.
func TestDrillScripts_SelfTestAndNoEchoGrepQ(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	script := filepath.Join(repoRoot(t), "scripts", "drills", "selftest.sh")
	out, err := exec.Command(bash, script).CombinedOutput() // #nosec G204 -- fixed in-repo script path
	if err != nil {
		t.Fatalf("scripts/drills/selftest.sh failed: %v\n%s", err, out)
	}
}
