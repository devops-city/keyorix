// Package lib holds no Go code; it exists so `go test ./...` runs the shell tests
// of the scripts/e2e helper libraries in default CI.
package lib

import (
	"os/exec"
	"testing"
)

// TestFreePortScript runs free-port_test.sh (#3174): port_in_use must see a listener
// on [::1] as well as 127.0.0.1, free_port must skip both, and the base override and
// randomisation must behave.
func TestFreePortScript(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed: free-port_test.sh needs it to hold test listeners")
	}
	out, err := exec.Command("bash", "free-port_test.sh").CombinedOutput() // #nosec G204 -- fixed in-repo script
	if err != nil {
		t.Fatalf("free-port_test.sh failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
