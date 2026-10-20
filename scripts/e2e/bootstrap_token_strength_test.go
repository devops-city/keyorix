//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestBootstrapTokenStrength_SQLite runs the built keyorix-server the way an
// operator does (admin init, encryption init, migrate, start) with a pinned
// KEYORIX_BOOTSTRAP_TOKEN shorter than 32 characters: the process must exit
// non-zero before serving, print the remediation, and never echo the token.
// The matrix row for this is in docs/security/production-hardening-matrix.d/.
func TestBootstrapTokenStrength_SQLite(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir), "KEYORIX_MASTER_PASSWORD=e2e-bootstrap-strength-master-password")
	for _, args := range [][]string{
		{"init", "--dev", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
		{"migrate", "--config", "./keyorix.yaml"},
	} {
		if out, err := harness.RunAdminCmd(serverBin, dir, env, args...); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	harness.RewritePort(t, dir, harness.FreeTCPPort(t))

	const weak = "choose-a-bootstrap-token"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin) // #nosec G204 -- the binary this test built
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml", "KEYORIX_BOOTSTRAP_TOKEN="+weak)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("server with a %d-character pinned bootstrap token kept running instead of refusing to start:\n%s", len(weak), out)
	}
	if err == nil {
		t.Fatalf("server exited 0 with a weak pinned bootstrap token:\n%s", out)
	}
	const want = "KEYORIX_BOOTSTRAP_TOKEN too short (min 32 characters): generate one with: openssl rand -hex 32"
	if !strings.Contains(string(out), want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
	if strings.Contains(string(out), weak) {
		t.Errorf("output echoes the rejected token:\n%s", out)
	}
}
