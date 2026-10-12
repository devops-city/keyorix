package main

// admin_generate_secrets_integration_test.go drives the secret-blind host install
// (INSTALL-WITH-AI.md) through the built binary: `admin generate-secrets`, then
// every host-side step reading the generated secrets by path only
// (KEYORIX_MASTER_PASSWORD_FILE), ending in `admin validate --posture`. It asserts
// the install succeeds AND that no generated value -- nor any 8-character slice of
// one -- appears in any command's combined output.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminGenerateSecrets_SecretBlindHostInstall(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	var transcript strings.Builder
	step := func(args ...string) string {
		t.Helper()
		out, err := runAdmin(t, bin, dir, env, args...)
		transcript.WriteString(out)
		if err != nil {
			t.Fatalf("admin %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}

	out := step("generate-secrets")
	realDir, err := filepath.EvalSymlinks(dir) // the child's cwd is the resolved path (macOS /tmp)
	if err != nil {
		t.Fatal(err)
	}
	masterFile := filepath.Join(realDir, "secrets", "master_password")
	if !strings.Contains(out, "export KEYORIX_MASTER_PASSWORD_FILE="+masterFile) {
		t.Fatalf("generate-secrets did not print the _FILE line:\n%s", out)
	}
	env = append(env, "KEYORIX_MASTER_PASSWORD_FILE="+masterFile)

	step("init", "--config", "./keyorix.yaml")
	step("encryption", "init", "--config", "./keyorix.yaml")
	step("migrate", "--config", "./keyorix.yaml")
	out = step("validate", "--posture", "--config", "./keyorix.yaml")
	if !strings.Contains(out, "No deviations found.") {
		t.Fatalf("posture on a secret-blind install is not clean:\n%s", out)
	}

	all := transcript.String()
	for _, name := range []string{"master_password", "bootstrap_token", "admin_password", "metrics_token"} {
		b, err := os.ReadFile(filepath.Join(dir, "secrets", name)) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		v := strings.TrimSuffix(string(b), "\n")
		if len(v) < 16 {
			t.Fatalf("%s is only %d chars", name, len(v))
		}
		for i := 0; i+8 <= len(v); i++ {
			if strings.Contains(all, v[i:i+8]) {
				t.Fatalf("%s: part of its value (offset %d) appears in the install output", name, i)
			}
		}
	}
}
