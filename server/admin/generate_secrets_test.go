package admin

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/rules"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// runGenerateSecretsCaptured runs `admin generate-secrets args...` through the
// real command tree and returns everything written to stdout AND stderr, so a
// value leaking on either stream is caught. Not parallel-safe (os.Stdout).
func runGenerateSecretsCaptured(t *testing.T, args ...string) (string, int) {
	t.Helper()
	generateSecretsDir = "secrets" // reset the flag's package state between runs
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	code := Execute(append([]string{"generate-secrets"}, args...))
	os.Stdout, os.Stderr = origOut, origErr
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), code
}

func readSecretFileT(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSuffix(string(b), "\n")
}

// assertNoValueIn fails if out contains the value or any 8-character slice of
// it: a masked or partial print ("first 8 + last 4") is a leak too.
func assertNoValueIn(t *testing.T, out, name, value string) {
	t.Helper()
	if len(value) < 16 {
		t.Fatalf("%s: generated value is only %d chars", name, len(value))
	}
	for i := 0; i+8 <= len(value); i++ {
		if strings.Contains(out, value[i:i+8]) {
			t.Fatalf("%s: output contains part of the generated value (offset %d):\n%s", name, i, out)
		}
	}
}

func TestGenerateSecrets_CreatesPrivateFilesAndNeverPrintsValues(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	out, code := runGenerateSecretsCaptured(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}

	info, err := os.Stat(filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("secrets dir mode = %o, want 700", got)
	}
	absDir, _ := filepath.Abs("secrets")
	seen := map[string]bool{}
	for _, s := range installSecrets {
		path := filepath.Join(dir, "secrets", s.file)
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s not created: %v", s.file, err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", s.file, got)
		}
		v := readSecretFileT(t, path)
		assertNoValueIn(t, out, s.file, v)
		if seen[v] {
			t.Errorf("%s repeats another secret's value", s.file)
		}
		seen[v] = true
		wantExport := "export " + s.envVar + "_FILE=" + filepath.Join(absDir, s.file)
		if !strings.Contains(out, wantExport) {
			t.Errorf("output lacks %q:\n%s", wantExport, out)
		}
	}
}

// The files are only useful if the real readers accept them: the master
// passphrase through crypto.ResolvePassphrase (LookupChecked, mode-checked),
// the bootstrap token and admin password through secretenv.LookupChecked
// (cli/cmd/systeminit.go's lookupSecretEnv).
func TestGenerateSecrets_FilesAreAcceptedByTheRealReaders(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if out, code := runGenerateSecretsCaptured(t); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, s := range installSecrets {
		t.Setenv(s.envVar, "")
		t.Setenv(s.envVar+"_FILE", filepath.Join(dir, "secrets", s.file))
	}

	pass, err := crypto.ResolvePassphrase(crypto.PassphraseSource{}, "KEYORIX_MASTER_PASSWORD")
	if err != nil {
		t.Fatalf("master passphrase rejected by ResolvePassphrase: %v", err)
	}
	if string(pass) != readSecretFileT(t, filepath.Join(dir, "secrets", "master_password")) {
		t.Error("ResolvePassphrase returned a different passphrase than the file holds")
	}
	for _, name := range []string{"KEYORIX_BOOTSTRAP_TOKEN", "KEYORIX_ADMIN_PASSWORD"} {
		if _, found, err := secretenv.LookupChecked(name); err != nil || !found {
			t.Errorf("%s_FILE rejected: found=%v err=%v", name, found, err)
		}
	}
}

func TestGenerateSecrets_NeverOverwritesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("secrets", 0o700); err != nil {
		t.Fatal(err)
	}
	const existing = "operator-chosen-master-passphrase"
	if err := os.WriteFile(filepath.Join("secrets", "master_password"), []byte(existing+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code := runGenerateSecretsCaptured(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if got := readSecretFileT(t, filepath.Join("secrets", "master_password")); got != existing {
		t.Fatal("existing master_password was overwritten")
	}
	if !strings.Contains(out, "kept") || strings.Contains(out, existing) {
		t.Errorf("want a 'kept' line and no value:\n%s", out)
	}
	first := map[string]string{}
	for _, s := range installSecrets {
		first[s.file] = readSecretFileT(t, filepath.Join("secrets", s.file))
	}

	// A second run keeps everything.
	out, code = runGenerateSecretsCaptured(t)
	if code != 0 {
		t.Fatalf("second run exit %d:\n%s", code, out)
	}
	for _, s := range installSecrets {
		if readSecretFileT(t, filepath.Join("secrets", s.file)) != first[s.file] {
			t.Errorf("second run changed %s", s.file)
		}
	}
	if strings.Contains(out, "created") {
		t.Errorf("second run created something:\n%s", out)
	}
}

// A kept file the readers would refuse (too open) fails now, not at first start.
func TestGenerateSecrets_RefusesAnExistingLooseFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("secrets", 0o700); err != nil {
		t.Fatal(err)
	}
	const existing = "loose-file-passphrase-value"
	p := filepath.Join("secrets", "master_password")
	if err := os.WriteFile(p, []byte(existing+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runGenerateSecretsCaptured(t)
	if code == 0 {
		t.Fatalf("exit 0 for a 0644 master_password:\n%s", out)
	}
	if !strings.Contains(out, "chmod 600") || strings.Contains(out, existing) {
		t.Errorf("want a chmod hint and no value:\n%s", out)
	}
	if got := readSecretFileT(t, p); got != existing {
		t.Fatal("loose file was modified")
	}
}

func TestGenerateSecrets_AbsoluteDir(t *testing.T) {
	t.Chdir(t.TempDir())
	abs := filepath.Join(t.TempDir(), "install", "secrets")
	out, code := runGenerateSecretsCaptured(t, "--dir", abs)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, s := range installSecrets {
		fi, err := os.Stat(filepath.Join(abs, s.file))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: err=%v", s.file, err)
		}
	}
}

func TestGenerateSecrets_AdminPasswordAlwaysMeetsDefaultPolicy(t *testing.T) {
	policy := rules.DefaultPasswordPolicy()
	for i := 0; i < 500; i++ {
		pw, err := randomAdminPassword()
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Validate(pw, nil); err != nil {
			t.Fatalf("generated password fails the default policy: %v", err)
		}
	}
}
