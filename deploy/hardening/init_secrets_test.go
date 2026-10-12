package hardening

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// scripts/selfhost/init-secrets.sh creates the Docker-secrets files the compose
// stack mounts. Contract pinned here: files are 0640 (never world-accessible),
// existing files are never overwritten, --from-env migrates an existing .env's
// values byte-for-byte (the master password and DB password MUST NOT change on
// upgrade), and KEYORIX_SECRETS_GID lands in the env file.

// notTheProcessUID returns a server uid for INIT_SECRETS_SERVER_UID that differs from the
// test process's uid. The script refuses files owned by the server uid (default 1001), and
// CI runners are uid 1001, so tests that are not about that refusal must not collide with it.
func notTheProcessUID() string {
	if os.Getuid() == 65534 {
		return "65533"
	}
	return "65534"
}

func runInit(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	script := filepath.Join(repoRoot(), "scripts", "selfhost", "init-secrets.sh")
	cmd := exec.Command("sh", append([]string{script}, args...)...) //nolint:gosec // repo script, test-controlled args
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "INIT_SECRETS_SERVER_UID=" + notTheProcessUID()}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readTrim(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(b), "\n")
}

func TestInitSecrets_CreatesFilesWith0640AndGID(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("KEYORIX_DOMAIN=localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runInit(t, dir, "--dir", filepath.Join(dir, "secrets"), "--env-file", envFile)
	if err != nil {
		t.Fatalf("init-secrets: %v\n%s", err, out)
	}
	for _, name := range []string{"db_password", "master_password", "admin_password", "bootstrap_token"} {
		p := filepath.Join(dir, "secrets", name)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s not created: %v\n%s", name, err, out)
		}
		if info.Mode().Perm() != 0o640 {
			t.Errorf("%s: mode %04o, want 0640", name, info.Mode().Perm())
		}
		if v := readTrim(t, p); len(v) < 20 {
			t.Errorf("%s: generated value too short (%d)", name, len(v))
		}
		if strings.Contains(out, readTrim(t, p)) {
			t.Errorf("%s: the script printed a secret value", name)
		}
	}
	if pw := readTrim(t, filepath.Join(dir, "secrets", "admin_password")); len(pw) < 16 {
		t.Errorf("admin_password %q is shorter than the server's 16-character policy", pw)
	}
	u, _ := user.Current()
	gid, _ := strconv.Atoi(u.Gid)
	env := readTrim(t, envFile)
	if !strings.Contains(env, "KEYORIX_DOMAIN=localhost") {
		t.Errorf("existing .env content lost: %q", env)
	}
	if !strings.Contains(env, "KEYORIX_SECRETS_GID="+strconv.Itoa(gid)) {
		t.Errorf(".env lacks KEYORIX_SECRETS_GID=%d: %q", gid, env)
	}
}

func TestInitSecrets_NeverOverwritesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	sec := filepath.Join(dir, "secrets")
	if _, err := runInit(t, dir, "--dir", sec, "--env-file", envFile); err != nil {
		t.Fatal(err)
	}
	before := readTrim(t, filepath.Join(sec, "master_password"))
	out, err := runInit(t, dir, "--dir", sec, "--env-file", envFile)
	if err != nil {
		t.Fatalf("second run: %v\n%s", err, out)
	}
	if after := readTrim(t, filepath.Join(sec, "master_password")); after != before {
		t.Error("a second run replaced master_password: that would make every stored secret undecryptable")
	}
	if n := strings.Count(readTrim(t, envFile), "KEYORIX_SECRETS_GID="); n != 1 {
		t.Errorf("KEYORIX_SECRETS_GID appears %d times after two runs, want 1", n)
	}
}

func TestInitSecrets_FromEnvMigratesValuesExactly(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	content := "KEYORIX_DB_PASSWORD=old db/pass+with=chars\n" +
		"KEYORIX_MASTER_PASSWORD=\"quoted master $pass\"\n" +
		"KEYORIX_ADMIN_PASSWORD='Admin-Pass-1234567890!'\n" +
		"KEYORIX_BOOTSTRAP_TOKEN=tok-abc\n" +
		"KEYORIX_ADMIN_EMAIL=a@b.test\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "secrets")
	out, err := runInit(t, dir, "--dir", sec, "--env-file", envFile, "--from-env", envFile)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := map[string]string{
		"db_password":     "old db/pass+with=chars",
		"master_password": "quoted master $pass",
		"admin_password":  "Admin-Pass-1234567890!",
		"bootstrap_token": "tok-abc",
	}
	for name, v := range want {
		if got := readTrim(t, filepath.Join(sec, name)); got != v {
			t.Errorf("%s = %q, want %q", name, got, v)
		}
	}
	if !strings.Contains(out, "KEYORIX_MASTER_PASSWORD") {
		t.Errorf("migration output should tell the operator to remove the plaintext values from .env: %q", out)
	}
	if strings.Contains(out, "quoted master") || strings.Contains(out, "old db/pass") {
		t.Errorf("the script printed a secret value: %q", out)
	}
}

// The server container runs as uid 1001 and refuses a group-readable secret file it
// owns. A host user whose uid is 1001 would get 0640 files the server then rejects at
// `compose up`; the script must say so up front. The uid is overridable so the test
// can trigger it without being uid 1001, and the fix is a non-owner (never relaxing
// the server's rule).
func TestInitSecrets_WarnsWhenFilesAreOwnedByTheServerUID(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	sec := filepath.Join(dir, "secrets")

	cmdEnv := func(uid string) (string, error) {
		script := filepath.Join(repoRoot(), "scripts", "selfhost", "init-secrets.sh")
		cmd := exec.Command("sh", script, "--dir", sec, "--env-file", envFile) //nolint:gosec // repo script, test-controlled args
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "INIT_SECRETS_SERVER_UID=" + uid}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	u, _ := user.Current()
	out, err := cmdEnv(u.Uid)
	if err == nil {
		t.Fatalf("files owned by the server uid must fail the script, got success:\n%s", out)
	}
	if !strings.Contains(out, "owned by uid "+u.Uid) || !strings.Contains(out, "chown root:") {
		t.Errorf("error should name the uid and the chown fix: %q", out)
	}
	// The files were still written (and kept on the re-run): nothing is lost or regenerated.
	if _, statErr := os.Stat(filepath.Join(sec, "master_password")); statErr != nil {
		t.Errorf("master_password should exist after the failed check: %v", statErr)
	}
	// Any other server uid is fine.
	if out, err := cmdEnv(notTheProcessUID()); err != nil {
		t.Fatalf("a non-matching server uid must succeed: %v\n%s", err, out)
	}
	// A non-numeric override must be an error, never a silently disabled check.
	if out, err := cmdEnv("none"); err == nil || !strings.Contains(out, "must be a numeric uid") {
		t.Fatalf("a non-numeric INIT_SECRETS_SERVER_UID must fail loudly, err=%v\n%s", err, out)
	}
}

func TestInitSecrets_RefusesToOverwriteWithDifferentFromEnvValue(t *testing.T) {
	// Re-running --from-env after a file exists must keep the file (and say so),
	// not silently swap a master password.
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("KEYORIX_MASTER_PASSWORD=from-env\nKEYORIX_DB_PASSWORD=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(sec, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "master_password"), []byte("already-here\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := runInit(t, dir, "--dir", sec, "--env-file", envFile, "--from-env", envFile); err != nil {
		t.Fatal(err)
	}
	if got := readTrim(t, filepath.Join(sec, "master_password")); got != "already-here" {
		t.Errorf("existing master_password overwritten: %q", got)
	}
}
