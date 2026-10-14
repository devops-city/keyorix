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

// #3201: the server refuses a first-admin password that embeds the admin's username
// (or the email's local part, or "Administrator"), and an admin that cannot be
// bootstrapped crash-loops the backend. init-secrets.sh must therefore never GENERATE
// such a password, and must warn (not refuse: --from-env is an upgrade path and an
// install that already has its admin boots fine) about a supplied one.

// runInitWithEnv is runInit with extra environment entries and a stub directory first on PATH.
func runInitWithEnv(t *testing.T, dir, stubDir string, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	script := filepath.Join(repoRoot(), "scripts", "selfhost", "init-secrets.sh")
	cmd := exec.Command("sh", append([]string{script}, args...)...) //nolint:gosec // repo script, test-controlled args
	cmd.Dir = dir
	path := os.Getenv("PATH")
	if stubDir != "" {
		path = stubDir + string(os.PathListSeparator) + path
	}
	cmd.Env = append([]string{"PATH=" + path, "HOME=" + dir, "INIT_SECRETS_SERVER_UID=" + notTheProcessUID()}, extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// realOpenSSLUnlessRand is the first line of an `openssl` stub that only fakes
// `openssl rand`: every other call (the Postgres TLS pair, PG-TLS-3) runs the
// real openssl.
func realOpenSSLUnlessRand(t *testing.T) string {
	t.Helper()
	real, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	return "if [ \"$1\" != rand ]; then exec '" + real + "' \"$@\"; fi\n"
}

func TestInitSecrets_GeneratedAdminPasswordNeverEmbedsTheUsername(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "bin")
	if err := os.MkdirAll(stub, 0o750); err != nil {
		t.Fatal(err)
	}
	// A deterministic `openssl rand`: calls 1-2 (db, master) are benign, call 3 is the
	// first admin draw and embeds the username, calls 4+ are clean.
	counter := filepath.Join(dir, "calls")
	script := "#!/bin/sh\n" + realOpenSSLUnlessRand(t) +
		"n=$(cat '" + counter + "' 2>/dev/null || echo 0)\n" +
		"n=$((n + 1))\n" +
		"echo $n > '" + counter + "'\n" +
		"if [ \"$n\" = 3 ]; then echo 'ZZZZZZZZZZZZadminZZZZZZZZZZZZZZZZZZZZZZZZ'; else echo \"qWeRtYuIoPaSdFgHjKlZxCvBnM$n\"; fi\n"
	if err := os.WriteFile(filepath.Join(stub, "openssl"), []byte(script), 0o700); err != nil { //nolint:gosec // executable test stub
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "secrets")
	out, err := runInitWithEnv(t, dir, stub, nil, "--dir", sec, "--env-file", filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("init-secrets: %v\n%s", err, out)
	}
	pw := readTrim(t, filepath.Join(sec, "admin_password"))
	if strings.Contains(strings.ToLower(pw), "admin") {
		t.Fatalf("generated admin password embeds the username: %q", pw)
	}
	if n := readTrim(t, counter); n != "5" {
		t.Errorf("expected the embedding draw to be discarded and redrawn (5 random draws in total), got %s", n)
	}
}

func TestInitSecrets_GeneratedAdminPasswordAvoidsACustomUsernameFromEnvFile(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "bin")
	if err := os.MkdirAll(stub, 0o750); err != nil {
		t.Fatal(err)
	}
	counter := filepath.Join(dir, "calls")
	script := "#!/bin/sh\n" + realOpenSSLUnlessRand(t) +
		"n=$(cat '" + counter + "' 2>/dev/null || echo 0)\n" +
		"n=$((n + 1))\n" +
		"echo $n > '" + counter + "'\n" +
		"if [ \"$n\" = 3 ]; then echo 'ZZZZZZZZZZZZBossZZZZZZZZZZZZZZZZZZZZZZZZ'; else echo \"qWeRtYuIoPaSdFgHjKlZxCvBnM$n\"; fi\n"
	if err := os.WriteFile(filepath.Join(stub, "openssl"), []byte(script), 0o700); err != nil { //nolint:gosec // executable test stub
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("KEYORIX_ADMIN_USERNAME=boss\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "secrets")
	out, err := runInitWithEnv(t, dir, stub, nil, "--dir", sec, "--env-file", envFile)
	if err != nil {
		t.Fatalf("init-secrets: %v\n%s", err, out)
	}
	if pw := readTrim(t, filepath.Join(sec, "admin_password")); strings.Contains(strings.ToLower(pw), "boss") {
		t.Fatalf("generated admin password embeds the .env username: %q", pw)
	}
}

func TestInitSecrets_FromEnvAdminPasswordContainingTheUsernameWarnsButMigrates(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	const pw = "Dw5-Admin-Passphrase#2026"
	if err := os.WriteFile(envFile, []byte("KEYORIX_ADMIN_PASSWORD="+pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "secrets")
	out, err := runInit(t, dir, "--dir", sec, "--env-file", envFile, "--from-env", envFile)
	if err != nil {
		t.Fatalf("an upgrade must not be blocked: %v\n%s", err, out)
	}
	if got := readTrim(t, filepath.Join(sec, "admin_password")); got != pw {
		t.Errorf("the supplied password was changed: %q", got)
	}
	if !strings.Contains(out, `contains the username "admin"`) || !strings.Contains(out, "will not bootstrap") {
		t.Errorf("no clear warning about the embedded username:\n%s", out)
	}
	if strings.Contains(out, pw) {
		t.Errorf("the script printed the password:\n%s", out)
	}
}

func TestInitSecrets_FromEnvCompliantAdminPasswordDoesNotWarn(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("KEYORIX_ADMIN_PASSWORD=Correct-Horse-Battery-2026\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runInit(t, dir, "--dir", filepath.Join(dir, "secrets"), "--env-file", envFile, "--from-env", envFile)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("a compliant password produced a warning:\n%s", out)
	}
}

// PG-TLS-3: the compose Postgres' certificate and key live next to the other
// secrets. An install from v0.96.0 has the four old files and no certificate:
// the script must add the pair and change nothing else (the database password
// must keep matching the existing postgres volume).
func TestInitSecrets_UpgradeFromV096AddsOnlyThePostgresTLSPair(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	sec := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(sec, 0o750); err != nil {
		t.Fatal(err)
	}
	old := map[string]string{"db_password": "db-pw-v096", "master_password": "master-v096", "admin_password": "Admin-v096-Aa1!xxxxxx", "bootstrap_token": "tok-v096"}
	for name, v := range old {
		if err := os.WriteFile(filepath.Join(sec, name), []byte(v+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	out, err := runInit(t, dir, "--dir", sec, "--env-file", envFile)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for name, v := range old {
		if got := readTrim(t, filepath.Join(sec, name)); got != v {
			t.Errorf("%s changed on upgrade: %q", name, got)
		}
	}
	for _, name := range []string{"postgres_tls.crt", "postgres_tls.key"} {
		info, err := os.Stat(filepath.Join(sec, name))
		if err != nil {
			t.Fatalf("%s not created on upgrade: %v\n%s", name, err, out)
		}
		if info.Mode().Perm() != 0o640 {
			t.Errorf("%s: mode %04o, want 0640", name, info.Mode().Perm())
		}
	}
	// A second run keeps the pair byte for byte.
	crt, key := readTrim(t, filepath.Join(sec, "postgres_tls.crt")), readTrim(t, filepath.Join(sec, "postgres_tls.key"))
	if out, err := runInit(t, dir, "--dir", sec, "--env-file", envFile); err != nil {
		t.Fatalf("second run: %v\n%s", err, out)
	}
	if readTrim(t, filepath.Join(sec, "postgres_tls.crt")) != crt || readTrim(t, filepath.Join(sec, "postgres_tls.key")) != key {
		t.Error("a second run regenerated the Postgres certificate: the running stack would be pinned to the old one")
	}
	if strings.Contains(out, "BEGIN") {
		t.Errorf("the script printed key or certificate material: %q", out)
	}
}

// A certificate without its key (or the reverse) can never work together: the
// script refuses instead of generating a pair that silently replaces the one
// that is there.
func TestInitSecrets_RefusesHalfAPostgresTLSPair(t *testing.T) {
	for _, existing := range []string{"postgres_tls.crt", "postgres_tls.key"} {
		dir := t.TempDir()
		sec := filepath.Join(dir, "secrets")
		if err := os.MkdirAll(sec, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sec, existing), []byte("operator-provided\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		out, err := runInit(t, dir, "--dir", sec, "--env-file", filepath.Join(dir, ".env"))
		if err == nil {
			t.Fatalf("%s alone: the script must refuse, got success:\n%s", existing, out)
		}
		if !strings.Contains(out, "only one of") {
			t.Errorf("%s alone: error should explain the half pair: %q", existing, out)
		}
		if got := readTrim(t, filepath.Join(sec, existing)); got != "operator-provided" {
			t.Errorf("%s was overwritten: %q", existing, got)
		}
	}
}
