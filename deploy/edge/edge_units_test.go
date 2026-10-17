package edge

// edge_units_test.go keeps the shipped systemd unit and launchd plist honest
// (docs/edge-deployment.md, "Unattended operation"). A unit file is the kind of
// artefact that rots silently: nobody boots it in CI, so a renamed flag or a
// dropped directive is found by an operator at 3 a.m. These tests do two things
// a reader of the file cannot:
//
//   - run the unit's real ExecStart line (the credential file systemd's
//     LoadCredential= hands over) against the freshly built server,
//     kill -9 it and run the same line again, which is what Restart=always does;
//   - pin the directives an unattended device depends on, so removing one fails
//     a test instead of a site.
//
// Not covered, and said so in the files themselves: booting under a real
// systemd or launchd (pending the e2e VM / a real device).

import (
	"encoding/xml"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above " + dir)
		}
		dir = parent
	}
}

// unitDirectives returns every `Key=Value` of the unit's sections, by section.
func unitDirectives(t *testing.T, path string) map[string]map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string][]string{}
	section := ""
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			out[section] = map[string][]string{}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			t.Fatalf("unit line is neither a section nor Key=Value: %q", line)
		}
		out[section][k] = append(out[section][k], v)
	}
	return out
}

func TestSystemdUnit_UnattendedDirectives(t *testing.T) {
	u := unitDirectives(t, "keyorix-server.service")
	one := func(section, key string) string {
		t.Helper()
		v := u[section][key]
		if len(v) != 1 {
			t.Fatalf("[%s] %s: want exactly one value, got %v", section, key, v)
		}
		return v[0]
	}
	// A crashed or killed server must come back, and the supervisor must never
	// give up: there is nobody to run `systemctl reset-failed`.
	if got := one("Service", "Restart"); got != "always" {
		t.Errorf("Restart=%s, want always", got)
	}
	if got := one("Unit", "StartLimitIntervalSec"); got != "0" {
		t.Errorf("StartLimitIntervalSec=%s, want 0 (never stop retrying)", got)
	}
	// Boot-time start, after the data volume is there.
	if got := one("Install", "WantedBy"); got != "multi-user.target" {
		t.Errorf("WantedBy=%s, want multi-user.target", got)
	}
	if mount := one("Unit", "RequiresMountsFor"); mount != one("Service", "WorkingDirectory") {
		t.Errorf("RequiresMountsFor=%s must be the data directory (WorkingDirectory=%s): a missing volume must be an outage, not an empty install",
			mount, one("Service", "WorkingDirectory"))
	}
	// Not root; clean stop.
	if got := one("Service", "User"); got == "" || got == "root" {
		t.Errorf("User=%q: the server must not run as root", got)
	}
	if got := one("Service", "KillSignal"); got != "SIGTERM" {
		t.Errorf("KillSignal=%s, want SIGTERM (graceful shutdown)", got)
	}
	// The passphrase must come from the credential, not argv or the environment.
	execStart := one("Service", "ExecStart")
	cred := one("Service", "LoadCredential")
	name, _, _ := strings.Cut(cred, ":")
	if !strings.Contains(execStart, "--passphrase-file=${CREDENTIALS_DIRECTORY}/"+name) {
		t.Errorf("ExecStart does not pass LoadCredential=%s to --passphrase-file: %s", cred, execStart)
	}
	for _, v := range u["Service"]["Environment"] {
		if strings.Contains(strings.ToUpper(v), "PASSWORD") || strings.Contains(strings.ToUpper(v), "PASSPHRASE") {
			t.Errorf("Environment=%s puts the passphrase in the process environment (ADR-099)", v)
		}
	}
	if got := one("Service", "NoNewPrivileges"); got != "true" {
		t.Errorf("NoNewPrivileges=%s, want true", got)
	}
}

func buildServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keyorix-server")
	cmd := exec.Command("go", "build", "-o", bin, "./server") //nolint:gosec // fixed arguments
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./server: %v\n%s", err, out)
	}
	return bin
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// TestSystemdUnit_ExecStartBootsAndRestarts runs the unit's own ExecStart line:
// a credential directory with the passphrase on disk, the server started with
// it on fd 3, kill -9, and the same line again. Everything an operator would
// otherwise have to do by hand between the two is asserted not to exist.
func TestSystemdUnit_ExecStartBootsAndRestarts(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the server")
	}
	u := unitDirectives(t, "keyorix-server.service")
	execStart := u["Service"]["ExecStart"][0]
	const shipped = "/usr/local/bin/keyorix-server"
	if !strings.Contains(execStart, shipped) {
		t.Fatalf("ExecStart no longer names %s; update this test with it: %s", shipped, execStart)
	}

	bin := buildServer(t)
	dir := t.TempDir()
	credDir := t.TempDir()
	const passphrase = "edge-unit-test-passphrase-0123456789"
	// A real credential file ends with a newline (and systemd makes it 0400); the server must cope.
	if err := os.WriteFile(filepath.Join(credDir, "master-password"), []byte(passphrase+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}

	baseEnv := []string{"HOME=" + dir, "PATH=/usr/bin:/bin"}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		baseEnv = append(baseEnv, "TMPDIR="+tmp)
	}
	admin := func(args ...string) {
		t.Helper()
		cmd := exec.Command(bin, append([]string{"admin"}, args...)...) //nolint:gosec // test binary
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, baseEnv...), "KEYORIX_MASTER_PASSWORD="+passphrase)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	admin("init", "--dev", "--config", "./keyorix.yaml")
	admin("encryption", "init", "--config", "./keyorix.yaml")
	admin("migrate", "--config", "./keyorix.yaml")

	port := freePort(t)
	cfg := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfg) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `port: "8080"`) {
		t.Fatal("generated config no longer has the 8080 port line this test rewrites")
	}
	if err := os.WriteFile(cfg, []byte(strings.Replace(string(raw), `port: "8080"`, `port: "`+port+`"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	// systemd expands ${CREDENTIALS_DIRECTORY} itself and does not use a shell:
	// do the same, with the test binary where /usr/local/bin/keyorix-server was.
	expanded := os.Expand(strings.Replace(execStart, shipped, bin, 1), func(k string) string {
		if k == "CREDENTIALS_DIRECTORY" {
			return credDir
		}
		t.Fatalf("ExecStart uses ${%s}, which this test does not provide", k)
		return ""
	})
	argv := strings.Fields(expanded)

	runUnit := func() (*exec.Cmd, chan struct{}) {
		t.Helper()
		// WITHOUT the passphrase in the environment: only the credential file.
		cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // the shipped unit's own line, with the test binary substituted
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, baseEnv...), "KEYORIX_CONFIG_PATH="+cfg)
		logf, err := os.OpenFile(filepath.Join(dir, "unit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test path
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); _ = logf.Close(); close(done) }()
		return cmd, done
	}
	waitHealthy := func(done chan struct{}) {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		client := &http.Client{Timeout: 2 * time.Second}
		for time.Now().Before(deadline) {
			select {
			case <-done:
				log, _ := os.ReadFile(filepath.Join(dir, "unit.log")) //nolint:gosec // test path
				t.Fatalf("the unit's ExecStart exited before becoming healthy:\n%s", log)
			default:
			}
			if resp, err := client.Get("http://127.0.0.1:" + port + "/health"); err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("server never became healthy under the unit's ExecStart")
	}

	for boot := 1; boot <= 2; boot++ { // boot 2 is Restart=always after a kill -9
		cmd, done := runUnit()
		waitHealthy(done)
		_ = cmd.Process.Signal(syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("server did not die on SIGKILL")
		}
	}
}

// plist is the subset of Apple's property-list XML this test reads: a flat
// <dict> of <key>/value pairs.
type plist struct {
	Dict struct {
		Items []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
			Inner   []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:",any"`
	} `xml:"dict"`
}

func TestLaunchdPlist_UnattendedKeys(t *testing.T) {
	raw, err := os.ReadFile("io.keyorix.server.plist")
	if err != nil {
		t.Fatal(err)
	}
	var p plist
	if err := xml.Unmarshal(raw, &p); err != nil {
		t.Fatalf("plist is not well-formed XML: %v", err)
	}
	// Flatten key -> first following sibling element name (true/false/string/array/dict/integer).
	kinds := map[string]string{}
	strs := map[string]string{}
	var key string
	for _, it := range p.Dict.Items {
		switch it.XMLName.Local {
		case "key":
			key = strings.TrimSpace(it.Value)
		default:
			kinds[key] = it.XMLName.Local
			strs[key] = strings.TrimSpace(it.Value)
		}
	}
	for k, want := range map[string]string{
		"Label": "string", "ProgramArguments": "array", "RunAtLoad": "true", "KeepAlive": "true",
		"UserName": "string", "WorkingDirectory": "string", "EnvironmentVariables": "dict",
	} {
		if kinds[k] != want {
			t.Errorf("plist key %s: element %q, want %q", k, kinds[k], want)
		}
	}
	if strs["UserName"] == "root" {
		t.Error("the plist runs the server as root")
	}
	// The flag the plist passes must still exist in the server.
	main, err := os.ReadFile(filepath.Join(repoRoot(t), "server", "main.go")) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "--passphrase-file") || !strings.Contains(string(main), `"passphrase-file"`) {
		t.Error("the plist's --passphrase-file is not a flag the server defines")
	}
}
