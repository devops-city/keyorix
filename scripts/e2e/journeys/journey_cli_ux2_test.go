//go:build e2e

package journeys

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// runCLIExitCode runs the CLI with data on stdin and returns stdout, stderr and the process
// exit code (-1 when it did not run at all).
func runCLIExitCode(cliBin string, env []string, stdin string, args ...string) (stdout, stderr string, code int) {
	cmd := exec.Command(cliBin, args...) // #nosec G204 -- the journey's own built binary and fixed arguments
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return so.String(), se.String(), ee.ExitCode()
	}
	if err != nil {
		return so.String(), se.String(), -1
	}
	return so.String(), se.String(), 0
}

// TestJourney_CLIUX2 drives CLI-UX-2 against a real server (native SQLite): a webhook URL
// goes in through --url-file and never comes back in full, KEYORIX_TOKEN_FILE and
// `machine token issue --output-file` keep tokens out of the environment and the terminal,
// refusals exit 2, and a private-network dynamic-secret target is refused in words.
func TestJourney_CLIUX2(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	// No KEYORIX_ALLOW_INSECURE_SECRET_FLAGS: this is what a user's shell looks like.
	strict := []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + s.BaseURL, "KEYORIX_TOKEN=" + adminToken}

	const webhook = "https://93.184.216.34/services/T000/B000/JOURNEYTOKEN9999"

	t.Run("webhook URL: --url-file in, masked out, --url refused with exit 2", func(t *testing.T) {
		out, errOut, code := runCLIExitCode(cliBin, strict, webhook+"\n", "notification", "channel", "add", "ops-hook", "--type", "webhook", "--url-file", "-")
		if code != 0 {
			t.Fatalf("add --url-file -: exit %d\n%s%s", code, out, errOut)
		}

		got := runCLI(t, cliBin, strict, "notification", "channel", "get", "ops-hook")
		if strings.Contains(got, "JOURNEYTOKEN9999") || strings.Contains(got, "/services/") {
			t.Fatalf("channel get returned (part of) the full URL:\n%s", got)
		}
		if !strings.Contains(got, "https://93.184.216.34/…") || !strings.Contains(got, "--url-file") {
			t.Fatalf("channel get should show the masked URL and how to replace it:\n%s", got)
		}
		if list := runCLI(t, cliBin, strict, "notification", "channel", "list", "-o", "json"); strings.Contains(list, "JOURNEYTOKEN9999") {
			t.Fatalf("channel list leaked the token:\n%s", list)
		}

		out, errOut, code = runCLIExitCode(cliBin, strict, "", "notification", "channel", "add", "ops-hook-flag", "--type", "webhook", "--url", webhook) // secretflag:allow refusal check: this journey proves --url is a usage error
		if code != 2 {
			t.Fatalf("--url must be a usage error (exit 2), got %d\n%s%s", code, out, errOut)
		}
		if !strings.Contains(errOut, "--url-file") || strings.Contains(out+errOut, "JOURNEYTOKEN9999") {
			t.Fatalf("refusal must name --url-file and never echo the URL:\n%s%s", out, errOut)
		}
		if strings.Contains(runCLI(t, cliBin, strict, "notification", "channel", "list"), "ops-hook-flag") {
			t.Fatal("the refused command still created the channel")
		}

		out, errOut, code = runCLIExitCode(cliBin, strict, "https://93.184.216.34/services/T000/B000/REPLACEDTOKEN\n", "notification", "channel", "update", "ops-hook", "--url-file", "-")
		if code != 0 {
			t.Fatalf("update --url-file -: exit %d\n%s%s", code, out, errOut)
		}
		if got := runCLI(t, cliBin, strict, "notification", "channel", "get", "ops-hook"); strings.Contains(got, "REPLACEDTOKEN") {
			t.Fatalf("channel get leaked the replacement URL:\n%s", got)
		}
	})

	t.Run("KEYORIX_TOKEN_FILE: a 0600 file works, a 0644 file is refused", func(t *testing.T) {
		dir := t.TempDir()
		good := filepath.Join(dir, "good.token")
		if err := os.WriteFile(good, []byte(adminToken+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		fileEnv := []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + s.BaseURL, "KEYORIX_TOKEN_FILE=" + good}
		out, errOut, code := runCLIExitCode(cliBin, fileEnv, "", "project", "list")
		if code != 0 {
			t.Fatalf("project list with KEYORIX_TOKEN_FILE: exit %d\n%s%s", code, out, errOut)
		}

		loose := filepath.Join(dir, "loose.token")
		if err := os.WriteFile(loose, []byte(adminToken+"\n"), 0o644); err != nil { // #nosec G306 -- deliberately too open: this is the refusal under test
			t.Fatal(err)
		}
		if err := os.Chmod(loose, 0o644); err != nil { // #nosec G302 -- same
			t.Fatal(err)
		}
		fileEnv[3] = "KEYORIX_TOKEN_FILE=" + loose
		out, errOut, code = runCLIExitCode(cliBin, fileEnv, "", "project", "list")
		if code != 3 || !strings.Contains(errOut, "too open") || strings.Contains(out+errOut, adminToken) {
			t.Fatalf("a loose token file must be refused (exit 3, 'too open', no token in the text): exit %d\n%s%s", code, out, errOut)
		}
	})

	t.Run("machine token issue --output-file keeps the token off the terminal", func(t *testing.T) {
		const proj = "j-cliux2"
		runCLI(t, cliBin, strict, "project", "create", "--name", proj)
		runCLI(t, cliBin, strict, "machine", "create", "--project", proj, "--name", "ci-bot", "--type", "ci")

		path := filepath.Join(t.TempDir(), "ci.token")
		out, errOut, code := runCLIExitCode(cliBin, strict, "", "machine", "token", "issue", "ci-bot", "--project", proj, "--name", "t1", "--output-file", path)
		if code != 0 {
			t.Fatalf("issue --output-file: exit %d\n%s%s", code, out, errOut)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tok := strings.TrimSpace(string(data))
		if tok == "" || strings.Contains(out+errOut, tok) {
			t.Fatalf("the token must be in the file and nowhere in the terminal output (file %q)\n%s%s", tok, out, errOut)
		}
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v, want 0600", st.Mode().Perm())
		}
		if !regexp.MustCompile(`ID:\s+\d+`).MatchString(out) {
			t.Errorf("stdout should still show the token id:\n%s", out)
		}

		// The issued token really authenticates, read back from the file.
		tokEnv := []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + s.BaseURL, "KEYORIX_TOKEN_FILE=" + path}
		if _, errOut, code := runCLIExitCode(cliBin, tokEnv, "", "status"); code != 0 {
			t.Errorf("status with the issued token file: exit %d\n%s", code, errOut)
		}

		// A second issue to the same path is refused before a token is minted.
		before := runCLI(t, cliBin, strict, "machine", "token", "list", "ci-bot", "--project", proj)
		_, errOut, code = runCLIExitCode(cliBin, strict, "", "machine", "token", "issue", "ci-bot", "--project", proj, "--name", "t2", "--output-file", path)
		if code == 0 || !strings.Contains(errOut, "no token was issued") {
			t.Fatalf("an existing --output-file must be refused (exit %d)\n%s", code, errOut)
		}
		if after := runCLI(t, cliBin, strict, "machine", "token", "list", "ci-bot", "--project", proj); after != before {
			t.Errorf("a refused issue still minted a token:\nbefore:\n%s\nafter:\n%s", before, after)
		}
		if again, _ := os.ReadFile(path); string(again) != string(data) {
			t.Error("the existing token file was overwritten")
		}

		// Stdout stays the default for piping.
		piped, errOut, code := runCLIExitCode(cliBin, strict, "", "machine", "token", "issue", "ci-bot", "--project", proj, "--name", "t3")
		if code != 0 || !strings.Contains(piped, "Token:") {
			t.Fatalf("default issue must still print the token: exit %d\n%s%s", code, piped, errOut)
		}
	})

	t.Run("dynamic-secret create on a private-network target says what and which setting", func(t *testing.T) {
		const proj = "j-cliux2-dyn"
		runCLI(t, cliBin, strict, "project", "create", "--name", proj)
		pid := projectID(t, s, adminToken, proj)
		eid := environmentID(t, s, adminToken, pid, "development")
		env := append(append([]string{}, strict...), "KEYORIX_DYNAMIC_ADMIN_DSN=postgres://admin:S3cretPw@10.0.0.5:5432/app")
		out, errOut, code := runCLIExitCode(cliBin, env, "", "dynamic-secret", "create", "--name", "priv",
			"--project-id", strconv.Itoa(pid), "--environment-id", strconv.Itoa(eid), "--backend", "postgres",
			"--creation-template", "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};")
		text := out + errOut
		if code == 0 {
			t.Fatalf("a private-network target must be refused:\n%s", text)
		}
		for _, want := range []string{"10.0.0.5", "dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets"} {
			if !strings.Contains(text, want) {
				t.Errorf("refusal lacks %q:\n%s", want, text)
			}
		}
		if strings.Contains(text, "internal error") || strings.Contains(text, "S3cretPw") {
			t.Errorf("the refusal must not be the generic internal error and must not echo credentials:\n%s", text)
		}
	})

	t.Run("doctor: a bad --output is a usage error (exit 2) and a failing check exits 1", func(t *testing.T) {
		_, errOut, code := runCLIExitCode(cliBin, strict, "", "doctor", "-o", "xml")
		if code != 2 || !strings.Contains(errOut, "table, json or yaml") {
			t.Fatalf("doctor -o xml: exit %d, want 2\n%s", code, errOut)
		}
		down := []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=http://127.0.0.1:1", "KEYORIX_TOKEN=x"}
		out, _, code := runCLIExitCode(cliBin, down, "", "doctor")
		if code != 1 || !strings.Contains(out, "connection refused") || strings.Contains(out, "dial tcp") {
			t.Fatalf("doctor against a dead server: exit %d, want 1 with the described transport error\n%s", code, out)
		}
	})
}
