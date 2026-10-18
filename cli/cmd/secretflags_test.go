package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// secretish is the vocabulary a flag or positional carrying a secret tends to use. The
// guard below makes every match a decision: refused, or explained in notSecretFlags.
var secretish = regexp.MustCompile(`(?i)(password|passphrase|passwd|secret|token|key|credential|code|otp|value|auth|bearer|cookie|private|seal|dsn)`)

func secretFlagKey(c *cobra.Command, flag string) string {
	return strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ") + " --" + flag
}

func positionalKey(c *cobra.Command) string {
	return strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ") + strings.TrimPrefix(c.Use, c.Name())
}

// TestSecretFlagsAreAllClassified is the audit of CLI-UX-1 item 5 as a test: walk every
// command, and for every string flag or positional argument whose name looks like it
// carries a secret, require a decision in secretflags.go. A new `--api-key` flag fails
// here until it is refused (and given a safe way in) or explained as not secret.
func TestSecretFlagsAreAllClassified(t *testing.T) {
	refused := map[string]secretFlag{}
	for _, sf := range refusedSecretFlags {
		refused[sf.Command+" --"+sf.Flag] = sf
	}

	seenRefused, seenExplained := map[string]bool{}, map[string]bool{}
	checked := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
		}
		if c == rootCmd || c.Name() == "help" || c.Name() == "completion" {
			return
		}
		c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
			checked++
			switch f.Value.Type() {
			case "string", "stringArray", "stringSlice":
			default:
				return // a bool, number or duration cannot carry a secret
			}
			key := secretFlagKey(c, f.Name)
			if _, ok := refused[key]; ok {
				seenRefused[key] = true
				return
			}
			if _, ok := notSecretFlags[key]; ok {
				seenExplained[key] = true
				return
			}
			if secretish.MatchString(f.Name) {
				t.Errorf("%s looks like it carries a secret but is neither refused (refusedSecretFlags) nor explained (notSecretFlags): "+
					"a secret flag must be refused and given a prompt/stdin/file/env alternative", key)
			}
		})
		if i := strings.IndexAny(c.Use, "<["); i >= 0 {
			key := positionalKey(c)
			if _, ok := notSecretFlags[key]; ok {
				seenExplained[key] = true
			} else if secretish.MatchString(c.Use[i:]) {
				t.Errorf("%q has a positional argument that looks like it carries a secret and is not explained in notSecretFlags", key)
			}
		}
	}
	walk(rootCmd)
	if checked < 300 {
		t.Fatalf("only %d flags walked; the audit is vacuous", checked)
	}

	var stale []string
	for key := range refused {
		if !seenRefused[key] {
			stale = append(stale, "refusedSecretFlags: "+key)
		}
	}
	for key := range notSecretFlags {
		if !seenExplained[key] {
			stale = append(stale, "notSecretFlags: "+key)
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("%s does not match any string flag or positional of the command tree: remove or fix the entry", s)
	}
}

// Every refused flag is refused with the same behaviour, on the real command tree.
func TestRefusedSecretFlagsAreRefused(t *testing.T) {
	const canary = "CANARY-s3cret-v4lue-9f2c"
	for _, sf := range refusedSecretFlags {
		name := sf.Command + " --" + sf.Flag
		t.Run(name, func(t *testing.T) {
			isolateSecretFlagEnv(t)
			args := append(strings.Fields(sf.Command), "--"+sf.Flag, canary)
			// A command with required flags checks them before it runs; satisfy them so the
			// test reaches the refusal.
			if c, _, err := rootCmd.Find(strings.Fields(sf.Command)); err == nil {
				c.Flags().VisitAll(func(f *pflag.Flag) {
					if _, req := f.Annotations[cobra.BashCompOneRequiredFlag]; req && f.Name != sf.Flag {
						args = append(args, "--"+f.Name, "http://127.0.0.1:1")
					}
				})
			}
			err := executeForTest(t, args...)
			if err == nil {
				t.Fatalf("keyorix %s %s: want a refusal, got success", sf.Command, "--"+sf.Flag)
			}
			msg := err.Error()
			for _, want := range []string{"--" + sf.Flag + " is not accepted", sf.Instead, allowInsecureSecretFlagsEnv} {
				if !strings.Contains(msg, want) {
					t.Errorf("refusal lacks %q: %s", want, msg)
				}
			}
			if strings.Contains(msg, canary) {
				t.Errorf("the refusal echoed the secret value: %s", msg)
			}

			// The flag is out of --help, so it is not advertised.
			c, _, ferr := rootCmd.Find(strings.Fields(sf.Command))
			if ferr != nil {
				t.Fatal(ferr)
			}
			if f := c.Flags().Lookup(sf.Flag); f == nil || !f.Hidden {
				t.Errorf("--%s should exist but be hidden", sf.Flag)
			}

			// The documented escape hatch turns the refusal back into the old warning.
			t.Setenv(allowInsecureSecretFlagsEnv, "1")
			err = executeForTest(t, args...)
			if err != nil && strings.Contains(err.Error(), "is not accepted") {
				t.Errorf("%s=1 must let the flag through, got: %v", allowInsecureSecretFlagsEnv, err)
			}
		})
	}
}

func isolateSecretFlagEnv(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("APPDATA", home)
	for _, k := range []string{"KEYORIX_SERVER", "KEYORIX_TOKEN", allowInsecureSecretFlagsEnv} {
		t.Setenv(k, "")
	}
}

// executeForTest runs the CLI the way the binary does (so the tree-wide policy is
// applied) and returns the error, with output discarded.
func executeForTest(t *testing.T, args ...string) error {
	t.Helper()
	resetAllFlags(rootCmd)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(args)
	defer func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) }()
	var err error
	captureStdoutAndStderr(t, func() { err = Execute() })
	return err
}

// resetAllFlags puts every flag in the tree back to its default and not-Changed. One
// process runs one command, but a test runs many in the same process, and cobra keeps
// the parsed values (and Changed) of an earlier run.
func resetAllFlags(c *cobra.Command) {
	reset := func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	c.Flags().VisitAll(reset)
	c.PersistentFlags().VisitAll(reset)
	for _, s := range c.Commands() {
		resetAllFlags(s)
	}
}

// secret create/update read the value from stdin with `--from-file -`.
func TestSecretValueFromStdin(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{"hunter2", "hunter2", ""},
		{"hunter2\n", "hunter2", ""},           // echo adds a newline
		{"hunter2\r\n", "hunter2", ""},         // so does a Windows editor
		{"line1\nline2\n", "line1\nline2", ""}, // only ONE trailing newline is dropped
		{"  spaced  ", "  spaced  ", ""},       // nothing else is touched
		{"", "", "nothing on stdin"},
		{"\n", "", "nothing on stdin"},
	}
	for _, c := range cases {
		got, err := readSecretValueFromStdin(strings.NewReader(c.in))
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%q: want error %q, got %v", c.in, c.wantErr, err)
			}
			continue
		}
		if err != nil || string(got) != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := readSecretValueFromStdin(strings.NewReader(strings.Repeat("x", maxSecretFileSize+1))); err == nil {
		t.Error("an oversized value must be refused")
	}
}

func TestSecretCreateAndUpdateTakeTheValueFromStdin(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/version":
			http.NotFound(w, r)
		case r.URL.Path == "/api/v1/secrets" && r.Method == http.MethodPost, strings.HasPrefix(r.URL.Path, "/api/v1/secrets/") && r.Method == http.MethodPut:
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			bodies = append(bodies, b)
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			}
			_, _ = fmt.Fprint(w, `{"data":{"id":7,"name":"S","type":"generic"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setSystemCreds(t, srv)
	t.Setenv(allowInsecureSecretFlagsEnv, "")

	real := secretValueStdin
	defer func() { secretValueStdin = real; secretCreateFromFile, secretUpdateFromFile = "", "" }()

	secretValueStdin = bytes.NewReader([]byte("piped-create-value\n"))
	if err := executeForTest(t, "secret", "create", "--name", "S", "--project", "1", "--environment", "1", "--from-file", "-"); err != nil {
		t.Fatalf("secret create --from-file -: %v", err)
	}
	secretValueStdin = bytes.NewReader([]byte("piped-update-value"))
	if err := executeForTest(t, "secret", "update", "--id", "7", "--from-file", "-"); err != nil {
		t.Fatalf("secret update --from-file -: %v", err)
	}
	if len(bodies) != 2 || bodies[0]["value"] != "piped-create-value" || bodies[1]["value"] != "piped-update-value" {
		t.Fatalf("the server did not receive the piped values: %+v", bodies)
	}
}

func TestChangePasswordTakesPasswordsFromTheEnvironment(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/auth/change-password" {
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = fmt.Fprint(w, `{"data":{}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setSystemCreds(t, srv)
	resetAllFlags(rootCmd)
	t.Setenv("KEYORIX_CURRENT_PASSWORD", "old-pw-1")
	t.Setenv("KEYORIX_NEW_PASSWORD", "new-pw-2")

	defer func() { changePasswordCurrent, changePasswordNew = "", "" }()
	out := captureStdout(t, func() {
		if err := runChangePassword(changePasswordCmd, nil); err != nil {
			t.Fatalf("change-password: %v", err)
		}
	})
	if got["current_password"] != "old-pw-1" || got["new_password"] != "new-pw-2" {
		t.Fatalf("the server did not receive the environment passwords: %v", got)
	}
	if strings.Contains(out, "old-pw-1") || strings.Contains(out, "new-pw-2") {
		t.Fatalf("a password was echoed: %q", out)
	}

	// Both variables set at once for one value is an error, never a silent choice.
	t.Setenv("KEYORIX_CURRENT_PASSWORD_FILE", "/nonexistent")
	if err := runChangePassword(changePasswordCmd, nil); err == nil || !strings.Contains(err.Error(), "set exactly one") {
		t.Fatalf("want an ambiguity error, got %v", err)
	}
}
