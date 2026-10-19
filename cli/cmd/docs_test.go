package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// capture runs the real CLI entry (Execute, so every tree-wide setup the binary does has
// been done) with args and returns what it wrote to stdout.
func capture(t *testing.T, args ...string) string {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs(args)
	defer func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) }()
	// cobra's generated `completion` commands write to the stdout that was current when
	// they were created, not to SetOut, so stdout is captured as well.
	stdout := captureStdout(t, func() {
		if err := Execute(); err != nil {
			t.Fatalf("keyorix %s: %v\n%s", strings.Join(args, " "), err, buf.String())
		}
	})
	return buf.String() + stdout
}

// TestCLIReferenceIsFresh fails when docs/cli-reference.md or docs/man/keyorix.1 no longer
// match the command tree: a command, flag, example or help text changed and the generated
// documents were not regenerated. Fix: `make -C cli docs`.
func TestCLIReferenceIsFresh(t *testing.T) {
	for _, tc := range []struct {
		sub  string
		file string
	}{
		{"markdown", filepath.Join("..", "..", "docs", "cli-reference.md")},
		{"man", filepath.Join("..", "..", "docs", "man", "keyorix.1")},
	} {
		want, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("%s is missing (%v): run `make -C cli docs`", tc.file, err)
		}
		got := capture(t, "docs", tc.sub)
		if got != string(want) {
			t.Errorf("%s is stale: it differs from `keyorix docs %s` (first difference near %q). Run `make -C cli docs` and commit the result.",
				tc.file, tc.sub, firstDifference(string(want), got))
		}
	}
}

func firstDifference(a, b string) string {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	end := min(i+60, len(b))
	return b[max(i-20, 0):end]
}

// The generated text must not depend on who generates it: no home directory, no host.
func TestCLIReferenceHasNoMachineSpecificText(t *testing.T) {
	md := capture(t, "docs", "markdown")
	home, _ := os.UserHomeDir()
	for _, bad := range []string{home, os.TempDir(), "/Users/", "/home/runner"} {
		if bad != "" && bad != "/" && strings.Contains(md, bad) {
			t.Errorf("the reference contains the machine-specific text %q", bad)
		}
	}
}

// Every command a user can run has a section; nothing hidden leaks in.
func TestCLIReferenceCoversEveryCommand(t *testing.T) {
	md := capture(t, "docs", "markdown")
	man := capture(t, "docs", "man")
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			if s.Hidden || s.Name() == "help" {
				continue
			}
			if !strings.Contains(md, "## `"+s.CommandPath()+"`") {
				t.Errorf("reference has no section for %q", s.CommandPath())
			}
			if !strings.Contains(man, ".SS "+strings.ReplaceAll(s.CommandPath(), "-", "\\-")+"\n") {
				t.Errorf("man page has no section for %q", s.CommandPath())
			}
			walk(s)
		}
	}
	walk(rootCmd)
	if !strings.Contains(md, "## `keyorix secret get`") || !strings.Contains(md, "## `keyorix completion bash`") {
		t.Error("the walk missed well-known commands (secret get, completion bash)")
	}
}

// The three shells the brief names (plus PowerShell, which cobra also generates) get a
// completion script, and the script is valid for the shell when that shell is installed.
// The scripts are produced with the same cobra calls the `completion` subcommands make;
// those subcommands write to the stdout that was current when cobra first created them,
// which a test cannot redirect, and TestCLIReferenceCoversEveryCommand checks they exist.
func TestShellCompletionScripts(t *testing.T) {
	capture(t, "version") // builds the full tree the way the binary does
	for _, tc := range []struct {
		shell string
		gen   func(w *bytes.Buffer) error
		check []string // argv of a syntax check; the script is passed on stdin
	}{
		{"bash", func(w *bytes.Buffer) error { return rootCmd.GenBashCompletionV2(w, true) }, []string{"bash", "-n"}},
		{"zsh", func(w *bytes.Buffer) error { return rootCmd.GenZshCompletion(w) }, []string{"zsh", "-n"}},
		{"fish", func(w *bytes.Buffer) error { return rootCmd.GenFishCompletion(w, true) }, []string{"fish", "--no-execute"}},
		{"powershell", func(w *bytes.Buffer) error { return rootCmd.GenPowerShellCompletionWithDesc(w) }, nil},
	} {
		t.Run(tc.shell, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.gen(&buf); err != nil {
				t.Fatal(err)
			}
			script := buf.String()
			if len(script) < 500 || !strings.Contains(script, "keyorix") {
				t.Fatalf("%s completion script looks empty (%d bytes)", tc.shell, len(script))
			}
			if tc.check == nil {
				return
			}
			bin, err := exec.LookPath(tc.check[0])
			if err != nil {
				t.Skipf("%s is not installed; script generated but not syntax-checked", tc.check[0])
			}
			cmd := exec.Command(bin, tc.check[1:]...) // #nosec G204 -- fixed shell binary and flags from the test table
			cmd.Stdin = strings.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s rejects its completion script: %v\n%s", tc.shell, err, out)
			}
		})
	}
}

// Completion actually offers this CLI's commands and flags (what the script asks the
// binary for through cobra's hidden __complete command).
func TestCompletionOffersCommandsAndFlags(t *testing.T) {
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"__complete", "sec"}, []string{"secret"}},
		{[]string{"__complete", "secret", "li"}, []string{"list"}},
		{[]string{"__complete", "secret", "list", "--pro"}, []string{"--project"}},
		{[]string{"__complete", "docs", ""}, []string{"markdown", "man"}},
	}
	for _, tc := range cases {
		out := capture(t, tc.args...)
		for _, w := range tc.want {
			if !strings.Contains(out, w+"\t") && !strings.Contains(out, w+"\n") {
				t.Errorf("keyorix %s: completion lacks %q:\n%s", strings.Join(tc.args, " "), w, out)
			}
		}
	}
}
