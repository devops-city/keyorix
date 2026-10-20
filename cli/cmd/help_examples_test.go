package cmd

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// leafCommands returns every runnable leaf below root, excluding cobra's own
// generated `help` and `completion` trees, and its hidden `__complete` /
// `__completeNoDesc` commands (added to rootCmd by any test that exercises shell
// completion, so their presence depends on test order).
func leafCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root && (c.Name() == "help" || c.Name() == "completion" ||
			c.Name() == cobra.ShellCompRequestCmd || c.Name() == cobra.ShellCompNoDescRequestCmd) {
			return
		}
		if !c.HasAvailableSubCommands() {
			out = append(out, c)
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	return out
}

func commandKey(c *cobra.Command) string {
	return strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ")
}

// splitExampleLine splits one example line into words, honouring double quotes, and
// drops a trailing shell redirect ("> file").
func splitExampleLine(line string) []string {
	var words []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote, have = !inQuote, true
		case r == ' ' && !inQuote:
			if have {
				words = append(words, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		words = append(words, cur.String())
	}
	for i, w := range words {
		if w == ">" {
			return words[:i]
		}
	}
	return words
}

// flagsThatCarrySecrets are the flags no example may demonstrate: a secret value on
// the command line ends up in shell history and `ps` output.
var flagsThatCarrySecrets = map[string]bool{
	"value": true, "password": true, "current-password": true, "new-password": true,
	"admin-password": true, "bootstrap-token": true, "mfa-code": true, "code": true,
}

// TestHelpExamples_EveryLeafHasAValidExample is the guard behind helpExamples: it
// fails when a command is added without an example, when an entry outlives its
// command, and when an example uses a flag the command no longer has (or hands a
// secret to the command line).
func TestHelpExamples_EveryLeafHasAValidExample(t *testing.T) {
	applyHelpExamples()

	leaves := leafCommands(rootCmd)
	if len(leaves) < 200 {
		t.Fatalf("only %d leaf commands found; the walk is broken", len(leaves))
	}
	known := map[string]bool{}
	for _, c := range leaves {
		key := commandKey(c)
		known[key] = true
		if strings.TrimSpace(c.Example) == "" {
			t.Errorf("%q has no Example: add it to helpExamples (help_examples.go)", key)
			continue
		}
		for line := range strings.SplitSeq(c.Example, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			words := splitExampleLine(line)
			if len(words) == 0 || words[0] != "keyorix" {
				// A command's own hand-written Example may show other tools.
				if _, ours := helpExamples[key]; ours {
					t.Errorf("%q example line must start with \"keyorix\": %q", key, line)
				}
				continue
			}
			found, _, err := rootCmd.Find(words[1:])
			if err != nil || found != c {
				t.Errorf("%q example runs a different command (%v): %q", key, found.CommandPath(), line)
				continue
			}
			for _, w := range words[1:] {
				if w == "--" {
					break
				}
				if !strings.HasPrefix(w, "--") {
					continue
				}
				name, _, _ := strings.Cut(strings.TrimPrefix(w, "--"), "=")
				f := c.Flags().Lookup(name)
				if f == nil {
					f = c.InheritedFlags().Lookup(name)
				}
				if f == nil {
					t.Errorf("%q example uses unknown flag --%s: %q", key, name, line)
				} else if f.Deprecated != "" {
					t.Errorf("%q example teaches the deprecated flag --%s (%s): %q", key, name, f.Deprecated, line)
				}
				if flagsThatCarrySecrets[name] {
					t.Errorf("%q example puts a secret on the command line (--%s): %q", key, name, line)
				}
			}
		}
	}

	var stale []string
	for key := range helpExamples {
		if !known[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("helpExamples has an entry for %q, which is not a command", key)
	}
}
