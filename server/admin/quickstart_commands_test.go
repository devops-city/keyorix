// quickstart_commands_test.go -- sibling of cli/cmd/quickstart_commands_test.go for
// the `keyorix-server admin ...` command tree (Phase 5 switch, ADR-108). See that
// file's header for the full rationale; split across these two packages because
// `keyorix ...` and `keyorix-server admin ...` are different binaries with different
// cobra trees, and cli/ (a separate Go module, per cli/internal/depguard) must not
// import this package to check both from one place.
//
// Two independent claims, two independent extractors:
//   - QUICK_START.md: every `./bin/keyorix-server admin ...` line inside a fenced
//     code block.
//   - entrypoint.sh / NOTES.txt: every backtick-quoted `keyorix-server admin ...`
//     span.
//
// Scope, stated so a green run is not read as more than it is: this verifies that
// commands and flags EXIST. It does not run them, does not check flag values or
// argument counts, and says nothing about whether the surrounding prose is true.
package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var adminDocCobraBuiltinFlags = map[string]bool{"help": true, "version": true}

// adminDocTokenize splits a shell-ish command line, honouring single and double
// quotes so a value containing spaces does not become two tokens.
func adminDocTokenize(line string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func adminDocRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..")
}

const adminBin = "./bin/keyorix-server admin"

// quickStartAdminInvocations extracts every `./bin/keyorix-server admin ...`
// invocation from a fenced code block in QUICK_START.md.
func quickStartAdminInvocations(t *testing.T) [][]string {
	t.Helper()
	return adminBinInvocations(t, "QUICK_START.md", true)
}

// adminBinInvocations extracts every `./bin/keyorix-server admin ...` invocation
// from the repo-relative file rel: from fenced code blocks only when fencedOnly
// (Markdown, including fences inside a `> ` blockquote), or from every line (a
// shell script).
func adminBinInvocations(t *testing.T, rel string, fencedOnly bool) [][]string {
	t.Helper()
	path := filepath.Join(adminDocRepoRoot(t), rel)
	b, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	joined := strings.ReplaceAll(string(b), "\\\n", " ")

	var out [][]string
	inFence := false
	for _, line := range strings.Split(joined, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimSpace(strings.TrimPrefix(line, ">")) // a fence inside a blockquote
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if fencedOnly && !inFence {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		i := strings.Index(line, adminBin)
		if i < 0 {
			continue
		}
		toks := adminDocTokenize(line[i+len(adminBin):])
		if len(toks) == 0 {
			continue
		}
		out = append(out, toks)
	}
	return out
}

// backtickKeyorixServerAdminRe matches a backtick-quoted span starting with
// `keyorix-server admin `.
var backtickKeyorixServerAdminRe = regexp.MustCompile("`keyorix-server admin ([^`]+)`")

// deploymentDocAdminInvocations extracts every backtick-quoted
// `keyorix-server admin ...` command mention from the given repo-relative files.
func deploymentDocAdminInvocations(t *testing.T, relFiles []string) [][]string {
	t.Helper()
	var out [][]string
	for _, rel := range relFiles {
		path := filepath.Join(adminDocRepoRoot(t), rel)
		b, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative paths
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range backtickKeyorixServerAdminRe.FindAllStringSubmatch(string(b), -1) {
			toks := adminDocTokenize(m[1])
			if len(toks) == 0 {
				continue
			}
			out = append(out, toks)
		}
	}
	return out
}

func assertAdminInvocationsResolve(t *testing.T, root *cobra.Command, invocations [][]string, source string) {
	t.Helper()
	for _, toks := range invocations {
		var path []string
		for _, tk := range toks {
			if strings.HasPrefix(tk, "-") {
				break
			}
			path = append(path, tk)
		}
		if len(path) == 0 {
			continue // bare `keyorix-server admin --help`
		}

		// cobra's Find does NOT error on an unresolvable trailing segment -- see
		// cli/cmd/quickstart_commands_test.go's sibling comment for the exact failure
		// mode this remaining-args check catches that a bare cmd/err check misses.
		cmd, remaining, err := root.Find(path)
		if err != nil || cmd == nil || len(remaining) > 0 {
			t.Errorf("%s documents `keyorix-server admin %s`, which is not a command (cobra: %v, unresolved: %v). "+
				"Fix the doc, or the command was renamed and the doc was not updated.",
				source, strings.Join(path, " "), err, remaining)
			continue
		}

		for _, tk := range toks {
			if !strings.HasPrefix(tk, "--") {
				continue
			}
			name := strings.TrimPrefix(tk, "--")
			if i := strings.Index(name, "="); i >= 0 {
				name = name[:i]
			}
			if name == "" || adminDocCobraBuiltinFlags[name] {
				continue
			}
			if adminLookupFlag(cmd, name) == nil {
				t.Errorf("%s uses `--%s` with `keyorix-server admin %s`, but that command has no such flag.",
					source, name, strings.Join(path, " "))
			}
		}
	}
}

// TestQuickStartAdminCommandsExist checks every `./bin/keyorix-server admin ...`
// invocation QUICK_START.md documents against the real cobra tree.
//
// Deliberately NOT t.Parallel(): this and TestDeploymentDocsReferenceRealAdminCommands
// both resolve flags against the same package-level rootCmd tree via cobra's
// InheritedFlags(), which lazily builds and caches each command's inherited-flag
// set on first access (an unsynchronized write) -- two goroutines racing that
// lazy init on the same tree is a genuine data race, not a false positive
// (confirmed by the identical issue in cli/cmd/quickstart_commands_test.go,
// caught by CI's -race jobs). These are fast, doc-parsing checks with nothing
// to gain from running concurrently with each other.
func TestQuickStartAdminCommandsExist(t *testing.T) {
	invocations := quickStartAdminInvocations(t)
	if len(invocations) == 0 {
		t.Fatalf("extracted zero ./bin/keyorix-server admin invocations from QUICK_START.md; expected at " +
			"least one (system host setup). Either the examples were removed or the extractor has " +
			"drifted and this guard is no longer checking anything")
	}
	assertAdminInvocationsResolve(t, rootCmd, invocations, "QUICK_START.md")
}

// TestDeploymentDocsReferenceRealAdminCommands is decision #1's guard (Phase 5
// switch, ADR-108), the `keyorix-server admin` half: no instruction in
// server/entrypoint.sh or the Helm NOTES.txt may point at a
// `keyorix-server admin ...` command the shipped binary doesn't have.
//
// Unlike TestQuickStartAdminCommandsExist, this one does NOT hard-fail on zero
// matches: as of this writing, neither file has a legitimate reason to mention an
// on-host admin command (entrypoint.sh runs inside an already-built container;
// the Helm chart configures everything declaratively, no initContainer/Job calls
// `admin init`/`admin migrate`) -- both bootstrap over the network instead, which
// cli/cmd's sibling test covers. A hard-fail here would be a guard with nothing to
// guard, exactly the vacuous-check trap CLAUDE.md warns about. Skipping on zero
// does cost something, stated plainly: it can no longer catch the extractor itself
// silently breaking, only a real future `keyorix-server admin ...` mention that's
// wrong. The moment either file legitimately grows one, this starts checking it.
// Deliberately NOT t.Parallel() -- see TestQuickStartAdminCommandsExist's comment.
func TestDeploymentDocsReferenceRealAdminCommands(t *testing.T) {
	files := []string{"server/entrypoint.sh", "deploy/helm/keyorix/templates/NOTES.txt"}
	invocations := deploymentDocAdminInvocations(t, files)
	if len(invocations) == 0 {
		t.Skipf("no backtick-quoted `keyorix-server admin ...` mentions in %v -- expected today (see "+
			"this test's doc comment); this guard activates the moment one is added", files)
	}
	assertAdminInvocationsResolve(t, rootCmd, invocations, strings.Join(files, ", "))
}

// adminLookupFlag resolves a flag against a command's own, persistent, and
// inherited sets, plus the root's persistent flags.
func adminLookupFlag(cmd *cobra.Command, name string) *pflag.Flag {
	for _, set := range []*pflag.FlagSet{
		cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags(), rootCmd.PersistentFlags(),
	} {
		if set == nil {
			continue
		}
		if f := set.Lookup(name); f != nil {
			return f
		}
	}
	return nil
}

// TestInstallWithAIAdminCommandsExist is TestQuickStartAdminCommandsExist for the
// secret-blind install procedure (INSTALL-WITH-AI.md, including its HUMAN STEP
// blockquotes) and its script form (docs/install/offline-install.sh): an assistant
// follows these literally, so a renamed command or flag must fail here.
// Deliberately NOT t.Parallel() -- see TestQuickStartAdminCommandsExist.
func TestInstallWithAIAdminCommandsExist(t *testing.T) {
	for _, src := range []struct {
		rel        string
		fencedOnly bool
		min        int // generate-secrets, init, encryption init, migrate, recovery-key rotate x2, validate x2
	}{
		{"INSTALL-WITH-AI.md", true, 8},
		{"docs/install/offline-install.sh", false, 8},
	} {
		invocations := adminBinInvocations(t, src.rel, src.fencedOnly)
		if len(invocations) < src.min {
			t.Fatalf("extracted only %d ./bin/keyorix-server admin invocations from %s; expected at least %d "+
				"(the extractor has drifted, or the steps were removed)", len(invocations), src.rel, src.min)
		}
		assertAdminInvocationsResolve(t, rootCmd, invocations, src.rel)
	}
}
