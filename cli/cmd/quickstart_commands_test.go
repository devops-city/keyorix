// quickstart_commands_test.go -- QUICK_START.md, server/entrypoint.sh, and
// deploy/helm/keyorix/templates/NOTES.txt each make promises about what `keyorix
// ...` commands exist. Ported from the old CLI's internal/cli/quickstart_commands_test.go
// (deleted alongside this file landing -- QUICK_START.md no longer documents old-CLI
// syntax, so that test would extract zero invocations and fail its own "did the
// extractor break" guard) for the Phase 5 switch (ADR-108): this module IS the CLI that
// ships as `keyorix` now, so this is where the check belongs.
//
// Two independent claims, two independent extractors:
//   - QUICK_START.md: every `./bin/keyorix ...` line inside a fenced code block (the
//     doc's own "commands are meant to be copy-pasteable" convention).
//   - entrypoint.sh / NOTES.txt: every backtick-quoted `keyorix ...` span. These files
//     are prose (a shell script's echo strings, a Helm NOTES.txt), not runnable
//     examples -- backticks are the convention this test relies on to find the claims
//     worth checking; a `keyorix ...` command mentioned outside backticks is invisible
//     to it.
//
// `keyorix-server admin ...` mentions are a DIFFERENT command tree (package
// server/admin, a different Go module's dependency graph entirely -- this module
// must not import it, per cli/internal/depguard) -- server/admin/quickstart_commands_test.go
// is the sibling check for those.
//
// Scope, stated so a green run is not read as more than it is: this verifies that
// commands and flags EXIST. It does not run them, does not check flag values or
// argument counts, and says nothing about whether the surrounding prose is true.
// scripts/smoke.sh is the executing counterpart -- it runs the documented flow
// against a real built binary. Neither mechanism is sufficient alone.
//
// See CLAUDE.md, "Core principle: prefer the machine-checked over the asserted."
package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// cobraBuiltinFlags are added by cobra at Execute time, not at registration, so
// they are absent from the tree a test inspects. They are valid in the doc.
var cobraBuiltinFlags = map[string]bool{"help": true, "version": true}

// tokenize splits a shell-ish command line, honouring single and double quotes
// so that a value containing spaces does not become two tokens.
func tokenize(line string) []string {
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

// repoRoot resolves the repository root from this test's own package directory
// (cli/cmd), independent of the module boundary between cli/ and the root module --
// the files this test reads (QUICK_START.md, server/entrypoint.sh, NOTES.txt) live
// outside this Go module entirely; plain file I/O doesn't care.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..")
}

// quickStartInvocations extracts every `./bin/keyorix ...` invocation from a fenced
// code block in QUICK_START.md, excluding `./bin/keyorix-server` lines.
func quickStartInvocations(t *testing.T) [][]string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "QUICK_START.md")
	b, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	// Join `\`-continued lines into one logical line.
	joined := strings.ReplaceAll(string(b), "\\\n", " ")

	var out [][]string
	inFence := false
	for _, line := range strings.Split(joined, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i]) // strip trailing shell comments
		}
		const bin = "./bin/keyorix"
		i := strings.Index(line, bin)
		if i < 0 || strings.HasPrefix(line[i:], bin+"-server") {
			continue
		}
		toks := tokenize(line[i+len(bin):])
		if len(toks) == 0 {
			continue
		}
		out = append(out, toks)
	}
	return out
}

// backtickKeyorixRe matches a backtick-quoted span starting with `keyorix ` (a
// literal space, so `keyorix-server ...` never matches -- that's the sibling
// check's job).
var backtickKeyorixRe = regexp.MustCompile("`keyorix ([^`]+)`")

// deploymentDocInvocations extracts every backtick-quoted `keyorix ...` command
// mention from the given repo-relative files (server/entrypoint.sh,
// deploy/helm/keyorix/templates/NOTES.txt).
func deploymentDocInvocations(t *testing.T, relFiles []string) [][]string {
	t.Helper()
	var out [][]string
	for _, rel := range relFiles {
		path := filepath.Join(repoRoot(t), rel)
		b, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative paths
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range backtickKeyorixRe.FindAllStringSubmatch(string(b), -1) {
			// entrypoint.sh writes the backticks as \` inside double-quoted echo
			// strings, so the span captures a trailing backslash.
			toks := tokenize(strings.TrimSuffix(m[1], `\`))
			if len(toks) == 0 {
				continue
			}
			out = append(out, toks)
		}
	}
	return out
}

// assertInvocationsResolve is shared by both extractors: every command's leading
// non-flag tokens must resolve to a real cobra command under root, and every
// `--flag` token must be a real flag on that command.
func assertInvocationsResolve(t *testing.T, root *cobra.Command, invocations [][]string, source string) {
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
			continue // bare `keyorix --help`
		}

		// cobra's Find does NOT error on an unresolvable trailing segment -- it silently
		// returns the deepest command it COULD match and hands back the rest as
		// leftover args (e.g. Find(["system","init"]) against a tree with no "init"
		// under "system" returns the "system" command itself, remaining=["init"], err=nil).
		// A non-empty remainder means the path did not fully resolve to a real command,
		// not that it did -- checking only cmd/err (as this test's first version did)
		// missed exactly this case.
		//
		// BUT a non-empty remainder is not automatically wrong: a leaf command with a
		// positional argument (e.g. `machine grant-role <name|id> --role R`, mirroring
		// `machine describe <name|id>`) legitimately leaves its positional value in
		// `remaining` -- Find has no way to know that token isn't a missing subcommand
		// name. Distinguish the two: if the resolved command has no subcommands of its
		// own (nothing else remaining COULD have matched) and its own Args validator
		// accepts the leftover tokens as positional arguments, this is a real,
		// documented invocation, not a typo/rename.
		cmd, remaining, err := root.Find(path)
		unresolved := err != nil || cmd == nil || cmd == root || len(remaining) > 0
		if unresolved && cmd != nil && cmd != root && len(remaining) > 0 && !cmd.HasSubCommands() && cmd.Args != nil {
			if cmd.Args(cmd, remaining) == nil {
				unresolved = false
			}
		}
		if unresolved {
			t.Errorf("%s documents `keyorix %s`, which is not a command (cobra: %v, unresolved: %v). "+
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
			if name == "" || cobraBuiltinFlags[name] {
				continue
			}
			if lookupFlag(cmd, name) == nil {
				t.Errorf("%s uses `--%s` with `keyorix %s`, but that command has no such flag.",
					source, name, strings.Join(path, " "))
			}
		}
	}
}

// TestQuickStartCommandsExist is the guard described in this file's header.
//
// Deliberately NOT t.Parallel(): this and TestDeploymentDocsReferenceRealCommands
// both call lookupFlag -> cmd.InheritedFlags() against the same package-level
// rootCmd tree. cobra/pflag lazily build and cache each command's inherited-flag
// set on first access (an unsynchronized write into the *cobra.Command's own
// fields) -- two goroutines racing that lazy init on the same tree is a genuine
// data race (caught by CI's `cli` job, which runs `go test -race`), not a false
// positive to silence. These two tests are fast, doc-parsing checks with nothing
// to gain from running concurrently with each other.
func TestQuickStartCommandsExist(t *testing.T) {
	invocations := quickStartInvocations(t)
	// A doc that stopped containing commands, or an extractor that stopped
	// matching them, would make this test silently vacuous. Both are failures.
	if len(invocations) < 8 {
		t.Fatalf("extracted only %d ./bin/keyorix invocations from QUICK_START.md; expected at least 8. "+
			"Either the examples were removed (they are the point of the page) or the extractor "+
			"has drifted and this guard is no longer checking anything", len(invocations))
	}
	assertInvocationsResolve(t, rootCmd, invocations, "QUICK_START.md")
}

// TestDeploymentDocsReferenceRealCommands is decision #1's guard (Phase 5 switch,
// ADR-108): no instruction in server/entrypoint.sh or the Helm NOTES.txt may point
// at a `keyorix ...` command the shipped binary doesn't have.
// Deliberately NOT t.Parallel() -- see TestQuickStartCommandsExist's comment.
func TestDeploymentDocsReferenceRealCommands(t *testing.T) {
	files := []string{"server/entrypoint.sh", "deploy/helm/keyorix/templates/NOTES.txt"}
	invocations := deploymentDocInvocations(t, files)
	if len(invocations) == 0 {
		t.Fatalf("extracted zero backtick-quoted `keyorix ...` mentions from %v; expected at least one. "+
			"Either the mentions were removed or the extractor has drifted and this guard is no "+
			"longer checking anything", files)
	}
	assertInvocationsResolve(t, rootCmd, invocations, strings.Join(files, ", "))
}

// lookupFlag resolves a flag against a command's own, persistent, and inherited
// sets, plus the root's persistent flags.
func lookupFlag(cmd *cobra.Command, name string) *pflag.Flag {
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
