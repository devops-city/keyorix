// docs_lock_claims_test.go -- DOCS-DRIFT-1: the operator docs' claim about the
// exclusive database-presence lock must match what the admin command's own help
// says. docs/CONFIGURATION.md called `admin encryption migrate-provider` "fast, no
// DB lock" while the command holds the lock for its whole run and refuses to run
// next to a live server (PROD-OPS-1 finding 7).
//
// The help text is the source of truth here: each admin command's Long says either
// "Holds this tree's exclusive database-presence lock" or "does NOT take" it. For
// every paragraph in the documents docsCmdDocs lists that names an `admin
// <command path>` of a command with such a statement, the paragraph must not deny
// the lock for a lock-holding command, and must not claim it for a read-only one.
//
// What it does NOT check: paragraphs that do not name the command in backticks, a
// claim phrased in a way the two patterns below do not know ("lock-free", "needs no
// lock"), and commands whose help says nothing about the lock (skipped, not
// guessed).
package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

var (
	// docsLockDenial: a doc paragraph saying the command takes no database lock.
	docsLockDenial = regexp.MustCompile(`(?i)\bno (db|database)([- ]presence)? lock|without (a |the )?(exclusive )?(db|database)([- ]presence)? lock|(does not|doesn't) (take|hold) (a |the )?(exclusive )?(db|database)([- ]presence)? lock`)
	// docsLockClaim: a doc paragraph saying the command holds the lock.
	docsLockClaim = regexp.MustCompile(`(?i)\b(holds|takes|acquires)\b[^.]{0,40}(db|database)([- ]presence)? lock`)
	// docsLockAdminCmd: `keyorix-server admin <path>` inside a backticked span or fence line.
	docsLockAdminCmd = regexp.MustCompile(`keyorix-server admin ((?:[a-z][a-z0-9-]*)(?: [a-z][a-z0-9-]*)*)`)
)

// docsLockHelpHolds reports whether cmd's help states the lock behaviour, and which.
func docsLockHelpHolds(cmd *cobra.Command) (holds, known bool) {
	text := cmd.Long
	switch {
	case strings.Contains(text, "does NOT take"):
		return false, true
	case strings.Contains(text, "exclusive database-presence lock"):
		return true, true
	}
	return false, false
}

// docsLockProblems checks one document's paragraphs against root's help text.
func docsLockProblems(root *cobra.Command, rel, doc string) []string {
	var problems []string
	line := 1
	for para := range strings.SplitSeq(doc, "\n\n") {
		start := line
		line += strings.Count(para, "\n") + 2
		flat := strings.Join(strings.Fields(strings.ReplaceAll(para, ">", " ")), " ")
		seen := map[string]bool{}
		for _, m := range docsLockAdminCmd.FindAllStringSubmatch(flat, -1) {
			words := strings.Fields(m[1])
			// Longest prefix of words that resolves to a real command.
			for n := len(words); n > 0; n-- {
				cmd, _, err := root.Find(words[:n])
				if err != nil || cmd == root || cmd.CommandPath() == "" || len(strings.Fields(strings.TrimPrefix(cmd.CommandPath(), root.CommandPath()))) != n {
					continue
				}
				name := strings.Join(words[:n], " ")
				if seen[name] {
					break
				}
				seen[name] = true
				holds, known := docsLockHelpHolds(cmd)
				if !known {
					break
				}
				if holds && docsLockDenial.MatchString(flat) {
					problems = append(problems, rel+":"+strconv.Itoa(start)+": `admin "+name+"` holds the exclusive database-presence lock (its help says so) but the doc denies a database lock")
				}
				if !holds && docsLockClaim.MatchString(flat) {
					problems = append(problems, rel+":"+strconv.Itoa(start)+": `admin "+name+"` is read-only and takes no database-presence lock (its help says so) but the doc says it holds one")
				}
				break
			}
		}
	}
	return problems
}

// Deliberately NOT t.Parallel(): cobra's lazily built flag sets are an
// unsynchronized write (see TestDocsServerCommandsExist).
func TestDocsLockClaimsMatchCommandHelp(t *testing.T) {
	// The help texts the check reads must still carry a statement, else it is vacuous.
	for _, path := range [][]string{{"encryption", "migrate-provider"}, {"encryption", "status"}} {
		cmd, _, err := rootCmd.Find(path)
		if err != nil || cmd == rootCmd {
			t.Fatalf("admin %s not found: the check has drifted", strings.Join(path, " "))
		}
		if _, known := docsLockHelpHolds(cmd); !known {
			t.Fatalf("admin %s's help no longer states its lock behaviour: the check has nothing to compare", strings.Join(path, " "))
		}
	}
	for _, rel := range docsCmdDocs(t) {
		b, err := os.ReadFile(filepath.Join(adminDocRepoRoot(t), filepath.FromSlash(rel))) // #nosec G304 -- fixed repo-relative paths
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, p := range docsLockProblems(rootCmd, rel, string(b)) {
			t.Error(p)
		}
	}
}

// TestDocsLockClaimsCheckCatchesPlantedError is the red proof: the wrong sentence
// that was in CONFIGURATION.md is reported, the corrected one is not, and the
// opposite error (a read-only command said to hold the lock) is reported too.
func TestDocsLockClaimsCheckCatchesPlantedError(t *testing.T) {
	wrong := "Switching providers is `keyorix-server admin encryption migrate-provider --confirm`: fast, no DB lock.\n"
	if p := docsLockProblems(rootCmd, "planted.md", wrong); len(p) != 1 {
		t.Errorf("planted denial of the lock not reported exactly once: %v", p)
	}
	right := "Switching providers is `keyorix-server admin encryption migrate-provider --confirm`. It holds the exclusive\ndatabase-presence lock for its whole run: stop the servers first.\n"
	if p := docsLockProblems(rootCmd, "good.md", right); len(p) != 0 {
		t.Errorf("correct sentence reported: %v", p)
	}
	inverse := "`keyorix-server admin encryption status` holds the exclusive database-presence lock while it reads.\n"
	if p := docsLockProblems(rootCmd, "inverse.md", inverse); len(p) != 1 {
		t.Errorf("planted lock claim on a read-only command not reported exactly once: %v", p)
	}
}
