package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryServerCommandNamedInAMessageExists: every `keyorix-server admin ...` command (and
// flag) that a string literal of the repository's Go code tells an operator to run exists in
// the admin command tree. The CLI side (`keyorix ...`) is cli/cmd/cmdrefs_guard_test.go.
func TestEveryServerCommandNamedInAMessageExists(t *testing.T) {
	checkCommandRefs(t, cmdRefsRepoRoot(t), rootCmd, "keyorix-server admin", cmdRefsKnownStale)
}

// cmdRefsKnownStale lists references that are real although the cobra tree cannot show it.
var cmdRefsKnownStale = map[string]string{
	"keyorix-server admin version": "answered by Execute before cobra, on purpose (see Execute)",
}

// The checker exists twice because the CLI module and the main module cannot import each
// other; the copies must not drift.
func TestCmdRefsCheckerCopiesAreIdentical(t *testing.T) {
	root := cmdRefsRepoRoot(t)
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Replace(string(b), "package cmd\n", "package admin\n", 1)
	}
	if read("cli/cmd/cmdrefs_check_test.go") != read("server/admin/cmdrefs_check_test.go") {
		t.Error("cli/cmd/cmdrefs_check_test.go and server/admin/cmdrefs_check_test.go differ: " +
			"edit one and copy it over the other (only the package clause may differ)")
	}
}
