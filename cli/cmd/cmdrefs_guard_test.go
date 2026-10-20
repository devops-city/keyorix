package cmd

import "testing"

// TestEveryCommandNamedInAMessageExists: an operator-visible message that says "run
// `keyorix encryption rotate --confirm`" is a promise. This sweep reads every string
// literal of the repository's Go code and checks each `keyorix ...` command it names
// (in backticks or single quotes) against the real command tree of the CLI, flags
// included. The server side (`keyorix-server admin ...`) is checked by
// server/admin/cmdrefs_guard_test.go with the same checker (cmdrefs_check_test.go is
// byte-identical in both packages apart from the package clause; the server copy's
// TestCmdRefsCheckerCopiesAreIdentical fails when they drift).
func TestEveryCommandNamedInAMessageExists(t *testing.T) {
	root := cmdRefsRepoRoot(t)
	checkCommandRefs(t, root, rootCmd, "keyorix", cmdRefsKnownStale)
}

// cmdRefsKnownStale lists references that are deliberately not live commands (for example
// a message that says a command was removed). Every entry says why; none today.
var cmdRefsKnownStale = map[string]string{}
