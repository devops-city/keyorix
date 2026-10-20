package journeys

// No build tag on purpose: this guard reads journey sources, needs no server or binaries, and
// so runs in the ordinary `go test` (the journeys themselves are //go:build e2e).

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Since #3325 the CLI refuses a secret given as a flag and reads it from a prompt, stdin, a
// file or a KEYORIX_* variable. The journeys used to pass secrets as flags behind
// KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1; that override is gone from the harness, and this guard
// keeps the flags out of the journey sources.
//
// The flag list is read from the CLI's own refusedSecretFlags table (cli/cmd/secretflags.go),
// so a flag the CLI starts refusing is guarded here without a second list to forget. The
// floor list below keeps the guard meaningful if that file is moved or reshaped: the test
// fails loudly if fewer flags are found than the floor, instead of passing on an empty set.
//
// What it does NOT cover: flags of other binaries (keyorix-migrate's --token / --vault-token in
// journey 4 are that tool's own and not part of #3325), a flag name assembled at run time, and
// the "--flag=value" spelling is covered only for the quoted-literal form ("--value=...").
const (
	secretFlagsSource = "../../../cli/cmd/secretflags.go"
	// refusalJourney is the one journey allowed to pass secret flags: it exists to prove the
	// refusal, its message and its exit code end to end.
	refusalJourney = "journey_cli_secret_flags_test.go"
	// allowMarker on a line exempts it (an output assertion that looks for a flag name in the
	// CLI's text, or a refusal check inside another journey). Say why after the marker.
	allowMarker = "secretflag:allow"
)

// floorSecretFlags are always guarded, whatever secretflags.go says.
var floorSecretFlags = []string{
	"value", "password", "mfa-code", "code", "current-password", "new-password",
	"admin-password", "bootstrap-token", "url",
}

var refusedFlagRowRE = regexp.MustCompile(`(?m)^\s*\{"[a-z][a-z -]*", "([a-z][a-z-]*)", `)

// guardedSecretFlags returns the flag names to keep out of journey sources.
func guardedSecretFlags(t *testing.T) []string {
	t.Helper()
	set := map[string]bool{}
	for _, f := range floorSecretFlags {
		set[f] = true
	}
	src, err := os.ReadFile(secretFlagsSource)
	if err != nil {
		t.Fatalf("read the CLI's refused-flag table %s: %v (the guard would otherwise run on its floor list only)", secretFlagsSource, err)
	}
	rows := refusedFlagRowRE.FindAllStringSubmatch(string(src), -1)
	if len(rows) < len(floorSecretFlags) {
		t.Fatalf("found %d rows in %s, want at least %d: the table's shape changed and this guard no longer reads it",
			len(rows), secretFlagsSource, len(floorSecretFlags))
	}
	for _, r := range rows {
		set[r[1]] = true
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// secretFlagLiteralRE builds a matcher for a quoted flag literal: "--value" or "--value=...".
func secretFlagLiteralRE(flags []string) *regexp.Regexp {
	return regexp.MustCompile(`"--(` + strings.Join(flags, "|") + `)(=[^"]*)?"`)
}

// secretFlagViolations returns "file:line: text" for every secret-flag literal in src that is
// not on a comment line and not marked with allowMarker.
func secretFlagViolations(name, src string, re *regexp.Regexp) []string {
	var out []string
	for i, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.Contains(line, allowMarker) {
			continue
		}
		if re.MatchString(line) {
			out = append(out, name+":"+strconv.Itoa(i+1)+": "+trimmed)
		}
	}
	return out
}

func TestJourneySourcesPassNoSecretAsFlag(t *testing.T) {
	re := secretFlagLiteralRE(guardedSecretFlags(t))
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	var bad []string
	for _, f := range files {
		if f == refusalJourney || f == "secret_flags_guard_test.go" {
			continue
		}
		src, err := os.ReadFile(f) // #nosec G304 -- the journeys' own source files, from Glob("*.go")
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		bad = append(bad, secretFlagViolations(f, string(src), re)...)
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d journey files: the guard would be vacuous", scanned)
	}
	if len(bad) > 0 {
		t.Errorf("a journey passes a secret as a command-line flag (the CLI refuses it since #3325). Use the helpers in helpers.go: "+
			"runCLISecret / runCLIRotate (stdin), withEnv with KEYORIX_PASSWORD / KEYORIX_MFA_CODE / KEYORIX_INITIAL_PASSWORD / "+
			"KEYORIX_CURRENT_PASSWORD / KEYORIX_NEW_PASSWORD. Only %s may use the flags, to prove the refusal:\n  %s",
			refusalJourney, strings.Join(bad, "\n  "))
	}
}

// TestSecretFlagGuardFires proves the matcher in both directions on in-memory sources: red on
// every spelling it must catch, green on the safe forms and on the exempt lines.
func TestSecretFlagGuardFires(t *testing.T) {
	re := secretFlagLiteralRE(guardedSecretFlags(t))
	red := []string{
		`runCLI(t, cliBin, env, "secret", "create", "--value", v)`,
		`runCLI(t, cliBin, env, "login", "--password", pw)`,
		`runCLI(t, cliBin, env, "login", "--mfa-code", c)`,
		`runCLI(t, cliBin, env, "mfa", "activate", "--code", c)`,
		`runCLI(t, cliBin, env, "change-password", "--new-password", pw)`,
		`runCLI(t, cliBin, env, "secret", "create", "--value=abc")`,
		`runCLI(t, cliBin, env, "notification", "channel", "add", "--url", u)`,
	}
	for _, line := range red {
		if v := secretFlagViolations("planted.go", line, re); len(v) != 1 {
			t.Errorf("not flagged (want 1 violation): %s", line)
		}
	}
	green := []string{
		`runCLISecret(t, cliBin, env, v, "secret", "create", "--name", n)`,
		`runCLI(t, cliBin, withEnv(env, "KEYORIX_PASSWORD="+pw), "login", "--username", u)`,
		`runCLI(t, cliBin, env, "secret", "create", "--from-file", "-")`,
		`runCLI(t, cliBin, env, "secret", "acl", "grant", "--secret", id)`,
		`// runCLI(t, cliBin, env, "login", "--password", pw) is what the old journey did`,
		`strings.Contains(out, "--mfa-code") /* secretflag:allow output assertion */`,
	}
	for _, line := range green {
		if v := secretFlagViolations("fine.go", line, re); len(v) != 0 {
			t.Errorf("flagged but safe: %s -> %v", line, v)
		}
	}
}
