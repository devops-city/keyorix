package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// relativeSentinel is what every NAME_FILE is set to: a relative path that is
// exactly what an operator who mistook NAME_FILE for NAME would type. No error
// and no stderr line may print it (SECRETENV-REVIEW-1 F4; Andrei's decision
// secretenv-relative-file-path-echo, option a).
const relativeSentinel = "SENTINEL-secret-value-do-not-print"

var relativeFailureModes = []struct {
	name    string
	prepare func(t *testing.T, p string)
}{
	{"missing", func(*testing.T, string) {}},
	{"unreadable", func(t *testing.T, p string) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-000 file")
		}
		writeModeFile(t, p, "x\n", 0o000)
	}},
	{"empty", func(t *testing.T, p string) { writeModeFile(t, p, "", 0o600) }},
	{"directory", func(t *testing.T, p string) {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}},
	{"too-open", func(t *testing.T, p string) { writeModeFile(t, p, "x\n", 0o644) }},
}

func writeModeFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func notShownCLI(name string) string {
	return name + "_FILE (" + relativeSecretPathNotShown + ")"
}

// discoverCLISecretFileVars returns every NAME passed to lookupSecretEnv in the
// cli module's non-test source (not a hand list). A computed name fails the
// test: it could not be discovered, so it could not be covered.
func discoverCLISecretFileVars(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..") // the cli module root (tests run in cli/cmd)
	names := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		af, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != "lookupSecretEnv" || len(call.Args) != 1 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				t.Errorf("%s: lookupSecretEnv with a computed name; spell the variable name as a literal so the relative-sentinel test covers it", fset.Position(call.Pos()))
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err == nil {
				names[s] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out := slices.Sorted(maps.Keys(names))
	if len(out) < 5 {
		t.Fatalf("discovered only %v from lookupSecretEnv calls: the scan is broken", out)
	}
	return out
}

// TestLookupSecretEnv_RelativeFileValueNeverEchoed sets each NAME_FILE the CLI
// reads to the relative sentinel, in every failure mode, and asserts the error
// names the variable with the not-shown text and never prints the value.
func TestLookupSecretEnv_RelativeFileValueNeverEchoed(t *testing.T) {
	names := discoverCLISecretFileVars(t)
	t.Logf("variables: %v", names)
	for _, mode := range relativeFailureModes {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			mode.prepare(t, filepath.Join(dir, relativeSentinel))
			for _, n := range names {
				t.Setenv(n, "")
				t.Setenv(n+"_FILE", relativeSentinel)
				_, _, err := lookupSecretEnv(n)
				if err == nil {
					t.Errorf("lookupSecretEnv(%s) accepted a %s file", n, mode.name)
					continue
				}
				if strings.Contains(err.Error(), relativeSentinel) {
					t.Errorf("lookupSecretEnv(%s) printed the relative value: %v", n, err)
				}
				if !strings.Contains(err.Error(), notShownCLI(n)) {
					t.Errorf("lookupSecretEnv(%s): error does not say %q: %v", n, notShownCLI(n), err)
				}
			}
		})
	}
	t.Run("absolute path still shown", func(t *testing.T) {
		abs := filepath.Join(t.TempDir(), "missing")
		t.Setenv("KEYORIX_TOKEN", "")
		t.Setenv("KEYORIX_TOKEN_FILE", abs)
		if _, _, err := lookupSecretEnv("KEYORIX_TOKEN"); err == nil || !strings.Contains(err.Error(), strconv.Quote(abs)) {
			t.Errorf("an absolute NAME_FILE must stay visible: %v", err)
		}
	})
}

// cliCommandFor is the command line that reads name, derived from the refused
// secret-flag table (each row says which NAME[_FILE] replaces the flag), plus
// KEYORIX_TOKEN, which every API command reads. cliDrive adds what a command
// needs to get as far as reading the variable: its required flags, and the
// variables it reads first.
func cliCommandFor(t *testing.T, name string) (args []string, env map[string]string) {
	t.Helper()
	if name == "KEYORIX_TOKEN" {
		return []string{"project", "list"}, nil
	}
	if d, ok := cliDrive[name]; ok && d.command != "" {
		return d.args(), d.env
	}
	re := regexp.MustCompile(`\b` + name + `_FILE\b`)
	for _, f := range refusedSecretFlags {
		if re.MatchString(f.Instead) {
			d := cliDrive[name]
			d.command = f.Command
			return d.args(), d.env
		}
	}
	t.Fatalf("no command in refusedSecretFlags reads %s_FILE; add the variable to the table or to cliDrive", name)
	return nil, nil
}

type cliDriver struct {
	command string // overrides the refusedSecretFlags row
	extra   []string
	env     map[string]string
}

func (d cliDriver) args() []string { return append(strings.Fields(d.command), d.extra...) }

var (
	systemInitArgs = []string{"--server", "http://127.0.0.1:1", "--admin-username", "admin", "--admin-email", "a@example.invalid"}
	cliDrive       = map[string]cliDriver{
		"KEYORIX_PASSWORD":         {extra: []string{"--username", "admin"}},
		"KEYORIX_MFA_CODE":         {command: "mfa stepup"}, // login reads it only once the server asks for a second factor
		"KEYORIX_NEW_PASSWORD":     {env: map[string]string{"KEYORIX_CURRENT_PASSWORD": "current-password-1"}},
		"KEYORIX_ADMIN_PASSWORD":   {extra: systemInitArgs, env: map[string]string{"KEYORIX_BOOTSTRAP_TOKEN": "bootstrap-token-1"}},
		"KEYORIX_BOOTSTRAP_TOKEN":  {extra: systemInitArgs, env: map[string]string{"KEYORIX_ADMIN_PASSWORD": "admin-password-1"}},
		"KEYORIX_INITIAL_PASSWORD": {extra: []string{"--username", "sentinel-user", "--email", "s@example.invalid"}},
	}
)

// TestRefusedSecretFlagFileVarsAreRead: every NAME_FILE the refusal of a secret
// flag tells the user to set is actually read through lookupSecretEnv (found
// with KEYORIX_INITIAL_PASSWORD_FILE, which `user create` advertised but never
// read), so the relative-sentinel tests cover it.
func TestRefusedSecretFlagFileVarsAreRead(t *testing.T) {
	read := discoverCLISecretFileVars(t)
	re := regexp.MustCompile(`\b([A-Z][A-Z0-9_]*)_FILE\b`)
	for _, f := range refusedSecretFlags {
		for _, m := range re.FindAllStringSubmatch(f.Instead, -1) {
			if !slices.Contains(read, m[1]) {
				t.Errorf("keyorix %s --%s tells the user to set %s_FILE, but no lookupSecretEnv(%q) reads it", f.Command, f.Flag, m[1], m[1])
			}
		}
	}
}

// TestCLI_RelativeFileValueNeverEchoed runs the real command that reads each
// discovered NAME_FILE (through Run, the binary's entry point, so cobra's error
// printing and every wrapper are included) with the relative sentinel, in every
// failure mode, and asserts stderr names the variable with the not-shown text
// and never prints the value.
func TestCLI_RelativeFileValueNeverEchoed(t *testing.T) {
	names := discoverCLISecretFileVars(t)
	for _, mode := range relativeFailureModes {
		t.Run(mode.name, func(t *testing.T) {
			for _, n := range names {
				t.Run(n, func(t *testing.T) {
					isolateCredentials(t)
					dir := t.TempDir()
					t.Chdir(dir)
					mode.prepare(t, filepath.Join(dir, relativeSentinel))
					t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1")
					if n != "KEYORIX_TOKEN" {
						t.Setenv("KEYORIX_TOKEN", "kx_sentinel_test_token")
					}
					t.Setenv(n, "")
					t.Setenv(n+"_FILE", relativeSentinel)
					args, env := cliCommandFor(t, n)
					for k, v := range env {
						t.Setenv(k, v)
					}
					resetCommandFlags(t, args)
					code, stderr := runCLIForTest(t, args...)
					if code == 0 {
						t.Fatalf("keyorix %s succeeded with a %s %s_FILE", strings.Join(args, " "), mode.name, n)
					}
					if strings.Contains(stderr, relativeSentinel) {
						t.Errorf("keyorix %s printed the relative %s_FILE value:\n%s", strings.Join(args, " "), n, stderr)
					}
					if !strings.Contains(stderr, notShownCLI(n)) {
						t.Errorf("keyorix %s: stderr does not say %q (the command never read %s_FILE?):\n%s", strings.Join(args, " "), notShownCLI(n), n, stderr)
					}
				})
			}
		})
	}
}

// TestDescribeSecretFile_MatchesSecretenv holds this module's copy of the
// not-shown text to internal/secretenv's (read from the source: the cli module
// cannot import the main module, ADR-108 A).
func TestDescribeSecretFile_MatchesSecretenv(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "secretenv", "describe.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const RelativePathNotShown = (".*")`).FindSubmatch(src)
	if m == nil {
		t.Fatal("internal/secretenv/describe.go no longer declares RelativePathNotShown")
	}
	want, err := strconv.Unquote(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if relativeSecretPathNotShown != want {
		t.Errorf("relativeSecretPathNotShown = %q, internal/secretenv says %q", relativeSecretPathNotShown, want)
	}
	if got := describeSecretFile("X_FILE", "/run/secrets/x"); got != `X_FILE="/run/secrets/x"` {
		t.Errorf("absolute: %s", got)
	}
	if got := describeSecretFile("X_FILE", "./x"); got != "X_FILE ("+want+")" {
		t.Errorf("relative: %s", got)
	}
}

// resetCommandFlags puts the flags of the command args names back to their
// defaults (and not Changed) before and after the run: rootCmd is shared by the
// whole package, and an earlier test's --password would otherwise still count as
// given.
func resetCommandFlags(t *testing.T, args []string) {
	t.Helper()
	c, _, err := rootCmd.Find(args)
	if err != nil {
		t.Fatal(err)
	}
	reset := func() {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				_ = sv.Replace(nil) // Set would append to a slice
			} else {
				_ = f.Value.Set(f.DefValue)
			}
			f.Changed = false
		})
	}
	reset()
	t.Cleanup(reset)
}
