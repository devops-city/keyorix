package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// testTree builds a cobra tree that exercises every shape the walker must
// handle: nesting, a persistent flag, a local flag, a hidden command, a hidden
// flag, a command group and a Long description with indented "Commands"-like lines.
func testTree() *cobra.Command {
	root := &cobra.Command{
		Use:  "tool",
		Long: "tool does things.\n\nExit codes:\n  0  success\n  1  failure\n\nExample Commands:\n  tool nothing   not a real section line\n",
	}
	root.PersistentFlags().String("ca-file", "", "trust this CA")
	root.AddGroup(&cobra.Group{ID: "core", Title: "Core Commands:"})

	secret := &cobra.Command{Use: "secret", Short: "Manage secrets", GroupID: "core"}
	get := &cobra.Command{Use: "get", Short: "Get one", Run: func(*cobra.Command, []string) {}}
	get.Flags().Int("id", 0, "ID")
	get.Flags().String("name", "", "name")
	get.Flags().Bool("secret-flag", false, "hidden")
	_ = get.Flags().MarkHidden("secret-flag")
	list := &cobra.Command{Use: "list", Short: "List", Run: func(*cobra.Command, []string) {}}
	list.Flags().BoolP("all", "a", false, "everything")
	secret.AddCommand(get, list)

	login := &cobra.Command{Use: "login", Short: "Log in", Run: func(*cobra.Command, []string) {}}
	login.Flags().String("server", "", "server URL")
	hidden := &cobra.Command{Use: "internal", Short: "x", Hidden: true, Run: func(*cobra.Command, []string) {}}

	root.AddCommand(secret, login, hidden)
	root.Version = "1.0" // adds --version, which must not be counted
	return root
}

// helpFor renders --help of the command at path from a fresh tree, the same
// text a built binary prints.
func helpFor(t *testing.T) helpFunc {
	t.Helper()
	return func(path []string) (string, error) {
		root := testTree()
		var buf bytes.Buffer
		root.SetOut(&buf)
		root.SetErr(&buf)
		root.SetArgs(append(append([]string{}, path...), "--help"))
		err := root.Execute()
		return buf.String(), err
	}
}

func TestWalkCobra_CountsCommandsAndFlags(t *testing.T) {
	got, err := walkCobra(helpFor(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cmd login",
		"cmd secret",
		"cmd secret get",
		"cmd secret list",
		"flag (root) --ca-file",
		"flag login --server",
		"flag secret get --id",
		"flag secret get --name",
		"flag secret list --all",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("walk mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestWalkCobra_StartsFromPrefix(t *testing.T) {
	got, err := walkCobra(helpFor(t), []string{"secret"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cmd get", "cmd list", "flag get --id", "flag get --name", "flag list --all"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

// The walker must not count cobra's own help/completion commands, the
// --help/--version flags, hidden commands or hidden flags, and must not read
// indented lines of a Long description as commands.
func TestWalkCobra_IgnoresBuiltinsHiddenAndLongText(t *testing.T) {
	got, err := walkCobra(helpFor(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range got {
		for _, bad := range []string{"help", "completion", "--version", "--help", "internal", "secret-flag", "nothing"} {
			if strings.Contains(line, bad) {
				t.Errorf("walk contains %q: %q", bad, line)
			}
		}
	}
}

// A refactor that renames or restructures a command must change the output,
// not be absorbed: removing one subcommand removes exactly its lines.
func TestWalkCobra_DetectsRemovedCommand(t *testing.T) {
	before, err := walkCobra(helpFor(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	pruned := func(path []string) (string, error) {
		root := testTree()
		for _, c := range root.Commands() {
			if c.Name() == "login" {
				root.RemoveCommand(c)
			}
		}
		var buf bytes.Buffer
		root.SetOut(&buf)
		root.SetErr(&buf)
		root.SetArgs(append(append([]string{}, path...), "--help"))
		err := root.Execute()
		return buf.String(), err
	}
	after, err := walkCobra(pruned, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(before)-len(after) != 2 { // "cmd login" and "flag login --server"
		t.Fatalf("expected exactly 2 fewer lines, got %d fewer\nbefore %q\nafter %q", len(before)-len(after), before, after)
	}
}

func TestWalkCobra_DepthGuard(t *testing.T) {
	endless := func(path []string) (string, error) {
		return "Usage:\n  tool [command]\n\nAvailable Commands:\n  again   loops forever\n", nil
	}
	if _, err := walkCobra(endless, nil); err == nil {
		t.Fatal("a tree that never ends must fail, not hang")
	}
}

func TestParseHelp_RealCobraGroupedAndPlain(t *testing.T) {
	text, err := helpFor(t)(nil)
	if err != nil {
		t.Fatal(err)
	}
	subs, flags := parseHelp(text)
	if !reflect.DeepEqual(subs, []string{"secret", "login"}) {
		t.Errorf("subs = %q (grouped command first, then ungrouped; builtins and hidden excluded)", subs)
	}
	// A persistent flag defined on the root is listed under the root's "Flags:".
	if !reflect.DeepEqual(flags, []string{"ca-file"}) {
		t.Errorf("flags = %q, want only ca-file (help and version excluded)", flags)
	}
}

func TestParseOpenAPI_PathsTimesMethods(t *testing.T) {
	spec := `
openapi: 3.0.0
paths:
  /a:
    parameters: [{name: x}]
    get: {}
    post: {}
  /b/{id}:
    summary: not an operation
    delete: {}
    x-internal: true
`
	got, err := parseOpenAPI([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DELETE /b/{id}", "GET /a", "POST /a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseProto_ServicesAndRPCs(t *testing.T) {
	src := `
syntax = "proto3";
// service Fake { rpc Nope(X) returns (Y); }
/* service Fake2 { rpc Nope2(X) returns (Y); } */
service Secrets {
  rpc Get(GetReq) returns (GetResp) { option (google.api.http) = { get: "/x" }; }
  rpc Watch(stream WatchReq) returns (stream WatchResp);
}
service Admin { rpc Ping(Empty) returns (Empty); }
message M { string a = 1; }
`
	got := parseProto(src)
	want := []string{"Secrets/Get", "Secrets/Watch", "Admin/Ping"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseLock_V9(t *testing.T) {
	lock := `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^19
        version: 19.0.0
    devDependencies:
      vitest:
        specifier: ^3
        version: 3.0.0
packages:
  react@19.0.0:
    resolution: {integrity: x}
  vitest@3.0.0:
    resolution: {integrity: y}
  '@scope/pkg@1.0.0':
    resolution: {integrity: z}
snapshots:
  react@19.0.0: {}
`
	got, err := parseLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	var direct, pkgs int
	for _, l := range got {
		switch {
		case strings.HasPrefix(l, "direct "):
			direct++
		case strings.HasPrefix(l, "package "):
			pkgs++
		}
	}
	if direct != 2 || pkgs != 3 {
		t.Fatalf("direct=%d packages=%d, want 2 and 3 (snapshots must not be counted): %q", direct, pkgs, got)
	}
}

func TestParseLock_V6TopLevelAndSlashKeys(t *testing.T) {
	lock := `
lockfileVersion: '6.0'
dependencies:
  react:
    specifier: ^18
    version: 18.0.0
packages:
  /react@18.0.0:
    resolution: {integrity: x}
`
	got, err := parseLock([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"direct react", "package react@18.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestEnvVars_RecognisedCallFormsAndConstants(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/a/a.go", `package a
import ("os"; "x/secretenv")
const envFoo = "KEYORIX_FOO"
var envBar = "KEYORIX_BAR"
func f(dyn string) {
	_ = os.Getenv("KEYORIX_LITERAL")
	_, _ = os.LookupEnv(envFoo)
	_, _, _ = secretenv.Lookup("KEYORIX_SECRET")
	_ = os.Getenv(envBar)
	_ = os.Getenv(dyn)        // unresolved
	_ = os.Getenv("KEYORIX_" + dyn) // unresolved
	_ = resolveSecret("KEYORIX_VIA_HELPER", "")           // project helper: found by the literal rule
	_ = []string{"KEYORIX_IN_TABLE"}                      // name table: found by the literal rule
	_ = "KEYORIX_SSO_"                                    // prefix, not a variable
	_ = "set KEYORIX_IN_A_MESSAGE to a longer value"      // prose, not a name
	_ = os.Getenv("KEYORIX_TEST_KNOB")                    // test knob in a non-test file: dropped
	_ = os.Getenv("HOME")                                 // not a project variable, but a real read
}
func resolveSecret(string, string) string { return "" }
`)
	write("internal/b/b.go", `package b
import ("os"; "x/a")
func g() { _ = os.Getenv(a.Shared) }
`)
	write("internal/c/c.go", `package c
const Shared = "KEYORIX_SHARED"
`)
	write("internal/a/a_test.go", `package a
import "os"
func TestX() { _ = os.Getenv("KEYORIX_ONLY_IN_TEST") }
`)
	write("internal/a/testdata/t.go", `package t
import "os"
func x() { _ = os.Getenv("KEYORIX_TESTDATA") }
`)
	names, unresolved, err := envVars(root, []string{"internal", "missing-dir"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HOME", "KEYORIX_BAR", "KEYORIX_FOO", "KEYORIX_IN_TABLE", "KEYORIX_LITERAL", "KEYORIX_SECRET", "KEYORIX_SHARED", "KEYORIX_VIA_HELPER"}
	// KEYORIX_SHARED is declared as a literal in package c, so the literal rule
	// finds it even though the read in package b cannot be resolved by name.
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %q, want %q", names, want)
	}
	// dyn, "KEYORIX_"+dyn, and a.Shared (package name "a" resolves nothing: Shared is declared in package c).
	if unresolved != 3 {
		t.Fatalf("unresolved = %d, want 3", unresolved)
	}
}
