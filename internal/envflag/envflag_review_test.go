package envflag

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// TestEnabled_SpellingTable (REVIEW-COVERAGE-2) pins exactly which values
// switch an insecure mode on: the six truthy spellings strconv.ParseBool
// accepts. Everything else, including whitespace around a truthy value, other
// casings, "yes"/"on", numbers other than 1 and look-alike characters, is off.
func TestEnabled_SpellingTable(t *testing.T) {
	const name = "KEYORIX_ENVFLAG_REVIEW_TEST"
	on := []string{"1", "t", "T", "true", "TRUE", "True"}
	off := []string{
		"", "0", "f", "false", "FALSE", "False",
		" true", "true ", "true\n", "\ttrue", "1 ", " 1",
		"tRUE", "tRuE", "TrUe", "yes", "YES", "y", "on", "ON", "enabled", "enable",
		"2", "-1", "01", "0x1", "1.0", "+1",
		"\uff54\uff52\uff55\uff45", "\uff11", "\u200btrue", // full-width and zero-width look-alikes (a NUL cannot be in an environment value)
	}
	for _, v := range on {
		t.Setenv(name, v)
		if !Enabled(name) {
			t.Errorf("Enabled(%q) = false, want true", v)
		}
	}
	for _, v := range off {
		t.Setenv(name, v)
		if Enabled(name) {
			t.Errorf("Enabled(%q) = true, want false (fail closed)", v)
		}
	}
	// Environment variable names are exact: another casing of the name is a
	// different, unset variable.
	t.Setenv(name, "true")
	if Enabled(strings.ToLower(name)) {
		t.Error("a lower-case spelling of the variable name enabled the flag")
	}
}

// directInsecureEnvReads returns the os.Getenv/os.LookupEnv calls in src whose
// argument (a string literal or an identifier) names an INSECURE variable.
func directInsecureEnvReads(t *testing.T, fset *token.FileSet, file string, src []byte) []string {
	t.Helper()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "os" || (sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv") {
			return true
		}
		var arg string
		switch a := call.Args[0].(type) {
		case *ast.BasicLit:
			arg = a.Value
		case *ast.Ident:
			arg = a.Name
		case *ast.SelectorExpr:
			arg = a.Sel.Name
		}
		if strings.Contains(strings.ToUpper(arg), "INSECURE") {
			out = append(out, fset.Position(call.Pos()).String())
		}
		return true
	})
	return out
}

// TestInsecureEnvGatesGoThroughEnabled: docs/security/SECURE-CODING.md §6 says
// an insecure-mode opt-in is read through Enabled, never a bespoke os.Getenv
// comparison (os.Getenv(X) != "" would turn on for X=false). This fails on a
// direct os.Getenv/os.LookupEnv of a variable whose literal or constant name
// contains INSECURE anywhere in the root module's production code.
//
// What it does NOT see: a variable name without INSECURE in it (name the
// constant accordingly), a read through a helper other than os.Getenv/LookupEnv
// (secretenv, viper), and the nested modules (cli has its own
// KEYORIX_ALLOW_INSECURE_SECRET_FLAGS gate, which accepts "1" only).
func TestInsecureEnvGatesGoThroughEnabled(t *testing.T) {
	fset := token.NewFileSet()
	// The matcher sees both shapes it must catch.
	probe := []byte("package p\nimport \"os\"\nconst EnvAllowInsecureX = \"KEYORIX_ALLOW_INSECURE_X\"\n" +
		"func a() bool { return os.Getenv(EnvAllowInsecureX) != \"\" }\n" +
		"func b() bool { _, ok := os.LookupEnv(\"KEYORIX_ALLOW_INSECURE_Y\"); return ok }\n")
	if got := directInsecureEnvReads(t, fset, "probe.go", probe); len(got) != 2 {
		t.Fatalf("matcher self-test: found %v, want both direct reads", got)
	}

	root := srcpath.RepoRoot()
	var bad []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if _, serr := os.Stat(filepath.Join(path, "go.mod")); serr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || rel == "internal/envflag/envflag.go" {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- repo source walked by a test
		if err != nil {
			return err
		}
		if !strings.Contains(strings.ToUpper(string(src)), "INSECURE") {
			return nil
		}
		bad = append(bad, directInsecureEnvReads(t, fset, rel, src)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Errorf("%s reads an insecure-mode environment variable directly: use envflag.Enabled (fail closed on anything but a ParseBool truthy value)", b)
	}
}
