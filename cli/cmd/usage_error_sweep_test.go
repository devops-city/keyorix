package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// usageMessage matches the wording of a mistake in the flags/arguments the user gave:
// a missing value, or two flags that exclude each other.
var usageMessage = regexp.MustCompile(`(?i)\b(is|are) required\b|mutually exclusive|cannot be combined|cannot combine|set together|set exactly one`)

// filesNotYetConverted are command files that still build such errors with fmt.Errorf /
// errors.New, so they exit 1 instead of 2. They belong to the login / MFA / first-run
// setup flows, which another session (FIX-3277) is changing; convert them once that
// lands, then delete the entry. The list may only shrink.
var filesNotYetConverted = map[string]bool{
	"login.go":      true,
	"mfa.go":        true,
	"systeminit.go": true,
}

// TestUsageMistakesAreUsageErrors is the family guard behind exit code 2: in every
// command file, an error built from a "... is required" / "mutually exclusive" message
// must be made with usageErrorf, not fmt.Errorf or errors.New, or the CLI would exit 1
// for a plain typo. It sweeps the source with go/parser; the shapes it recognises are
// fmt.Errorf("<literal>", ...) and errors.New("<literal>"), which is how every command
// in this package builds a plain error.
func TestUsageMistakesAreUsageErrors(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) < 50 {
		t.Fatalf("glob: %v (%d files)", err, len(files))
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "exitcodes.go" {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
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
			if !ok || !((pkg.Name == "fmt" && sel.Sel.Name == "Errorf") || (pkg.Name == "errors" && sel.Sel.Name == "New")) {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			msg, err := strconv.Unquote(lit.Value)
			if err != nil || !usageMessage.MatchString(msg) {
				return true
			}
			if filesNotYetConverted[name] {
				return true
			}
			t.Errorf("%s: %q looks like a usage mistake; build it with usageErrorf so the CLI exits 2",
				fset.Position(call.Pos()), msg)
			return true
		})
	}
	if checked < 50 {
		t.Fatalf("only %d files swept", checked)
	}
	for name := range filesNotYetConverted {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("filesNotYetConverted names %s, which does not exist: delete the entry", name)
		}
	}
}
