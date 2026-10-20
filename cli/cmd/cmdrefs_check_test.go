package cmd

// Shared checker. server/admin/cmdrefs_check_test.go is a byte-identical copy apart from
// the package clause (the CLI module cannot import the main module and vice versa).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// cmdRefsRepoRoot walks up from the test's directory to the repository root.
func cmdRefsRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if st, err := os.Stat(filepath.Join(dir, "changelog.d")); err == nil && st.IsDir() {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repository root (the directory holding changelog.d) not found above the test directory")
	return ""
}

// A command reference is a quoted span that starts with the binary name: `keyorix a b --c`
// or 'keyorix a b'. Prose ("the keyorix server") is not quoted that way and is ignored.
var quotedCmdSpan = regexp.MustCompile("[`']((?:keyorix-server|keyorix)[ \t][^`'\n]*)[`']")

type cmdRef struct {
	file, text string
	line       int
}

// literalCmdRefs returns every quoted command reference in the string literals (not the
// comments) of the repository's non-test Go files.
func literalCmdRefs(t *testing.T, root string) []cmdRef {
	t.Helper()
	skipDir := map[string]bool{".git": true, "node_modules": true, "web": true, ".scratch": true,
		"testdata": true, "vendor": true, ".claude": true, ".gopath": true}
	var refs []cmdRef
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Errorf("cannot parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			for _, m := range quotedCmdSpan.FindAllStringSubmatch(s, -1) {
				rel, _ := filepath.Rel(root, path)
				refs = append(refs, cmdRef{file: rel, line: fset.Position(lit.Pos()).Line, text: m[1]})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

// checkCommandRefs fails for every reference that starts with prefix (e.g. "keyorix",
// "keyorix-server admin") and names a subcommand or flag that root does not have.
// A word that looks like a placeholder or a value (<id>, $VAR, [opt], UPPER, a.b, 3) ends the
// command path; flags after it are still checked.
func checkCommandRefs(t *testing.T, repoRoot string, root *cobra.Command, prefix string, stale map[string]string) {
	t.Helper()
	prefixWords := strings.Fields(prefix)
	refs := literalCmdRefs(t, repoRoot)
	checked := 0
	var problems []string
	for _, r := range refs {
		words := strings.Fields(r.text)
		if len(words) <= len(prefixWords) || strings.Join(words[:len(prefixWords)], " ") != prefix {
			continue // another binary, or the bare binary name
		}
		checked++
		if _, ok := stale[r.text]; ok {
			continue
		}
		if msg := resolveCmdRef(root, words[len(prefixWords):]); msg != "" {
			problems = append(problems, r.file+":"+strconv.Itoa(r.line)+": `"+r.text+"`: "+msg)
		}
	}
	if checked < 3 {
		t.Fatalf("only %d references with prefix %q found: the sweep is broken", checked, prefix)
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

var placeholderWord = regexp.MustCompile(`^[<\[{$(]|[.*|>&;=:/\\"]|^[A-Z0-9]|^-$`)

// resolveCmdRef walks words down the cobra tree and returns "" when every command word and
// every flag exists, or a one-line reason.
func resolveCmdRef(root *cobra.Command, words []string) string {
	cur := root
	inPath := true
	for _, w := range words {
		switch {
		case w == "--":
			return ""
		case strings.HasPrefix(w, "--"):
			inPath = false
			name, _, _ := strings.Cut(strings.TrimPrefix(w, "--"), "=")
			if name == "" || name == "help" || name == "version" || strings.ContainsAny(name[:1], "<[{$") {
				continue // cobra's own flags, or a placeholder such as --<flag>
			}
			if cur.Flags().Lookup(name) == nil && cur.InheritedFlags().Lookup(name) == nil &&
				cur.PersistentFlags().Lookup(name) == nil && root.PersistentFlags().Lookup(name) == nil {
				return "`" + cur.CommandPath() + "` has no flag --" + name
			}
		case strings.HasPrefix(w, "-"):
			inPath = false // short flag: not checked
		case inPath && !placeholderWord.MatchString(w):
			var next *cobra.Command
			for _, c := range cur.Commands() {
				if c.Name() == w || c.HasAlias(w) {
					next = c
					break
				}
			}
			switch {
			case next != nil:
				cur = next
			case cur.HasSubCommands() && !(cur == root && w == "help"):
				return "`" + cur.CommandPath() + "` has no subcommand `" + w + "`"
			default:
				inPath = false // a positional argument of a leaf command
			}
		default:
			inPath = false
		}
	}
	return ""
}
