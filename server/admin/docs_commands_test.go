// docs_commands_test.go -- DOCS-DRIFT-1 item 2: every `keyorix-server ...`
// command the operator docs show must name a subcommand and flags the binary has.
//
// quickstart_commands_test.go already does this for QUICK_START.md,
// INSTALL-WITH-AI.md and the install script, but only for the literal prefix
// `./bin/keyorix-server admin`. The pilot-facing docs write the same command as
// `docker compose run --rm backend ./keyorix-server admin ...`, `keyorix-server
// admin ...` inside prose, or the bare server (`./bin/keyorix-server &`); none of
// those were checked. This file covers:
//
//   - documents: docs/CONFIGURATION.md, docs/SELF_HOSTING.md, QUICK_START.md,
//     docs/AIRGAP_RUNBOOK.md and docs/operator/*.md;
//   - places: fenced code lines and backticked inline spans, whatever wrapper
//     precedes the binary (docker/podman/kubectl exec|run, sudo, env, VAR=value);
//   - `keyorix-server admin <sub>... [--flag]`: resolved against the real cobra
//     tree (rootCmd): each subcommand word, each long or short flag;
//   - `keyorix-server [--flag]` (the server itself): flags resolved against the
//     flag.* declarations in server/main.go, read as source (this package cannot
//     import package main, and main.go is not edited), plus --version/-version
//     and -h/--help. A positional word other than `admin` is refused: the Go flag
//     package stops at it and the server would start silently ignoring the rest.
//
// What it does NOT check, so a green run is not read as more: flag VALUES and
// argument counts; commands in prose that are not backticked; lines where the
// binary is not the command being run (cp, go build -o, kubectl logs, image
// names); and the CLI half. `keyorix ...` lines are a documented non-goal here:
// the CLI is a separate Go module (cli/, owned by CLI-UX-2) that this package
// must not import, and cli/cmd/quickstart_commands_test.go already checks the
// QUICK_START.md CLI lines against the CLI's own flag definitions. Nothing builds
// the CLI binary in this test environment, so there is no `keyorix --help` to walk.
package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// docsCmdDocs returns the repo-relative documents checked.
func docsCmdDocs(t *testing.T) []string {
	t.Helper()
	docs := []string{"docs/CONFIGURATION.md", "docs/SELF_HOSTING.md", "QUICK_START.md", "docs/AIRGAP_RUNBOOK.md"}
	root := adminDocRepoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, "docs", "operator", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		rel, _ := filepath.Rel(root, m)
		docs = append(docs, filepath.ToSlash(rel))
	}
	sort.Strings(docs)
	return docs
}

// docsCmdInvocation is one documented use of the server binary.
type docsCmdInvocation struct {
	Source string // file:line
	Toks   []string
}

var (
	docsCmdInlineSpan = regexp.MustCompile("`([^`\n]+)`")
	docsCmdOperators  = map[string]bool{"|": true, "||": true, "&&": true, ";": true, "&": true, ">": true, ">>": true, "<": true, "2>&1": true}
	docsCmdWrappers   = map[string]bool{"sudo": true, "exec": true, "env": true, "nohup": true, "time": true, "$": true}
	docsCmdWord       = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	docsCmdNegNumber  = regexp.MustCompile(`^-\d`)
	docsCmdVarAssign  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	docsCmdContainer  = map[string]bool{"docker": true, "podman": true, "kubectl": true}
	// container subcommands that mention the binary without running it.
	docsCmdNotRun = map[string]bool{"build": true, "cp": true, "logs": true, "pull": true, "push": true, "tag": true, "inspect": true, "images": true, "describe": true, "get": true}
)

// docsCmdServerArgs returns the arguments after the server binary when tokens
// is a command line that RUNS keyorix-server, or ok=false. The binary must be
// the command: first token after wrappers, or, behind docker/podman/kubectl,
// somewhere after a subcommand that runs things (exec/run), never `cp`, `build`
// or `logs`. A trailing shell operator ends the command.
func docsCmdServerArgs(tokens []string) (args []string, ok bool) {
	for i, tk := range tokens {
		if docsCmdOperators[tk] {
			tokens = tokens[:i]
			break
		}
	}
	isBin := func(s string) bool { return s == "keyorix-server" || strings.HasSuffix(s, "/keyorix-server") }
	i := 0
	for i < len(tokens) && (docsCmdWrappers[tokens[i]] || docsCmdVarAssign.MatchString(tokens[i])) {
		i++
	}
	if i >= len(tokens) {
		return nil, false
	}
	if isBin(tokens[i]) {
		return tokens[i+1:], true
	}
	if !docsCmdContainer[tokens[i]] {
		return nil, false
	}
	for _, tk := range tokens[i+1:] {
		if docsCmdNotRun[tk] {
			return nil, false
		}
	}
	for j := i + 1; j < len(tokens); j++ {
		if isBin(tokens[j]) {
			return tokens[j+1:], true
		}
	}
	return nil, false
}

// docsCmdInvocations extracts every server invocation of one document.
func docsCmdInvocations(rel, doc string) []docsCmdInvocation {
	joined := strings.ReplaceAll(doc, "\\\n", " ")
	var out []docsCmdInvocation
	inFence := false
	for n, line := range strings.Split(joined, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimSpace(strings.TrimPrefix(line, ">")) // fence inside a blockquote
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			inFence = !inFence
			continue
		}
		src := rel + ":" + strconv.Itoa(n+1)
		if inFence {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.Index(line, " #"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if args, ok := docsCmdServerArgs(adminDocTokenize(line)); ok {
				out = append(out, docsCmdInvocation{src, args})
			}
			continue
		}
		for _, m := range docsCmdInlineSpan.FindAllStringSubmatch(line, -1) {
			if args, ok := docsCmdServerArgs(adminDocTokenize(m[1])); ok {
				out = append(out, docsCmdInvocation{src, args})
			}
		}
	}
	return out
}

// docsCmdServerFlag is one flag declared in server/main.go.
type docsCmdServerFlag struct{ takesValue bool }

// docsCmdMainFlags reads server/main.go and returns the flags its flag.* calls
// declare. Recognised forms (the enumeration, stated so a reviewer can check it):
// flag.Func("name", ...), flag.<Type>("name", ...) and flag.<Type>Var(&v, "name",
// ...) for Bool/String/Int/Int64/Uint/Uint64/Float64/Duration. A flag declared
// any other way (a custom flag.FlagSet, flag.Var) is not seen; the test then
// fails on the doc that uses it, which is the safe direction.
func docsCmdMainFlags(t *testing.T) map[string]docsCmdServerFlag {
	t.Helper()
	path := filepath.Join(adminDocRepoRoot(t), "server", "main.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse server/main.go: %v", err)
	}
	flags := map[string]docsCmdServerFlag{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" {
			return true
		}
		name := sel.Sel.Name
		idx := 0
		switch {
		case name == "Func":
		case strings.HasSuffix(name, "Var"):
			idx = 1
		case name == "Bool" || name == "String" || name == "Int" || name == "Int64" || name == "Uint" || name == "Uint64" || name == "Float64" || name == "Duration":
		default:
			return true
		}
		if len(call.Args) <= idx {
			return true
		}
		lit, ok := call.Args[idx].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		flags[s] = docsCmdServerFlag{takesValue: name != "Bool" && name != "BoolVar"}
		return true
	})
	return flags
}

// docsCmdCheckServerArgs validates args of a non-admin server invocation.
func docsCmdCheckServerArgs(args []string, flags map[string]docsCmdServerFlag) (problems []string) {
	for i := 0; i < len(args); i++ {
		tk := args[i]
		if !strings.HasPrefix(tk, "-") || tk == "-" {
			problems = append(problems, "positional argument "+strconv.Quote(tk)+" (the server takes no subcommand other than `admin`; Go's flag package stops parsing at it)")
			return problems
		}
		name := strings.TrimLeft(tk, "-")
		hasValue := false
		if j := strings.Index(name, "="); j >= 0 {
			name, hasValue = name[:j], true
		}
		switch name {
		case "version", "h", "help":
			continue
		}
		fl, known := flags[name]
		if !known {
			problems = append(problems, "unknown flag "+strconv.Quote(tk))
			continue
		}
		if fl.takesValue && !hasValue {
			i++ // the next token is the value
		}
	}
	return problems
}

// docsCmdCheckAdminArgs validates args following `keyorix-server admin`.
func docsCmdCheckAdminArgs(root *cobra.Command, args []string) (problems []string) {
	if len(args) == 0 {
		return nil
	}
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		return nil // answered by Execute before cobra
	}
	cmd := root
	i := 0
	for ; i < len(args); i++ {
		tk := args[i]
		if strings.HasPrefix(tk, "-") {
			break
		}
		var next *cobra.Command
		for _, c := range cmd.Commands() {
			if c.Name() == tk || c.HasAlias(tk) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		cmd = next
	}
	if i < len(args) && !strings.HasPrefix(args[i], "-") && cmd.HasSubCommands() && docsCmdWord.MatchString(args[i]) {
		problems = append(problems, "`admin "+cmd.CommandPath()[len(root.CommandPath()):]+"` has no subcommand "+strconv.Quote(args[i]))
		return problems
	}
	for ; i < len(args); i++ {
		tk := args[i]
		if !strings.HasPrefix(tk, "-") || tk == "-" || docsCmdNegNumber.MatchString(tk) {
			continue
		}
		if name, isLong := strings.CutPrefix(tk, "--"); isLong {
			if j := strings.Index(name, "="); j >= 0 {
				name = name[:j]
			}
			if name == "" || adminDocCobraBuiltinFlags[name] {
				continue
			}
			if adminLookupFlag(cmd, name) == nil {
				problems = append(problems, "`"+cmd.CommandPath()+"` has no flag --"+name)
			}
			continue
		}
		short := strings.TrimPrefix(tk, "-")
		if short == "h" {
			continue
		}
		found := false
		for _, fs := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags(), rootCmd.PersistentFlags()} {
			if fs != nil && len(short) == 1 && fs.ShorthandLookup(short) != nil {
				found = true
			}
		}
		if !found {
			problems = append(problems, "`"+cmd.CommandPath()+"` has no shorthand flag "+tk)
		}
	}
	return problems
}

func docsCmdFindProblems(root *cobra.Command, flags map[string]docsCmdServerFlag, inv docsCmdInvocation) []string {
	if len(inv.Toks) > 0 && inv.Toks[0] == "admin" {
		return docsCmdCheckAdminArgs(root, inv.Toks[1:])
	}
	return docsCmdCheckServerArgs(inv.Toks, flags)
}

// Deliberately NOT t.Parallel(): see TestQuickStartAdminCommandsExist (cobra's
// lazily built inherited-flag sets are an unsynchronized write).
func TestDocsServerCommandsExist(t *testing.T) {
	flags := docsCmdMainFlags(t)
	for _, want := range []string{"passphrase-fd", "passphrase-file", "passphrase-stdin"} {
		if _, ok := flags[want]; !ok {
			t.Fatalf("flag extractor did not find --%s in server/main.go (found %v): the extractor has drifted", want, flags)
		}
	}
	total := 0
	for _, rel := range docsCmdDocs(t) {
		b, err := os.ReadFile(filepath.Join(adminDocRepoRoot(t), filepath.FromSlash(rel))) // #nosec G304 -- fixed repo-relative paths
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		invs := docsCmdInvocations(rel, string(b))
		total += len(invs)
		for _, inv := range invs {
			for _, p := range docsCmdFindProblems(rootCmd, flags, inv) {
				t.Errorf("%s: `keyorix-server %s`: %s", inv.Source, strings.Join(inv.Toks, " "), p)
			}
		}
	}
	if total < 30 {
		t.Fatalf("extracted only %d keyorix-server invocations from the docs; the extractor has drifted (expected dozens)", total)
	}
	t.Logf("checked %d keyorix-server invocations", total)
}

// TestDocsServerCommandsCheckCatchesPlantedError is the red proof: a doc line with
// a renamed subcommand, a missing flag, or a stray positional must be reported,
// and the same lines written correctly must not.
func TestDocsServerCommandsCheckCatchesPlantedError(t *testing.T) {
	flags := docsCmdMainFlags(t)
	bad := "```sh\n" +
		"docker compose run --rm backend ./keyorix-server admin recovery-key rotat\n" +
		"docker compose run --rm backend ./keyorix-server admin backup --outptu /x\n" +
		"./bin/keyorix-server serve --passphrase-stdin\n" +
		"./bin/keyorix-server --no-such-flag\n" +
		"```\n"
	invs := docsCmdInvocations("planted.md", bad)
	if len(invs) != 4 {
		t.Fatalf("extracted %d invocations from the planted doc, want 4: %v", len(invs), invs)
	}
	for _, inv := range invs {
		if len(docsCmdFindProblems(rootCmd, flags, inv)) == 0 {
			t.Errorf("planted error not reported: %v", inv.Toks)
		}
	}

	good := "```sh\n" +
		"docker compose run --rm backend ./keyorix-server admin recovery-key rotate\n" +
		"docker compose run --rm backend ./keyorix-server admin backup --output /x\n" +
		"KEYORIX_CONFIG_PATH=./k.yaml ./bin/keyorix-server --passphrase-file /run/pw &\n" +
		"cp /path/to/keyorix-server .\n" +
		"```\n"
	invs = docsCmdInvocations("good.md", good)
	if len(invs) != 3 {
		t.Fatalf("extracted %d invocations from the good doc, want 3 (cp must not count): %v", len(invs), invs)
	}
	for _, inv := range invs {
		if p := docsCmdFindProblems(rootCmd, flags, inv); len(p) != 0 {
			t.Errorf("correct line reported: %v: %v", inv.Toks, p)
		}
	}
}
