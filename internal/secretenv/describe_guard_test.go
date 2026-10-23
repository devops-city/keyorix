package secretenv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// fileEnvReaders are the only non-test files that may hold the raw value of a
// <NAME>_FILE variable: they read it and name it in errors only through
// DescribeFile (cli/cmd/secretfile.go: its copy, describeSecretFile).
var fileEnvReaders = []string{
	"internal/secretenv/secretenv.go",
	"cli/cmd/secretfile.go",
}

// rawPathAPICallers are the non-test files outside this package that may call
// the functions returning a raw *_FILE value (FileVars, FilePaths and config's
// SecretFilePaths). Each was reviewed to name the path only through DescribeFile,
// NewFileError or CheckPermissionsNamed; a new caller needs the same review.
var rawPathAPICallers = []string{
	"internal/config/config.go",     // EnforceSecretFilePermissions: CheckPermissionsNamed; SecretFilePaths
	"internal/crypto/passphrase.go", // PassphraseSource.Describe: DescribeFile
	"cmd/keyorix-k8s-sync/main.go",  // resolveToken: NewFileError
}

// nonSecretFileEnvVars are *_FILE variables whose value is not a secret's path
// but a public trust anchor or an output location: a relative value cannot be a
// mistyped secret, and showing it is what the operator needs. Adding a name here
// is a review decision: a secret's _FILE variable belongs in secretenv.
var nonSecretFileEnvVars = map[string]string{
	"KEYORIX_CA_FILE": "CLI trust anchor: the PEM CA bundle to trust (cli/cmd/client.go), public material",
}

// fileEnvRead is a call that reads an environment variable whose name ends in
// _FILE: os.Getenv / os.LookupEnv / syscall.Getenv with a literal "X_FILE", or an
// expression `name + "_FILE"` / `name + FileSuffix` / `name + secretenv.FileSuffix`.
type fileEnvRead struct {
	pos  string
	name string // the literal name, "" when it is computed; "raw-path API" for FileVars & co.
}

// TestSecretFileEnvReadsGoThroughSecretenv is the enforcement half of F4
// (Andrei's decision secretenv-relative-file-path-echo, option a): a relative
// X_FILE value must never appear in an error, a log line or stderr. Every error
// that names a secret file goes through DescribeFile; this guard makes sure the
// raw value cannot reach any other formatting call, because no code outside
// fileEnvReaders can obtain it from the environment. Outside those files a
// *_FILE variable may only be tested for presence (os.Getenv(...) == "" / != "").
//
// Recognised call forms (the enumeration this guard knows): os.Getenv,
// os.LookupEnv and syscall.Getenv, with the name spelled as a string literal
// ending in _FILE (directly or through a string constant declared in the same
// file), or as a `+` expression whose last operand is the literal
// "_FILE" or an identifier/selector named FileSuffix. Not recognised: a name
// built any other way (fmt.Sprintf, a variable or another file's constant holding
// "X_FILE"), and
// os.Environ() scans; TestRelativeFileValueNeverEchoed (server, cli/cmd and
// entrypoint runners) covers the variables behaviourally. Scope: every Go module
// in the repository, non-test files, except vendor/, node_modules/ and testdata/.
func TestSecretFileEnvReadsGoThroughSecretenv(t *testing.T) {
	root := repoRoot(t)
	var bad []string
	for rel, reads := range scanFileEnvReads(t, root) {
		if slices.Contains(fileEnvReaders, rel) {
			continue
		}
		for _, r := range reads {
			if r.name == rawPathAPI && slices.Contains(rawPathAPICallers, rel) {
				continue
			}
			if _, ok := nonSecretFileEnvVars[r.name]; ok && r.name != "" {
				continue
			}
			bad = append(bad, strings.TrimPrefix(r.pos, root+string(filepath.Separator))+" reads "+cmpOr(r.name, "a computed *_FILE name"))
		}
	}
	slices.Sort(bad)
	if len(bad) > 0 {
		t.Errorf("a *_FILE variable's value is read outside internal/secretenv (and the cli copy); "+
			"use secretenv.Lookup/LookupChecked/FileVars and name the path only through secretenv.DescribeFile "+
			"(a relative X_FILE may be the secret itself), or test only for presence (== \"\"):\n  %s",
			strings.Join(bad, "\n  "))
	}
}

const rawPathAPI = "raw-path API (FileVars/FilePaths/SecretFilePaths)"

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// TestFileEnvReadScanner_RedGreen proves the scanner sees each recognised form
// and lets presence checks through.
func TestFileEnvReadScanner_RedGreen(t *testing.T) {
	src := `package p
import ("os"; "syscall"; "fmt")
const FileSuffix = "_FILE"
const caEnv = "KEYORIX_CA_FILE"
func f(n string) {
	a := os.Getenv("KEYORIX_X_FILE")              // read
	b, _ := os.LookupEnv(n + "_FILE")              // read
	c := syscall.Getenv(n + FileSuffix)            // read
	d := os.Getenv(n + secretenv.FileSuffix)       // read
	if os.Getenv("KEYORIX_Y_FILE") != "" {}        // presence: allowed
	if "" == os.Getenv(n+FileSuffix) {}            // presence: allowed
	e := os.Getenv("KEYORIX_X")                    // not a _FILE variable
	g := os.Getenv(caEnv)                          // read, through a constant
	h := secretenv.FileVars("KEYORIX_X")           // raw-path API
	fmt.Println(a, b, c, d, e, g, h, cfg.SecretFilePaths())
}`
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "p.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	got := fileEnvReadsIn(fset, af)
	if len(got) != 7 {
		t.Fatalf("scanner found %d reads, want 7 (Getenv literal, LookupEnv +\"_FILE\", syscall + FileSuffix, + secretenv.FileSuffix, constant, FileVars, SecretFilePaths): %v", len(got), got)
	}
	if got[5].name != rawPathAPI || got[6].name != rawPathAPI {
		t.Fatalf("FileVars/SecretFilePaths calls not flagged as the raw-path API: %v", got[5:])
	}
	if got[4].name != "KEYORIX_CA_FILE" {
		t.Fatalf("constant read named %q, want KEYORIX_CA_FILE", got[4].name)
	}
	if got[0].name != "KEYORIX_X_FILE" || got[1].name != "" {
		t.Fatalf("names = %q, %q; want KEYORIX_X_FILE and computed", got[0].name, got[1].name)
	}
}

func scanFileEnvReads(t *testing.T, root string) map[string][]fileEnvRead {
	t.Helper()
	out := map[string][]fileEnvRead{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git", ".scratch":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- repository source walked by a test
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), "_FILE") && !strings.Contains(string(src), "FileSuffix") {
			return nil
		}
		af, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return nil // not this guard's business; the build catches it
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if reads := fileEnvReadsIn(fset, af); len(reads) > 0 {
			out[rel] = reads
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fileEnvReadsIn(fset *token.FileSet, af *ast.File) []fileEnvRead {
	// String constants declared in this file: os.Getenv(caFileEnv) with
	// const caFileEnv = "KEYORIX_CA_FILE" is a literal read too.
	consts := map[string]string{}
	ast.Inspect(af, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return true
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := strconv.Unquote(lit.Value); err == nil {
							consts[id.Name] = s
						}
					}
				}
			}
		}
		return true
	})
	presence := map[*ast.CallExpr]bool{}
	ast.Inspect(af, func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || (be.Op != token.EQL && be.Op != token.NEQ) {
			return true
		}
		for _, pair := range [][2]ast.Expr{{be.X, be.Y}, {be.Y, be.X}} {
			if call, ok := pair[0].(*ast.CallExpr); ok && isEmptyString(pair[1]) {
				presence[call] = true
			}
		}
		return true
	})
	var out []fileEnvRead
	ast.Inspect(af, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || presence[call] {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "SecretFilePaths" ||
			((sel.Sel.Name == "FileVars" || sel.Sel.Name == "FilePaths") && isIdent(sel.X, "secretenv")) {
			out = append(out, fileEnvRead{pos: fset.Position(call.Pos()).String(), name: rawPathAPI})
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !((pkg.Name == "os" && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv")) ||
			(pkg.Name == "syscall" && sel.Sel.Name == "Getenv")) {
			return true
		}
		if len(call.Args) != 1 {
			return true
		}
		if name, ok := fileEnvName(call.Args[0], consts); ok {
			out = append(out, fileEnvRead{pos: fset.Position(call.Pos()).String(), name: name})
		}
		return true
	})
	return out
}

// fileEnvName reports whether e names a *_FILE variable, and the name when it is
// a literal.
func fileEnvName(e ast.Expr, consts map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.Ident:
		if s, ok := consts[x.Name]; ok && strings.HasSuffix(s, "_FILE") {
			return s, true
		}
	case *ast.BasicLit:
		if s, err := strconv.Unquote(x.Value); err == nil && strings.HasSuffix(s, "_FILE") {
			return s, true
		}
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		switch y := x.Y.(type) {
		case *ast.BasicLit:
			if s, err := strconv.Unquote(y.Value); err == nil && s == "_FILE" {
				return "", true
			}
		case *ast.Ident:
			return "", y.Name == "FileSuffix"
		case *ast.SelectorExpr:
			return "", y.Sel.Name == "FileSuffix"
		}
	case *ast.ParenExpr:
		return fileEnvName(x.X, consts)
	}
	return "", false
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func isEmptyString(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
}
