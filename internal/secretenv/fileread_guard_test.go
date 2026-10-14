package secretenv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestSecretFileReadsGoThroughOpenRegular is the class guard for "a secret or key
// file read blocks on a FIFO" (REVIEW-3161, FIFO-2). A plain os.Open / os.ReadFile /
// os.OpenFile(O_RDONLY) blocks in open(2) on a FIFO until a writer appears, and a
// 0600 FIFO passes a mode check first, so the process hangs at boot or in a CLI
// command. OpenRegular opens non-blocking and refuses a non-regular file on the
// same descriptor.
//
// It walks the non-test Go files of the packages that read operator-supplied
// secret/key files and fails on any read-side os.Open, os.OpenFile (no write/create
// flag) or os.ReadFile / ioutil.ReadFile that is neither inside OpenRegular nor
// listed in nonSecretFileReads with a reason. A new read therefore has to either
// use OpenRegular or be added to the list (a reviewable, one-line decision).
//
// What it recognises: calls spelled os.Open, os.OpenFile, os.ReadFile and
// ioutil.ReadFile through the file's own import name for "os" / "io/ioutil". It does
// not see a read hidden behind a function value, a reflected call, a different
// package that wraps os.ReadFile, or the cli/ and operator/ modules (their own
// go.mod; cli/cmd/secretfile.go carries its own copy of the pattern). Write-side
// OpenFile calls (O_WRONLY, O_RDWR, O_CREATE, O_APPEND, O_TRUNC) are skipped.
func TestSecretFileReadsGoThroughOpenRegular(t *testing.T) {
	root := repoRoot(t)
	found := scanFileReads(t, root, guardedDirs)

	allowed := map[string]bool{}
	for k := range nonSecretFileReads {
		allowed[k] = false
	}
	var bypass []string
	for _, site := range found {
		if _, ok := allowed[site.key]; ok {
			allowed[site.key] = true
			continue
		}
		bypass = append(bypass, site.String())
	}
	if len(bypass) > 0 {
		t.Errorf("file read(s) bypass secretenv.OpenRegular (a FIFO at that path would hang open(2)).\n"+
			"Use secretenv.OpenRegular, or, if the file is not a secret/key (public data, our own staged file), add \"<file>:<func>\" to nonSecretFileReads with the reason:\n  %s",
			strings.Join(bypass, "\n  "))
	}
	var stale []string
	for k, used := range allowed {
		if !used {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("nonSecretFileReads has entries that match no file read any more (remove them): %s", strings.Join(stale, ", "))
	}
}

// guardedDirs are the repo-relative directories (recursive) and files scanned.
var guardedDirs = []string{
	"internal/crypto",
	"internal/securefiles",
	"internal/keyfiles",
	"internal/encryption",
	"internal/encryptionops",
	"internal/config",
	"internal/secretenv",
	"server/admin",
	"server/main.go",
	"internal/k8ssync",
	"internal/startup",
	"internal/auditverify",
	"cmd",
}

// nonSecretFileReads lists the read sites that are deliberately not routed through
// OpenRegular, keyed "<repo-relative file>:<enclosing func>". Each is public data,
// our own just-written file, a read of the very file the operator is restoring, or
// an operator-supplied archive. None holds a KEK, share, passphrase, token or
// private key. Do NOT add a secret/key reader here: use OpenRegular.
var nonSecretFileReads = map[string]string{
	"server/admin/restore.go:runAdminRestoreV2":                "operator-supplied backup archive; our own staged file, checksum-verified by ExtractArchive",
	"server/admin/restore.go:stageKeyFilesForKEKUnwrap":        "our own staged file, checksum-verified by ExtractArchive",
	"server/admin/restore.go:archiveHeadFromStagedAuditEvents": "our own staged file, checksum-verified by ExtractArchive",
	"internal/k8ssync/rest_sink.go:NewInClusterSink":           "fixed kubelet-mounted ServiceAccount paths (constants), not operator-supplied",
	"internal/securefiles/securefiles.go:SyncDir":              "directory open for fsync, not a file read",
	"server/admin/restore.go:fsyncDir":                         "directory open for fsync, not a file read",
}

type readSite struct {
	file, fn, call string
	line           int
	key            string
}

func (s readSite) String() string {
	return s.file + ":" + strconv.Itoa(s.line) + " " + s.call + " in " + s.fn + " (key " + s.key + ")"
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func scanFileReads(t *testing.T, root string, targets []string) []readSite {
	t.Helper()
	var files []string
	for _, tgt := range targets {
		p := filepath.Join(root, tgt)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("guarded path %s: %v (update guardedDirs)", tgt, err)
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(files)
	var out []readSite
	fset := token.NewFileSet()
	for _, path := range files {
		af, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		out = append(out, fileReadsIn(fset, af, filepath.ToSlash(rel))...)
	}
	return out
}

// fileReadsIn returns the read-side file opens in one parsed file, except those
// inside secretenv.OpenRegular itself and auditverify's local readRegularFile copy.
func fileReadsIn(fset *token.FileSet, af *ast.File, rel string) []readSite {
	osName, ioutilName := "", ""
	for _, imp := range af.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch p {
		case "os":
			osName = name
		case "io/ioutil":
			ioutilName = name
		}
	}
	var out []readSite
	for _, decl := range af.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if rel == "internal/secretenv/secretenv.go" && fd.Name.Name == "OpenRegular" {
			continue
		}
		// internal/auditverify may not import secretenv (independence from the
		// code that wrote the audit chain), so it carries a local copy of the
		// same open-nonblocking + fstat reader.
		if rel == "internal/auditverify/witness.go" && fd.Name.Name == "readRegularFile" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// securefiles.SecureOpenBeneath (or the bare name, inside package
			// securefiles): a read-side open must carry O_NONBLOCK. Its callers
			// (SafeReadFile) then fstat the fd for a regular file.
			if isCallTo(call, "SecureOpenBeneath") {
				flags := flagNames(call, 2)
				if flags.write || flags.names["O_NONBLOCK"] {
					return true
				}
				out = append(out, readSite{
					file: rel, fn: fd.Name.Name, call: "SecureOpenBeneath(read, no O_NONBLOCK)",
					line: fset.Position(call.Pos()).Line,
					key:  rel + ":" + fd.Name.Name,
				})
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := pkg.Name + "." + sel.Sel.Name
			switch {
			case osName != "" && pkg.Name == osName && (sel.Sel.Name == "Open" || sel.Sel.Name == "ReadFile"):
			case osName != "" && pkg.Name == osName && sel.Sel.Name == "OpenFile":
				if flagNames(call, 1).write {
					return true
				}
			case ioutilName != "" && pkg.Name == ioutilName && sel.Sel.Name == "ReadFile":
			default:
				return true
			}
			out = append(out, readSite{
				file: rel, fn: fd.Name.Name, call: name,
				line: fset.Position(call.Pos()).Line,
				key:  rel + ":" + fd.Name.Name,
			})
			return true
		})
	}
	return out
}

// isCallTo reports whether call is name(...) or pkg.name(...).
func isCallTo(call *ast.CallExpr, name string) bool {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name == name
	case *ast.SelectorExpr:
		return f.Sel.Name == name
	}
	return false
}

// openFlags is what a call's flags argument spells: the O_* names, and whether any
// is write-side (O_WRONLY, O_RDWR, O_CREATE, O_APPEND, O_TRUNC). A flags expression
// not spelled as pkg.O_* identifiers yields no names and write=false, which is
// treated as a read (the conservative direction: it is flagged).
type openFlags struct {
	names map[string]bool
	write bool
}

func flagNames(call *ast.CallExpr, argIdx int) openFlags {
	out := openFlags{names: map[string]bool{}}
	if len(call.Args) <= argIdx {
		return out
	}
	ast.Inspect(call.Args[argIdx], func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "O_") {
			out.names[sel.Sel.Name] = true
			switch sel.Sel.Name {
			case "O_WRONLY", "O_RDWR", "O_CREATE", "O_APPEND", "O_TRUNC":
				out.write = true
			}
		}
		return true
	})
	return out
}

// The guard must fire on a violation and stay quiet on a conforming file: both
// directions, on synthetic sources.
func TestFileReadScanner_RedGreen(t *testing.T) {
	scan := func(src string) []readSite {
		t.Helper()
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return fileReadsIn(fset, af, "pkg/x.go")
	}
	const imp = "package p\nimport \"os\"\n"
	for name, src := range map[string]string{
		"ReadFile":                         imp + "func f(p string) { _, _ = os.ReadFile(p) }",
		"Open":                             imp + "func f(p string) { _, _ = os.Open(p) }",
		"OpenFile read":                    imp + "func f(p string) { _, _ = os.OpenFile(p, os.O_RDONLY, 0) }",
		"aliased os":                       "package p\nimport o \"os\"\nfunc f(p string) { _, _ = o.ReadFile(p) }",
		"ioutil":                           "package p\nimport \"io/ioutil\"\nfunc f(p string) { _, _ = ioutil.ReadFile(p) }",
		"SecureOpenBeneath read, blocking": "package p\nimport \"golang.org/x/sys/unix\"\nfunc f(b, p string) { _, _ = SecureOpenBeneath(b, p, unix.O_RDONLY, 0) }",
	} {
		if got := scan(src); len(got) != 1 {
			t.Errorf("%s: want 1 site flagged, got %d", name, len(got))
		}
	}
	for name, src := range map[string]string{
		"write open":                          imp + "func f(p string) { _, _ = os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o600) }",
		"OpenRegular":                         "package p\nimport \"x/secretenv\"\nfunc f(p string) { _, _, _ = secretenv.OpenRegular(p, 0) }",
		"SecureOpenBeneath read, nonblocking": "package p\nimport \"golang.org/x/sys/unix\"\nfunc f(b, p string) { _, _ = SecureOpenBeneath(b, p, unix.O_RDONLY|unix.O_NONBLOCK, 0) }",
		"SecureOpenBeneath write":             "package p\nimport \"golang.org/x/sys/unix\"\nfunc f(b, p string) { _, _ = SecureOpenBeneath(b, p, unix.O_WRONLY|unix.O_CREAT, 0o600) }",
		"unrelated":                           imp + "func f() { _ = os.Getenv(\"X\") }",
	} {
		if got := scan(src); len(got) != 0 {
			t.Errorf("%s: want no site flagged, got %v", name, got)
		}
	}
}
