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

// TestModeChecksAlsoJudgeTheOwner is the class guard for #3393/#3410: a key or
// secret file judged by its mode alone ("nothing for group or other") still
// trusts a file that another unprivileged account owns, and that account can
// chmod and rewrite it whatever the mode. #3393 fixed secretenv; #3410 found the
// same shape in --passphrase-file, the DEK/salt/TLS key check and the file KEK
// provider.
//
// It walks the non-test Go files of guardedDirs (the same packages the
// OpenRegular guard scans) and fails on any function that masks a mode with the
// literal 0o077 / 0077 (the "group or other" test) but never calls one of
// ownerChecks. A new mode-only check therefore has to judge the owner too, or be
// listed in modeOnlyAllowed with the reason.
//
// What it recognises: a binary & with an integer literal equal to 0o077 on either
// side, in a function body (closures included). What it does NOT see, so a green
// run says nothing about these: a mode test written with another mask (0o007,
// 0o044, a named constant), a comparison against an exact mode (FixFilePerms
// compares perm != spec.Mode and judges the owner itself), an owner check made by
// a caller rather than in the same function, packages outside guardedDirs, and
// the cli/ and operator/ modules. The two copies of the secret-file rule this
// cannot see (cli/cmd/secretfile.go, which masks with 0o007, and
// server/entrypoint.sh) are held to testdata/permission-matrix.tsv instead,
// with TestPermissionMatrix_Server as the reference run; both had missed the
// owner rule until SECRETENV-REVIEW-1.
func TestModeChecksAlsoJudgeTheOwner(t *testing.T) {
	root := repoRoot(t)
	var files []string
	for _, tgt := range guardedDirs {
		if strings.Contains(tgt, "*") {
			files = append(files, guardedGlobFiles(t, root, tgt)...)
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, tgt), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("guarded path %s: %v (update guardedDirs)", tgt, err)
		}
	}
	var bad []string
	seen := map[string]bool{}
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- repo source file under test
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, f)
		sites, err := modeOnlyChecks(filepath.ToSlash(rel), src)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sites {
			seen[s] = true
			if _, ok := modeOnlyAllowed[s]; !ok {
				bad = append(bad, s)
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("function(s) judge a key/secret file's mode (&0o077) but not its owner; call secretenv.CheckOwner on the same FileInfo (#3410), or add \"<file>:<func>\" to modeOnlyAllowed with the reason:\n  %s", strings.Join(bad, "\n  "))
	}
	for k := range modeOnlyAllowed {
		if !seen[k] {
			t.Errorf("modeOnlyAllowed entry %q matches no mode check any more; remove it", k)
		}
	}
}

// ownerChecks are the calls that apply the owner rule.
var ownerChecks = map[string]bool{"CheckOwner": true, "checkInfo": true, "CheckPermissions": true, "LookupChecked": true}

// modeOnlyAllowed lists mode-only checks that are deliberate, with the reason.
var modeOnlyAllowed = map[string]string{}

// modeOnlyChecks returns "<file>:<func>" for each function in src that masks with
// 0o077 and calls none of ownerChecks.
func modeOnlyChecks(rel string, src []byte) ([]string, error) {
	af, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, decl := range af.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		masks, owner := false, false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if x.Op == token.AND && (isGroupOtherMask(x.X) || isGroupOtherMask(x.Y)) {
					masks = true
				}
			case *ast.CallExpr:
				switch fn := x.Fun.(type) {
				case *ast.Ident:
					owner = owner || ownerChecks[fn.Name]
				case *ast.SelectorExpr:
					owner = owner || ownerChecks[fn.Sel.Name]
				}
			}
			return true
		})
		if masks && !owner {
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				recv := fd.Recv.List[0].Type
				if st, ok := recv.(*ast.StarExpr); ok {
					recv = st.X
				}
				if id, ok := recv.(*ast.Ident); ok {
					name = id.Name + "." + name
				}
			}
			out = append(out, rel+":"+name)
		}
	}
	return out, nil
}

func isGroupOtherMask(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseInt(lit.Value, 0, 64)
	return err == nil && v == 0o077
}

func TestModeOnlyCheckScanner_RedGreen(t *testing.T) {
	const head = "package p\nimport (\"os\"; \"github.com/keyorixhq/keyorix/internal/secretenv\")\n"
	cases := map[string]struct {
		src  string
		want bool
	}{
		"mode only":            {head + "func f(i os.FileInfo) bool { return i.Mode().Perm()&0o077 != 0 }\nvar _ = secretenv.FileSuffix", true},
		"old-style literal":    {head + "func f(i os.FileInfo) bool { return 0077&i.Mode().Perm() != 0 }\nvar _ = secretenv.FileSuffix", true},
		"method":               {head + "type T struct{}\nfunc (*T) f(i os.FileInfo) bool { return i.Mode().Perm()&0o077 != 0 }\nvar _ = secretenv.FileSuffix", true},
		"mode and owner":       {head + "func f(i os.FileInfo) error { if i.Mode().Perm()&0o077 != 0 { return nil }; return secretenv.CheckOwner(i) }", false},
		"other mask":           {head + "func f(i os.FileInfo) bool { return i.Mode().Perm()&0o007 != 0 }\nvar _ = secretenv.FileSuffix", false},
		"umask is not a check": {"package p\nimport \"syscall\"\nfunc f() { syscall.Umask(0o077) }", false},
	}
	for name, tc := range cases {
		got, err := modeOnlyChecks("p/x.go", []byte(tc.src))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (len(got) == 1) != tc.want || len(got) > 1 {
			t.Errorf("%s: got %v, want flagged=%v", name, got, tc.want)
		}
	}
}
