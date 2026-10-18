package srcpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoRootIsRootModule(t *testing.T) {
	root := RepoRoot()
	if !filepath.IsAbs(root) {
		t.Fatalf("RepoRoot %q is not absolute", root)
	}
	if got := modulePath(filepath.Join(root, "go.mod")); got != rootModule {
		t.Fatalf("go.mod at %s declares %q, want %q", root, got, rootModule)
	}
}

func TestFindRootSkipsNestedModules(t *testing.T) {
	tmp := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+rootModule+"\n\ngo 1.27\n")
	write("cli/go.mod", "module "+rootModule+"/cli\n")
	write("cli/sub/x.go", "package sub\n")

	got, err := findRoot(filepath.Join(tmp, "cli", "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if got != tmp {
		t.Fatalf("findRoot = %s, want %s", got, tmp)
	}
	if _, err := findRoot(t.TempDir()); err == nil {
		t.Fatal("findRoot outside the repo must fail")
	}
}

func TestPkgDirIsWorkingDir(t *testing.T) {
	wd, _ := os.Getwd()
	if PkgDir() != wd {
		t.Fatalf("PkgDir %s != cwd %s", PkgDir(), wd)
	}
}
