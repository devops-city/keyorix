package ci_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// global-guards.txt is the single source of the packages run-guards.sh (and the
// coordinator preflight) test on every merge-queue run. run-guards.sh exits 1
// on a listed directory that does not exist, but only inside the queue; this
// fails the PR that introduces the typo instead.
func TestGlobalGuardsPackagesExist(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("global-guards.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		dir := filepath.Join(root, strings.TrimPrefix(line, "./"))
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Errorf("global-guards.txt lists %q, which is not a directory in the repo (run-guards.sh would exit 1 in the queue)", line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("global-guards.txt lists no packages")
	}
}
