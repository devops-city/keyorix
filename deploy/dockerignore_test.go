package deploy

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerignoreKeepsEveryFileTheServerCompiles: server/Dockerfile builds
// with `COPY . .` filtered by .dockerignore, which excludes configs/* except
// named files. A new non-test Go file (or embedded file) in a package the
// server links, matched by an exclude, breaks `docker build` while `go build`
// and every Go test stay green. Found by SECURE-DEFAULT-1: configs/dev_template.go
// was excluded and the image failed with "undefined: configs.DevConfigTemplate".
//
// The file list comes from `go list -deps` of ./server, for the default build
// and for the air-gapped tags server/Dockerfile's BUILD_TAGS uses. The matcher
// implements Docker's rules for the pattern shapes .dockerignore uses today
// (plain globs matched against the path and each parent directory, a trailing
// "/", a leading "**/", "!" negation, last match wins) and FAILS on any other
// shape, so a new kind of pattern cannot be silently misread.
func TestDockerignoreKeepsEveryFileTheServerCompiles(t *testing.T) {
	patterns := parseDockerignore(t, readRepoFile(t, ".dockerignore"))
	files := serverBuildFiles(t, "")
	files = append(files, serverBuildFiles(t, "noaws,noazure,nogcp")...)
	if len(files) < 100 {
		t.Fatalf("go list found only %d files the server compiles; the check would be near-vacuous", len(files))
	}
	for _, f := range files {
		if dockerignoreExcludes(patterns, f) {
			t.Errorf(".dockerignore excludes %s, which ./server compiles or embeds; `docker build -f server/Dockerfile .` fails without it (add a !%s line)", f, f)
		}
	}
}

// The matcher itself, against the cases that matter here (both directions).
func TestDockerignoreMatcher(t *testing.T) {
	p := parseDockerignore(t, "docs/\nconfigs/*\n!configs/embed.go\n*.md\n**/node_modules\n")
	for path, want := range map[string]bool{
		"docs/a/b.go":             true,
		"configs/dev_template.go": true,
		"configs/embed.go":        false,
		"README.md":               true,
		"internal/x/README.md":    false, // *.md is root-only in Docker
		"web/node_modules/x/y.js": true,
		"internal/config/x.go":    false,
	} {
		if got := dockerignoreExcludes(p, path); got != want {
			t.Errorf("excludes(%q) = %v, want %v", path, got, want)
		}
	}
}

type ignorePattern struct {
	glob   string
	negate bool
	anyDir bool // leading "**/"
}

func parseDockerignore(t *testing.T, content string) []ignorePattern {
	t.Helper()
	var out []ignorePattern
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := ignorePattern{}
		if strings.HasPrefix(line, "!") {
			p.negate = true
			line = line[1:]
		}
		line = strings.TrimPrefix(strings.TrimSuffix(line, "/"), "/")
		if strings.HasPrefix(line, "**/") {
			p.anyDir = true
			line = strings.TrimPrefix(line, "**/")
		}
		if strings.Contains(line, "**") || strings.ContainsAny(line, "[\\") {
			t.Fatalf(".dockerignore pattern %q has a shape this matcher does not implement; extend it", line)
		}
		if _, err := filepath.Match(line, ""); err != nil {
			t.Fatalf(".dockerignore pattern %q: %v", line, err)
		}
		p.glob = line
		out = append(out, p)
	}
	return out
}

// dockerignoreExcludes applies the patterns in order (last match wins). A
// pattern matching a parent directory matches everything under it.
func dockerignoreExcludes(patterns []ignorePattern, path string) bool {
	parts := strings.Split(path, "/")
	excluded := false
	for _, p := range patterns {
		if p.matches(parts) {
			excluded = !p.negate
		}
	}
	return excluded
}

func (p ignorePattern) matches(parts []string) bool {
	starts := []int{0}
	if p.anyDir {
		starts = starts[:0]
		for i := range parts {
			starts = append(starts, i)
		}
	}
	for _, s := range starts {
		for end := s + 1; end <= len(parts); end++ {
			if ok, _ := filepath.Match(p.glob, strings.Join(parts[s:end], "/")); ok {
				return true
			}
		}
	}
	return false
}

// serverBuildFiles returns repo-relative paths of every non-test Go file and
// every embedded file in this module's packages that ./server depends on.
func serverBuildFiles(t *testing.T, tags string) []string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"list", "-deps", "-json=ImportPath,Dir,GoFiles,EmbedFiles,Module"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "./server")
	cmd := exec.Command("go", args...) //nolint:gosec // fixed binary and arguments
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	var files []string
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var pkg struct {
			Dir        string
			GoFiles    []string
			EmbedFiles []string
			Module     *struct{ Path string }
		}
		if err := dec.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		if pkg.Module == nil || pkg.Module.Path != "github.com/keyorixhq/keyorix" {
			continue
		}
		rel, err := filepath.Rel(root, pkg.Dir)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		for _, f := range append(pkg.GoFiles, pkg.EmbedFiles...) {
			files = append(files, filepath.ToSlash(filepath.Join(rel, f)))
		}
	}
	return files
}
