// Package srcpath locates source files for tests that read the repository
// (static guards, AST sweeps, chart/openapi loaders).
//
// It exists because runtime.Caller's file name is NOT a usable filesystem path
// under `go build -trimpath`: it becomes module-relative
// ("github.com/keyorixhq/keyorix/server/http/router.go"). Building with
// -trimpath keeps absolute workspace directories out of the Go build-cache key,
// so identical code in many clones shares compiled cache entries.
//
// `go test` runs each test binary with the package directory as the working
// directory, so both helpers start from os.Getwd() and never look at
// runtime.Caller file names. Keep runtime.Caller only for function names and
// line numbers, never for opening files.
package srcpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const rootModule = "github.com/keyorixhq/keyorix"

var (
	rootOnce sync.Once
	rootDir  string
	rootErr  error
)

// RepoRoot returns the absolute directory of the repository's root module
// (the go.mod declaring github.com/keyorixhq/keyorix). Nested modules (cli,
// operator, migrate, devtools/...) have their own go.mod files and are skipped
// while walking up. It panics if the root cannot be found, which only happens
// when the test binary runs outside the repository.
func RepoRoot() string {
	rootOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			rootErr = err
			return
		}
		rootDir, rootErr = findRoot(wd)
	})
	if rootErr != nil {
		panic("srcpath: " + rootErr.Error())
	}
	return rootDir
}

// PkgDir returns the absolute directory of the package under test (the
// working directory `go test` gives the test binary).
func PkgDir() string {
	wd, err := os.Getwd()
	if err != nil {
		panic("srcpath: " + err.Error())
	}
	return wd
}

func findRoot(start string) (string, error) {
	dir := start
	for {
		if modulePath(filepath.Join(dir, "go.mod")) == rootModule {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod for module %s at or above %s", rootModule, start)
		}
		dir = parent
	}
}

// modulePath returns the module path declared in a go.mod file, or "" if the
// file is missing or has no module line.
func modulePath(goMod string) string {
	data, err := os.ReadFile(goMod) // #nosec G304 -- walks up from the test working directory
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module"); ok && rest != line {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}
