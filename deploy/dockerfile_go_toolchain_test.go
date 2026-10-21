package deploy

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	goModToolchainRE = regexp.MustCompile(`(?m)^toolchain go(\d+\.\d+\.\d+)\s*$`)
	// Matches `FROM [--platform=...] golang:<tag>[@sha256:<digest>]`.
	dockerfileGolangRE = regexp.MustCompile(`(?m)^FROM\s+(?:--\S+\s+)?golang:(\S+?)(?:@sha256:[0-9a-f]{64})?(?:\s+AS\s+\S+)?\s*$`)
)

// TestDockerfileGolangTagMatchesGoModToolchain: the official golang images set
// GOTOOLCHAIN=local, so a Dockerfile compiles with the Go version in its FROM
// tag no matter what go.mod's toolchain line says. When #3516 moved go.mod to
// go1.27.3 the four Go Dockerfiles stayed on golang:1.27.2-alpine; every
// `go build` and CI test stayed green while the shipped binaries were built
// with 1.27.2 and Trivy failed the images on HIGH CVE-2026-111943.
//
// This asserts the condition (tag == go.mod toolchain), not the conclusion.
// It scans every Dockerfile under the repo and FAILS if it finds none, so a
// layout change cannot turn it vacuous. It does not check the digest matches
// the tag (that needs the registry); the digest pin is checked by Trivy/CI.
func TestDockerfileGolangTagMatchesGoModToolchain(t *testing.T) {
	want := goModToolchain(t, readRepoFile(t, "go.mod"))
	files := repoDockerfiles(t)
	var checked int
	for _, f := range files {
		for _, tag := range golangTags(readRepoFile(t, f)) {
			checked++
			if got := strings.TrimSuffix(tag, "-alpine"); got != want {
				t.Errorf("%s: FROM golang:%s compiles with Go %s but go.mod says toolchain go%s; bump the tag and its @sha256 digest together", f, tag, got, want)
			}
		}
	}
	if checked < 4 {
		t.Fatalf("found only %d golang FROM lines in %d Dockerfiles (expected server, operator, keyorix-mcp, keyorix-k8s-sync); the check would be near-vacuous", checked, len(files))
	}
}

// Both directions of the extraction/comparison on synthetic input.
func TestDockerfileGolangTagExtraction(t *testing.T) {
	const digest = "@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd"
	df := "FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine" + digest + " AS builder\n" +
		"FROM golang:1.27.3-alpine" + digest + " AS b2\n" +
		"FROM alpine:3.24\n# FROM golang:9.9.9\n"
	got := golangTags(df)
	if len(got) != 2 || got[0] != "1.27.2-alpine" || got[1] != "1.27.3-alpine" {
		t.Fatalf("golangTags = %v, want [1.27.2-alpine 1.27.3-alpine]", got)
	}
	if v := goModToolchain(t, "module x\n\ngo 1.27\n\ntoolchain go1.27.3\n"); v != "1.27.3" {
		t.Fatalf("goModToolchain = %q", v)
	}
}

func goModToolchain(t *testing.T, gomod string) string {
	t.Helper()
	m := goModToolchainRE.FindStringSubmatch(gomod)
	if m == nil {
		t.Fatal("go.mod has no `toolchain goX.Y.Z` line; the Dockerfile golang tags have nothing to be compared with")
	}
	return m[1]
}

func golangTags(dockerfile string) []string {
	var tags []string
	for _, m := range dockerfileGolangRE.FindAllStringSubmatch(dockerfile, -1) {
		tags = append(tags, m[1])
	}
	return tags
}

// repoDockerfiles returns repo-relative paths of every file named Dockerfile or
// Dockerfile.*, skipping vendored and VCS trees.
func repoDockerfiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".scratch", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if n := d.Name(); n == "Dockerfile" || strings.HasPrefix(n, "Dockerfile.") {
			rel, rerr := filepath.Rel("..", p)
			if rerr != nil {
				return rerr
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk repo for Dockerfiles: %v", err)
	}
	return out
}
