// dockerfile_embed_test.go -- #2752: every image built from server/Dockerfile served the
// committed placeholder page, because nothing in the build ran `pnpm build` before the Go
// compile that `//go:embed all:dist` reads from. The release TARBALLS never had the gap
// (`make release` depends on populate-webui-dist); only Docker did.
//
// TestDockerfileEmbedsARealWebBuild asserts the four structural facts that make the fix
// hold, DERIVED from server/Dockerfile's own text rather than restated by hand:
//
//  1. A stage exists that builds the dashboard, on a digest-pinned base (consistent with
//     every other FROM in that file) and with a lockfile-frozen install.
//  2. The Go build stage replaces server/webui/dist from that stage.
//  3. It does so AFTER the `COPY . .` that brings the committed placeholder in (otherwise
//     the placeholder would clobber the real build) and BEFORE `go build ./server` (which
//     is what //go:embed reads).
//  4. That replacement is unconditional -- not gated on BUILD_TAGS -- so the air-gapped
//     variant gets the same real dashboard. ADR-109's "one file" air-gap profile claims
//     exactly this, and the published -airgap image is what #2752 reported as not
//     delivering it.
//
// What this does NOT check, stated so a green run is not read as more than it is: that a
// built image actually SERVES the dashboard. Nothing on the image's filesystem
// distinguishes a real embed from the placeholder -- the binary carries it -- so only
// booting a container and fetching / can tell, which is
// scripts/docker-webui-embedded-check.sh's job (both directions: not the placeholder, AND
// a real Vite build whose bundle is reachable). This test is the cheap, always-run half
// that catches the stage being deleted or reordered; that script is the half that proves
// the result.
package webui

import (
	"os"
	"slices"
	"strings"
	"testing"
)

const dockerfilePath = "../Dockerfile"

func dockerfileLines(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("read %s: %v", dockerfilePath, err)
	}
	return strings.Split(string(raw), "\n")
}

// findLine returns the index of the first line containing every substring in want,
// ignoring comment lines, or -1.
func findLine(lines []string, want ...string) int {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		all := true
		for _, w := range want {
			if !strings.Contains(trimmed, w) {
				all = false
				break
			}
		}
		if all {
			return i
		}
	}
	return -1
}

func TestDockerfileEmbedsARealWebBuild(t *testing.T) {
	lines := dockerfileLines(t)

	// (1) a web-build stage, digest-pinned, lockfile-frozen.
	stage := findLine(lines, "FROM", " AS webui")
	if stage < 0 {
		t.Fatalf("%s has no `FROM ... AS webui` stage: without one, nothing builds the "+
			"dashboard and every image serves the placeholder (#2752)", dockerfilePath)
	}
	if !strings.Contains(lines[stage], "@sha256:") {
		t.Errorf("the webui stage's base image is not pinned by digest: %q", strings.TrimSpace(lines[stage]))
	}
	if findLine(lines, "pnpm install", "--frozen-lockfile") < 0 {
		t.Errorf("%s does not install the web dependencies with --frozen-lockfile: an "+
			"unpinned resolve would make the embedded bundle non-reproducible", dockerfilePath)
	}
	if findLine(lines, "pnpm build") < 0 {
		t.Errorf("%s never runs `pnpm build`", dockerfilePath)
	}

	// (2)+(3) the replacement happens between `COPY . .` and `go build ./server`.
	copyAll := findLine(lines, "COPY . .")
	replace := findLine(lines, "COPY --from=webui", "server/webui/dist")
	// `go build` and its `./server` package argument sit on different physical lines (the
	// RUN is a backslash continuation), so match the compile invocation itself and then
	// confirm the package argument follows it within the same continuation.
	goBuild := findLine(lines, "go build", "-tags")

	if replace < 0 {
		t.Fatalf("%s never copies the built dashboard over server/webui/dist from the webui "+
			"stage, so //go:embed all:dist embeds the committed placeholder (#2752)", dockerfilePath)
	}
	if copyAll < 0 {
		t.Fatalf("%s has no `COPY . .` line -- this guard's premise about ordering is gone; "+
			"re-derive it rather than deleting it", dockerfilePath)
	}
	if goBuild < 0 {
		t.Fatalf("%s has no `go build -tags ...` line -- this guard's premise about ordering "+
			"is gone; re-derive it rather than deleting it", dockerfilePath)
	}
	if !strings.Contains(strings.Join(lines[goBuild:min(goBuild+4, len(lines))], "\n"), "./server") {
		t.Fatalf("the `go build` at line %d does not build ./server within its own continuation "+
			"-- re-derive this guard", goBuild+1)
	}
	if replace < copyAll {
		t.Errorf("the dist replacement (line %d) runs BEFORE `COPY . .` (line %d), which would "+
			"overwrite the real build with the committed placeholder", replace+1, copyAll+1)
	}
	if replace > goBuild {
		t.Errorf("the dist replacement (line %d) runs AFTER `go build ./server` (line %d); "+
			"//go:embed reads dist/ at compile time, so it would embed the placeholder",
			replace+1, goBuild+1)
	}

	// (4) unconditional: the replacement must not be gated on BUILD_TAGS, or the
	// air-gapped variant silently keeps the placeholder.
	for _, idx := range []int{replace, replace - 1} {
		if idx < 0 || idx >= len(lines) {
			continue
		}
		if strings.Contains(lines[idx], "BUILD_TAGS") && strings.Contains(lines[idx], "if") {
			t.Errorf("the dist replacement looks conditional on BUILD_TAGS (line %d: %q) -- "+
				"both variants, full and -airgap, must embed the real dashboard",
				idx+1, strings.TrimSpace(lines[idx]))
		}
	}
}

// TestDockerignoreKeepsWebSourcesButNotItsBuildOutputs pins the build-context side of the
// same fix: the webui stage can only build what .dockerignore lets through. web/ must be
// sent (it was never excluded, but nothing said it must not be), while node_modules and a
// stale local web/dist must not -- node_modules would be copied straight over the stage's
// own frozen install, and is host-arch-specific.
func TestDockerignoreKeepsWebSourcesButNotItsBuildOutputs(t *testing.T) {
	raw, err := os.ReadFile("../../.dockerignore")
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	var patterns []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	has := func(p string) bool {
		return slices.Contains(patterns, p)
	}
	for _, excluded := range []string{"web", "web/", "web/*"} {
		if has(excluded) {
			t.Errorf(".dockerignore excludes %q, so server/Dockerfile's webui stage has no "+
				"sources to build and every image falls back to the placeholder (#2752)", excluded)
		}
	}
	for _, wanted := range []string{"**/node_modules", "web/dist"} {
		if !has(wanted) {
			t.Errorf(".dockerignore does not exclude %q: it would be sent into the build "+
				"context and copied over the webui stage's own frozen install / fresh build", wanted)
		}
	}
}
