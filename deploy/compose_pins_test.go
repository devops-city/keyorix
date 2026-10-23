package deploy

import (
	"fmt"
	"os"
	"regexp"
	"testing"
)

// TestComposeImagePinsMatchLatestRelease guards RELEASING.md's "bump the
// docker-compose.yml pins" step (#2601): the keyorix-server / keyorix-web image
// pins must equal each other and must not be older than the newest released
// version in CHANGELOG.md. Registry tags carry no leading "v" (release v0.95.3
// -> image 0.95.3).
//
// "Not older", not "equal": patch releases (v0.96.1..v0.96.3) are cut from a
// release branch, so their CHANGELOG headings exist at the tag but not on main,
// and the pins on main are legitimately ahead of main's newest heading. The exact
// "pin == the tag being cut" check is scripts/release/check-docs-version.sh,
// which RELEASING.md runs before tagging.
//
// It does NOT verify the image exists in the registry, and it takes the newest
// "## vX.Y.Z" heading of CHANGELOG.md as the source of truth for "latest
// release" (RELEASING.md requires the CHANGELOG entry before tagging). Only
// images under ghcr.io/keyorixhq/ are checked; third-party images are not.
func TestComposeImagePinsMatchLatestRelease(t *testing.T) {
	changelog := readRepoFile(t, "CHANGELOG.md")
	m := changelogHeadingRE.FindStringSubmatch(changelog)
	if m == nil {
		t.Fatal("no \"## vX.Y.Z\" release heading found in CHANGELOG.md; the check would be vacuous")
	}
	latest := m[1]

	pins := composePinRE.FindAllStringSubmatch(readRepoFile(t, "docker-compose.yml"), -1)
	if len(pins) < 2 {
		t.Fatalf("found %d ghcr.io/keyorixhq image pins in docker-compose.yml, want at least 2 (server, web)", len(pins))
	}
	for _, p := range pins {
		if p[2] != pins[0][2] {
			t.Errorf("docker-compose.yml pins %s:%s but %s:%s -- the images must share one release tag", p[1], p[2], pins[0][1], pins[0][2])
		}
		if semverLess(t, p[2], latest) {
			t.Errorf("docker-compose.yml pins %s:%s but the latest release in CHANGELOG.md is v%s -- bump the pins (RELEASING.md step 3)", p[1], p[2], latest)
		}
	}
}

func semverLess(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y [3]int
	if _, err := fmt.Sscanf(a, "%d.%d.%d", &x[0], &x[1], &x[2]); err != nil {
		t.Fatalf("parse %q: %v", a, err)
	}
	if _, err := fmt.Sscanf(b, "%d.%d.%d", &y[0], &y[1], &y[2]); err != nil {
		t.Fatalf("parse %q: %v", b, err)
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

var (
	changelogHeadingRE = regexp.MustCompile(`(?m)^## v(\d+\.\d+\.\d+)\b`)
	composePinRE       = regexp.MustCompile(`(?m)^\s*image:\s*(ghcr\.io/keyorixhq/[\w.-]+):(\d+\.\d+\.\d+)\b`)
)

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../" + name) // #nosec G304 -- fixed repo-relative names from this file
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
