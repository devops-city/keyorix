package edge

// arm_build_test.go keeps the 32-bit and ARM compile fixes from EDGE-1 fixed.
// Three packages did not build for linux/arm (armv7, where int is 32 bits)
// because an untyped constant above 2^31 was used as an int: the dynamic-secret
// TTL bound, the bundle component size limit, and a project-id range check in
// migrate. Nothing on amd64 or arm64 can see that class of break, and an edge
// device is exactly where a 32-bit board turns up.
//
// This is compile-only (no link, no run): it proves the packages type-check for
// the target, which is the part that broke. The full matrix, every shipped
// component for linux/arm64 and linux/arm, is scripts/edge/cross-build.sh.

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func armRepoRoot(t *testing.T) string {
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
			t.Fatal("go.mod not found above " + dir)
		}
		dir = parent
	}
}

func goBuildFor(t *testing.T, moduleDir string, goarch string, pkgs ...string) {
	t.Helper()
	args := append([]string{"build"}, pkgs...)
	cmd := exec.Command("go", args...) //nolint:gosec // fixed arguments
	cmd.Dir = moduleDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch, "GOWORK=off")
	if goarch == "arm" {
		cmd.Env = append(cmd.Env, "GOARM=7")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %v for linux/%s failed:\n%s", pkgs, goarch, out)
	}
}

func TestPackagesBuildFor32BitAndArm(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles for other architectures")
	}
	root := armRepoRoot(t)
	for _, goarch := range []string{"arm", "arm64"} {
		t.Run("root module/"+goarch, func(t *testing.T) {
			goBuildFor(t, root, goarch, "./internal/core", "./pkg/bundleverify")
		})
		t.Run("migrate module/"+goarch, func(t *testing.T) {
			goBuildFor(t, filepath.Join(root, "migrate"), goarch, "./internal/accesstarget")
		})
	}
}
