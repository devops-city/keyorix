package demo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin #3149: up.sh must not silently reuse a demo image built from a
// different source tree, and down.sh --wipe must not delete the default-named volume
// without --force-default. They run the REAL up.sh/down.sh against a throwaway git
// checkout, with `docker`, `make` and `pnpm` replaced by shims that record their calls
// (no Docker needed). They prove the scripts' decisions, not a real image build: the
// container-level run is scripts/demo/check.sh / demo-readiness in CI.

const fakeDocker = `#!/usr/bin/env bash
echo "$*" >> "$FAKE/calls"
case "$1" in
  image)   # image inspect [-f FMT] TAG
    [ -f "$FAKE/image" ] || exit 1
    [ "$2" = inspect ] && [ "${3:-}" = "-f" ] && cat "$FAKE/image"
    exit 0 ;;
  ps)
    case "$*" in
      *ancestor=*) cat "$FAKE/foreign" 2>/dev/null || true ;;
      *) cat "$FAKE/running" 2>/dev/null || true ;;
    esac
    exit 0 ;;
  build|volume|rm|logs|exec) exit 0 ;;
  *) exit 1 ;;
esac
`

type env struct {
	root string // throwaway checkout
	fake string // shim state dir
	path string
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{root: t.TempDir(), fake: t.TempDir()}
	bin := t.TempDir()
	e.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	write := func(p, body string, mode os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "docker"), fakeDocker, 0o755)
	write(filepath.Join(bin, "make"), "#!/bin/sh\necho make \"$@\" >> \"$FAKE/calls\"\n", 0o755)
	write(filepath.Join(bin, "pnpm"), "#!/bin/sh\n", 0o755)
	for _, f := range []string{"up.sh", "down.sh", "lib.sh", "image-stamp.sh", "seed.sh"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(e.root, "scripts", "demo", f), string(raw), 0o755)
	}
	// up.sh only builds these when missing; the shims make the build a no-op.
	write(filepath.Join(e.root, "bin", "keyorix"), "#!/bin/sh\n", 0o755)
	write(filepath.Join(e.root, "bin", "totpgen"), "#!/bin/sh\n", 0o755)
	write(filepath.Join(e.root, "server", "main.go"), "package main\n", 0o644)
	git(t, e.root, "init", "-q")
	git(t, e.root, "add", "-A")
	git(t, e.root, "commit", "-q", "-m", "init")
	return e
}

func (e *env) setImage(t *testing.T, label string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.fake, "image"), []byte(label), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *env) calls(t *testing.T) string {
	b, _ := os.ReadFile(filepath.Join(e.fake, "calls"))
	return string(b)
}

func (e *env) run(t *testing.T, script string, extraEnv []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(e.root, "scripts", "demo", script)}, args...)...)
	cmd.Dir = e.root
	cmd.Env = append(os.Environ(), "PATH="+e.path, "FAKE="+e.fake)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestUp_NoBuildFailsFastOnStaleImage(t *testing.T) {
	e := newEnv(t)
	head := git(t, e.root, "rev-parse", "--short=12", "HEAD")
	e.setImage(t, "0123456789ab")
	out, code := e.run(t, "up.sh", nil, "--no-build")
	if code != 1 || !strings.Contains(out, "is stale: built from 0123456789ab, this checkout is "+head) ||
		!strings.Contains(out, "--no-build forbids building") {
		t.Fatalf("want exit 1 naming both commits, got %d:\n%s", code, out)
	}
	if strings.Contains(e.calls(t), "build ") {
		t.Fatalf("--no-build must not build:\n%s", e.calls(t))
	}
}

func TestUp_UnlabelledImageIsStale(t *testing.T) {
	e := newEnv(t)
	e.setImage(t, "") // an image from before labels existed
	out, code := e.run(t, "up.sh", nil, "--no-build")
	if code != 1 || !strings.Contains(out, "built from an unknown source") {
		t.Fatalf("want a stale verdict for an unlabelled image, got %d:\n%s", code, out)
	}
}

func TestUp_MatchingImageIsReusedAndNeverRebuilt(t *testing.T) {
	e := newEnv(t)
	head := git(t, e.root, "rev-parse", "--short=12", "HEAD")
	e.setImage(t, head)
	out, _ := e.run(t, "up.sh", nil) // fails later at the fake `docker run`; only the image decision matters
	if !strings.Contains(out, "Reusing image keyorix-demo:airgap: built from "+head+", which matches this checkout") {
		t.Fatalf("matching image not reused:\n%s", out)
	}
	if strings.Contains(e.calls(t), "build ") {
		t.Fatalf("matching image was rebuilt:\n%s", e.calls(t))
	}
}

func TestUp_StaleImageIsRebuiltWithLabel(t *testing.T) {
	e := newEnv(t)
	head := git(t, e.root, "rev-parse", "--short=12", "HEAD")
	e.setImage(t, "0123456789ab")
	out, _ := e.run(t, "up.sh", nil)
	if !strings.Contains(out, "is stale: built from 0123456789ab") {
		t.Fatalf("up.sh did not say why it rebuilds:\n%s", out)
	}
	if !strings.Contains(e.calls(t), "build -f server/Dockerfile") ||
		!strings.Contains(e.calls(t), "--label io.keyorix.demo.source="+head) {
		t.Fatalf("stale image not rebuilt with the checkout's label:\n%s", e.calls(t))
	}
}

func TestUp_UncommittedChangeMakesImageStale(t *testing.T) {
	e := newEnv(t)
	head := git(t, e.root, "rev-parse", "--short=12", "HEAD")
	e.setImage(t, head) // built from the clean commit
	if err := os.WriteFile(filepath.Join(e.root, "server", "main.go"), []byte("package main\n// edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := e.run(t, "up.sh", nil, "--no-build")
	if code != 1 || !strings.Contains(out, "this checkout is "+head+"+dirty-") {
		t.Fatalf("an edited working tree must not match the clean-commit image, got %d:\n%s", code, out)
	}
}

func TestUp_RefusesToRetagWhileAnotherContainerRunsFromIt(t *testing.T) {
	e := newEnv(t)
	e.setImage(t, "0123456789ab")
	if err := os.WriteFile(filepath.Join(e.fake, "foreign"), []byte("someone-elses-demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := e.run(t, "up.sh", nil)
	if code != 1 || !strings.Contains(out, "someone-elses-demo") || !strings.Contains(out, "KEYORIX_DEMO_IMAGE=") {
		t.Fatalf("want a refusal naming the other container, got %d:\n%s", code, out)
	}
	if strings.Contains(e.calls(t), "build ") {
		t.Fatalf("re-tagged an image another container runs from:\n%s", e.calls(t))
	}
}

func TestUp_ContradictoryFlags(t *testing.T) {
	e := newEnv(t)
	if _, code := e.run(t, "up.sh", nil, "--rebuild", "--no-build"); code != 1 {
		t.Fatalf("--rebuild --no-build must be rejected, got %d", code)
	}
}

func TestDown_WipeRefusesDefaultVolumeWithoutForce(t *testing.T) {
	e := newEnv(t)
	out, code := e.run(t, "down.sh", nil, "--wipe")
	if code != 2 || !strings.Contains(out, "refusing to wipe the default-named volume keyorix-demo-data") {
		t.Fatalf("want exit 2 + refusal, got %d:\n%s", code, out)
	}
	for _, want := range []string{"container  keyorix-demo", "volume     keyorix-demo-data", ".demo-2-state", ".demo-2-cli-home"} {
		if !strings.Contains(out, want) {
			t.Fatalf("refusal does not list %q:\n%s", want, out)
		}
	}
	if c := e.calls(t); strings.Contains(c, "volume rm") || strings.Contains(c, "rm -f") {
		t.Fatalf("a refused wipe removed something:\n%s", c)
	}
}

func TestDown_ForceDefaultWipes(t *testing.T) {
	e := newEnv(t)
	out, code := e.run(t, "down.sh", nil, "--wipe", "--force-default")
	if code != 0 || !strings.Contains(e.calls(t), "volume rm keyorix-demo-data") {
		t.Fatalf("--force-default did not wipe, exit %d:\n%s\ncalls:\n%s", code, out, e.calls(t))
	}
}

func TestDown_WipeOfOwnNamedVolumeNeedsNoForce(t *testing.T) {
	e := newEnv(t)
	out, code := e.run(t, "down.sh", []string{"KEYORIX_DEMO_VOLUME=fix3149-data", "KEYORIX_DEMO_CONTAINER=fix3149"}, "--wipe")
	if code != 0 || !strings.Contains(e.calls(t), "volume rm fix3149-data") || strings.Contains(e.calls(t), "keyorix-demo-data") {
		t.Fatalf("own-named wipe failed or touched the default, exit %d:\n%s\ncalls:\n%s", code, out, e.calls(t))
	}
}

func TestDown_PlainDownKeepsVolume(t *testing.T) {
	e := newEnv(t)
	if _, code := e.run(t, "down.sh", nil); code != 0 || strings.Contains(e.calls(t), "volume rm") {
		t.Fatalf("plain down must keep the volume (exit %d):\n%s", code, e.calls(t))
	}
}

func TestDown_ForceDefaultAloneIsRejected(t *testing.T) {
	e := newEnv(t)
	if _, code := e.run(t, "down.sh", nil, "--force-default"); code != 1 {
		t.Fatalf("--force-default without --wipe must be rejected, got %d", code)
	}
}
