package demo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin DEMO-WALK-4 finding 10: native-up.sh did not build the helpers the
// scenarios need (bin/keyorix-mcp, bin/demo-oidcissuer, bin/demo-fakevault,
// bin/keyorix-migrate, bin/demo-dbexec), so four of the scenarios stopped at "missing: go
// build ...". They run the REAL native-up.sh --build-only in a throwaway checkout with `go`
// replaced by a shim that records each build and creates the output file (no compiling, no
// server is started). They prove which builds the script asks for and how it reacts to a
// failure; that the commands really compile is checked once by hand and by CI's `go build`.

const fakeGo = `#!/usr/bin/env bash
printf '%s|GOWORK=%s|%s\n' "$PWD" "${GOWORK:-}" "$*" >> "$FAKE/calls"
out=""
while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
if [ -n "${FAKE_FAIL:-}" ]; then case "$out" in *"$FAKE_FAIL") exit 1 ;; esac; fi
printf '#!/bin/sh\n' > "$out"
chmod +x "$out"
`

type nativeEnv struct {
	root, fake, path string
}

func newNativeEnv(t *testing.T) *nativeEnv {
	t.Helper()
	for _, tool := range []string{"python3", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed: native-up.sh requires it", tool)
		}
	}
	e := &nativeEnv{root: t.TempDir(), fake: t.TempDir()}
	bin := t.TempDir()
	e.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"native-up.sh", "lib.sh", "seed.sh", "seed-demo.sh"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(e.root, "scripts", "demo", f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"cli", "migrate"} { // native-up.sh cd's into these module dirs
		if err := os.MkdirAll(filepath.Join(e.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *nativeEnv) run(t *testing.T, extraEnv []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(e.root, "scripts", "demo", "native-up.sh")}, args...)...)
	cmd.Dir = e.root
	cmd.Env = append(os.Environ(), "PATH="+e.path, "FAKE="+e.fake, "KEYORIX_DEMO_DIR="+filepath.Join(e.root, ".demo-native"))
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

func (e *nativeEnv) calls(t *testing.T) []string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(e.fake, "calls"))
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (e *nativeEnv) built(name string) bool {
	_, err := os.Stat(filepath.Join(e.root, "bin", name))
	return err == nil
}

var scenarioHelpers = []string{"demo-dbexec", "keyorix-mcp", "demo-oidcissuer", "demo-fakevault", "keyorix-migrate"}

func TestNativeUp_BuildsEveryScenarioHelperByDefault(t *testing.T) {
	e := newNativeEnv(t)
	out, code := e.run(t, nil, "--build-only")
	if code != 0 {
		t.Fatalf("--build-only exit %d:\n%s", code, out)
	}
	for _, name := range append([]string{"keyorix-server", "keyorix", "totpgen"}, scenarioHelpers...) {
		if !e.built(name) {
			t.Errorf("bin/%s was not built:\n%s", name, out)
		}
	}
	all := strings.Join(e.calls(t), "\n")
	for _, want := range []string{
		"build -o " + filepath.Join(e.root, "bin", "keyorix-mcp") + " ./cmd/keyorix-mcp",
		"build -o " + filepath.Join(e.root, "bin", "demo-oidcissuer") + " ./scripts/demo/oidcissuer",
		"build -o " + filepath.Join(e.root, "bin", "demo-fakevault") + " ./scripts/demo/fakevault",
		"build -o " + filepath.Join(e.root, "bin", "demo-dbexec") + " ./scripts/demo/dbexec",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing build call %q in:\n%s", want, all)
		}
	}
	// keyorix-migrate is its own module: built from migrate/ with GOWORK=off.
	var migrate string
	for _, c := range e.calls(t) {
		if strings.HasSuffix(strings.SplitN(c, "|", 3)[2], "keyorix-migrate .") {
			migrate = c
		}
	}
	if !strings.Contains(migrate, "/migrate|GOWORK=off|") {
		t.Errorf("keyorix-migrate must be built inside migrate/ with GOWORK=off, got %q", migrate)
	}
	if !strings.Contains(out, "--build-only: nothing started") {
		t.Errorf("--build-only did not say it started nothing:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(e.root, ".demo-native", "server.pid")); err == nil {
		t.Error("--build-only started a server")
	}
}

func TestNativeUp_SecondRunBuildsNothingAgain(t *testing.T) {
	e := newNativeEnv(t)
	if out, code := e.run(t, nil, "--build-only"); code != 0 {
		t.Fatalf("first run exit %d:\n%s", code, out)
	}
	first := len(e.calls(t))
	if out, code := e.run(t, nil, "--build-only"); code != 0 {
		t.Fatalf("second run exit %d:\n%s", code, out)
	}
	if n := len(e.calls(t)); n != first {
		t.Fatalf("second run rebuilt binaries that already exist (%d -> %d calls):\n%s", first, n, strings.Join(e.calls(t), "\n"))
	}
}

func TestNativeUp_NoHelpersBuildsOnlyTheCore(t *testing.T) {
	e := newNativeEnv(t)
	out, code := e.run(t, nil, "--no-helpers", "--build-only")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, name := range scenarioHelpers {
		if e.built(name) {
			t.Errorf("--no-helpers built bin/%s", name)
		}
	}
	for _, name := range []string{"keyorix-server", "keyorix", "totpgen"} {
		if !e.built(name) {
			t.Errorf("--no-helpers must still build bin/%s", name)
		}
	}
	if !strings.Contains(out, "not built (--no-helpers)") {
		t.Errorf("--no-helpers skipped silently:\n%s", out)
	}
}

func TestNativeUp_ExistingHelperIsNotRebuilt(t *testing.T) {
	e := newNativeEnv(t)
	mcp := filepath.Join(e.root, "bin", "keyorix-mcp")
	if err := os.MkdirAll(filepath.Dir(mcp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mcp, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, code := e.run(t, nil, "--build-only"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if b, _ := os.ReadFile(mcp); !strings.Contains(string(b), "echo mine") {
		t.Fatalf("an existing bin/keyorix-mcp was overwritten:\n%s", b)
	}
}

func TestNativeUp_HelperBuildFailureIsReportedAndOthersStillBuild(t *testing.T) {
	e := newNativeEnv(t)
	out, code := e.run(t, []string{"FAKE_FAIL=keyorix-migrate"}, "--build-only")
	if code != 1 || !strings.Contains(out, "building bin/keyorix-migrate failed") ||
		!strings.Contains(out, "rest of the demo is unaffected") {
		t.Fatalf("want exit 1 naming bin/keyorix-migrate and what is affected, got %d:\n%s", code, out)
	}
	for _, name := range []string{"demo-dbexec", "keyorix-mcp", "demo-oidcissuer", "demo-fakevault"} {
		if !e.built(name) {
			t.Errorf("a failing helper stopped the others: bin/%s missing", name)
		}
	}
}

func TestNativeUp_UnknownFlagRejected(t *testing.T) {
	e := newNativeEnv(t)
	out, code := e.run(t, nil, "--bogus")
	if code != 1 || !strings.Contains(out, "unknown argument: --bogus") {
		t.Fatalf("want exit 1, got %d:\n%s", code, out)
	}
	if len(e.calls(t)) > 1 || e.built("keyorix-server") {
		t.Fatal("an unknown flag must not build anything")
	}
}
