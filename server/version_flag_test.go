package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsVersionRequest(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"long flag", []string{"keyorix-server", "--version"}, true},
		{"go-style flag", []string{"keyorix-server", "-version"}, true},
		{"no args", []string{"keyorix-server"}, false},
		{"with other flag", []string{"keyorix-server", "--version", "-passphrase-stdin"}, false},
		{"admin version is not the flag", []string{"keyorix-server", "admin", "--version"}, false},
		{"near miss", []string{"keyorix-server", "--versions"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isVersionRequest(tc.args); got != tc.want {
				t.Errorf("isVersionRequest(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestBuiltBinaryReportsInjectedBuildInfo builds the real binary with the same -X
// ldflags the Makefile/Dockerfile use and checks that both `--version` and
// `admin version` print the injected values and the Go toolchain, with no config file
// present and no listener or database touched.
func TestBuiltBinaryReportsInjectedBuildInfo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the server binary")
	}
	bin := filepath.Join(t.TempDir(), "keyorix-server")
	const pkg = "github.com/keyorixhq/keyorix/internal/version."
	ldflags := "-X " + pkg + "Version=v9.8.7 -X " + pkg + "Commit=abc1234 -X " + pkg + "BuildDate=2026-10-13T01:02:03Z"
	build := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	want := []string{"v9.8.7", "commit: abc1234", "built: 2026-10-13T01:02:03Z", "go: " + runtime.Version()}
	for _, args := range [][]string{{"--version"}, {"admin", "version"}} {
		cmd := exec.Command(bin, args...)
		cmd.Dir = t.TempDir() // no keyorix.yaml here
		cmd.Env = []string{"PATH=" + t.TempDir()}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		for _, w := range want {
			if !strings.Contains(string(out), w) {
				t.Errorf("%v output missing %q:\n%s", args, w, out)
			}
		}
	}
}
