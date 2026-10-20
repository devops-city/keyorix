package apiclient

// TestGeneratedClient_IsFresh regenerates types.gen.go and client.gen.go from
// server/http/handlers/openapi.yaml into a temp dir, exactly as `make -C cli client`
// does, and requires the committed files to be byte-identical. The same idea as
// web's `check:api-types-fresh`.
//
// Why it exists: the committed client drifted from the spec four times (PAT-GUARD-1,
// REBASE-22, SUSPEND-PURGE-1, FOLLOWUP-ENV-FREEZE), each time found by accident. A
// spec change that adds a field or a response and does not regenerate now fails here.
// The fix is always `make -C cli client`.
//
// The oapi-codegen version is read from cli/Makefile (OAPI_CODEGEN_VERSION), so the
// pin lives in one place. The generator runs through `go run <pkg>@<version>`, which
// needs the Go module proxy (or a warm module cache): when it cannot run, the test
// FAILS rather than skips, because a skipped freshness check reads like a passing one.
//
// migrate/internal/apiclient carries the same test for migrate's own client (separate
// module and filterspec, so the helper is repeated rather than shared).

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

const (
	// Paths relative to this package directory, which is `go test`'s working directory.
	freshSpecPath     = "../../../server/http/handlers/openapi.yaml"
	freshMakefilePath = "../../Makefile"
)

var freshOapiVersionRe = regexp.MustCompile(`(?m)^OAPI_CODEGEN_VERSION\s*=\s*(v\d+\.\d+\.\d+)\s*$`)

func freshRun(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tool names and test-controlled paths
	// The module is excluded from the repo's go.work (cli/Makefile exports the same).
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v failed: %v\n%s\n(this check needs the Go module proxy or a warm module cache; "+
			"it fails rather than skips so a missing generator cannot read as a pass)", name, args, err, out.String())
	}
}

// firstDifference describes where a and b first differ, or "" when they are equal.
func firstDifference(a, b []byte) string {
	if bytes.Equal(a, b) {
		return ""
	}
	al, bl := bytes.Split(a, []byte("\n")), bytes.Split(b, []byte("\n"))
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y []byte
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if !bytes.Equal(x, y) {
			return fmt.Sprintf("line %d:\n  committed:   %q\n  regenerated: %q", i+1, x, y)
		}
	}
	return "files differ"
}

func TestGeneratedClient_IsFresh(t *testing.T) {
	spec, err := filepath.Abs(freshSpecPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spec); err != nil {
		t.Fatalf("openapi spec not found at %s: %v (the repo layout this check relies on changed)", spec, err)
	}
	mk, err := os.ReadFile(freshMakefilePath)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	m := freshOapiVersionRe.FindSubmatch(mk)
	if m == nil {
		t.Fatalf("OAPI_CODEGEN_VERSION not found in %s: the Makefile pin this check reads moved", freshMakefilePath)
	}
	codegen := "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@" + string(m[1])

	tmp := t.TempDir()
	filtered := filepath.Join(tmp, "openapi-filtered.yaml")
	freshRun(t, "go", "run", "./gen", spec, filtered)

	for _, kind := range []string{"types", "client"} {
		file := kind + ".gen.go"
		regenerated := filepath.Join(tmp, file)
		freshRun(t, "go", "run", codegen, "-generate", kind, "-package", "apiclient", "-o", regenerated, filtered)
		want, err := os.ReadFile(regenerated)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if d := firstDifference(got, want); d != "" {
			t.Errorf("%s is stale against server/http/handlers/openapi.yaml (first difference at %s)\n"+
				"Regenerate with `make -C cli client` and commit the result.", file, d)
		}
	}
}
