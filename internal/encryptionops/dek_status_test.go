package encryptionops

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// printedProviderStatus captures PrintProviderStatus's stdout.
func printedProviderStatus(t *testing.T, kp config.KeyProviderConfig) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	PrintProviderStatus(kp)
	os.Stdout = stdout
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// An env KEK provider whose _FILE is too open is refused when the KEK is read
// (secretenv.LookupChecked), so the status must report it as misconfigured, not
// as set.
func TestPrintProviderStatus_EnvKEKFileTooOpenIsMisconfigured(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("kek\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	kp := config.KeyProviderConfig{Type: "env", EnvVar: "KX_STATUS_KEK"}

	t.Setenv("KX_STATUS_KEK_FILE", write("open", 0o644))
	if out := printedProviderStatus(t, kp); !strings.Contains(out, "misconfigured") {
		t.Fatalf("a 0644 KEK file must be reported misconfigured, got:\n%s", out)
	}

	t.Setenv("KX_STATUS_KEK_FILE", write("strict", 0o600))
	if out := printedProviderStatus(t, kp); !strings.Contains(out, "env var set") {
		t.Fatalf("a 0600 KEK file is set, got:\n%s", out)
	}
}
