package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// TestResolveToken_RelativeFileValueNotEchoed: a relative KEYORIX_TOKEN_FILE
// may be the token itself (an operator who mistook _FILE for the value), so no
// failure may print it (SECRETENV-REVIEW-1 F4). An absolute path stays visible.
func TestResolveToken_RelativeFileValueNotEchoed(t *testing.T) {
	const sentinel = "SENTINEL-secret-value-do-not-print"
	want := "KEYORIX_TOKEN_FILE (" + secretenv.RelativePathNotShown + ")"
	for _, mode := range []struct {
		name    string
		prepare func(t *testing.T, p string)
	}{
		{"missing", func(*testing.T, string) {}},
		{"unreadable", func(t *testing.T, p string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 file")
			}
			if err := os.WriteFile(p, []byte("tok\n"), 0o000); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty", func(t *testing.T, p string) {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"whitespace only", func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte("  \n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			mode.prepare(t, filepath.Join(dir, sentinel))
			t.Setenv("KEYORIX_TOKEN", "")
			t.Setenv("KEYORIX_TOKEN_FILE", sentinel)
			_, err := resolveToken()
			if err == nil {
				t.Fatalf("resolveToken accepted a %s token file", mode.name)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Errorf("error prints the relative KEYORIX_TOKEN_FILE value: %v", err)
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not say %q: %v", want, err)
			}
		})
	}
	t.Run("absolute path still shown", func(t *testing.T) {
		abs := filepath.Join(t.TempDir(), "missing-token")
		t.Setenv("KEYORIX_TOKEN", "")
		t.Setenv("KEYORIX_TOKEN_FILE", abs)
		if _, err := resolveToken(); err == nil || !strings.Contains(err.Error(), abs) {
			t.Errorf("an absolute KEYORIX_TOKEN_FILE must stay visible: %v", err)
		}
	})
}
