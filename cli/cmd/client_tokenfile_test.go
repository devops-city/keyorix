package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tokenFileCanary = "kxtok-CANARY-0123456789abcdef"

func writeTokenFile(t *testing.T, mode os.FileMode, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // WriteFile is subject to the umask
		t.Fatal(err)
	}
	return p
}

func TestResolveToken_FromKeyorixTokenFile(t *testing.T) {
	doctorIsolateEnv(t)
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1")
	t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o600, tokenFileCanary+"\n"))
	store, err := resolveCredStore()
	if err != nil {
		t.Fatal(err)
	}
	server, token, err := resolveServerAndToken(store)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if server != "http://127.0.0.1:1" || token != tokenFileCanary {
		t.Fatalf("got server=%q token=%q, want the file's token with its newline stripped", server, token)
	}
}

func TestResolveToken_FileBeatsStoredCredentials(t *testing.T) {
	doctorIsolateEnv(t)
	store, err := resolveCredStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1")
	t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o400, tokenFileCanary))
	_, token, err := resolveServerAndToken(store)
	if err != nil || token != tokenFileCanary {
		t.Fatalf("token=%q err=%v", token, err)
	}
}

func TestResolveToken_FileRefusals(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T)
		wantText string
		wantCode int
	}{
		{"mode too open", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o644, tokenFileCanary))
		}, "too open", exitAuth},
		{"empty file", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o600, "\n"))
		}, "empty", exitAuth},
		{"missing file", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN_FILE", filepath.Join(t.TempDir(), "nope"))
		}, "KEYORIX_TOKEN_FILE", exitAuth},
		{"both forms set", func(t *testing.T) {
			t.Setenv("KEYORIX_TOKEN", "x")
			t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o600, tokenFileCanary))
		}, "set exactly one", exitUsage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doctorIsolateEnv(t)
			t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1")
			c.setup(t)
			store, _ := resolveCredStore()
			_, _, err := resolveServerAndToken(store)
			if err == nil {
				t.Fatal("want an error, never a silent fallback to another token")
			}
			if !strings.Contains(err.Error(), c.wantText) {
				t.Errorf("error should mention %q: %v", c.wantText, err)
			}
			if strings.Contains(err.Error(), tokenFileCanary) {
				t.Errorf("error leaked the token: %v", err)
			}
			if code, _ := classifyError(err, true); code != c.wantCode {
				t.Errorf("exit code %d, want %d", code, c.wantCode)
			}
		})
	}
}

// doctor says where the token came from, and a bad token file is reported as such rather
// than as "no server is configured".
func TestDoctor_TokenFile(t *testing.T) {
	srv := "http://127.0.0.1:1" // the config check does not contact the server
	useServer(t, srv, "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o600, tokenFileCanary))
	c := runDoctorReport(t).check(t, "config")
	if c.Status != doctorPass || !strings.Contains(c.Detail, "KEYORIX_TOKEN_FILE") || strings.Contains(c.Detail, tokenFileCanary) {
		t.Errorf("config: %+v", c)
	}

	t.Setenv("KEYORIX_TOKEN_FILE", writeTokenFile(t, 0o644, tokenFileCanary))
	c = runDoctorReport(t).check(t, "config")
	if c.Status != doctorFail || !strings.Contains(c.Detail, "KEYORIX_TOKEN_FILE") || !strings.Contains(c.Detail, "too open") {
		t.Errorf("a bad token file must be named in the doctor report: %+v", c)
	}
}
