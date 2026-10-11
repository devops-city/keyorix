package cmd

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/credstore"
)

// SECURE-DEFAULT-1: `keyorix-server admin init` now generates a self-signed TLS
// certificate. These tests drive real commands against a self-signed TLS server and prove
// every way of naming the CA file (--ca-file, KEYORIX_CA_FILE, ca_file in the credentials
// file) reaches newAPIClient, and that without one the CLI still refuses the server.

// selfSignedServer answers the routes `status`, `login` and a skew-checked command call.
func selfSignedServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		case "/auth/login":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"token": "tok-ca"}})
		case "/api/v1/auth/profile":
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":1,"username":"admin"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "server.crt")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, caPath
}

// isolateCLI gives the test its own credentials dir and clears every CA source.
func isolateCLI(t *testing.T) *credstore.FileStore {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(caFileEnv, "")
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("SSL_CERT_FILE", "")
	caFileFlag = ""
	t.Cleanup(func() { caFileFlag = "" })
	path, err := credstore.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	return credstore.NewFileStore(path)
}

// runCLI runs the root command with args, returning stdout and the error.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		rootCmd.SetArgs(args)
		err = rootCmd.Execute()
	})
	rootCmd.SetArgs(nil)
	caFileFlag = "" // cobra does not reset a persistent flag between Execute calls
	return out, err
}

func TestCAFile_SelfSignedServerRefusedWithoutCA(t *testing.T) {
	isolateCLI(t)
	srv, _ := selfSignedServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)

	_, err := runCLI(t, "status")
	if err == nil {
		t.Fatal("status against a self-signed server succeeded without a CA file")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("want a certificate verification error, got: %v", err)
	}
}

func TestCAFile_FlagTrustsServer(t *testing.T) {
	isolateCLI(t)
	srv, caPath := selfSignedServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)

	out, err := runCLI(t, "--ca-file", caPath, "status")
	if err != nil {
		t.Fatalf("status --ca-file: %v", err)
	}
	if !strings.Contains(out, "Health: healthy") {
		t.Fatalf("status output = %q, want Health: healthy", out)
	}
}

func TestCAFile_EnvTrustsServer(t *testing.T) {
	isolateCLI(t)
	srv, caPath := selfSignedServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv(caFileEnv, caPath)

	out, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status with KEYORIX_CA_FILE: %v", err)
	}
	if !strings.Contains(out, "Health: healthy") {
		t.Fatalf("status output = %q, want Health: healthy", out)
	}
}

func TestCAFile_ConfigSetGetUnset(t *testing.T) {
	store := isolateCLI(t)
	srv, caPath := selfSignedServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)

	if _, err := runCLI(t, "config", "set", "ca_file", caPath); err != nil {
		t.Fatalf("config set ca_file: %v", err)
	}
	creds, err := store.Load()
	if err != nil {
		t.Fatalf("Load after config set: %v", err)
	}
	if creds.CAFile != caPath {
		t.Fatalf("stored ca_file = %q, want %q", creds.CAFile, caPath)
	}

	out, err := runCLI(t, "config", "get", "ca_file")
	if err != nil || !strings.Contains(out, caPath) || !strings.Contains(out, "credentials") {
		t.Fatalf("config get ca_file = %q, %v; want the path and its source", out, err)
	}

	if out, err := runCLI(t, "status"); err != nil || !strings.Contains(out, "Health: healthy") {
		t.Fatalf("status with stored ca_file = %q, %v", out, err)
	}

	if _, err := runCLI(t, "config", "unset", "ca_file"); err != nil {
		t.Fatalf("config unset: %v", err)
	}
	if _, err := runCLI(t, "status"); err == nil {
		t.Fatal("status still trusted the self-signed server after config unset ca_file")
	}
}

// A wrong file is refused when set, not on the next command; an unknown key is refused.
func TestCAFile_ConfigSetRefusesBadInput(t *testing.T) {
	store := isolateCLI(t)
	bad := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(bad, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCLI(t, "config", "set", "ca_file", bad); err == nil {
		t.Fatal("config set accepted a file with no certificate")
	}
	if _, err := runCLI(t, "config", "set", "server_url", "https://x"); err == nil {
		t.Fatal("config set accepted an unknown key")
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("a refused config set still wrote the credentials file")
	}
}

// The flag wins over the stored value: a bad --ca-file fails even when the stored one is
// good, and the error names the flag as the source.
func TestCAFile_FlagOverridesStoredValue(t *testing.T) {
	store := isolateCLI(t)
	srv, caPath := selfSignedServer(t)
	if err := store.Save(credstore.Credentials{ServerURL: srv.URL, CAFile: caPath}); err != nil {
		t.Fatal(err)
	}
	_, err := runCLI(t, "--ca-file", filepath.Join(t.TempDir(), "missing.pem"), "status")
	if err == nil || !strings.Contains(err.Error(), "--ca-file") {
		t.Fatalf("status with a missing --ca-file = %v, want an error naming --ca-file", err)
	}
}

// login with --ca-file stores the CA file it verified the server with, so the next
// command needs no flag.
func TestCAFile_LoginPersistsCAFile(t *testing.T) {
	store := isolateCLI(t)
	srv, caPath := selfSignedServer(t)

	if _, err := runCLI(t, "login", "--ca-file", caPath, "--server", srv.URL, "--username", "admin", "--password", "pw"); err != nil {
		t.Fatalf("login --ca-file: %v", err)
	}
	creds, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if creds.CAFile != caPath || creds.Token != "tok-ca" {
		t.Fatalf("stored credentials = %+v, want ca_file %q and the token", creds, caPath)
	}
	if out, err := runCLI(t, "status"); err != nil || !strings.Contains(out, "Health: healthy") {
		t.Fatalf("status after login --ca-file = %q, %v", out, err)
	}
}
