package apiclient

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeServerCA writes srv's self-signed certificate as a PEM file and returns its path.
// httptest's TLS server certificate is the same shape `keyorix-server admin init`
// generates: one self-signed certificate for localhost/127.0.0.1, not in any system store.
func writeServerCA(t *testing.T, srv *httptest.Server, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Without a CA file, the hardened client uses the system roots and must refuse the
// self-signed server: the CA option adds trust, it never turns verification off.
func TestHardenedClient_SelfSignedServerRefusedWithoutCA(t *testing.T) {
	srv := newTLSServer(t)
	resp, err := NewHardenedHTTPClient().Get(srv.URL) //nolint:noctx
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected a certificate verification error against a self-signed server")
	}
}

// The pool is built by Go's x509 from the file itself (no SSL_CERT_FILE, no platform
// verifier), so this behaves the same on macOS and Linux.
func TestHardenedClient_TrustsServerFromCAFile(t *testing.T) {
	srv := newTLSServer(t)
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")

	c, err := NewHardenedHTTPClientWithCAFile(writeServerCA(t, srv, 0o600))
	if err != nil {
		t.Fatalf("NewHardenedHTTPClientWithCAFile: %v", err)
	}
	resp, err := c.Get(srv.URL) //nolint:noctx
	if err != nil {
		t.Fatalf("Get with the server's CA file: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body %q", body)
	}

	// The hardening still applies to the CA-file client.
	if c.Timeout <= 0 || c.CheckRedirect == nil {
		t.Fatal("CA-file client lost the timeout or the redirect refusal")
	}
}

// A CA file for one server must not make a different self-signed server trusted.
func TestHardenedClient_CAFileDoesNotTrustOtherServers(t *testing.T) {
	trusted := newTLSServer(t)
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	other.StartTLS()
	t.Cleanup(other.Close)

	c, err := NewHardenedHTTPClientWithCAFile(writeServerCA(t, trusted, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if string(trusted.Certificate().Raw) == string(other.Certificate().Raw) {
		t.Skip("httptest reused one certificate for both servers; nothing to distinguish")
	}
	resp, err := c.Get(other.URL) //nolint:noctx
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("a CA file for one server made an unrelated certificate trusted")
	}
}

func TestLoadCAPool_FailsClosed(t *testing.T) {
	srv := newTLSServer(t)
	dir := t.TempDir()

	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	cases := []struct {
		name string
		path string
		want string
	}{
		{"missing", filepath.Join(dir, "nope.pem"), "read CA file"},
		{"empty", write("empty.pem", "", 0o600), "no PEM certificate"},
		{"garbage", write("garbage.pem", "not a certificate\n", 0o600), "no PEM certificate"},
		{"private key", write("key.pem", certPEM+"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", 0o600), "private key"},
		{"world-writable", write("ww.pem", certPEM, 0o666), "writable by group or others"},
		{"group-writable", write("gw.pem", certPEM, 0o620), "writable by group or others"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCAPool(tc.path)
			if err == nil {
				t.Fatalf("LoadCAPool(%s) succeeded, want an error containing %q", tc.name, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadCAPool(%s) error = %v, want it to contain %q", tc.name, err, tc.want)
			}
		})
	}

	// A world-READABLE CA file is fine: a CA certificate is public.
	if _, err := LoadCAPool(write("ok.pem", certPEM, 0o644)); err != nil {
		t.Fatalf("LoadCAPool on a 0644 certificate: %v", err)
	}
}
