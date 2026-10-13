//go:build unix

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// FIFO-4: the server's operator-supplied non-secret files (CA bundle, license,
// SAML IdP metadata) must refuse a FIFO at once instead of blocking the boot in
// open(2). A regular file and a symlink to one must still be read.

func fifo4CertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fifo4-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func fifo4Within(t *testing.T, d time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("blocked on a FIFO instead of refusing it within %s", d)
		return nil
	}
}

func fifo4MkFIFO(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(p, 0o600))
	t.Cleanup(func() {
		// Release a reader still blocked in open(2) on old code.
		if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	return p
}

func TestServerOperatorFiles_FIFORefused_RegularAndSymlinkStillWork(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		read    func(path string) error
		wantOK  bool
	}{
		{
			name:    "tls.client_ca / audit CA bundle (loadCertPool)",
			content: fifo4CertPEM(t),
			wantOK:  true,
			read: func(p string) error {
				_, err := loadCertPool(p)
				return err
			},
		},
		{
			name:    "sso saml idp_metadata_file (buildSAMLProvider)",
			content: []byte("<not-metadata/>"),
			read: func(p string) error {
				_, err := buildSAMLProvider(config.SSOProviderConfig{
					Name: "fifo4",
					SAML: &config.SAMLProviderConfig{IDPMetadataFile: p},
				})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("fifo refused", func(t *testing.T) {
				err := fifo4Within(t, time.Second, func() error { return tc.read(fifo4MkFIFO(t)) })
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not a regular file")
			})
			t.Run("directory refused", func(t *testing.T) {
				err := fifo4Within(t, time.Second, func() error { return tc.read(t.TempDir()) })
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not a regular file")
			})
			t.Run("symlink to fifo refused", func(t *testing.T) {
				link := filepath.Join(t.TempDir(), "link")
				require.NoError(t, os.Symlink(fifo4MkFIFO(t), link))
				err := fifo4Within(t, time.Second, func() error { return tc.read(link) })
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not a regular file")
			})
			t.Run("regular file and symlink work", func(t *testing.T) {
				dir := t.TempDir()
				reg := filepath.Join(dir, "input")
				require.NoError(t, os.WriteFile(reg, tc.content, 0o600))
				link := filepath.Join(dir, "link")
				require.NoError(t, os.Symlink(reg, link))
				for _, p := range []string{reg, link} {
					err := fifo4Within(t, 5*time.Second, func() error { return tc.read(p) })
					if tc.wantOK {
						assert.NoError(t, err, p)
					} else if err != nil {
						assert.NotContains(t, err.Error(), "not a regular file", p)
					}
				}
			})
		})
	}
}

func TestServerOperatorFiles_LicenseFIFORefused(t *testing.T) {
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	var token string
	require.NoError(t, fifo4Within(t, time.Second, func() error {
		token = loadLicenseToken(fifo4MkFIFO(t))
		return nil
	}))
	assert.Empty(t, token, "a FIFO must not yield a license token")
	assert.Contains(t, logBuf.String(), "not a regular file")

	dir := t.TempDir()
	reg := filepath.Join(dir, "license.jwt")
	require.NoError(t, os.WriteFile(reg, []byte("  tok.en.value\n"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(reg, link))
	assert.Equal(t, "tok.en.value", loadLicenseToken(reg))
	assert.Equal(t, "tok.en.value", loadLicenseToken(link))
	assert.Empty(t, loadLicenseToken(""))
}
