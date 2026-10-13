package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// KEYORIX_LOCAL_CA_FILE is copied to a world-readable (0644) file on the volume
// shared with the web container. The entrypoint must refuse anything that is not
// a plain PEM certificate bundle, above all a private key. These tests run the
// shipped functions and the shipped copy block from entrypoint.sh (not a copy of
// them) in sh.
//
// Not covered: the surrounding `admin init --secure-files` step (needs the
// server binary); the web container's use of the copied file.

func publicCertShell(t *testing.T) (funcs, block string) {
	t.Helper()
	b, err := os.ReadFile("entrypoint.sh")
	require.NoError(t, err)
	s := string(b)
	begin := strings.Index(s, "# --- BEGIN public_cert")
	end := strings.Index(s, "# --- END public_cert ---")
	require.True(t, begin >= 0 && end > begin, "public_cert markers missing from entrypoint.sh")
	funcs = s[begin:end]
	start := strings.Index(s, "    if [ -n \"$KEYORIX_PUBLIC_CA_FILE\" ]; then")
	require.True(t, start >= 0, "KEYORIX_PUBLIC_CA_FILE block missing from entrypoint.sh")
	rest := s[start:]
	fi := strings.Index(rest, "\n    fi\n")
	require.True(t, fi > 0, "end of the KEYORIX_PUBLIC_CA_FILE block not found")
	return funcs, rest[:fi+len("\n    fi\n")]
}

func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "keyorix-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testKeyPEM(t *testing.T, blockType string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// runPublicCA runs the shipped copy block with the given source and returns
// exit status, stderr, and the destination file path.
func runPublicCA(t *testing.T, src string) (rc int, stderr, dst string) {
	t.Helper()
	funcs, block := publicCertShell(t)
	dst = filepath.Join(t.TempDir(), "public-ca.crt")
	script := funcs + "\n" + block + "\necho reached-after-copy\n"
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"KEYORIX_LOCAL_CA_FILE=" + src,
		"KEYORIX_PUBLIC_CA_FILE=" + dst,
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else {
		require.NoError(t, err)
	}
	if rc == 0 {
		assert.Contains(t, so.String(), "reached-after-copy")
	} else {
		assert.NotContains(t, so.String(), "reached-after-copy", "a refusal must stop the entrypoint")
	}
	return rc, se.String(), dst
}

func writeFileT(t *testing.T, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src")
	require.NoError(t, os.WriteFile(p, content, 0o600))
	return p
}

func TestEntrypointPublicCA_AcceptsCertificateBundles(t *testing.T) {
	cert := testCertPEM(t)
	two := append(append([]byte{}, cert...), append([]byte("\n"), cert...)...)
	crlf := bytes.ReplaceAll(cert, []byte("\n"), []byte("\r\n"))
	for name, content := range map[string][]byte{"one": cert, "bundle": two, "crlf": crlf} {
		t.Run(name, func(t *testing.T) {
			rc, stderr, dst := runPublicCA(t, writeFileT(t, content))
			require.Equal(t, 0, rc, stderr)
			got, err := os.ReadFile(dst)
			require.NoError(t, err)
			assert.Equal(t, content, got)
			fi, err := os.Stat(dst)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
			_, err = os.Stat(dst + ".tmp")
			assert.True(t, os.IsNotExist(err), "no .tmp left behind")
		})
	}
	t.Run("symlink to a certificate", func(t *testing.T) {
		real := writeFileT(t, cert)
		link := filepath.Join(t.TempDir(), "link")
		require.NoError(t, os.Symlink(real, link))
		rc, stderr, _ := runPublicCA(t, link)
		require.Equal(t, 0, rc, stderr)
	})
}

func TestEntrypointPublicCA_RefusesPrivateKeysAndNonCertificates(t *testing.T) {
	cert := testCertPEM(t)
	var enc bytes.Buffer
	enc.WriteString("-----BEGIN ENCRYPTED PRIVATE KEY-----\nQUJDRA==\n-----END ENCRYPTED PRIVATE KEY-----\n")
	cases := map[string][]byte{
		"ec key":            testKeyPEM(t, "EC PRIVATE KEY"),
		"pkcs8 key":         testKeyPEM(t, "PRIVATE KEY"),
		"rsa key":           testKeyPEM(t, "RSA PRIVATE KEY"),
		"encrypted key":     enc.Bytes(),
		"cert then key":     append(append([]byte{}, cert...), testKeyPEM(t, "EC PRIVATE KEY")...),
		"key then cert":     append(testKeyPEM(t, "EC PRIVATE KEY"), cert...),
		"key in a comment":  append([]byte("# PRIVATE KEY lives elsewhere\n"), cert...),
		"empty":             {},
		"plain text":        []byte("hello\n"),
		"text before cert":  append([]byte("Certificate:\n    Data:\n"), cert...),
		"text after cert":   append(append([]byte{}, cert...), []byte("trailing\n")...),
		"public key block":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")}),
		"unterminated cert": []byte("-----BEGIN CERTIFICATE-----\nQUJD\n"),
		"junk in cert body": []byte("-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"),
		"oversized":         append(append([]byte{}, cert...), bytes.Repeat([]byte("\n"), 300000)...),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			rc, stderr, dst := runPublicCA(t, writeFileT(t, content))
			assert.NotEqual(t, 0, rc, "must refuse")
			assert.Contains(t, stderr, "ERROR: KEYORIX_LOCAL_CA_FILE")
			assert.NotContains(t, stderr, "BEGIN", "never echo file contents")
			_, err := os.Stat(dst)
			assert.True(t, os.IsNotExist(err), "no world-readable file may be created")
			_, err = os.Stat(dst + ".tmp")
			assert.True(t, os.IsNotExist(err), "the private temp copy must be removed")
		})
	}
	t.Run("private key message", func(t *testing.T) {
		_, stderr, _ := runPublicCA(t, writeFileT(t, testKeyPEM(t, "EC PRIVATE KEY")))
		assert.Contains(t, stderr, "PRIVATE KEY")
	})
}

func TestEntrypointPublicCA_RefusesNonRegularFiles(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		rc, stderr, dst := runPublicCA(t, t.TempDir())
		assert.NotEqual(t, 0, rc)
		assert.Contains(t, stderr, "not a readable regular file")
		_, err := os.Stat(dst)
		assert.True(t, os.IsNotExist(err))
	})
	t.Run("missing", func(t *testing.T) {
		rc, stderr, _ := runPublicCA(t, filepath.Join(t.TempDir(), "nope"))
		assert.NotEqual(t, 0, rc)
		assert.Contains(t, stderr, "not a readable regular file")
	})
	t.Run("fifo", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		rc, stderr, _ := runPublicCA(t, p) // would hang in cp if not refused first
		assert.NotEqual(t, 0, rc)
		assert.Contains(t, stderr, "not a readable regular file")
	})
}
