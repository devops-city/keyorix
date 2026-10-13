//go:build unix

package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// FIFO-4: every operator-supplied non-secret input of the admin commands must
// refuse a FIFO (and other non-regular files) at once, not block in open(2). A
// regular file and a symlink to one must still be read.

func testCertPEM(t *testing.T) []byte {
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

func testSSHPublicKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	spk, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return ssh.MarshalAuthorizedKey(spk)
}

func testArchiveBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte(`{"format_version":1}`)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "MANIFEST.json", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}))
	_, err := tw.Write(body)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// runWithin runs fn and fails the test if it has not returned within d.
func runWithin(t *testing.T, d time.Duration, fn func() error) error {
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

func mkFIFO(t *testing.T) string {
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

func TestOperatorFiles_FIFORefused_RegularAndSymlinkStillWork(t *testing.T) {
	certPEM := testCertPEM(t)

	// setAnchorFlag / setTSAFlag / setRestoreInput point the package-level flag
	// variables at path for the duration of the call.
	cases := []struct {
		name    string
		content []byte
		// read exercises one entry point against path.
		read func(t *testing.T, path string) error
		// wantOK: the content is valid, so a regular file must give no error.
		wantOK bool
	}{
		{
			name:    "verify-audit --anchor",
			content: []byte(`{}`),
			read: func(t *testing.T, path string) error {
				old := verifyAuditAnchorFile
				verifyAuditAnchorFile = path
				t.Cleanup(func() { verifyAuditAnchorFile = old })
				_, _, err := buildVerifyAuditOptions(configLoadState{})
				return err
			},
		},
		{
			name:    "verify-audit config audit.offline_anchor_path",
			content: []byte(`{}`),
			read: func(t *testing.T, path string) error {
				old := verifyAuditAnchorFile
				verifyAuditAnchorFile = ""
				t.Cleanup(func() { verifyAuditAnchorFile = old })
				cfg := &config.Config{}
				cfg.Audit.OfflineAnchorPath = path
				_, _, err := buildVerifyAuditOptions(configLoadState{cfg: cfg})
				return err
			},
		},
		{
			name:    "verify-audit --tsa-roots",
			content: certPEM,
			wantOK:  true,
			read: func(t *testing.T, path string) error {
				_, err := readTSARootsFile(path)
				return err
			},
		},
		{
			name:    "recovery-key rotate --recipient",
			content: testSSHPublicKey(t),
			wantOK:  true,
			read: func(t *testing.T, path string) error {
				_, err := parseRecoveryKeyRecipient(path)
				return err
			},
		},
		{
			name:    "restore --input (format peek)",
			content: testArchiveBytes(t),
			wantOK:  true,
			read: func(t *testing.T, path string) error {
				v, err := peekFormatVersion(path)
				if err == nil {
					assert.Equal(t, 1, v)
				}
				return err
			},
		},
		{
			name:    "restore --input (v1 archive reader)",
			content: testArchiveBytes(t),
			read: func(t *testing.T, path string) error {
				_, _, _, err := readBackupArchive(path, 0, 0)
				return err
			},
		},
		{
			name:    "restore --input (v2 extract)",
			content: testArchiveBytes(t),
			read: func(t *testing.T, path string) error {
				old := restoreInput
				restoreInput = path
				t.Cleanup(func() { restoreInput = old })
				return runAdminRestoreV2(&config.Config{})
			},
		},
		{
			name:    "restore post-verify audit.offline_anchor_path",
			content: []byte(`{}`),
			read: func(t *testing.T, path string) error {
				cfg := &config.Config{}
				cfg.Audit.OfflineAnchorPath = path
				return runVerifyRestoredAudit(cfg, nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("fifo refused", func(t *testing.T) {
				err := runWithin(t, time.Second, func() error { return tc.read(t, mkFIFO(t)) })
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not a regular file")
				assert.True(t, errors.Is(err, secretenv.ErrNotRegular), "want errors.Is(ErrNotRegular): %v", err)
			})
			t.Run("directory refused", func(t *testing.T) {
				err := runWithin(t, time.Second, func() error { return tc.read(t, t.TempDir()) })
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
					err := runWithin(t, 5*time.Second, func() error { return tc.read(t, p) })
					if tc.wantOK {
						assert.NoError(t, err, p)
					} else if err != nil {
						assert.False(t, strings.Contains(err.Error(), "not a regular file"), "%s: %v", p, err)
					}
				}
			})
			t.Run("symlink to fifo refused", func(t *testing.T) {
				link := filepath.Join(t.TempDir(), "link")
				require.NoError(t, os.Symlink(mkFIFO(t), link))
				err := runWithin(t, time.Second, func() error { return tc.read(t, link) })
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not a regular file")
			})
		})
	}
}
