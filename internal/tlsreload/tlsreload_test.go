package tlsreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a self-signed ECDSA cert/key pair with the given serial number.
func writePair(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	// Make the rotation visible even on a filesystem with coarse mtimes.
	future := time.Now().Add(time.Duration(serial) * time.Second)
	_ = os.Chtimes(certFile, future, future)
	_ = os.Chtimes(keyFile, future, future)
}

func servedSerial(t *testing.T, r *Reloader) int64 {
	t.Helper()
	cert, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.Int64()
}

func withCheckInterval(t *testing.T, d time.Duration) {
	t.Helper()
	old := CheckInterval
	CheckInterval = d
	t.Cleanup(func() { CheckInterval = old })
}

// TestReloader_PicksUpRotatedPair: a pair replaced on disk is served after the
// next check, without a restart.
func TestReloader_PicksUpRotatedPair(t *testing.T) {
	withCheckInterval(t, 0)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	r, err := New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := servedSerial(t, r); got != 1 {
		t.Fatalf("serial %d, want 1", got)
	}
	writePair(t, certFile, keyFile, 2)
	if got := servedSerial(t, r); got != 2 {
		t.Fatalf("after rotation: serial %d, want 2", got)
	}
}

// TestReloader_BrokenRotationKeepsServingPrevious: a rotation that leaves a pair
// that does not load (half-written, mismatched key) is not served; the previous pair
// is, and a later good pair is picked up.
func TestReloader_BrokenRotationKeepsServingPrevious(t *testing.T) {
	withCheckInterval(t, 0)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	r, err := New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, future, future)
	if got := servedSerial(t, r); got != 1 {
		t.Fatalf("after a broken rotation: serial %d, want the previous pair (1)", got)
	}
	writePair(t, certFile, keyFile, 3)
	if got := servedSerial(t, r); got != 3 {
		t.Fatalf("after the fixed rotation: serial %d, want 3", got)
	}
}

// TestReloader_ChecksAtMostOncePerInterval: within CheckInterval a handshake does
// not touch the files.
func TestReloader_ChecksAtMostOncePerInterval(t *testing.T) {
	withCheckInterval(t, time.Hour)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	r, err := New(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	writePair(t, certFile, keyFile, 2)
	if got := servedSerial(t, r); got != 1 {
		t.Fatalf("serial %d inside the check interval, want 1", got)
	}
}

// TestNew_FailsOnUnloadablePair: a broken configuration still stops the server.
func TestNew_FailsOnUnloadablePair(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("New succeeded on missing files")
	}
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, 1)
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(certFile, keyFile); err == nil {
		t.Fatal("New succeeded on a pair that does not load")
	}
}
