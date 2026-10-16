package grpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/keyorixhq/keyorix/internal/tlsreload"
)

func writeECDSAPairGRPC(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
	future := time.Now().Add(time.Duration(serial) * time.Second)
	_ = os.Chtimes(certFile, future, future)
	_ = os.Chtimes(keyFile, future, future)
}

// TestNewServer_TLS_ECDSAOverTLS12_H2_AndCertReload drives NewServer's TLS listener
// with an ECDSA certificate: a TLS 1.2-only client completes the handshake (main's
// RSA-only suite list could not), ALPN negotiates h2, and a pair rotated on disk is
// served to the next connection without a restart.
func TestNewServer_TLS_ECDSAOverTLS12_H2_AndCertReload(t *testing.T) {
	old := tlsreload.CheckInterval
	tlsreload.CheckInterval = 0
	t.Cleanup(func() { tlsreload.CheckInterval = old })

	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeECDSAPairGRPC(t, certFile, keyFile, 1)

	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS = config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
	srv, err := NewServer(cfg, h.CoreService)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	dial := func(maxVersion uint16) *tls.Conn {
		t.Helper()
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- throwaway self-signed test cert; the test reads the served serial
			MaxVersion:         maxVersion,
			NextProtos:         []string{"h2"},
		})
		if err != nil {
			t.Fatalf("TLS dial (max %#x): %v", maxVersion, err)
		}
		return conn
	}

	conn := dial(tls.VersionTLS12)
	st := conn.ConnectionState()
	if st.Version != tls.VersionTLS12 {
		t.Errorf("negotiated %#x, want TLS 1.2", st.Version)
	}
	if st.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN negotiated %q, want h2", st.NegotiatedProtocol)
	}
	if got := st.PeerCertificates[0].SerialNumber.Int64(); got != 1 {
		t.Fatalf("serial %d, want 1", got)
	}
	_ = conn.Close()

	writeECDSAPairGRPC(t, certFile, keyFile, 2)
	conn = dial(tls.VersionTLS13)
	defer func() { _ = conn.Close() }()
	if got := conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64(); got != 2 {
		t.Fatalf("after rotating the files: serial %d, want 2", got)
	}
}
