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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// writeSelfSignedCert generates a minimal self-signed ECDSA certificate and key
// pair, writes them to dir/cert.pem and dir/key.pem, and returns their paths.
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	if err := certFile.Close(); err != nil {
		t.Fatalf("close cert file: %v", err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatalf("close key file: %v", err)
	}

	return certPath, keyPath
}

// TestCreateGRPCTLSConfig_ManualCertAppliesHardening exercises the non-AutoCert
// branch: certificate loaded from disk, TLS hardening still applied.
func TestCreateGRPCTLSConfig_ManualCertAppliesHardening(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = false
	cfg.Server.GRPC.TLS.CertFile = certPath
	cfg.Server.GRPC.TLS.KeyFile = keyPath

	tlsConfig, err := createGRPCTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createGRPCTLSConfig: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want tls.VersionTLS12", tlsConfig.MinVersion)
	}
	if len(tlsConfig.CipherSuites) == 0 {
		t.Fatal("CipherSuites must not be empty on the manual-cert branch")
	}
	// The certificate loaded from disk is served through GetCertificate (tlsreload),
	// so a rotated pair is picked up without a restart.
	if tlsConfig.GetCertificate == nil {
		t.Fatal("GetCertificate must serve the certificate loaded from disk")
	}
	if cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{}); err != nil || cert == nil || len(cert.Certificate) == 0 {
		t.Fatalf("GetCertificate = %v, %v: want the certificate loaded from disk", cert, err)
	}
}

// TestCreateGRPCTLSConfig_ManualCertMissingFile tests that a missing cert file
// returns an error rather than silently succeeding.
func TestCreateGRPCTLSConfig_ManualCertMissingFile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = false
	cfg.Server.GRPC.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.Server.GRPC.TLS.KeyFile = "/nonexistent/key.pem"

	if _, err := createGRPCTLSConfig(cfg); err == nil {
		t.Error("createGRPCTLSConfig must return an error for a missing certificate file")
	}
}

// TestApplyTLSHardening_AllowedCiphersOverridesDefault verifies that an operator
// can override the hardcoded cipher list via AllowedCiphers.
func TestApplyTLSHardening_AllowedCiphersOverridesDefault(t *testing.T) {
	tlsCfg := config.TLSConfig{
		AllowedCiphers: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}
	result := &tls.Config{}
	if err := applyTLSHardening(result, tlsCfg, ""); err != nil {
		t.Fatalf("applyTLSHardening: %v", err)
	}
	if len(result.CipherSuites) != 1 || result.CipherSuites[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Errorf("CipherSuites = %v, want [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]", result.CipherSuites)
	}
}
