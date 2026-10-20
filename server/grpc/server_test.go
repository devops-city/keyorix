package grpc

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// AUTH-2 item 3: there is no ACME on gRPC. createGRPCTLSConfig used to return a
// hardened config with no certificate for auto_cert, so the server started and every
// handshake failed. It must refuse the flag (Config.Validate refuses it at boot too).
func TestCreateGRPCTLSConfig_RefusesAutoCert(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = true

	tlsConfig, err := createGRPCTLSConfig(cfg)
	if !errors.Is(err, config.ErrGRPCAutoCertUnsupported) {
		t.Fatalf("createGRPCTLSConfig(auto_cert) = %v, %v; want ErrGRPCAutoCertUnsupported", tlsConfig, err)
	}
}

// hardenedGRPCTLSConfig runs the hardening createGRPCTLSConfig applies to every
// config it returns, without needing a certificate on disk.
func hardenedGRPCTLSConfig(t *testing.T, cfg *config.Config) (*tls.Config, error) {
	t.Helper()
	tlsConfig := &tls.Config{} // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion -- applyTLSHardening sets MinVersion; the tests assert it
	err := applyTLSHardening(tlsConfig, cfg.Server.GRPC.TLS, cfg.Server.GRPC.TLSMode)
	return tlsConfig, err
}

// #172: the hardened MinVersion/CipherSuites apply to the gRPC TLS config.
func TestApplyTLSHardening_GRPCDefaults(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true

	tlsConfig, err := hardenedGRPCTLSConfig(t, cfg)
	if err != nil {
		t.Fatalf("applyTLSHardening: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want tls.VersionTLS12", tlsConfig.MinVersion)
	}
	if len(tlsConfig.CipherSuites) == 0 {
		t.Fatal("CipherSuites must not be empty")
	}
}

// #333: when tls.allowed_ciphers is unset, the gRPC hardening must keep the existing
// hardcoded secure default CipherSuites unchanged (no regression).
func TestCreateGRPCTLSConfig_DefaultPreservedWhenAllowedCiphersUnset(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true

	tlsConfig, err := hardenedGRPCTLSConfig(t, cfg)
	if err != nil {
		t.Fatalf("applyTLSHardening: %v", err)
	}
	if !grpcCipherSuitesEqual(tlsConfig.CipherSuites, hardenedCipherSuites) {
		t.Errorf("CipherSuites = %v, want the unchanged hardcoded default %v", tlsConfig.CipherSuites, hardenedCipherSuites)
	}
}

// #333: when tls.allowed_ciphers names a valid, specific TLS 1.2 AEAD suite list, the
// hardened tls.Config must reflect exactly that list, not the hardcoded default.
func TestCreateGRPCTLSConfig_HonorsConfiguredAllowedCiphers(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AllowedCiphers = []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}
	want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	tlsConfig, err := hardenedGRPCTLSConfig(t, cfg)
	if err != nil {
		t.Fatalf("applyTLSHardening: %v", err)
	}
	if !grpcCipherSuitesEqual(tlsConfig.CipherSuites, want) {
		t.Errorf("CipherSuites = %v, want the configured %v (not the hardcoded default %v)", tlsConfig.CipherSuites, want, hardenedCipherSuites)
	}
}

// #333: an invalid/weak/deprecated cipher suite name must be rejected, not silently
// accepted, by the gRPC hardening.
func TestCreateGRPCTLSConfig_RejectsWeakOrUnknownCipher(t *testing.T) {
	for _, name := range []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"not-a-real-cipher-suite",
	} {
		cfg := &config.Config{}
		cfg.Server.GRPC.TLS.Enabled = true
		cfg.Server.GRPC.TLS.AllowedCiphers = []string{name}

		if _, err := hardenedGRPCTLSConfig(t, cfg); err == nil {
			t.Errorf("the gRPC hardening must reject weak/unknown cipher suite %q", name)
		}
	}
}

// grpcCipherSuitesEqual reports whether two ordered cipher-suite ID slices are identical.
func grpcCipherSuitesEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
