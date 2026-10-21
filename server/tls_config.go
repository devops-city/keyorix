package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/tlsmetrics"
	"github.com/keyorixhq/keyorix/internal/tlsreload"
	"golang.org/x/crypto/acme/autocert"
)

func createTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.HTTP.TLS.AutoCert {
		// AutoCert mode builds its tls.Config separately, from the autocert.Manager
		// (see buildAutoCertTLSConfig) — it still gets the same hardening applied.
		return nil, nil
	}

	// The certificate is served through tlsreload so a pair rotated on disk is
	// picked up without a restart; a pair that does not load still fails here.
	reloader, err := tlsreload.New(cfg.Server.HTTP.TLS.CertFile, cfg.Server.HTTP.TLS.KeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{GetCertificate: tlsmetrics.Wrap(tlsmetrics.HTTP, reloader.GetCertificate)} // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion -- applyTLSHardening below sets MinVersion unconditionally on every path
	if err := applyTLSHardening(tlsConfig, cfg.Server.HTTP.TLS, cfg.Server.HTTP.TLSMode); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// hardenedCipherSuites is the explicit AEAD-only cipher suite allowlist applied to
// every HTTP TLS listener, regardless of how its certificate is sourced, UNLESS the
// operator has explicitly configured tls.allowed_ciphers (#333) — in which case that
// configured list is honored instead (see applyTLSHardening).
var hardenedCipherSuites = config.DefaultCipherSuites

// applyTLSHardening layers the hardened MinVersion/CipherSuites onto tlsConfig in
// place. The protocol-version floor and cipher-suite allowlist are independent of how
// the certificate itself is sourced, so this must be applied uniformly whether
// tlsConfig came from a manually configured cert/key pair (createTLSConfig) or from an
// autocert.Manager (buildAutoCertTLSConfig) — AutoCert should only supply the
// certificate, not silently determine the rest of the TLS posture too (#172).
//
// CipherSuites is resolved from tlsCfg.AllowedCiphers (#333): when the operator has
// left tls.allowed_ciphers unset, the hardcoded hardenedCipherSuites default above
// applies unchanged (no regression for existing deployments); when they've set it,
// their configured suite list is honored instead — validated against
// config.SecureCipherSuiteNames, so a weak/deprecated/misspelled suite name fails
// closed at startup rather than being silently ignored (the previous behavior) or
// silently accepted. MinVersion stays fixed at TLS 1.2 UNLESS mode is
// config.TLSModeStrict (ADR-112 §3, "tls_mode: strict"), in which case Min/MaxVersion
// are both pinned to TLS 1.3 and CipherSuites is left untouched: TLS 1.3 has no
// equivalent per-suite selection (crypto/tls negotiates its own, always-AEAD suite
// set), so there is nothing for allowed_ciphers to configure under either mode.
func applyTLSHardening(tlsConfig *tls.Config, tlsCfg config.TLSConfig, mode string) error {
	if mode == config.TLSModeStrict {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
		return nil
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	suites, err := tlsCfg.ResolveCipherSuites(hardenedCipherSuites)
	if err != nil {
		return fmt.Errorf("invalid TLS configuration: %w", err)
	}
	tlsConfig.CipherSuites = suites
	return nil
}

// buildAutoCertTLSConfig builds the tls.Config for HTTP AutoCert (Let's Encrypt-style
// automatic certificate management) mode: the autocert.Manager supplies the
// certificate (via GetCertificate/NextProtos), and the same hardened
// MinVersion/CipherSuites as the non-AutoCert path (createTLSConfig) are layered on
// top instead of being silently discarded (#172), honoring tls.allowed_ciphers the
// same way createTLSConfig does (#333).
func buildAutoCertTLSConfig(domains []string, tlsCfg config.TLSConfig, mode string) (*tls.Config, error) {
	cacheDir := tlsCfg.CertCacheDir
	if cacheDir == "" {
		cacheDir = "certs"
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, fmt.Errorf("autocert: cannot create cert cache dir %q: %w", cacheDir, err)
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
	}
	tlsConfig := m.TLSConfig()
	if err := applyTLSHardening(tlsConfig, tlsCfg, mode); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

// bindListener is the only place the server opens a TCP listener for its HTTP
// and gRPC transports. It binds server.<transport>.host (default
// config.DefaultBindHost, loopback only) so the address in the startup log is
// the address actually bound (#2939: it used to bind ":port", all interfaces,
// while the log claimed 127.0.0.1).
func bindListener(inst config.ServerInstanceConfig) (net.Listener, error) {
	return net.Listen("tcp", inst.ListenAddr())
}

// bindScopeNote returns a log suffix saying who can reach a listener bound to
// host. Empty for loopback, a warning for any wider bind.
func bindScopeNote(host string) string {
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return ""
	}
	if ip != nil && ip.IsUnspecified() {
		return " (ALL interfaces: reachable from the network; set server.*.host to 127.0.0.1 to restrict)"
	}
	return " (non-loopback interface: reachable from the network)"
}
