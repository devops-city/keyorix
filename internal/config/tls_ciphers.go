package config

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
)

// TLSModeStrict is the only non-empty value server.http/grpc.tls_mode accepts
// (ADR-112 §3): TLS 1.3 only, no fallback to 1.2. Empty ("") is the default
// posture — the TLS 1.2 floor restricted to forward-secret AEAD suites.
const TLSModeStrict = "strict"

// validateTLSMode rejects any server.http/grpc.tls_mode value other than ""
// (the default) or TLSModeStrict — a typo here (e.g. "Strict", "tls13")
// must fail loudly at startup, not silently fall back to the TLS 1.2
// default while the operator believes strict mode is active.
func validateTLSMode(field, mode string) error {
	if mode != "" && mode != TLSModeStrict {
		return fmt.Errorf("%s: %q is not a recognized TLS mode (must be empty, or %q)", field, mode, TLSModeStrict)
	}
	return nil
}

// SecureCipherSuiteNames is the allowlist of TLS 1.2 cipher-suite names an operator may
// list under tls.allowed_ciphers. It is deliberately restricted to modern AEAD suites
// (AES-GCM and ChaCha20-Poly1305) — RC4, 3DES, and CBC-mode suites are excluded outright
// because they're cryptographically weak/deprecated (RC4/3DES are broken; CBC-mode TLS
// suites are Lucky-13/padding-oracle-adjacent) and must never be selectable via config,
// even by a misinformed operator.
//
// TLS 1.3 is intentionally NOT represented here: crypto/tls negotiates its (always-AEAD)
// suite set automatically and tls.Config.CipherSuites has no effect on TLS 1.3
// connections, so there is nothing for an "allowed_ciphers" list to select among on 1.3.
var SecureCipherSuiteNames = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
}

// DefaultCipherSuites is the TLS 1.2 suite list both listeners offer when
// tls.allowed_ciphers is unset: forward-secret AEAD only, for RSA AND ECDSA
// certificates. With only the ECDHE_RSA suites (the list before HARDEN-HTTP-1), a
// server holding an ECDSA certificate (cert-manager's and many ACME setups' default)
// had no TLS 1.2 suite it could sign with, so every TLS 1.2 client failed the
// handshake and only TLS 1.3 worked.
var DefaultCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// ResolveCipherSuites turns the operator-configured tls.allowed_ciphers list (a list of
// cipher-suite NAMES, e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") into the resolved
// []uint16 IDs the standard library's tls.Config.CipherSuites expects (#333).
//
// When AllowedCiphers is empty/unset, defaultSuites is returned unchanged — an operator
// who has never touched this field keeps exactly the same hardened default posture as
// before, so this cannot make an existing deployment's TLS weaker by omission.
//
// When AllowedCiphers is set, every entry must name a suite in SecureCipherSuiteNames;
// any unknown, misspelled, or deliberately weak/deprecated suite (RC4, 3DES, CBC-mode,
// etc.) fails closed with a descriptive error rather than being silently dropped or
// silently accepted, so a typo or a weak choice is caught at startup instead of quietly
// producing a different (possibly weaker, possibly merely wrong) posture at runtime.
func (t TLSConfig) ResolveCipherSuites(defaultSuites []uint16) ([]uint16, error) {
	if len(t.AllowedCiphers) == 0 {
		return defaultSuites, nil
	}
	resolved := make([]uint16, 0, len(t.AllowedCiphers))
	for _, name := range t.AllowedCiphers {
		id, ok := SecureCipherSuiteNames[strings.TrimSpace(name)]
		if !ok {
			return nil, fmt.Errorf(
				"tls.allowed_ciphers: %q is not a recognized, secure TLS 1.2 cipher suite (allowed: %s) — "+
					"weak/deprecated suites (RC4, 3DES, CBC-mode) are rejected outright",
				name, strings.Join(sortedCipherSuiteNames(), ", "),
			)
		}
		resolved = append(resolved, id)
	}
	return resolved, nil
}

// sortedCipherSuiteNames returns SecureCipherSuiteNames' keys sorted, for stable,
// readable error messages.
func sortedCipherSuiteNames() []string {
	names := make([]string, 0, len(SecureCipherSuiteNames))
	for name := range SecureCipherSuiteNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
