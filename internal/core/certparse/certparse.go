package certparse

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// MaxCertBlocks bounds pem.Decode/x509.ParseCertificate attempts, gated on
// ATTEMPTS not on blocks successfully parsed, specifically so a value that is
// mostly non-CERTIFICATE or unparseable blocks can't turn the loop unbounded.
// Exported so internal/core/certificate_test.go's exactness regression test
// (TestParseLeafCertificate_AttemptBound) can still pin against it.
const MaxCertBlocks = 64

// ParseLeafCertificate parses value (a PEM chain or a single raw DER
// certificate) and returns the leaf certificate to key an expiry/hygiene
// control off.
//
// It does NOT trust block order. PEM chains are routinely stored leaf-last (a
// CA bundle, or a root/intermediate pasted ahead of the serving cert), so
// returning the FIRST block would let a long-lived CA's NotAfter mask a
// short-lived leaf and silently defeat the ADR-055/056 expiry monitor; an
// unparseable first block would likewise hide a valid leaf behind it.
// Instead it parses every CERTIFICATE block, skips the ones that don't
// parse, and selects the leaf via SelectLeafCertificate.
func ParseLeafCertificate(value []byte) (*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := value
	sawPEMBlock := false
	// Bound by ATTEMPTS, not by len(certs): a PEM value that's mostly non-CERTIFICATE
	// blocks (e.g. PRIVATE KEY) or unparseable CERTIFICATE blocks never grows certs,
	// so gating on len(certs) doesn't actually cap the number of pem.Decode/
	// x509.ParseCertificate calls — the CPU-bounding this constant exists for.
	for range MaxCertBlocks {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEMBlock = true
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		// Skip an unparseable CERTIFICATE block rather than aborting — a corrupt block
		// must not hide a valid (possibly soon-expiring) leaf elsewhere in the value.
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	if !sawPEMBlock {
		// Not PEM — try raw DER (a single certificate).
		return x509.ParseCertificate(value)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no parseable X.509 certificate found")
	}
	return SelectLeafCertificate(certs), nil
}

// SelectLeafCertificate picks the certificate the expiry/hygiene control should key
// off: the soonest-expiring END-ENTITY (non-CA) certificate, so a chain that stores a
// long-lived CA/intermediate ahead of a short-lived leaf can't hide the leaf's
// expiry. Falls back to the soonest-expiring certificate overall when every block is a
// CA. Order-independent by construction.
func SelectLeafCertificate(certs []*x509.Certificate) *x509.Certificate {
	var chosen *x509.Certificate
	for _, cert := range certs {
		if cert.IsCA {
			continue
		}
		if chosen == nil || cert.NotAfter.Before(chosen.NotAfter) {
			chosen = cert
		}
	}
	if chosen != nil {
		return chosen
	}
	// All blocks are CAs — still pick the soonest-expiring so the control fails safe.
	chosen = certs[0]
	for _, cert := range certs[1:] {
		if cert.NotAfter.Before(chosen.NotAfter) {
			chosen = cert
		}
	}
	return chosen
}
