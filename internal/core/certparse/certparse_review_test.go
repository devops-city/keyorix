package certparse

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Leaf-selection cases from the REVIEW-COVERAGE-1 pass (2026-10-17), in this
// package itself; internal/core/certificate_test.go already pins CA-first
// bundles, a corrupt leading block, the all-CA fallback and the attempt bound.

var reviewBase = time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)

func mkCert(t *testing.T, cn string, notAfter time.Time, isCA bool) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             reviewBase.Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: isCA,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParseLeafCertificate_ReviewCases(t *testing.T) {
	soon := mkCert(t, "soon.example", reviewBase.Add(10*24*time.Hour), false)
	late := mkCert(t, "late.example", reviewBase.Add(300*24*time.Hour), false)
	ca := mkCert(t, "Root CA", reviewBase.Add(3650*24*time.Hour), true)

	cases := []struct {
		name   string
		value  []byte
		wantCN string // "" = must error
	}{
		{"two leaves, soonest first", cat(pemOf(soon), pemOf(late)), "soon.example"},
		{"two leaves, soonest last", cat(pemOf(late), pemOf(soon)), "soon.example"},
		{"leaf between CAs", cat(pemOf(ca), pemOf(soon), pemOf(ca)), "soon.example"},
		{"text before the PEM block is skipped", cat([]byte("subject=CN=soon\nissuer=...\n"), pemOf(soon)), "soon.example"},
		{"non-CERTIFICATE blocks are skipped", cat(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), pemOf(late)), "late.example"},
		{"raw DER single certificate", soon, "soon.example"},
		{"raw DER with trailing bytes is refused", cat(soon, []byte{0}), ""},
		{"PEM with only unparseable CERTIFICATE blocks", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), ""},
		{"empty value", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := ParseLeafCertificate(tc.value)
			if tc.wantCN == "" {
				if err == nil {
					t.Fatalf("want an error, got %q", cert.Subject.CommonName)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cert.Subject.CommonName != tc.wantCN {
				t.Fatalf("selected %q, want %q", cert.Subject.CommonName, tc.wantCN)
			}
		})
	}
}
