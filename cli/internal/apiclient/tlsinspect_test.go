package apiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCA(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInspectTLS_VerifiedWithCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	rep, err := InspectTLS(context.Background(), srv.URL, writeCA(t, srv.Certificate()))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Verified || rep.VerifyError != "" || len(rep.Chain) == 0 || !strings.HasPrefix(rep.TLSVersion, "TLS 1.") {
		t.Fatalf("want a verified chain: %+v", rep)
	}
	if rep.TrustSource == "system roots" {
		t.Errorf("TrustSource should name the CA file, got %q", rep.TrustSource)
	}
	if !rep.Chain[0].NotAfter.After(time.Now()) {
		t.Errorf("leaf expiry missing: %+v", rep.Chain[0])
	}
}

func TestInspectTLS_UntrustedCertificateIsAVerdictNotAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	rep, err := InspectTLS(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("an untrusted certificate is a result, not an error: %v", err)
	}
	if rep.Verified || !strings.Contains(rep.VerifyError, "unknown authority") || rep.TrustSource != "system roots" {
		t.Fatalf("want an unverified report naming the problem: %+v", rep)
	}
	if len(rep.Chain) == 0 || rep.Chain[0].Subject == "" {
		t.Fatalf("the presented chain should still be shown: %+v", rep)
	}
}

func TestInspectTLS_WrongHostName(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	// The httptest certificate is valid for 127.0.0.1 and example.com, not "localhost".
	rep, err := InspectTLS(context.Background(), "https://localhost:"+port, writeCA(t, srv.Certificate()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified || !strings.Contains(rep.VerifyError, "localhost") {
		t.Fatalf("want a host-name mismatch: %+v", rep)
	}
}

func TestInspectTLS_ExpiredCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired.test"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()

	rep, err := InspectTLS(context.Background(), srv.URL, writeCA(t, cert))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified || !strings.Contains(rep.VerifyError, "expired") {
		t.Fatalf("want an expiry verdict: %+v", rep)
	}
	if len(rep.Chain) != 1 || !rep.Chain[0].NotAfter.Before(time.Now()) {
		t.Fatalf("the expired certificate should be in the report: %+v", rep.Chain)
	}
}

func TestInspectTLS_NotHTTPSAndUnreachable(t *testing.T) {
	if _, err := InspectTLS(context.Background(), "http://127.0.0.1:1", ""); !errors.Is(err, ErrNotHTTPS) {
		t.Errorf("http URL: want ErrNotHTTPS, got %v", err)
	}
	if _, err := InspectTLS(context.Background(), "::not a url", ""); err == nil {
		t.Error("garbage URL must be an error")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if rep, err := InspectTLS(context.Background(), "https://"+addr, ""); err == nil {
		t.Errorf("a closed port is a connection error, got a report: %+v", rep)
	}
	if _, err := InspectTLS(context.Background(), "https://127.0.0.1:1", filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("an unreadable CA file must be an error")
	}
}
