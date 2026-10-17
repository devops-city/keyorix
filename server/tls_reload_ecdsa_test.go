package main

import (
	"context"
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
	"github.com/keyorixhq/keyorix/internal/tlsreload"
)

// writeECDSAPair writes a self-signed P-256 cert/key pair with the given serial.
func writeECDSAPair(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
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

func peerSerial(conn *tls.Conn) int64 {
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

// TestStartHTTPServer_TLSReloadsRotatedCertificateAndNegotiatesH2 drives the real
// startHTTPServer with a cert/key file pair: the listener negotiates h2 over ALPN,
// and a pair rotated on disk is served to the next connection without a restart.
// On main the pair loaded at start was served until the process restarted.
func TestStartHTTPServer_TLSReloadsRotatedCertificateAndNegotiatesH2(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)
	old := tlsreload.CheckInterval
	tlsreload.CheckInterval = 0
	t.Cleanup(func() { tlsreload.CheckInterval = old })

	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeECDSAPair(t, certFile, keyFile, 1)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	cfg := &config.Config{
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: "tls_reload.db"}},
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{
			Enabled: true,
			Port:    itoa(port),
			TLS:     config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
		}},
	}
	coreService := mustInitCoreService(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- startHTTPServer(ctx, cfg, coreService) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	dialTLS := func() *tls.Conn {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- throwaway self-signed test cert; the test reads the served serial
				NextProtos:         []string{"h2", "http/1.1"},
			})
			if err == nil {
				return conn
			}
			if time.Now().After(deadline) {
				t.Fatalf("TLS dial %s: %v", addr, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	conn := dialTLS()
	if got := peerSerial(conn); got != 1 {
		t.Fatalf("serial %d, want 1", got)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Errorf("ALPN negotiated %q, want h2", p)
	}
	_ = conn.Close()

	writeECDSAPair(t, certFile, keyFile, 2)
	conn = dialTLS()
	defer func() { _ = conn.Close() }()
	if got := peerSerial(conn); got != 2 {
		t.Fatalf("after rotating the files: serial %d, want 2 (the rotated certificate)", got)
	}
}

// TestTLSHandshake_ECDSACertificate_TLS12: with the default suite list a server
// holding an ECDSA certificate completes a TLS 1.2 handshake. With only the
// ECDHE_RSA suites (main) it had no suite it could sign with.
func TestTLSHandshake_ECDSACertificate_TLS12(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeECDSAPair(t, certFile, keyFile, 1)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}} // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion -- applyTLSHardening sets MinVersion
	if err := applyTLSHardening(tlsConfig, config.TLSConfig{}, ""); err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- throwaway self-signed test cert
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("TLS 1.2 handshake with an ECDSA certificate: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if v := conn.ConnectionState().Version; v != tls.VersionTLS12 {
		t.Fatalf("negotiated %#x, want TLS 1.2", v)
	}
}
