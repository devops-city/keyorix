// tls_mode_handshake_test.go -- ADR-112 §3 (secure-by-default baseline, item
// 3): a REAL TLS handshake between a genuine net.Listen server (running
// applyTLSHardening exactly as the real server does) and a genuine tls.Dial
// client, for both the default mode (TLS 1.2 floor, forward-secret AEAD
// suites only) and tls_mode: strict (TLS 1.3 only). Unlike
// transport_tls_test.go's TestApplyTLSHardening_* tests (which only inspect
// the resulting *tls.Config's MinVersion/CipherSuites fields), these tests
// prove the floor is actually enforced over the wire.
package main

import (
	"crypto/tls"
	"net"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// startTLSHandshakeServer builds a *tls.Config via applyTLSHardening --
// exactly the code path createTLSConfig/createGRPCTLSConfig use -- for mode,
// and serves one Accept+Handshake per connection on a loopback listener until
// cleanup is called. A failed handshake is expected and normal for the
// reject cases below; it is deliberately never treated as a test failure
// here, since the CLIENT side's err return is this test's real assertion.
func startTLSHandshakeServer(t *testing.T, mode string) (addr string, cleanup func()) {
	t.Helper()
	certFile, keyFile := writeSelfSignedCert(t, t.TempDir())
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load self-signed cert: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	if err := applyTLSHardening(tlsConfig, config.TLSConfig{}, mode); err != nil {
		t.Fatalf("applyTLSHardening: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close() //nolint:errcheck
		<-done
	}
}

// dial attempts a real TLS handshake against addr, offering only versions in
// [minVersion, maxVersion]. InsecureSkipVerify is correct here, not a
// shortcut: the cert is a throwaway self-signed test cert with no real trust
// chain to verify, and this test is entirely about version/cipher
// negotiation, never about certificate trust.
func dial(addr string, minVersion, maxVersion uint16) (*tls.Conn, error) {
	return tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- test-only self-signed cert, see doc comment
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	})
}

// -- Default mode: TLS 1.2 floor --

func TestTLSHandshake_DefaultMode_RejectsBelowTLS12(t *testing.T) {
	addr, cleanup := startTLSHandshakeServer(t, "")
	defer cleanup()
	conn, err := dial(addr, tls.VersionTLS10, tls.VersionTLS11)
	if err == nil {
		conn.Close() //nolint:errcheck
		t.Fatal("expected a client offering only TLS 1.0/1.1 to be rejected under the default TLS 1.2 floor")
	}
}

func TestTLSHandshake_DefaultMode_AcceptsTLS12WithAHardenedCipher(t *testing.T) {
	addr, cleanup := startTLSHandshakeServer(t, "")
	defer cleanup()
	conn, err := dial(addr, tls.VersionTLS12, tls.VersionTLS12)
	if err != nil {
		t.Fatalf("expected a TLS 1.2 client to be accepted under the default floor: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	negotiated := conn.ConnectionState().CipherSuite
	found := slices.Contains(hardenedCipherSuites, negotiated)
	if !found {
		t.Errorf("negotiated cipher suite %#04x is not in hardenedCipherSuites (not forward-secret AEAD)", negotiated)
	}
}

// -- tls_mode: strict --

func TestTLSHandshake_StrictMode_RejectsTLS12(t *testing.T) {
	addr, cleanup := startTLSHandshakeServer(t, config.TLSModeStrict)
	defer cleanup()
	conn, err := dial(addr, tls.VersionTLS12, tls.VersionTLS12)
	if err == nil {
		conn.Close() //nolint:errcheck
		t.Fatal("expected a TLS-1.2-only client to be rejected under tls_mode: strict")
	}
}

func TestTLSHandshake_StrictMode_AcceptsTLS13(t *testing.T) {
	addr, cleanup := startTLSHandshakeServer(t, config.TLSModeStrict)
	defer cleanup()
	conn, err := dial(addr, tls.VersionTLS13, tls.VersionTLS13)
	if err != nil {
		t.Fatalf("expected a TLS 1.3 client to be accepted under tls_mode: strict: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	if got := conn.ConnectionState().Version; got != tls.VersionTLS13 {
		t.Errorf("expected the negotiated version to be TLS 1.3, got %#04x", got)
	}
}

// A client willing to use either 1.2 or 1.3 must still land on 1.3 under
// strict mode -- the ADR's actual requirement ("TLS 1.3 only"), exercised
// from the client's realistic perspective (most real clients offer a RANGE,
// not a single pinned version). NOTE: with no TLS version newer than 1.3 for
// crypto/tls to support, MinVersion=TLS13 alone already forces this outcome
// today -- applyTLSHardening's MaxVersion=TLS13 pin is not independently
// provable red/green against the current Go toolchain (there is no higher
// version for it to roll back from); it is still correct defensive
// future-proofing against a later Go version adding TLS 1.4+, which this
// test alone cannot demonstrate.
func TestTLSHandshake_StrictMode_ClientOfferingBothStillNegotiatesTLS13(t *testing.T) {
	addr, cleanup := startTLSHandshakeServer(t, config.TLSModeStrict)
	defer cleanup()
	conn, err := dial(addr, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		t.Fatalf("expected the handshake to succeed (client offers both 1.2 and 1.3): %v", err)
	}
	defer conn.Close() //nolint:errcheck
	if got := conn.ConnectionState().Version; got != tls.VersionTLS13 {
		t.Errorf("expected tls_mode: strict to force TLS 1.3 even though the client also offered 1.2, got %#04x", got)
	}
}
