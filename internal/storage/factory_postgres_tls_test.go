// factory_postgres_tls_test.go -- PG-VERIFYFULL-1: storage.database.ssl_root_cert
// reaches the driver and decides the TLS handshake, through the real factory
// path (config.ResolvePostgresConnConfig -> stdlib.OpenDB/pgx -> crypto/tls).
//
// No TLS-enabled PostgreSQL is needed (kpg and CI's Postgres are plaintext):
// a PostgreSQL client opens with an 8-byte SSLRequest and starts TLS on the
// same socket once the server answers 'S'. fakeTLSPostgres answers exactly
// that and then runs a real crypto/tls server handshake, recording whether it
// completed. The verification decision is made by pgx's own TLS config, so a
// trusted CA lets the handshake finish and an untrusted CA or a wrong host
// name aborts it -- the property under test. After the handshake the fake
// closes the connection, so CreateStorage still fails; the tests assert on
// what the handshake did, not on CreateStorage succeeding.
package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// writeFile writes the CA certificate (only) to dir, mode 0644.
func (ca *testCA) writeFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, ca.pem, 0o644))
	require.NoError(t, os.Chmod(p, 0o644))
	return p
}

// serverCert issues a leaf for the given IP SANs.
func (ca *testCA) serverCert(t *testing.T, ips ...net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "pg-server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type fakeTLSPostgres struct {
	addr        *net.TCPAddr
	mu          sync.Mutex
	conns       int
	handshakeOK int
}

func (f *fakeTLSPostgres) counts() (conns, ok int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns, f.handshakeOK
}

// startFakeTLSPostgres listens on 127.0.0.1 and serves cert after answering
// the client's SSLRequest.
func startFakeTLSPostgres(t *testing.T, cert tls.Certificate) *fakeTLSPostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeTLSPostgres{addr: ln.Addr().(*net.TCPAddr)}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				req := make([]byte, 8) // int32 length 8 + int32 code 80877103
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if _, err := c.Write([]byte{'S'}); err != nil {
					return
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				if tc.Handshake() == nil {
					f.mu.Lock()
					f.handshakeOK++
					f.mu.Unlock()
				}
			})
		}
	})
	return f
}

func tlsTestConfig(f *fakeTLSPostgres, mode, rootCert string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database = config.DatabaseConfig{
		Host: "127.0.0.1", Port: strconv.Itoa(f.addr.Port), Name: "keyorix", User: "keyorix",
		SSLMode: mode, SSLRootCert: rootCert,
	}
	return cfg
}

func TestCreateStorage_Postgres_VerifyFull_TrustedVsUntrustedCA(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	t.Setenv("HOME", t.TempDir()) // no ~/.postgresql/root.crt
	t.Setenv("PGSSLROOTCERT", "")
	t.Setenv("PGCONNECT_TIMEOUT", "5")

	dir := t.TempDir()
	serverCA := newTestCA(t, "database-ca")
	otherCA := newTestCA(t, "some-other-ca")
	trusted := serverCA.writeFile(t, dir, "trusted.pem")
	untrusted := otherCA.writeFile(t, dir, "untrusted.pem")

	t.Run("trusted CA: handshake completes", func(t *testing.T) {
		f := startFakeTLSPostgres(t, serverCA.serverCert(t, net.ParseIP("127.0.0.1")))
		_, err := NewStorageFactory().CreateStorage(tlsTestConfig(f, "verify-full", trusted))
		require.Error(t, err, "the fake closes after the handshake")
		assert.NotContains(t, err.Error(), "certificate", "a trusted CA must not fail verification")
		_, ok := f.counts()
		assert.GreaterOrEqual(t, ok, 1, "the TLS handshake must complete against the configured CA")
	})

	t.Run("untrusted CA: handshake refused by the client", func(t *testing.T) {
		f := startFakeTLSPostgres(t, serverCA.serverCert(t, net.ParseIP("127.0.0.1")))
		_, err := NewStorageFactory().CreateStorage(tlsTestConfig(f, "verify-full", untrusted))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate signed by unknown authority")
		conns, ok := f.counts()
		assert.GreaterOrEqual(t, conns, 1, "premise: the client did connect")
		assert.Equal(t, 0, ok, "no handshake may complete against a CA the config does not trust")
	})

	t.Run("trusted CA, wrong host name: verify-full refuses, verify-ca accepts", func(t *testing.T) {
		wrongHost := serverCA.serverCert(t, net.ParseIP("10.255.255.1"))

		f := startFakeTLSPostgres(t, wrongHost)
		_, err := NewStorageFactory().CreateStorage(tlsTestConfig(f, "verify-full", trusted))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "127.0.0.1")
		_, ok := f.counts()
		assert.Equal(t, 0, ok, "verify-full checks the host name")

		f = startFakeTLSPostgres(t, wrongHost)
		_, err = NewStorageFactory().CreateStorage(tlsTestConfig(f, "verify-ca", trusted))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "certificate")
		_, ok = f.counts()
		assert.GreaterOrEqual(t, ok, 1, "verify-ca checks the chain only")
	})

	t.Run("verify-full with no CA: refused before any connection", func(t *testing.T) {
		f := startFakeTLSPostgres(t, serverCA.serverCert(t, net.ParseIP("127.0.0.1")))
		_, err := NewStorageFactory().CreateStorage(tlsTestConfig(f, "verify-full", ""))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")
		_, err = OpenGormDB(tlsTestConfig(f, "verify-full", ""))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")
		conns, _ := f.counts()
		assert.Equal(t, 0, conns, "no connection may be opened without a named CA")
	})
}

// TestCreateStorage_Postgres_RealTLS_TrustedVsUntrustedCA is the same property
// against a real TLS-enabled PostgreSQL, through the field-built config
// (ssl_mode + ssl_root_cert) the server boots from. Gated: CI's and kpg's
// Postgres are plaintext. Set
//
//	KEYORIX_TEST_PG_TLS=postgres://user:pass@127.0.0.1:port/db  (no query string)
//	KEYORIX_TEST_PG_TLS_CA=<PEM of the CA that signed the server certificate>
//	KEYORIX_TEST_PG_TLS_UNTRUSTED_CA=<PEM of an unrelated CA>
//
// with a server certificate whose only SAN is the IP 127.0.0.1, so "localhost"
// is a wrong host name for verify-full. Run on the e2e VM (PG-VERIFYFULL-1
// report has the docker command).
func TestCreateStorage_Postgres_RealTLS_TrustedVsUntrustedCA(t *testing.T) {
	raw := os.Getenv("KEYORIX_TEST_PG_TLS")
	trusted, untrusted := os.Getenv("KEYORIX_TEST_PG_TLS_CA"), os.Getenv("KEYORIX_TEST_PG_TLS_UNTRUSTED_CA")
	if raw == "" || trusted == "" || untrusted == "" {
		t.Skip("KEYORIX_TEST_PG_TLS, KEYORIX_TEST_PG_TLS_CA and KEYORIX_TEST_PG_TLS_UNTRUSTED_CA not set (needs a TLS-enabled PostgreSQL)")
	}
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PGSSLROOTCERT", "")

	u, err := url.Parse(raw)
	require.NoError(t, err)
	pw, _ := u.User.Password()
	t.Setenv("KEYORIX_DB_PASSWORD", pw)
	cfgFor := func(host, mode, rootCert string) *config.Config {
		cfg := &config.Config{}
		cfg.Storage.Type = "postgres"
		cfg.Storage.Database = config.DatabaseConfig{
			Host: host, Port: u.Port(), Name: strings.TrimPrefix(u.Path, "/"), User: u.User.Username(),
			SSLMode: mode, SSLRootCert: rootCert, MaxOpenConns: 2,
		}
		return cfg
	}
	open := func(cfg *config.Config) error {
		st, err := NewStorageFactory().CreateStorage(cfg)
		if c, ok := st.(interface{ Close() error }); ok && err == nil {
			_ = c.Close()
		}
		return err
	}

	require.NoError(t, open(cfgFor("127.0.0.1", "verify-full", trusted)), "trusted CA, matching host: connects and migrates")

	err = open(cfgFor("127.0.0.1", "verify-full", untrusted))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate signed by unknown authority")

	err = open(cfgFor("localhost", "verify-full", trusted))
	require.Error(t, err, "verify-full checks the host name")
	assert.Contains(t, err.Error(), "certificate")
	require.NoError(t, open(cfgFor("localhost", "verify-ca", trusted)), "verify-ca checks the chain only")

	err = open(cfgFor("127.0.0.1", "verify-full", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")

	require.NoError(t, open(cfgFor("127.0.0.1", "require", "")), "require without a CA is unchanged")
}
