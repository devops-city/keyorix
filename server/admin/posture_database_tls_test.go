package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// writeDBTestCA writes a self-signed CA certificate (PEM, 0644) into dir.
func writeDBTestCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "posture-db-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	p := filepath.Join(dir, "pg-ca.pem")
	require.NoError(t, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.Chmod(p, 0o644))
	return p
}

func pgPostureConfig(mode, rootCert string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database = config.DatabaseConfig{
		Host: "127.0.0.1", Port: "1", Name: "keyorix", User: "keyorix", SSLMode: mode, SSLRootCert: rootCert,
	}
	return cfg
}

// PG-VERIFYFULL-1: `admin validate --posture` loads the config without
// Validate, so it must itself report a database TLS setting the server would
// refuse to boot on -- as a counted deviation -- and describe a valid one.
func TestCollectDatabaseTLSPosture(t *testing.T) {
	ca := writeDBTestCA(t, t.TempDir())

	t.Run("verify-full without a CA is a deviation", func(t *testing.T) {
		report := &postureReport{}
		collectDatabaseTLSPosture(pgPostureConfig("verify-full", ""), report)
		devs := deviationsIn(report, "database-tls")
		require.Len(t, devs, 1)
		assert.Contains(t, devs[0].detail, "ssl_root_cert")
		assert.Contains(t, devs[0].detail, "refusing to start")
	})
	t.Run("an unusable CA file is a deviation", func(t *testing.T) {
		report := &postureReport{}
		collectDatabaseTLSPosture(pgPostureConfig("verify-full", filepath.Join(t.TempDir(), "missing.pem")), report)
		require.Len(t, deviationsIn(report, "database-tls"), 1)
	})
	t.Run("verify-full with a CA is reported, not counted", func(t *testing.T) {
		report := &postureReport{}
		collectDatabaseTLSPosture(pgPostureConfig("verify-full", ca), report)
		assert.Empty(t, report.deviations)
		require.Len(t, report.informational, 1)
		assert.Contains(t, report.informational[0], "verify-full")
		assert.Contains(t, report.informational[0], ca)
	})
	t.Run("require is reported as unverified, not counted (Helm bundled-DB baseline)", func(t *testing.T) {
		report := &postureReport{}
		collectDatabaseTLSPosture(pgPostureConfig("require", ""), report)
		assert.Empty(t, report.deviations)
		require.Len(t, report.informational, 1)
		assert.Contains(t, report.informational[0], "NOT verified")
	})
	t.Run("SQLite has no database TLS line", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Storage.Type = "local"
		report := &postureReport{}
		collectDatabaseTLSPosture(cfg, report)
		assert.Empty(t, report.deviations)
		assert.Empty(t, report.informational)
	})
}

// Through runAdminValidatePosture: the deviation is printed and counted, and
// the database step fails on the TLS refusal itself -- ResolvePostgresConnConfig
// refuses before any connection is attempted (port 1 would otherwise answer
// with a connection error). The full `admin validate --posture` command stops
// one step earlier, at its server-presence check, with the same message
// (serverguard also builds its DSN through ResolvePostgresConnConfig).
func TestRunAdminValidatePosture_VerifyFullWithoutCA(t *testing.T) {
	yaml := `
locale:
  language: en
  fallback_language: en
storage:
  type: postgres
  database:
    host: 127.0.0.1
    port: "1"
    name: keyorix
    user: keyorix
    ssl_mode: verify-full
  encryption:
    enabled: false
security:
  enable_file_permission_check: false
  require_transport_tls: false
`
	cfgPath, cfg := writePostureFixture(t, yaml, 0600)

	out, err := captureStdout(t, func() error { return runAdminValidatePosture(cfg, cfgPath) })
	require.Error(t, err)
	assert.Contains(t, out, "[database-tls/explicit]")
	assert.Contains(t, out, "storage.database.ssl_mode is verify-full but no CA certificate is configured")
	assert.NotContains(t, out, "connection refused", "no connection may be attempted without a named CA")
}

// `admin init` on a Postgres config prints the database TLS posture, and fails
// on a setting the server would refuse to boot on.
func TestInitializeAdminDatabase_ReportsDatabaseTLS(t *testing.T) {
	ca := writeDBTestCA(t, t.TempDir())

	out, err := captureStdout(t, func() error { return initializeAdminDatabase(pgPostureConfig("verify-full", ca)) })
	require.NoError(t, err)
	assert.Contains(t, out, "database TLS: storage.database.ssl_mode=verify-full")

	out, err = captureStdout(t, func() error { return initializeAdminDatabase(pgPostureConfig("require", "")) })
	require.NoError(t, err)
	assert.True(t, strings.Contains(out, "NOT verified"), out)

	_, err = captureStdout(t, func() error { return initializeAdminDatabase(pgPostureConfig("verify-full", "")) })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")
}
