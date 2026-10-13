package config

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
)

// testCAPEM returns a freshly generated self-signed CA certificate, PEM-encoded.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pg-verifyfull-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeTestCA writes a CA PEM into dir/name with mode 0644 and returns its path.
func writeTestCA(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, testCAPEM(t), 0o644))
	require.NoError(t, os.Chmod(p, 0o644))
	return p
}

func pgFields(mode, rootCert string) *DatabaseConfig {
	return &DatabaseConfig{Host: "db.internal", Name: "keyorix", User: "keyorix", SSLMode: mode, SSLRootCert: rootCert}
}

func postgresConfig(d *DatabaseConfig) *Config {
	cfg := &Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database = *d
	return cfg
}

// The headline red proof: verify-full (and verify-ca) with no CA named in the
// config refuses at Config.Validate, which server/main.go runs before it opens
// any connection.
func TestValidate_VerifyingSSLModeWithoutRootCert_RefusesToStart(t *testing.T) {
	for _, mode := range []string{"verify-full", "verify-ca"} {
		t.Run(mode, func(t *testing.T) {
			err := postgresConfig(pgFields(mode, "")).Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "storage.database.ssl_mode is "+mode)
			assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")
			assert.Contains(t, err.Error(), "refusing to start")
		})
	}
}

// PGSSLROOTCERT and ~/.postgresql/root.crt are exactly the implicit trust the
// key replaces: neither satisfies verify-full.
func TestValidate_VerifyFull_ImplicitDriverCAIsNotEnough(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".postgresql"), 0o700))
	writeTestCA(t, filepath.Join(home, ".postgresql"), "root.crt")
	t.Setenv("HOME", home)
	t.Setenv("PGSSLROOTCERT", writeTestCA(t, t.TempDir(), "env-ca.pem"))

	err := postgresConfig(pgFields("verify-full", "")).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")
}

func TestValidate_VerifyFullWithUsableRootCert_Starts(t *testing.T) {
	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")
	for _, d := range []*DatabaseConfig{
		pgFields("verify-full", ca),
		pgFields("verify-ca", ca),
		pgFields("verify-full", SSLRootCertSystem),
		pgFields("require", ca),
		pgFields("require", ""), // unchanged: encrypted, unverified
		pgFields("", ""),        // default require
		pgFields("disable", ""), // counted by the insecure-settings registry, not refused
	} {
		require.NoError(t, postgresConfig(d).Validate(), "ssl_mode=%q ssl_root_cert=%q", d.SSLMode, d.SSLRootCert)
	}
}

// An unusable CA file never falls back to anything: each shape refuses.
func TestValidate_UnusableRootCert_RefusesToStart(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), mode))
		require.NoError(t, os.Chmod(p, mode))
		return p
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	groupWritable := writeTestCA(t, dir, "group-writable.pem")
	require.NoError(t, os.Chmod(groupWritable, 0o664))
	unreadable := writeTestCA(t, dir, "unreadable.pem")
	require.NoError(t, os.Chmod(unreadable, 0o000))
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })

	cases := map[string]struct {
		path string
		want string
	}{
		"missing":         {filepath.Join(dir, "nope.pem"), "read CA file"},
		"directory":       {dir, "not a regular file"},
		"empty":           {write("empty.pem", "", 0o644), "no PEM certificate found"},
		"not PEM":         {write("garbage.pem", "this is not a certificate\n", 0o644), "no PEM certificate found"},
		"corrupt cert":    {write("corrupt.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", 0o644), "parse certificate"},
		"private key":     {write("key.pem", string(testCAPEM(t))+keyPEM, 0o644), "contains a private key"},
		"group-writable":  {groupWritable, "writable by group or others"},
		"world-writable":  {write("world.pem", string(testCAPEM(t)), 0o646), "writable by group or others"},
		"too large":       {write("huge.pem", strings.Repeat("x", maxDatabaseCAFileBytes+1), 0o644), "larger than"},
		"unreadable mode": {unreadable, "read CA file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if name == "unreadable mode" && os.Geteuid() == 0 {
				t.Skip("root reads a 0000 file; the mode cannot make it unreadable")
			}
			for _, mode := range []string{"verify-full", "verify-ca", "require"} {
				err := postgresConfig(pgFields(mode, tc.path)).Validate()
				require.Error(t, err, "ssl_mode=%s", mode)
				assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")
				assert.Contains(t, err.Error(), tc.want)
			}
		})
	}
}

func TestValidate_RootCertContradictions_Refuse(t *testing.T) {
	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")

	err := postgresConfig(pgFields("disable", ca)).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssl_mode is disable")

	d := &DatabaseConfig{DSN: "host=db dbname=k user=k sslmode=verify-full sslrootcert=" + ca, SSLRootCert: ca}
	err = postgresConfig(d).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be combined with storage.database.dsn")
}

func TestValidate_DSN_VerifyingModeNeedsSSLRootCert(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")
	refused := []string{
		"host=db dbname=k user=k password=hunter2 sslmode=verify-full",
		"host=db dbname=k user=k sslmode = 'verify-ca'",
		"postgres://k:hunter2@db/k?sslmode=verify-full",
		// last occurrence wins, as in pgx; net/url's Query().Get would read "require"
		"postgres://k@db/k?sslmode=require&sslmode=verify-full",
		"postgresql://k@db/k?ssl%6Dode=verify-full",
		"host=db sslmode=verify-full sslrootcert=" + filepath.Join(t.TempDir(), "missing.pem"),
	}
	for _, dsn := range refused {
		err := postgresConfig(&DatabaseConfig{DSN: dsn}).Validate()
		require.Error(t, err, dsn)
		assert.NotContains(t, err.Error(), "hunter2", "the DSN (and its password) must never be echoed")
	}
	allowed := []string{
		"host=db dbname=k user=k sslmode=require",
		"host=db dbname=k user=k sslmode=verify-full sslrootcert=" + ca,
		"host=db dbname=k user=k sslmode=verify-full sslrootcert=system",
		"postgres://k@db/k?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://k@db/k",
	}
	for _, dsn := range allowed {
		require.NoError(t, postgresConfig(&DatabaseConfig{DSN: dsn}).Validate(), dsn)
	}

	// No sslmode in the DSN: pgx takes PGSSLMODE, so the check does too.
	t.Setenv("PGSSLMODE", "verify-full")
	require.Error(t, postgresConfig(&DatabaseConfig{DSN: "host=db dbname=k user=k"}).Validate())
}

func TestValidate_DSN_Unparseable_RefusesWithoutEchoingIt(t *testing.T) {
	err := postgresConfig(&DatabaseConfig{DSN: "host=db password='hunter2"}).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage.database.dsn")
	assert.NotContains(t, err.Error(), "hunter2")
}

// ResolvePostgresConnConfig is the guard every connection goes through (the
// factory, OpenGormDB, serverguard, admin restore/verify-audit): it returns the
// same refusal instead of a config, so an entry point that never ran Validate
// still cannot connect.
func TestResolvePostgresConnConfig_RefusesWhatValidateRefuses(t *testing.T) {
	cc, err := ResolvePostgresConnConfig(pgFields("verify-full", ""))
	require.Error(t, err)
	assert.Nil(t, cc)
	assert.Contains(t, err.Error(), "storage.database.ssl_root_cert")

	cc, err = ResolvePostgresConnConfig(&DatabaseConfig{DSN: "host=db sslmode=verify-full"})
	require.Error(t, err)
	assert.Nil(t, cc)
}

func TestResolvePostgresConnConfig_PassesSSLRootCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), `ca dir with 'quote`)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	ca := writeTestCA(t, dir, "pg ca.pem")

	dsn := buildPostgresDSNFromFields(pgFields("verify-full", ca))
	assert.Contains(t, dsn, "sslmode='verify-full'")
	assert.Contains(t, dsn, `sslrootcert='`+strings.ReplaceAll(ca, `'`, `\'`)+`'`)

	// The quoted value reads back as exactly the path (same grammar pgx uses;
	// TestDSNTLSSettings_AgreesWithPgx checks the grammar against pgx itself).
	mode, root, err := dsnTLSSettings(dsn)
	require.NoError(t, err)
	assert.Equal(t, "verify-full", mode)
	assert.Equal(t, ca, root)

	assert.NotContains(t, buildPostgresDSNFromFields(pgFields("require", "")), "sslrootcert", "no CA configured: none passed")

	// The driver gets exactly that CA, verifying the configured host name.
	cc, err := ResolvePostgresConnConfig(pgFields("verify-full", ca))
	require.NoError(t, err)
	want, _, err := LoadDatabaseCAPool(ca)
	require.NoError(t, err)
	require.NotNil(t, cc.TLSConfig)
	assert.True(t, want.Equal(cc.TLSConfig.RootCAs))
	assert.False(t, cc.TLSConfig.InsecureSkipVerify)
	assert.Equal(t, cc.Host, cc.TLSConfig.ServerName)
}

func TestLoad_SSLRootCert_AnchoredToConfigDir(t *testing.T) {
	dir := t.TempDir()
	writeTestCA(t, dir, "pg-ca.pem")
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	writeCfg := func(rootCert string) {
		require.NoError(t, os.WriteFile(cfgPath, []byte("storage:\n  type: postgres\n  database:\n"+
			"    host: db\n    name: keyorix\n    user: keyorix\n    ssl_mode: verify-full\n"+
			"    ssl_root_cert: "+rootCert+"\n"), 0o600))
	}

	writeCfg("pg-ca.pem")
	t.Chdir(t.TempDir()) // a different cwd must not change which file is trusted
	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "pg-ca.pem"), cfg.Storage.Database.SSLRootCert)
	require.NoError(t, cfg.Validate())

	writeCfg("system")
	cfg, err = Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, SSLRootCertSystem, cfg.Storage.Database.SSLRootCert)

	writeCfg("../elsewhere/ca.pem")
	_, err = Load(cfgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssl_root_cert")
}

func TestDatabaseTLSPosture_DescribesWhatIsVerified(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")
	cases := []struct {
		d    *DatabaseConfig
		want []string
	}{
		{pgFields("verify-full", ca), []string{"verify-full", "host name verified", ca, "1 certificate(s)"}},
		{pgFields("verify-full", SSLRootCertSystem), []string{"verify-full", "OS CA store"}},
		{pgFields("require", SSLRootCertSystem), []string{"verify-full", "OS CA store"}}, // pgx: sslrootcert=system forces verify-full
		{pgFields("verify-ca", ca), []string{"verify-ca", "host name NOT verified"}},
		{pgFields("require", ca), []string{"require", "chain verified", "host name NOT verified"}},
		{pgFields("require", ""), []string{"require", "NOT verified"}},
		{pgFields("disable", ""), []string{"disable", "NOT encrypted"}},
		{&DatabaseConfig{DSN: "host=db sslmode=verify-full sslrootcert=" + ca}, []string{"the dsn's sslmode=verify-full", ca}},
		{&DatabaseConfig{DSN: "host=db"}, []string{"prefer", "fall back to an unencrypted"}},
	}
	for _, tc := range cases {
		line, err := DatabaseTLSPosture(tc.d)
		require.NoError(t, err)
		for _, w := range tc.want {
			assert.Contains(t, line, w)
		}
	}

	_, err := DatabaseTLSPosture(pgFields("verify-full", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to start")
}
