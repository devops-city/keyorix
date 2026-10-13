package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dsnNoPwKeyword = "host=127.0.0.1 user=keyorix dbname=keyorix port=15439 sslmode=disable"
	dsnPwKeyword   = dsnNoPwKeyword + " password=in-dsn-secret"
	dsnNoPwURL     = "postgres://keyorix@127.0.0.1:15439/keyorix?sslmode=disable"
	dsnPwURL       = "postgres://keyorix:in-dsn-secret@127.0.0.1:15439/keyorix?sslmode=disable"
	dsnPwURLQuery  = dsnNoPwURL + "&password=in-dsn-secret"
)

// passwordSource sets one way of supplying the DB password and returns the
// secret value and the setting name the error is expected to mention.
type passwordSource struct {
	name  string
	apply func(t *testing.T, d *DatabaseConfig)
	want  string // setting named in a conflict error
}

func passwordSources() []passwordSource {
	return []passwordSource{
		{"env", func(t *testing.T, d *DatabaseConfig) { t.Setenv("KEYORIX_DB_PASSWORD", "other-secret") }, "KEYORIX_DB_PASSWORD"},
		{"file", func(t *testing.T, d *DatabaseConfig) {
			t.Setenv("KEYORIX_DB_PASSWORD_FILE", writeSecretFile(t, "other-secret\n"))
		}, "KEYORIX_DB_PASSWORD_FILE"},
		{"yaml", func(t *testing.T, d *DatabaseConfig) { d.Password = "other-secret" }, "storage.database.password"},
	}
}

// clearPGEnv clears the libpq environment variables pgx merges under the
// DSN, so a developer's shell cannot change what these tests parse.
func clearPGEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
		"PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGSERVICE", "PGSERVICEFILE", "PGAPPNAME",
		"PGOPTIONS", "PGSSLNEGOTIATION", "PGSSLSNI", "PGTARGETSESSIONATTRS"} {
		t.Setenv(k, "")
	}
	t.Setenv("HOME", t.TempDir()) // no ~/.pgpass, ~/.postgresql/root.crt
}

// tlsShape is the part of a *tls.Config that decides what a connection
// verifies: nil means plaintext.
type tlsShape struct {
	On, InsecureSkipVerify, CustomVerify bool
	ServerName                           string
	RootCAs                              *x509.CertPool
}

func shapeOf(c *tls.Config) tlsShape {
	if c == nil {
		return tlsShape{}
	}
	return tlsShape{On: true, InsecureSkipVerify: c.InsecureSkipVerify, CustomVerify: c.VerifyPeerCertificate != nil,
		ServerName: c.ServerName, RootCAs: c.RootCAs}
}

// assertSameConnection asserts that got connects exactly where, and exactly
// as securely as, pgx's own parse of base does -- host, port, database, user,
// TLS for the primary and every fallback, runtime parameters -- and with
// password wantPw.
func assertSameConnection(t *testing.T, base string, got *pgx.ConnConfig, wantPw string) {
	t.Helper()
	want, err := pgx.ParseConfig(base)
	require.NoError(t, err)
	assert.Equal(t, wantPw, got.Password, "password")
	assert.Equal(t, want.Host, got.Host, "host")
	assert.Equal(t, want.Port, got.Port, "port")
	assert.Equal(t, want.Database, got.Database, "database")
	assert.Equal(t, want.User, got.User, "user")
	assert.Equal(t, want.RuntimeParams, got.RuntimeParams, "runtime params")
	assertSameTLS(t, want.TLSConfig, got.TLSConfig)
	require.Len(t, got.Fallbacks, len(want.Fallbacks), "fallbacks")
	for i := range want.Fallbacks {
		assert.Equal(t, want.Fallbacks[i].Host, got.Fallbacks[i].Host, "fallback host")
		assert.Equal(t, want.Fallbacks[i].Port, got.Fallbacks[i].Port, "fallback port")
		assertSameTLS(t, want.Fallbacks[i].TLSConfig, got.Fallbacks[i].TLSConfig)
	}
}

func assertSameTLS(t *testing.T, want, got *tls.Config) {
	t.Helper()
	w, g := shapeOf(want), shapeOf(got)
	assert.True(t, w.RootCAs.Equal(g.RootCAs), "TLS root CAs")
	w.RootCAs, g.RootCAs = nil, nil
	assert.Equal(t, w, g, "TLS")
}

// DSN without a password + a password source: the password is applied (the
// #3151 bug: it was silently ignored), on the parsed config.
func TestResolvePostgresConnConfig_DSNWithoutPasswordGetsResolvedPassword(t *testing.T) {
	clearPGEnv(t)
	for _, dsn := range []string{dsnNoPwKeyword, dsnNoPwURL} {
		for _, src := range passwordSources() {
			t.Run(src.name+"/"+dsn[:8], func(t *testing.T) {
				d := &DatabaseConfig{DSN: dsn}
				src.apply(t, d)
				got, err := ResolvePostgresConnConfig(d)
				require.NoError(t, err)
				assertSameConnection(t, dsn, got, "other-secret")
			})
		}
	}
}

func TestResolvePostgresConnConfig_DSNWithoutPasswordNoSourceUnchanged(t *testing.T) {
	clearPGEnv(t)
	for _, dsn := range []string{dsnNoPwKeyword, dsnNoPwURL} {
		got, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err)
		assertSameConnection(t, dsn, got, "")
	}
}

// DSN with a password and no other source: used as-is (existing behaviour).
func TestResolvePostgresConnConfig_DSNWithPasswordAlone(t *testing.T) {
	clearPGEnv(t)
	for _, dsn := range []string{dsnPwKeyword, dsnPwURL, dsnPwURLQuery} {
		got, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err)
		assertSameConnection(t, dsn, got, "in-dsn-secret")
	}
}

// DSN with a password AND a password source: refuse, name the setting and the
// fix, never print either password or the DSN.
func TestResolvePostgresConnConfig_ConflictRefused(t *testing.T) {
	clearPGEnv(t)
	for _, dsn := range []string{dsnPwKeyword, dsnPwURL, dsnPwURLQuery} {
		for _, src := range passwordSources() {
			t.Run(src.name+"/"+dsn[:8], func(t *testing.T) {
				d := &DatabaseConfig{DSN: dsn}
				src.apply(t, d)
				got, err := ResolvePostgresConnConfig(d)
				require.Error(t, err)
				assert.Nil(t, got)
				msg := err.Error()
				assert.Contains(t, msg, "storage.database.dsn")
				assert.Contains(t, msg, src.want)
				assert.Contains(t, msg, "remove the password from storage.database.dsn")
				assert.NotContains(t, msg, "in-dsn-secret")
				assert.NotContains(t, msg, "other-secret")
				assert.NotContains(t, msg, "127.0.0.1")
			})
		}
	}
}

// Field-by-field form: the password goes on the parsed config, never into the
// field-built string.
func TestResolvePostgresConnConfig_Fields(t *testing.T) {
	clearPGEnv(t)
	const pw = "p w'd\\ sslmode=disable host=evil"
	t.Setenv("KEYORIX_DB_PASSWORD", pw)
	d := &DatabaseConfig{Host: "h", Name: "n", User: "u", SSLMode: "disable"}
	got, err := ResolvePostgresConnConfig(d)
	require.NoError(t, err)
	base := buildPostgresDSNFromFields(d)
	assert.NotContains(t, base, "password")
	assertSameConnection(t, base, got, pw)
	assert.Equal(t, "h", got.Host)
}

// Without a configured password, valid pgx forms net/url cannot parse
// (multi-host lists) still work, and a DSN pgx rejects is reported without
// the password it carries.
func TestResolvePostgresConnConfig_NoPasswordSource(t *testing.T) {
	clearPGEnv(t)
	ok := []string{
		"postgres://u@[::1]:5432,[::2]:5433/db?sslmode=disable",
		"postgres://u@h/db?options=-c%20x%3Dy&sslmode=disable",
	}
	for _, dsn := range ok {
		got, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err, dsn)
		assertSameConnection(t, dsn, got, "")
	}
	_, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: "postgres://u:in-dsn-secret@h:notaport/db"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage.database")
	assert.NotContains(t, err.Error(), "in-dsn-secret")
}

// The env password never reaches a parser: an invalid DSN with a password
// source is reported without it.
func TestResolvePostgresConnConfig_ParseErrorNeverShowsResolvedPassword(t *testing.T) {
	clearPGEnv(t)
	t.Setenv("KEYORIX_DB_PASSWORD", "env-secret-xyz")
	for _, dsn := range []string{"postgres://u@h:notaport/db", "host=h port=notaport", "host='unterminated"} {
		_, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: dsn})
		require.Error(t, err, dsn)
		assert.NotContains(t, err.Error(), "env-secret-xyz")
	}
}

// injectionPasswords are passwords that carry every character that means
// something to the keyword/value or URL grammar, and the reviewer's
// keyword-injection payloads.
var injectionPasswords = []string{
	"plain", "p w", "q'uote", `b\slash`, `a\`, `\`, "'", `\'`, "x=y", "a?b", "x@y", "a#b", "100%", "%zz", "a&b",
	"a:b", "a/b", "line\nbreak", "tab\tsep", " lead", "trail ", "a+b", "é",
	`a sslmode=disable host=evil x=\`,
	`' sslmode=disable host=evil x='`,
	`\' sslmode=disable host=evil`,
	"x' sslmode=disable sslrootcert=system host=evil",
	"@evil:1/db?sslmode=disable#",
	"p w+%@#:/?&=;'\"\\é",
}

// The password, whatever it holds, cannot change where or how the connection
// goes, for every base DSN shape including those the old splice misread:
// keyword DSNs ending in a backslash or an escaped trailing space, and URLs
// with '?', '@' or '#' in the userinfo.
func TestResolvePostgresConnConfig_PasswordCannotChangeTheConnection(t *testing.T) {
	clearPGEnv(t)
	ca := writeTestCA(t)
	caKW := strings.ReplaceAll(mustUnescapePath(t, ca), `'`, `\'`)
	bases := []string{
		dsnNoPwKeyword,
		dsnNoPwKeyword + " application_name='a b'",
		"host=db.internal sslmode=verify-full sslrootcert='" + caKW + "' application_name=x\\",
		"host=db.internal sslmode=verify-full sslrootcert='" + caKW + "' application_name=x\\ ",
		"host=db.internal sslmode=verify-full sslrootcert='" + caKW + "' application_name=x\\\t",
		"host=db.internal sslmode=verify-full sslrootcert='" + caKW + "' application_name=x \n",
		"host=db.internal sslmode=verify-full sslrootcert='" + caKW + "' application_name='x\\\\'",
		dsnNoPwURL,
		"postgres://u?x@db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://u?x@db.internal?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://u#x@db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://u%40x@db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://u:@db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://u@[::1]:5432,[::2]:5433/db?sslmode=verify-full&sslrootcert=" + ca,
		"postgresql://u@db.internal/k?application_name=a#frag&sslmode=verify-full&sslrootcert=" + ca,
	}
	for _, base := range bases {
		_, err := pgx.ParseConfig(base)
		require.NoError(t, err, "base DSN must be valid for pgx: %q", base)
		for _, pw := range injectionPasswords {
			t.Run(fmt.Sprintf("%q/%q", base, pw), func(t *testing.T) {
				t.Setenv("KEYORIX_DB_PASSWORD", pw)
				got, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: base})
				require.NoError(t, err)
				assertSameConnection(t, base, got, pw)
			})
		}
	}
}

// REVIEW-3162B problem 1, verbatim: a '?' in the URL userinfo made the splice
// put the password before it, and pgx then read host "u" with sslmode=prefer.
func TestResolvePostgresConnConfig_Review3162B_URLUserinfoQuestionMark(t *testing.T) {
	clearPGEnv(t)
	ca := writeTestCA(t)
	t.Setenv("KEYORIX_DB_PASSWORD", "secret")
	for _, base := range []string{
		"postgres://u?x@db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
		"postgres://u?x@db.internal?sslmode=verify-full&sslrootcert=" + ca,
	} {
		got, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: base})
		require.NoError(t, err)
		assert.Equal(t, "db.internal", got.Host)
		assert.Equal(t, "secret", got.Password)
		require.NotNil(t, got.TLSConfig, "TLS must stay on")
		assert.False(t, got.TLSConfig.InsecureSkipVerify, "verify-full must stay verify-full")
		assert.Equal(t, "db.internal", got.TLSConfig.ServerName)
		assert.Empty(t, got.Fallbacks, "no plaintext fallback")
	}
}

// REVIEW-3162B problem 2, verbatim: a keyword DSN ending in '\' swallowed the
// separator before the appended password, whose contents then became keywords.
func TestResolvePostgresConnConfig_Review3162B_KeywordTrailingBackslash(t *testing.T) {
	clearPGEnv(t)
	ca := mustUnescapePath(t, writeTestCA(t))
	const pw = `a sslmode=disable host=evil x=\`
	t.Setenv("KEYORIX_DB_PASSWORD", pw)
	for _, base := range []string{
		"host=db.internal sslmode=verify-full sslrootcert='" + ca + "' application_name=x\\",
		"host=db.internal sslmode=verify-full sslrootcert='" + ca + "' application_name=x\\ ",
	} {
		got, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: base})
		require.NoError(t, err)
		assert.Equal(t, "db.internal", got.Host)
		assert.Equal(t, pw, got.Password)
		require.NotNil(t, got.TLSConfig, "sslmode=disable must not be injected")
		assert.False(t, got.TLSConfig.InsecureSkipVerify)
		assert.Empty(t, got.Fallbacks)
	}
}

func mustUnescapePath(t *testing.T, escaped string) string {
	t.Helper()
	p, err := url.PathUnescape(escaped)
	require.NoError(t, err)
	return p
}

func TestDSNHasPassword(t *testing.T) {
	cases := map[string]bool{
		dsnNoPwKeyword:                 false,
		dsnPwKeyword:                   true,
		"host=h password='' user=u":    false,
		"host=h password='a b' user=u": true,
		"host=h password = x":          true,
		"host=h user=password":         false,
		"host=h user='password=x'":     false,
		dsnNoPwURL:                     false,
		dsnPwURL:                       true,
		dsnPwURLQuery:                  true,
		"postgres://u:@h/db":           false,
		"postgresql://u:p@h/db":        true,
		// pgx's userinfo rule: it ends at the first '@' before any '/'.
		"postgres://u:pa?ss@h/db":           true,
		"postgres://u?x@h/db":               false,
		"postgres://u?x:p@h/db":             true,
		"postgres://u#x:p@h/db":             true,
		"postgres://u@h/db?x=1&password=p":  true,
		"postgres://u@[::1?]/db?password=p": true,
		"postgres://u@[::1?password=x]/db":  false,
		"postgres://u?password=p@h/db":      false,
		"postgres://h/db?a=1@b&password=p":  true,
		"host='unterminated":                false,
		"host=h password='unterminated":     false, // pgx rejects it before
		"password=\f":                       false, // \f is whitespace to pgx
		"password=x password=''":            false, // the last one wins
		"password='' password=x":            true,
		"postgres://u:%20@h/db":             true,  // a one-space password
		"postgres://u: @h/db":               false, // raw spaces are dropped
		"postgres://u:p@h/db?password=":     false, // the query wins
		"postgres://u@h/db?pass%77ord=p":    true,
	}
	for dsn, want := range cases {
		assert.Equal(t, want, dsnHasPassword(dsn), dsn)
	}
}

// Validate (what the server and `admin validate` run) refuses the conflict.
func TestValidate_RefusesPostgresDSNPasswordConflict(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "other-secret")
	cfg := validLocalConfig()
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsnPwKeyword
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_DB_PASSWORD")
	assert.Contains(t, err.Error(), "storage.database.dsn")
	assert.NotContains(t, err.Error(), "other-secret")
	assert.NotContains(t, err.Error(), "in-dsn-secret")
}

func TestValidate_AcceptsPostgresDSNWithEnvPassword(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "other-secret")
	cfg := validLocalConfig()
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsnNoPwKeyword
	assert.NoError(t, cfg.Validate())
}

// writeTestCA writes a throwaway self-signed CA certificate to a path with a
// space in it and returns that path percent-escaped for use in a URL DSN
// (pgx reads sslrootcert at parse time, even for sslmode=disable).
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keyorix-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "my certs")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return (&url.URL{Path: path}).EscapedPath()
}
