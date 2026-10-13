package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

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

// DSN without a password + a password source: the password is applied (the
// #3151 bug: it was silently ignored).
func TestResolvePostgresDSN_DSNWithoutPasswordGetsResolvedPassword(t *testing.T) {
	for _, dsn := range []string{dsnNoPwKeyword, dsnNoPwURL} {
		for _, src := range passwordSources() {
			t.Run(src.name+"/"+dsn[:8], func(t *testing.T) {
				d := &DatabaseConfig{DSN: dsn}
				src.apply(t, d)
				got, err := ResolvePostgresDSN(d)
				require.NoError(t, err)
				has, err := dsnHasPassword(got)
				require.NoError(t, err)
				assert.True(t, has, "resolved password must be in the DSN")
				assert.Contains(t, got, "other-secret")
			})
		}
	}
}

func TestResolvePostgresDSN_DSNWithoutPasswordNoSourceUnchanged(t *testing.T) {
	for _, dsn := range []string{dsnNoPwKeyword, dsnNoPwURL} {
		got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err)
		assert.Equal(t, dsn, got)
	}
}

// DSN with a password and no other source: used as-is (existing behaviour).
func TestResolvePostgresDSN_DSNWithPasswordAlone(t *testing.T) {
	for _, dsn := range []string{dsnPwKeyword, dsnPwURL, dsnPwURLQuery} {
		got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err)
		assert.Equal(t, dsn, got)
	}
}

// DSN with a password AND a password source: refuse, name the setting and the
// fix, never print either password or the DSN.
func TestResolvePostgresDSN_ConflictRefused(t *testing.T) {
	for _, dsn := range []string{dsnPwKeyword, dsnPwURL, dsnPwURLQuery} {
		for _, src := range passwordSources() {
			t.Run(src.name+"/"+dsn[:8], func(t *testing.T) {
				d := &DatabaseConfig{DSN: dsn}
				src.apply(t, d)
				got, err := ResolvePostgresDSN(d)
				require.Error(t, err)
				assert.Empty(t, got)
				msg := err.Error()
				assert.Contains(t, msg, "storage.database.dsn")
				assert.Contains(t, msg, src.want)
				assert.Contains(t, msg, "remove the password from storage.database.dsn")
				assert.NotContains(t, msg, "in-dsn-secret")
				assert.NotContains(t, msg, "other-secret")
				assert.NotContains(t, msg, "127.0.0.1")
				assert.Empty(t, BuildPostgresDSN(d), "BuildPostgresDSN must fail closed")
			})
		}
	}
}

// Field-by-field form: unchanged behaviour, with quoting for awkward passwords.
func TestResolvePostgresDSN_Fields(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "p w'd\\")
	got, err := ResolvePostgresDSN(&DatabaseConfig{Host: "h", Name: "n", User: "u", SSLMode: "disable"})
	require.NoError(t, err)
	assert.Contains(t, got, `password='p w\'d\\'`)
	kv := parseKeywordDSN(got)
	var pw string
	for _, p := range kv {
		if p[0] == "password" {
			pw = p[1]
		}
	}
	assert.Equal(t, "p w'd\\", pw, "quoting must round-trip")
}

func TestResolvePostgresDSN_AppendQuotesKeywordPassword(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "has space")
	got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsnNoPwKeyword})
	require.NoError(t, err)
	assert.Contains(t, got, "password='has space'")
}

// Without a configured password the DSN is not inspected at all: valid pgx
// forms net/url cannot parse (multi-host lists) must pass through unchanged,
// and a malformed one is left for the driver to report.
func TestResolvePostgresDSN_NoPasswordSourceReturnsDSNUntouched(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u@[::1]:5432,[::2]:5433/db",
		"postgres://u:in-dsn-secret@h:notaport/db",
		"postgres://u@h/db?options=-c%20x=y&sslrootcert=/x%20y/ca.pem",
	} {
		got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err, dsn)
		assert.Equal(t, dsn, got)
	}
}

// URL-form DSNs round-trip byte-identically except for the inserted password,
// and the result is what pgx actually parses.
func TestResolvePostgresDSN_URLRoundTrip(t *testing.T) {
	passwords := []string{"plain", "p w", "a+b", "100%", "x@y", "a:b", "a/b", "a?b", "a#b", "@:/?#%", "p w+%@#:/?&=;'\"\\é"}
	cases := []struct {
		name               string
		before, after      string // DSN text around the insertion point
		sep                string // ":" normally; "" when the DSN already ends userinfo with ':'
		wantUser, wantHost string
		noUserinfo         bool
	}{
		{"user-only", "postgres://keyorix", "@127.0.0.1:15439/keyorix?sslmode=disable", ":", "keyorix", "127.0.0.1", false},
		{"postgresql-scheme", "postgresql://keyorix", "@db.example/keyorix", ":", "keyorix", "db.example", false},
		{"empty-password-colon", "postgres://keyorix:", "@db.example/keyorix", "", "keyorix", "db.example", false},
		{"no-userinfo", "postgres://", "db.example/keyorix?sslmode=disable", ":", "", "db.example", true},
		{"no-path", "postgres://keyorix", "@db.example", ":", "keyorix", "db.example", false},
		{"verify-full-rootcert", "postgres://keyorix", "@db.example:5432/keyorix?sslmode=verify-full&sslrootcert={CA}", ":", "keyorix", "db.example", false},
		{"param-order-and-plus", "postgres://keyorix", "@db.example/keyorix?sslrootcert={CA}&sslmode=disable&application_name=k%2Bx", ":", "keyorix", "db.example", false},
		{"options-and-semicolon-pair", "postgres://keyorix", "@db.example/keyorix?options=-c%20search_path%3Dx&sslmode=disable&junk;x=1", ":", "keyorix", "db.example", false},
	}
	ca := writeTestCA(t)
	for _, tc := range cases {
		for _, pw := range passwords {
			t.Run(tc.name+"/"+pw, func(t *testing.T) {
				after := strings.ReplaceAll(tc.after, "{CA}", ca)
				dsn := tc.before + after
				t.Setenv("KEYORIX_DB_PASSWORD", pw)
				got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsn})
				require.NoError(t, err)

				esc := url.UserPassword("x", pw).String()[len("x:"):]
				ins := tc.sep + esc
				if tc.noUserinfo {
					ins = ":" + esc + "@"
				}
				assert.Equal(t, tc.before+ins+after, got, "only the password may be inserted")

				cfg, err := pgconn.ParseConfig(got)
				require.NoError(t, err)
				assert.Equal(t, pw, cfg.Password)
				if tc.wantUser != "" {
					assert.Equal(t, tc.wantUser, cfg.User)
				}
				assert.Equal(t, tc.wantHost, cfg.Host)
			})
		}
	}
}

// Existing query parameters reach pgx exactly as they would without the
// password (the net/url Encode() regression: '+' for space, dropped pairs).
func TestResolvePostgresDSN_URLQueryParamsSurvive(t *testing.T) {
	base := "postgres://keyorix@db.example:5432/keyorix?sslmode=disable&sslrootcert=" + writeTestCA(t) +
		"&application_name=a%20b&options=-c%20search_path%3Dx&search_path=a+b"
	t.Setenv("KEYORIX_DB_PASSWORD", "p w+%@#")
	got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: base})
	require.NoError(t, err)
	want, err := pgconn.ParseConfig(base)
	require.NoError(t, err)
	have, err := pgconn.ParseConfig(got)
	require.NoError(t, err)
	assert.Equal(t, "p w+%@#", have.Password)
	assert.Equal(t, want.RuntimeParams, have.RuntimeParams)
	assert.Equal(t, "a b", have.RuntimeParams["application_name"])
	assert.Equal(t, "a+b", have.RuntimeParams["search_path"], "'+' must stay literal, as without the password")
	assert.Equal(t, want.Host, have.Host)
	assert.Equal(t, want.Port, have.Port)
	assert.Equal(t, want.Database, have.Database)
	assert.Equal(t, want.User, have.User)
}

// Multi-host DSN with a password source: spliced, still parseable by pgx.
func TestResolvePostgresDSN_MultiHostGetsPassword(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "p@ss:w/rd#1")
	got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: "postgres://u@[::1]:5432,[::2]:5433/db?sslmode=disable"})
	require.NoError(t, err)
	assert.Equal(t, "postgres://u:p%40ss%3Aw%2Frd%231@[::1]:5432,[::2]:5433/db?sslmode=disable", got)
	cfg, err := pgconn.ParseConfig(got)
	require.NoError(t, err)
	assert.Equal(t, "p@ss:w/rd#1", cfg.Password)
}

// key=value form: quoted password parses back through pgx.
func TestResolvePostgresDSN_KeywordRoundTrip(t *testing.T) {
	for _, pw := range []string{"plain", "p w", "q'uote", `b\slash`, "@:/?#%", "a b'c\\d@:/?#%"} {
		for _, base := range []string{
			dsnNoPwKeyword,
			dsnNoPwKeyword + " sslrootcert=/etc/ssl/ca.pem",
			dsnNoPwKeyword + " application_name='a b'",
		} {
			t.Run(pw, func(t *testing.T) {
				t.Setenv("KEYORIX_DB_PASSWORD", pw)
				got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: base})
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(got, base+" password="), "base DSN preserved verbatim")
				if strings.Contains(base, "sslrootcert") {
					assert.Contains(t, parseKeywordDSN(got), [2]string{"sslrootcert", "/etc/ssl/ca.pem"})
					return // pgconn would try to read the cert file
				}
				cfg, err := pgconn.ParseConfig(got)
				require.NoError(t, err)
				assert.Equal(t, pw, cfg.Password)
			})
		}
	}
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
	}
	for dsn, want := range cases {
		got, err := dsnHasPassword(dsn)
		require.NoError(t, err, dsn)
		assert.Equal(t, want, got, dsn)
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
