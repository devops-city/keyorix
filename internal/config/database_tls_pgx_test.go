package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDSNTLSSettings_AgreesWithPgx is the drift guard for dsnTLSSettings: the
// fail-closed check reads sslmode/sslrootcert with its own small parser
// (internal/config does not link the driver), so a DSN shape the two read
// differently is a DSN that could pass validation and then connect with
// verification the check never saw. For each connection string it compares
// what dsnTLSSettings predicts with what pgx actually builds:
//
//   - verifies: pgx checks the server certificate (no InsecureSkipVerify, or a
//     VerifyPeerCertificate hook for verify-ca);
//   - rootFromDSN: pgx's RootCAs came from the DSN's sslrootcert.
//
// HOME, PGSSLMODE and PGSSLROOTCERT are cleared so pgx's own defaults cannot
// supply a CA. Covers quoting, escapes, spacing around '=', repeated keys
// (last wins in both forms), percent-encoded URL keys and "+" in URL values,
// and sslrootcert=system (which pgx turns into verify-full).
//
// PG-TLS-2 adds a third comparison, the insecure-settings registry's oracle:
//
//   - plaintext: pgx can run the connection unencrypted (no TLS config, or a
//     plaintext entry among its fallbacks), exactly when the resolved
//     effective sslmode is disable, allow or prefer;
//
// and the URI-only ssl=true alias, which pgx reads as sslmode=require when no
// sslmode key follows it.
func TestDSNTLSSettings_AgreesWithPgx(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSSLROOTCERT", "")
	t.Setenv("PGSERVICE", "")

	dir := filepath.Join(t.TempDir(), "ca dir+x")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	ca := writeTestCA(t, dir, "pg'ca.pem")
	kvQuoted := quoteDSNValue(ca)
	urlCA := url.PathEscape(ca)
	plainCA := writeTestCA(t, t.TempDir(), "plain.pem")

	dsns := []string{
		"host=db sslmode=disable",
		"host=db sslmode=require",
		"host=db sslmode=prefer",
		"host=db",
		"host=db sslmode=verify-full sslrootcert=" + kvQuoted,
		"host=db sslmode=verify-ca sslrootcert=" + kvQuoted,
		"host=db sslmode=require sslrootcert=" + kvQuoted,
		"host=db sslmode=prefer sslrootcert=" + plainCA,
		"host=db sslmode = verify-full   sslrootcert =" + plainCA,
		"host=db sslmode=verify-full sslmode=require",
		"host=db sslmode=require sslmode=verify-full sslrootcert=" + plainCA,
		"host=db sslmode='verify-full' sslrootcert='system'",
		"host=db sslmode=require sslrootcert=system",
		"host=db sslmode=disable sslrootcert=system",
		`host=db sslmode=verify\-full sslrootcert=` + plainCA,
		"postgres://u@db/k?sslmode=verify-full&sslrootcert=" + urlCA,
		"postgres://u@db/k?sslmode=require&sslmode=verify-full&sslrootcert=" + urlCA,
		"postgres://u@db/k?sslmode=verify-full&sslmode=require",
		"postgresql://u@db/k?ssl%6Dode=verify-ca&sslrootcert=" + urlCA,
		"postgres://u@db/k?sslmode=require&sslrootcert=" + urlCA,
		"postgres://u@db/k?sslrootcert=system",
		"postgres://u@db/k",
		// The query starts where pgx finds it, not at the first '?': a '?' (or
		// '#', '&') in the userinfo or inside a bracketed IPv6 host is not one.
		"postgres://u:pa?ss@db/k?sslmode=verify-full",
		"postgres://u:pa?ss@db/k?sslmode=verify-full&sslrootcert=" + urlCA,
		"postgres://u:pa#ss@db/k?sslmode=verify-full",
		"postgres://u:pa&sslmode=disable@db/k?sslmode=verify-full",
		"postgres://u:p?sslmode=disable@db/k?sslmode=verify-full",
		"postgres://u?x@db?sslmode=verify-full",
		"postgres://u@[::1?x]/k?sslmode=verify-full",
		"postgres://u@[::1?sslmode=disable]:5432/k?sslmode=verify-full",
		"postgres://u@[::1?sslmode=verify-full]/k",
		"postgres://u@db/k?x=1@y&sslmode=verify-full",
		// pgx has no URL fragment: '#' is query text like any other byte.
		"postgres://u@db/k?#=&sslmode=verify-full",
		"postgres://0?#0=&sslrootcert=system",
		// pgx's ssl=true alias (PG-TLS-2): require, unless an sslmode key
		// comes after the last ssl key; any other ssl value is no alias.
		"postgres://u@db/k?ssl=true",
		"postgres://u@db/k?sslmode=verify-full&ssl=true",
		"postgres://u@db/k?ssl=true&sslmode=disable",
		"postgres://u@db/k?sslmode=disable&ssl=true",
		"postgres://u@db/k?sslmode=disable&ssl=true&ssl=false",
		"postgres://u@db/k?ssl=true&sslmode=verify-full&sslrootcert=" + urlCA,
		"postgres://u@db/k?sslmode=allow",
		"postgres://u@db/k?sslmode=prefer&sslrootcert=" + urlCA,
		"host=db sslmode=allow",
		"host=db ssl=true",
	}
	for _, dsn := range dsns {
		t.Run(dsn, func(t *testing.T) {
			pc, perr := pgconn.ParseConfig(dsn)
			require.NoError(t, perr, "the corpus must be DSNs pgx accepts")
			mode, root, err := dsnTLSSettings(dsn)
			require.NoError(t, err)

			tlsCfg := pc.TLSConfig
			pgxVerifies := tlsCfg != nil && (!tlsCfg.InsecureSkipVerify || tlsCfg.VerifyPeerCertificate != nil)
			pgxRoot := tlsCfg != nil && tlsCfg.RootCAs != nil

			predictedVerifies := sslModeVerifies(mode) || root == SSLRootCertSystem ||
				(root != "" && mode == "require")
			assert.Equal(t, pgxVerifies, predictedVerifies, "verifies: parsed sslmode=%q sslrootcert=%q", mode, root)
			assert.Equal(t, pgxRoot, root != "", "sslrootcert presence: parsed %q", root)
			if root != "" && root != SSLRootCertSystem {
				assert.True(t, root == ca || root == plainCA, "sslrootcert must read back as the exact path, got %q", root)
			}

			effective, err := EffectiveDatabaseSSLMode(&DatabaseConfig{DSN: dsn})
			require.NoError(t, err)
			assert.Equal(t, pgxMayBePlaintext(pc), sslModeMayBePlaintext(effective),
				"plaintext possible: effective sslmode %q", effective)
		})
	}
}

// pgxMayBePlaintext reports whether pgx can run a connection built from pc
// over the network without TLS: no TLS config on the primary attempt
// (disable, allow), or a plaintext fallback (prefer). A Unix-socket host
// (a path; pgx's default when no host is named) has no TLS config in any
// mode and never leaves the machine, so it is not counted.
func pgxMayBePlaintext(pc *pgconn.Config) bool {
	if pc.TLSConfig == nil && !strings.HasPrefix(pc.Host, "/") {
		return true
	}
	for _, fb := range pc.Fallbacks {
		if fb.TLSConfig == nil && !strings.HasPrefix(fb.Host, "/") {
			return true
		}
	}
	return false
}

// A connection string pgx refuses is refused here too, rather than parsed
// into something pgx would never use.
func TestDSNTLSSettings_RejectsWhatPgxRejects(t *testing.T) {
	for _, dsn := range []string{
		"host=db sslmode='verify-full",
		"host=db ssl mode=verify-full",
		"host=db =verify-full",
		"host=db\x00 sslmode=verify-full",
		"postgres://u@db/k?sslmode",
		"postgres://u@db/k?sslmode=a=b",
		"postgres://u@db/k?sslmode=%zz",
		"postgres://u@[::1/k?sslmode=verify-full",
		"postgres://u@[::1]x/k?sslmode=verify-full",
	} {
		_, perr := pgconn.ParseConfig(dsn)
		require.Error(t, perr, "premise: pgx rejects %q", dsn)
		_, _, err := dsnTLSSettings(dsn)
		assert.Error(t, err, "%q", strings.ReplaceAll(dsn, "\x00", `\0`))
	}
}

// buildPostgresDSNFromFields quotes every value it writes into the keyword/value DSN,
// so a field carrying ` sslmode=disable` (a password from KEYORIX_DB_PASSWORD,
// a user or database name) stays that field's literal value. Unquoted, pgx
// reads it as a second sslmode, which wins over the first: the connection
// would skip the verification ValidateDatabaseTLS approved. Checked against
// what pgx actually builds, not against the DSN text.
func TestResolvePostgresConnConfig_FieldValuesCannotInjectKeywords(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSSLROOTCERT", "")
	t.Setenv("KEYORIX_DB_PASSWORD", "")
	ca := writeTestCA(t, t.TempDir(), "ca.pem")
	const inject = ` sslmode=disable sslrootcert=system host=evil`

	for _, field := range []string{"password", "user", "dbname"} {
		t.Run(field, func(t *testing.T) {
			d := pgFields("verify-full", ca)
			value := `x'\` + inject
			switch field {
			case "password":
				d.Password = value
			case "user":
				d.User = value
			case "dbname":
				d.Name = value
			}
			pc, err := ResolvePostgresConnConfig(d)
			require.NoError(t, err)

			require.NotNil(t, pc.TLSConfig, "sslmode=verify-full must stay a TLS connection")
			assert.False(t, pc.TLSConfig.InsecureSkipVerify, "verify-full must keep verifying")
			assert.Equal(t, "db.internal", pc.TLSConfig.ServerName, "host name checked must be the configured host")
			assert.Equal(t, "db.internal", pc.Host)
			got := map[string]string{"password": pc.Password, "user": pc.User, "dbname": pc.Database}[field]
			assert.Equal(t, value, got, "the field must read back as its exact literal value")
		})
	}
}

// The password from KEYORIX_DB_PASSWORD (#3159) is set on the parsed config
// by ResolvePostgresConnConfig, in all three DSN shapes. Whatever it contains
// -- here a quote followed by a second host and sslmode -- it must stay the
// password: the final config has the configured host, the verifying TLS
// settings and the exact password.
func TestResolvePostgresConnConfig_EnvPasswordCannotInjectKeywords(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSSLROOTCERT", "")
	ca := writeTestCA(t, t.TempDir(), "ca.pem")
	for _, pw := range []string{
		`' host=evil`,
		`x' host=evil sslmode=disable sslrootcert=system`,
		`a@evil/db?sslmode=disable&host=evil#`,
		`\' host=evil`,
	} {
		t.Run(pw, func(t *testing.T) {
			t.Setenv("KEYORIX_DB_PASSWORD", pw)
			cases := map[string]*DatabaseConfig{
				"fields":  pgFields("verify-full", ca),
				"keyword": {DSN: "host=db.internal user=u dbname=k sslmode=verify-full sslrootcert=" + quoteDSNValue(ca)},
				"url":     {DSN: "postgres://u@db.internal/k?sslmode=verify-full&sslrootcert=" + url.QueryEscape(ca)},
			}
			for name, d := range cases {
				pc, err := ResolvePostgresConnConfig(d)
				require.NoError(t, err, name)
				assert.Equal(t, pw, pc.Password, name)
				assert.Equal(t, "db.internal", pc.Host, name)
				require.NotNil(t, pc.TLSConfig, name)
				assert.False(t, pc.TLSConfig.InsecureSkipVerify, name)
				assert.Equal(t, "db.internal", pc.TLSConfig.ServerName, name)
			}
		})
	}
}
