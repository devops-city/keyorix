package config

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkFinalPostgresTLS is the defence in depth REVIEW-3162B asked for: the TLS
// check validated one reading of the config; the final pgx config must have the
// TLS that reading promised. Fed the strings #3159's splice really produced for
// the reviewer's two repros (parsed by pgx), it refuses both.
func TestCheckFinalPostgresTLS_RefusesTheReview3162BSplices(t *testing.T) {
	clearPGEnv(t)
	ca := writeTestCA(t, t.TempDir(), "ca.pem")
	cases := []struct{ name, configured, spliced string }{
		{
			"url-userinfo-question-mark",
			"postgres://u?x@db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
			"postgres://:secret@u?x@db.internal/k?sslmode=verify-full&sslrootcert=" + ca,
		},
		{
			"keyword-trailing-backslash",
			"host=db.internal sslmode=verify-full sslrootcert=" + quoteDSNValue(ca) + ` application_name=x\`,
			"host=db.internal sslmode=verify-full sslrootcert=" + quoteDSNValue(ca) + ` application_name=x\ password='a sslmode=disable host=evil x=\\'`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &DatabaseConfig{DSN: c.configured}
			require.NoError(t, ValidateDatabaseTLS(d), "the configured DSN passes the check")
			good, err := pgx.ParseConfig(c.configured)
			require.NoError(t, err)
			require.NoError(t, checkFinalPostgresTLS(d, good), "pgx's reading of the configured DSN is what was validated")

			spliced, err := pgx.ParseConfig(c.spliced)
			require.NoError(t, err)
			err = checkFinalPostgresTLS(d, spliced)
			require.Error(t, err, "pgx reads host=%q from the spliced string", spliced.Host)
			assert.Contains(t, err.Error(), "differ from what the TLS check validated")
			assert.NotContains(t, err.Error(), "secret")
			assert.NotContains(t, err.Error(), "evil")
		})
	}
}

// Each way the final config can fall short of what was validated is refused;
// the untampered config passes.
func TestCheckFinalPostgresTLS_RefusesEveryWeakerFinalConfig(t *testing.T) {
	clearPGEnv(t)
	ca := writeTestCA(t, t.TempDir(), "ca.pem")
	other := x509.NewCertPool()
	multi := func(mode, root string) *DatabaseConfig {
		dsn := "postgres://u@a.internal,b.internal/k?sslmode=" + mode
		if root != "" {
			dsn += "&sslrootcert=" + root
		}
		return &DatabaseConfig{DSN: dsn}
	}
	lastFallbackPlaintext := func(cc *pgx.ConnConfig) { cc.Fallbacks[len(cc.Fallbacks)-1].TLSConfig = nil }

	type tamper func(cc *pgx.ConnConfig)
	for _, tc := range []struct {
		name    string
		d       *DatabaseConfig
		tamper  tamper
		wantErr string
	}{
		{"verify-full ok", &DatabaseConfig{DSN: "host=db.internal sslmode=verify-full sslrootcert=" + quoteDSNValue(ca)}, nil, ""},
		{"verify-ca ok", &DatabaseConfig{DSN: "host=db.internal sslmode=verify-ca sslrootcert=" + quoteDSNValue(ca)}, nil, ""},
		{"require+CA ok", pgFields("require", ca), nil, ""},
		{"require ok", pgFields("require", ""), nil, ""},
		{"prefer makes no claim", &DatabaseConfig{DSN: "host=db.internal sslmode=prefer"}, func(cc *pgx.ConnConfig) { cc.TLSConfig = nil }, ""},
		{"multi-host verify-full ok", multi("verify-full", ca), nil, ""},
		// A Unix-domain socket is local and never TLS (pgx and libpq): no TLS claim to check.
		// Fuzz-found: B first refused it.
		{"unix socket verify-full ok", &DatabaseConfig{DSN: "host=/var/run/postgresql sslmode=verify-full sslrootcert=system"}, nil, ""},
		{"unix socket, host moved to TCP", &DatabaseConfig{DSN: "host=/var/run/postgresql sslmode=verify-full sslrootcert=system"}, func(cc *pgx.ConnConfig) {
			cc.Host = "evil.internal"
		}, "not the configured one"},

		{"tls off", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) { cc.TLSConfig = nil }, "would not use TLS"},
		{"plaintext fallback", multi("verify-full", ca), lastFallbackPlaintext, "would not use TLS"},
		{"require plaintext fallback", multi("require", ""), lastFallbackPlaintext, "would not use TLS"},
		{"extra fallback", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) {
			cc.Fallbacks = append(cc.Fallbacks, &pgconn.FallbackConfig{Host: "db.internal", Port: 5432})
		}, "not the configured one"},
		{"dsn host moved, still verify-full against system CAs", &DatabaseConfig{DSN: "host=db.internal sslmode=verify-full sslrootcert=system"}, func(cc *pgx.ConnConfig) {
			cc.Host, cc.TLSConfig.ServerName = "evil", "evil"
		}, "not the configured one"},
		{"port moved", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) { cc.Port = 6543 }, "not the configured one"},
		{"user changed", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) { cc.User = "postgres" }, "not the configured one"},
		{"no verification", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) {
			cc.TLSConfig = &tls.Config{InsecureSkipVerify: true, RootCAs: cc.TLSConfig.RootCAs} // #nosec G402 -- the tampered config under test
		}, "would not be verified"},
		{"no CA pool", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) { cc.TLSConfig.RootCAs = nil }, "no CA pool"},
		{"other CA", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) { cc.TLSConfig.RootCAs = other }, "not the validated CA file"},
		{"other server name", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) { cc.TLSConfig.ServerName = "evil.internal" }, "host name would not be verified"},
		{"verify-ca where verify-full was validated", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) {
			cc.TLSConfig.InsecureSkipVerify = true
			cc.TLSConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		}, "host name would not be verified"},
		{"fields host moved", pgFields("verify-full", ca), func(cc *pgx.ConnConfig) { cc.Host = "evil.internal" }, "not the configured one"},
		{"multi-host fallback unverified", multi("verify-full", ca), func(cc *pgx.ConnConfig) {
			cc.Fallbacks[len(cc.Fallbacks)-1].TLSConfig.ServerName = "a.internal"
		}, "host name would not be verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, ValidateDatabaseTLS(tc.d))
			dsn := tc.d.DSN
			if dsn == "" {
				dsn = buildPostgresDSNFromFields(tc.d)
			}
			cc, err := pgx.ParseConfig(dsn)
			require.NoError(t, err)
			require.NoError(t, checkFinalPostgresTLS(tc.d, cc), "untampered")
			if tc.tamper == nil {
				return
			}
			tc.tamper(cc)
			err = checkFinalPostgresTLS(tc.d, cc)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
