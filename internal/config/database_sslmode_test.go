package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PG-TLS-2 item 1: ssl_mode takes only the values pgx accepts. Before, an
// unknown value passed validation (pgx refused it only at connect time), and
// the insecure-settings registry, which matched the literal "disable", could
// not classify it. The refusal lists the valid values.
func TestValidate_SSLModeAllowlist_RefusesUnknownValues(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	for _, mode := range []string{"Disable", "verify_full", "verify-full ", "on", "true", "ssl", "VERIFY-FULL", "none"} {
		err := postgresConfig(pgFields(mode, "")).Validate()
		require.Error(t, err, "ssl_mode=%q must be refused", mode)
		assert.Contains(t, err.Error(), "storage.database.ssl_mode")
		assert.Contains(t, err.Error(), "disable, allow, prefer, require, verify-ca, verify-full",
			"the refusal must list the valid values")

		_, err = ResolvePostgresConnConfig(pgFields(mode, ""))
		require.Error(t, err, "ResolvePostgresConnConfig must refuse ssl_mode=%q too (admin subcommands never run Validate)", mode)
	}

	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")
	for _, mode := range []string{"", "disable", "allow", "prefer", "require"} {
		require.NoError(t, postgresConfig(pgFields(mode, "")).Validate(), "ssl_mode=%q", mode)
	}
	for _, mode := range []string{"verify-ca", "verify-full"} {
		require.NoError(t, postgresConfig(pgFields(mode, ca)).Validate(), "ssl_mode=%q", mode)
	}
}

// The same allowlist applies to the sslmode pgx reads from the dsn, and to
// PGSSLMODE when the dsn has none. The dsn's value is never echoed.
func TestValidate_DSN_SSLModeAllowlist(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	for _, dsn := range []string{
		"host=db password=hunter2 sslmode=hunter2",
		"postgres://k:hunter2@db/k?sslmode=hunter2",
		"postgres://k@db/k?sslmode=verify-full&sslmode=hunter2",
	} {
		err := postgresConfig(&DatabaseConfig{DSN: dsn}).Validate()
		require.Error(t, err, dsn)
		assert.Contains(t, err.Error(), "the sslmode in storage.database.dsn is not a valid sslmode")
		assert.NotContains(t, err.Error(), "hunter2", "the DSN must never be echoed")
	}

	t.Setenv("PGSSLMODE", "verfy-full")
	err := postgresConfig(&DatabaseConfig{DSN: "host=db dbname=k user=k"}).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PGSSLMODE")
	// PGSSLMODE does not apply to a field-built connection (it always states
	// sslmode), so it does not refuse one.
	require.NoError(t, postgresConfig(pgFields("require", "")).Validate())
}

// PG-TLS-2 item 2: with a dsn set, ssl_mode used to be silently ignored, so
// "ssl_mode: verify-full" next to a dsn saying sslmode=disable connected in
// plaintext. Now they must agree; the dsn must state the mode itself (a dsn
// with no sslmode is "prefer" or PGSSLMODE, never what ssl_mode says).
func TestValidate_SSLModeWithDSN_MustAgree(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	ca := writeTestCA(t, t.TempDir(), "pg-ca.pem")

	refused := []struct {
		sslMode, dsn, want string
	}{
		{"verify-full", "host=db password=hunter2 sslmode=disable", "has a different sslmode"},
		{"require", "host=db sslmode=prefer", "has a different sslmode"},
		{"verify-full", "host=db password=hunter2", "has no sslmode"},
		{"require", "postgres://k:hunter2@db/k", "has no sslmode"},
		{"verify-full", "postgres://k:hunter2@db/k?sslmode=verify-full&sslmode=require", "has a different sslmode"},
		// "ssl=true" after the sslmode is pgx's alias for require.
		{"verify-full", "postgres://k@db/k?sslmode=verify-full&sslrootcert=" + ca + "&ssl=true", "has a different sslmode"},
		{"disable", "host=db sslmode=require", "has a different sslmode"},
	}
	for _, tc := range refused {
		err := postgresConfig(&DatabaseConfig{SSLMode: tc.sslMode, DSN: tc.dsn}).Validate()
		require.Error(t, err, "ssl_mode=%s dsn=%s", tc.sslMode, tc.dsn)
		assert.Contains(t, err.Error(), "storage.database.ssl_mode is "+tc.sslMode)
		assert.Contains(t, err.Error(), tc.want)
		assert.Contains(t, err.Error(), "sslmode="+tc.sslMode, "the fix names the sslmode to put in the dsn")
		assert.NotContains(t, err.Error(), "hunter2", "the DSN must never be echoed")

		_, err = ResolvePostgresConnConfig(&DatabaseConfig{SSLMode: tc.sslMode, DSN: tc.dsn})
		require.Error(t, err, "ResolvePostgresConnConfig must refuse it too")
	}

	// PGSSLMODE does not make a dsn without sslmode agree: the dsn must say it.
	t.Setenv("PGSSLMODE", "require")
	require.Error(t, postgresConfig(&DatabaseConfig{SSLMode: "require", DSN: "host=db"}).Validate())
	t.Setenv("PGSSLMODE", "")

	err := postgresConfig(&DatabaseConfig{SSLMode: "bogus", DSN: "host=db sslmode=bogus"}).Validate()
	require.Error(t, err, "agreeing on an invalid value is still invalid")
	assert.Contains(t, err.Error(), "not a valid sslmode")

	for _, d := range []*DatabaseConfig{
		{SSLMode: "require", DSN: "host=db sslmode=require"},
		{SSLMode: "verify-full", DSN: "host=db sslmode=verify-full sslrootcert=" + ca},
		{SSLMode: "verify-full", DSN: "postgres://k@db/k?sslmode=verify-full&sslrootcert=" + ca},
		{SSLMode: "require", DSN: "postgres://k@db/k?ssl=true"},
		{SSLMode: "prefer", DSN: "host=db sslmode=prefer"},
		{DSN: "host=db sslmode=prefer"}, // no ssl_mode: nothing to agree with
	} {
		require.NoError(t, postgresConfig(d).Validate(), "ssl_mode=%q dsn=%q", d.SSLMode, d.DSN)
	}
}

// The insecure-settings registry reads the sslmode the connection really
// uses. Before PG-TLS-2 it read ssl_mode only, so a dsn with sslmode=disable
// (and no ssl_mode) was never reported, and ssl_mode: disable next to a
// verifying dsn was reported although the connection was verified.
func TestInsecureRegistry_DatabaseTLS_ReadsEffectiveSSLMode(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	entry := insecureEntryNamed(t, "storage.database.insecure_disable_database_tls")
	assert.Contains(t, entry.SourcePaths, "storage.database.dsn", "the entry reads the dsn, so it must say so")

	cases := []struct {
		d        DatabaseConfig
		inEffect bool
	}{
		{DatabaseConfig{SSLMode: "disable"}, true},
		{DatabaseConfig{DSN: "host=db sslmode=disable"}, true},
		{DatabaseConfig{DSN: "postgres://k@db/k?sslmode=disable"}, true},
		{DatabaseConfig{DSN: "postgres://k@db/k?sslmode=require&sslmode=disable"}, true},
		{DatabaseConfig{SSLMode: "disable", DSN: "host=db sslmode=disable"}, true},
		{DatabaseConfig{SSLMode: "require"}, false},
		{DatabaseConfig{}, false}, // field-built default is require
		{DatabaseConfig{DSN: "host=db sslmode=require"}, false},
		// pgx upgrades any mode to verify-full with sslrootcert=system.
		{DatabaseConfig{DSN: "host=db sslmode=disable sslrootcert=system"}, false},
	}
	for _, tc := range cases {
		cfg := &Config{}
		cfg.Storage.Database = tc.d
		assert.Equal(t, tc.inEffect, entry.InEffect(cfg), "ssl_mode=%q dsn=%q", tc.d.SSLMode, tc.d.DSN)
		assert.Equal(t, boolStr(tc.inEffect), entry.Value(cfg), "ssl_mode=%q dsn=%q", tc.d.SSLMode, tc.d.DSN)
	}

	t.Setenv("PGSSLMODE", "disable")
	cfg := &Config{}
	cfg.Storage.Database = DatabaseConfig{DSN: "host=db"}
	assert.True(t, entry.InEffect(cfg), "a dsn with no sslmode runs with PGSSLMODE")
	cfg.Storage.Database = DatabaseConfig{SSLMode: "require"}
	assert.False(t, entry.InEffect(cfg), "a field-built connection states sslmode; PGSSLMODE does not apply")
}

func insecureEntryNamed(t *testing.T, name string) InsecureSetting {
	t.Helper()
	for _, e := range InsecureSettingsRegistry {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no InsecureSettingsRegistry entry %s", name)
	return InsecureSetting{}
}

// The posture line reads the same resolved mode, including PGSSLMODE and
// pgx's prefer default for a dsn without sslmode, and the ssl=true alias.
func TestDatabaseTLSPosture_ReadsEffectiveSSLMode(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	for dsn, want := range map[string]string{
		"host=db":                       "the dsn's sslmode=prefer -- may fall back to an unencrypted connection",
		"postgres://k@db/k?ssl=true":    "the dsn's sslmode=require -- encrypted, server certificate NOT verified",
		"host=db sslmode=allow":         "the dsn's sslmode=allow -- may fall back",
		"host=db sslmode=disable":       "the dsn's sslmode=disable -- connection is NOT encrypted",
		"host=db sslrootcert=system":    "the dsn's sslmode=verify-full",
		"postgres://k@db/k?sslmode=pre": "",
	} {
		line, err := DatabaseTLSPosture(&DatabaseConfig{DSN: dsn})
		if want == "" {
			require.Error(t, err, dsn)
			continue
		}
		require.NoError(t, err, dsn)
		assert.Contains(t, line, want, dsn)
	}
	t.Setenv("PGSSLMODE", "require")
	line, err := DatabaseTLSPosture(&DatabaseConfig{DSN: "host=db"})
	require.NoError(t, err)
	assert.Contains(t, line, "sslmode=require")
}

// A config file carrying ssl_mode and a disagreeing dsn is refused when the
// real loader's result is validated (Load reads; Validate is what server boot
// runs), not only on a hand-built struct: the yaml keys reach the check.
func TestLoad_SSLModeDisagreesWithDSN_Refused(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	t.Setenv("KEYORIX_DB_PASSWORD", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(p, []byte("storage:\n  type: postgres\n  database:\n"+
		"    dsn: \"host=db dbname=k user=k sslmode=disable\"\n    ssl_mode: verify-full\n"), 0o600))
	cfg, err := Load(p)
	require.NoError(t, err)
	err = cfg.Validate()
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "storage.database.ssl_mode is verify-full"), err.Error())
}
