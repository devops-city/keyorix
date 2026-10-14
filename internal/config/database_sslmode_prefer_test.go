package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// PG-TLS-3: sslmode prefer and allow encrypt only when the TLS attempt
// succeeds. Anyone on the network path who answers PostgreSQL's SSLRequest with
// "no" gets a plaintext connection, password exchange included, so both are a
// registered insecure setting (counted by `admin validate --posture`, warned at
// boot) -- like disable, but reachable by an active attacker rather than by
// configuration alone. pgx's default for a dsn with no sslmode is prefer, which
// counts too.
func TestInsecureRegistry_DatabasePlaintextFallback_PreferAndAllow(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Setenv("PGSERVICE", "")
	entry := insecureEntryNamed(t, "storage.database.insecure_allow_plaintext_database_fallback")
	assert.Contains(t, entry.SourcePaths, "storage.database.ssl_mode")
	assert.Contains(t, entry.SourcePaths, "storage.database.dsn", "the entry reads the dsn, so it must say so")
	assert.NotEmpty(t, entry.Describe)

	cases := []struct {
		d        DatabaseConfig
		inEffect bool
	}{
		{DatabaseConfig{SSLMode: "prefer"}, true},
		{DatabaseConfig{SSLMode: "allow"}, true},
		{DatabaseConfig{DSN: "host=db sslmode=prefer"}, true},
		{DatabaseConfig{DSN: "host=db sslmode=allow"}, true},
		{DatabaseConfig{DSN: "postgres://k@db/k?sslmode=prefer"}, true},
		{DatabaseConfig{DSN: "host=db"}, true},           // pgx's default is prefer
		{DatabaseConfig{DSN: "postgres://k@db/k"}, true}, // same, URL form
		// A later sslmode wins, as in pgx.
		{DatabaseConfig{DSN: "postgres://k@db/k?sslmode=verify-full&sslmode=prefer"}, true},
		{DatabaseConfig{DSN: "postgres://k@db/k?sslmode=prefer&sslmode=require"}, false},
		// The TLS modes, and the field-built default (require), are not fallbacks.
		{DatabaseConfig{}, false},
		{DatabaseConfig{SSLMode: "require"}, false},
		{DatabaseConfig{SSLMode: "verify-ca", SSLRootCert: SSLRootCertSystem}, false},
		{DatabaseConfig{SSLMode: "verify-full", SSLRootCert: SSLRootCertSystem}, false},
		{DatabaseConfig{DSN: "host=db sslmode=require"}, false},
		// disable is its own registered setting, not this one.
		{DatabaseConfig{SSLMode: "disable"}, false},
		// pgx upgrades any mode to verify-full with sslrootcert=system.
		{DatabaseConfig{DSN: "host=db sslmode=prefer sslrootcert=system"}, false},
	}
	for _, tc := range cases {
		cfg := &Config{}
		cfg.Storage.Database = tc.d
		assert.Equal(t, tc.inEffect, entry.InEffect(cfg), "ssl_mode=%q dsn=%q", tc.d.SSLMode, tc.d.DSN)
		assert.Equal(t, boolStr(tc.inEffect), entry.Value(cfg), "ssl_mode=%q dsn=%q", tc.d.SSLMode, tc.d.DSN)
	}

	t.Setenv("PGSSLMODE", "allow")
	cfg := &Config{}
	cfg.Storage.Database = DatabaseConfig{DSN: "host=db"}
	assert.True(t, entry.InEffect(cfg), "a dsn with no sslmode runs with PGSSLMODE")
	cfg.Storage.Database = DatabaseConfig{SSLMode: "require"}
	assert.False(t, entry.InEffect(cfg), "a field-built connection states sslmode; PGSSLMODE does not apply")
}
