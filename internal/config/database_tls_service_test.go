package config

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A PostgreSQL connection-service file is merged by pgx over the environment
// and under the connection string, so it can supply sslmode=verify-full with no
// sslrootcert (pgx then verifies against its implicit trust store) or point
// sslrootcert at a file the checks never open. The checks read only the dsn
// and ssl_* fields, so a selected service is refused instead.

// writeServiceFile writes a service file whose [svc] section turns on
// certificate verification without naming a CA, and points pgx at it.
func writeServiceFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pg_service.conf")
	require.NoError(t, os.WriteFile(p, []byte("[svc]\nhost=db.internal\nsslmode=verify-full\n"), 0o600))
	return p
}

func TestValidateDatabaseTLS_ConnectionServiceIsRefused(t *testing.T) {
	clearPGEnv(t)
	sf := writeServiceFile(t)

	cases := []struct {
		name string
		env  map[string]string
		d    *DatabaseConfig
	}{
		{"dsn keyword service=", map[string]string{"PGSERVICEFILE": sf}, &DatabaseConfig{DSN: "user=u dbname=k service=svc"}},
		{"dsn keyword empty service=", nil, &DatabaseConfig{DSN: "user=u dbname=k service=''"}},
		{"dsn keyword servicefile=", nil, &DatabaseConfig{DSN: "user=u dbname=k service=svc servicefile=" + quoteDSNValue(sf)}},
		{"dsn url ?service=", map[string]string{"PGSERVICEFILE": sf}, &DatabaseConfig{DSN: "postgres://u@db.internal/k?service=svc"}},
		{"dsn url ?servicefile=", nil, &DatabaseConfig{DSN: "postgres://u@db.internal/k?service=svc&servicefile=" + url.QueryEscape(sf)}},
		{"dsn url percent-encoded key", map[string]string{"PGSERVICEFILE": sf}, &DatabaseConfig{DSN: "postgres://u@db.internal/k?servic%65=svc"}},
		{"PGSERVICE with dsn", map[string]string{"PGSERVICE": "svc", "PGSERVICEFILE": sf}, &DatabaseConfig{DSN: "user=u dbname=k host=db.internal"}},
		{"PGSERVICE with fields", map[string]string{"PGSERVICE": "svc", "PGSERVICEFILE": sf}, pgFields("require", "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			err := ValidateDatabaseTLS(tc.d)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "connection service")
			assert.NotContains(t, err.Error(), "svc", "service and file names stay out of the error")

			cc, err := ResolvePostgresConnConfig(tc.d)
			require.Error(t, err, "ResolvePostgresConnConfig is the guard every connection goes through")
			assert.Nil(t, cc)
		})
	}
}

// The bypass the refusal closes: with this service file pgx verifies the
// server certificate, while the config names no CA at all.
func TestConnectionService_PgxVerifiesWhatTheConfigNeverNamed(t *testing.T) {
	clearPGEnv(t)
	t.Setenv("PGSERVICEFILE", writeServiceFile(t))
	pc, err := pgconn.ParseConfig("user=u dbname=k service=svc")
	require.NoError(t, err)
	require.NotNil(t, pc.TLSConfig)
	assert.False(t, pc.TLSConfig.InsecureSkipVerify, "the service file turned verify-full on")
	assert.Equal(t, "db.internal", pc.Host, "and chose the host")
}

// Neither a service file path alone nor a service-free dsn is affected.
func TestValidateDatabaseTLS_ServiceFileAloneIsInert(t *testing.T) {
	clearPGEnv(t)
	t.Setenv("PGSERVICEFILE", writeServiceFile(t))
	// pgx reads the file only when a service is selected.
	assert.NoError(t, ValidateDatabaseTLS(&DatabaseConfig{DSN: "host=db user=u dbname=k sslmode=require"}))
	assert.NoError(t, ValidateDatabaseTLS(pgFields("require", "")))
	pc, err := pgconn.ParseConfig("host=db user=u dbname=k sslmode=require")
	require.NoError(t, err)
	assert.Equal(t, "db", pc.Host)
	// A key that merely contains the word is not the service key.
	assert.NoError(t, ValidateDatabaseTLS(&DatabaseConfig{DSN: "host=db user=u dbname=k sslmode=require application_name=service"}))
	assert.NoError(t, ValidateDatabaseTLS(&DatabaseConfig{DSN: "postgres://u@db/k?sslmode=require&application_name=service%3Dx"}))
}
