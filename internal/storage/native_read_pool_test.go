package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestNativeReadPool_UsesTheResolvedConnConfig: the native read pool connects
// with exactly the connection config every other pool gets from
// config.ResolvePostgresConnConfig (the parsed DSN, the password set on it, the
// TLS settings), and it is sized and aged like the factory says. No server
// needed: the pool does not dial until first use.
func TestNativeReadPool_UsesTheResolvedConnConfig(t *testing.T) {
	d := &config.DatabaseConfig{
		DSN:                    "host=db.invalid port=5439 user=kx dbname=keyorix sslmode=disable search_path=kx TimeZone=Europe/Berlin",
		Password:               `p@ss word\' host=evil.invalid`,
		ConnMaxLifetimeMinutes: 7,
	}
	want, err := config.ResolvePostgresConnConfig(d)
	require.NoError(t, err)

	pool, err := openPostgresNativeReadPool(d, nativeReadPoolSize(DefaultPostgresMaxOpenConns))
	require.NoError(t, err)
	defer pool.Close()
	got := pool.Config()

	require.Equal(t, want.Host, got.ConnConfig.Host)
	require.Equal(t, want.Port, got.ConnConfig.Port)
	require.Equal(t, want.Database, got.ConnConfig.Database)
	require.Equal(t, want.User, got.ConnConfig.User)
	require.Equal(t, want.Password, got.ConnConfig.Password)
	require.Equal(t, `p@ss word\' host=evil.invalid`, got.ConnConfig.Password, "the password is set, never parsed")
	require.Equal(t, want.TLSConfig, got.ConnConfig.TLSConfig)
	require.Equal(t, want.RuntimeParams, got.ConnConfig.RuntimeParams)
	require.Equal(t, want.Fallbacks, got.ConnConfig.Fallbacks)
	require.Equal(t, want.DefaultQueryExecMode, got.ConnConfig.DefaultQueryExecMode, "pgx's statement cache, as the request pool")
	require.Equal(t, want.StatementCacheCapacity, got.ConnConfig.StatementCacheCapacity)
	require.NotNil(t, got.AfterConnect, "the DSN's time zone is applied to timestamp scans, as on the request pool")

	require.EqualValues(t, NativeReadPoolMaxSize, got.MaxConns)
	require.Zero(t, got.MinConns, "no connection until first use")
	require.Equal(t, 7*time.Minute, got.MaxConnLifetime)
	require.Equal(t, 4, nativeReadPoolSize(4), "never more than the request pool")
}
