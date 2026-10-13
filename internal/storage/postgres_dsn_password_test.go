package storage

import (
	"database/sql"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/require"
)

// TestPostgresDSN_PasswordFromEnvReachesRealServer is the #3151 end-to-end
// proof against a real Postgres: a DSN with NO password plus
// KEYORIX_DB_PASSWORD must authenticate (before the fix the env var was
// silently dropped and the server rejected the connection), a wrong env
// password must fail, and a DSN password plus an env password must be refused
// before any connection is attempted. Skips without a URL-form
// KEYORIX_TEST_PG_DSN carrying a password.
func TestPostgresDSN_PasswordFromEnvReachesRealServer(t *testing.T) {
	raw := os.Getenv("KEYORIX_TEST_PG_DSN")
	if raw == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		t.Skip("KEYORIX_TEST_PG_DSN is not a postgres:// URL with credentials")
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		t.Skip("KEYORIX_TEST_PG_DSN carries no password")
	}
	noPw := *u
	noPw.User = url.User(u.User.Username())

	ping := func(t *testing.T, d *config.DatabaseConfig) error {
		t.Helper()
		dsn, err := config.ResolvePostgresDSN(d)
		if err != nil {
			return err
		}
		db, err := sql.Open("pgx", dsn)
		require.NoError(t, err)
		defer db.Close() //nolint:errcheck
		return db.Ping()
	}

	t.Run("env password applied to password-less DSN", func(t *testing.T) {
		t.Setenv("KEYORIX_DB_PASSWORD", pw)
		require.NoError(t, ping(t, &config.DatabaseConfig{DSN: noPw.String()}))
	})
	t.Run("wrong env password is rejected by the server", func(t *testing.T) {
		t.Setenv("KEYORIX_DB_PASSWORD", pw+"-wrong")
		require.Error(t, ping(t, &config.DatabaseConfig{DSN: noPw.String()}))
	})
	t.Run("DSN password plus env password refused before connecting", func(t *testing.T) {
		t.Setenv("KEYORIX_DB_PASSWORD", pw)
		err := ping(t, &config.DatabaseConfig{DSN: raw})
		require.Error(t, err)
		require.Contains(t, err.Error(), "KEYORIX_DB_PASSWORD")
		require.NotContains(t, err.Error(), pw)
	})
}
