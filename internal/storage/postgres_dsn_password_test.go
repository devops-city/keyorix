package storage

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
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
		cc, err := config.ResolvePostgresConnConfig(d)
		if err != nil {
			return err
		}
		db := stdlib.OpenDB(*cc)
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

// TestPostgresDSN_InjectionPasswordReachesRealServer is REVIEW-3162B problem 2
// against a real server: a role whose password is the reviewer's keyword-
// injection payload logs in through a keyword DSN that ends in a backslash.
// Before the fix the password's contents became keywords (host=evil). Skips
// without KEYORIX_TEST_PG_DSN or without CREATE ROLE privilege; the role is
// dropped afterwards.
func TestPostgresDSN_InjectionPasswordReachesRealServer(t *testing.T) {
	raw := os.Getenv("KEYORIX_TEST_PG_DSN")
	if raw == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	admin, err := sql.Open("pgx", raw)
	require.NoError(t, err)
	defer admin.Close()                 //nolint:errcheck
	target, err := pgx.ParseConfig(raw) // URL or keyword/value form
	require.NoError(t, err)
	const role = "keyorix_inj_3162"
	const pw = `a sslmode=disable host=evil.invalid x=\`
	if _, err := admin.Exec(`DROP ROLE IF EXISTS ` + role); err != nil {
		t.Skipf("cannot manage roles: %v", err)
	}
	if _, err := admin.Exec(`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + strings.ReplaceAll(pw, "'", "''") + `'`); err != nil {
		t.Skipf("cannot create a role: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP ROLE IF EXISTS ` + role) })

	sslmode := "prefer"
	if target.TLSConfig == nil {
		sslmode = "disable"
	}
	base := fmt.Sprintf("host=%s port=%d dbname=%s user=%s sslmode=%s application_name=x\\",
		target.Host, target.Port, target.Database, role, sslmode)
	t.Setenv("KEYORIX_DB_PASSWORD", pw)
	cc, err := config.ResolvePostgresConnConfig(&config.DatabaseConfig{DSN: base})
	require.NoError(t, err)
	require.Equal(t, target.Host, cc.Host)
	db := stdlib.OpenDB(*cc)
	defer db.Close() //nolint:errcheck
	var who, app string
	require.NoError(t, db.QueryRow(`SELECT current_user, current_setting('application_name')`).Scan(&who, &app))
	require.Equal(t, role, who)
	require.Equal(t, "x", app)
}
