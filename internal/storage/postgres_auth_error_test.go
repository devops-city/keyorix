package storage

import (
	"errors"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/require"
)

// TestPostgresWrongPassword_ClearStartupError drives a REAL Postgres with a wrong
// password through every storage open path and requires the one clear
// config.PostgresAuthError: it names the host:port and the setting to check, never
// the password or the DSN, and keeps the server's SQLSTATE 28P01 reachable.
// Skips without a URL-form KEYORIX_TEST_PG_DSN carrying a password.
func TestPostgresWrongPassword_ClearStartupError(t *testing.T) {
	raw := os.Getenv("KEYORIX_TEST_PG_DSN")
	if raw == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		t.Skip("KEYORIX_TEST_PG_DSN is not a postgres:// URL with credentials")
	}
	if pw, _ := u.User.Password(); pw == "" {
		t.Skip("KEYORIX_TEST_PG_DSN carries no password")
	}
	const wrong = "definitely-wrong-pw-Xk7"
	bad := *u
	bad.User = url.UserPassword(u.User.Username(), wrong)
	badDSN := bad.String()

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = badDSN
	hostPort := net.JoinHostPort(u.Hostname(), u.Port())

	check := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		var ae *config.PostgresAuthError
		require.True(t, errors.As(err, &ae), "want PostgresAuthError, got: %v", err)
		msg := err.Error()
		require.Contains(t, msg, hostPort)
		require.Contains(t, msg, u.User.Username())
		require.Contains(t, msg, "KEYORIX_DB_PASSWORD")
		require.NotContains(t, msg, wrong)
		require.NotContains(t, msg, badDSN)
		require.NotContains(t, ae.Detail(), wrong)
		var pe *pgconn.PgError
		require.True(t, errors.As(err, &pe), "driver error must stay wrapped")
		require.Equal(t, "28P01", pe.Code)
	}

	t.Run("CreateStorage", func(t *testing.T) {
		_, err := NewStorageFactory().CreateStorage(cfg)
		check(t, err)
	})
	t.Run("OpenGormDB", func(t *testing.T) {
		_, err := OpenGormDB(cfg)
		check(t, err)
	})
}
