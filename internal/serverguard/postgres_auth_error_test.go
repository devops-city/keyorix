package serverguard

import (
	"errors"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/require"
)

// The server's very first database contact at startup is the presence lock; a
// wrong Postgres password there must surface the one clear auth error, with
// no password or DSN in it. Real Postgres; skips without a URL-form
// KEYORIX_TEST_PG_DSN carrying a password.
func TestAcquirePresence_WrongPostgresPassword_ClearError(t *testing.T) {
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

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = bad.String()

	for name, acquire := range map[string]func() error{
		"presence":  func() error { _, err := AcquirePresence(cfg); return err },
		"exclusive": func() error { _, err := AcquireExclusive(cfg); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := acquire()
			require.Error(t, err)
			var ae *config.PostgresAuthError
			require.True(t, errors.As(err, &ae), "want PostgresAuthError, got: %v", err)
			require.Contains(t, err.Error(), net.JoinHostPort(u.Hostname(), u.Port()))
			require.Contains(t, err.Error(), "KEYORIX_DB_PASSWORD")
			require.NotContains(t, err.Error(), wrong)
			require.NotContains(t, err.Error(), bad.String())
			require.NotContains(t, ae.Detail(), wrong)
		})
	}
}
