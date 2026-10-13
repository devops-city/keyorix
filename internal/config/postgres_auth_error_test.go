package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const authTestPassword = "s3cret-pw-Zq9"

// connectTo runs a real pgconn.Connect against addr and returns the driver's
// own error, so the classifier is exercised on genuine pgx error chains.
func connectTo(t *testing.T, addr string) (string, error) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	dsn := fmt.Sprintf("host=%s port=%s user=keyorix password=%s dbname=keyorix sslmode=disable connect_timeout=3", host, port, authTestPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgconn.Connect(ctx, dsn)
	if err == nil {
		_ = conn.Close(ctx)
		t.Fatal("connect unexpectedly succeeded")
	}
	return dsn, err
}

// startupDropper accepts one connection, reads the startup packet, then drops
// the socket the way a proxy does on a refused login: with a TCP reset
// (reset=true) or a plain close (reset=false).
func startupDropper(t *testing.T, reset bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Read(buf)
		if tc, ok := c.(*net.TCPConn); ok && reset {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	}()
	return ln.Addr().String()
}

func TestClassifyPostgresConnectError_ClosedDuringStartup(t *testing.T) {
	for _, reset := range []bool{true, false} {
		t.Run(fmt.Sprintf("reset=%v", reset), func(t *testing.T) {
			addr := startupDropper(t, reset)
			dsn, driverErr := connectTo(t, addr)
			t.Logf("driver error: %v", driverErr)

			got := ClassifyPostgresConnectError(driverErr, dsn)
			var ae *PostgresAuthError
			require.True(t, errors.As(got, &ae), "want PostgresAuthError, got %T: %v", got, got)
			require.True(t, ae.ClosedDuringStartup)
			require.Equal(t, "keyorix", ae.User)
			msg := got.Error()
			require.Contains(t, msg, addr)
			require.Contains(t, msg, "KEYORIX_DB_PASSWORD")
			require.Contains(t, msg, "KEYORIX_DB_PASSWORD_FILE")
			require.Contains(t, msg, "storage.database.dsn")
			require.NotContains(t, msg, authTestPassword)
			require.NotContains(t, msg, dsn)
			require.NotContains(t, ae.Detail(), authTestPassword)
			require.NotContains(t, ae.Detail(), dsn)
			// The original error stays reachable for debugging.
			require.Equal(t, driverErr, errors.Unwrap(got))
		})
	}
}

func TestClassifyPostgresConnectError_NotAuthIsUnchanged(t *testing.T) {
	// Connection refused: a dial failure must never be reported as bad credentials.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	dsn, refused := connectTo(t, addr)
	require.Same(t, refused, ClassifyPostgresConnectError(refused, dsn))

	// Errors that are not authentication failures pass through untouched.
	for name, e := range map[string]error{
		"nil":                nil,
		"plain":              errors.New("boom"),
		"eof outside driver": io.EOF,
		"non-auth sqlstate":  fmt.Errorf("open: %w", &pgconn.PgError{Code: "3D000", Message: "database does not exist"}),
		"too many clients":   &pgconn.PgError{Code: "53300"},
	} {
		t.Run(name, func(t *testing.T) {
			got := ClassifyPostgresConnectError(e, "host=h user=u password=p")
			if e == nil {
				require.NoError(t, got)
				return
			}
			require.Equal(t, e, got)
		})
	}
}

func TestClassifyPostgresConnectError_RejectedSQLState(t *testing.T) {
	for _, code := range []string{"28P01", "28000"} {
		t.Run(code, func(t *testing.T) {
			dsn := "postgres://appuser:" + authTestPassword + "@db.internal:6543/keyorix?sslmode=require"
			orig := fmt.Errorf("failed to connect to `user=appuser database=keyorix`: db.internal:6543: server error: %w",
				&pgconn.PgError{Severity: "FATAL", Code: code, Message: "password authentication failed for user \"appuser\" " + authTestPassword})
			got := ClassifyPostgresConnectError(orig, dsn)

			var ae *PostgresAuthError
			require.True(t, errors.As(got, &ae))
			require.False(t, ae.ClosedDuringStartup)
			require.Equal(t, "appuser", ae.User)
			require.Equal(t, "db.internal", ae.Host)
			require.Equal(t, "6543", ae.Port)
			msg := got.Error()
			require.Contains(t, msg, "db.internal:6543")
			require.Contains(t, msg, `"appuser"`)
			require.Contains(t, msg, "rejected the credentials")
			require.NotContains(t, msg, authTestPassword)
			require.NotContains(t, msg, dsn)
			require.NotContains(t, ae.Detail(), authTestPassword)
			require.Contains(t, ae.Detail(), code)
			// errors.As still reaches the driver's PgError through the wrapper.
			var pe *pgconn.PgError
			require.True(t, errors.As(got, &pe))
			require.Equal(t, code, pe.Code)
		})
	}
}

func TestRedactSecrets_LongestFirst(t *testing.T) {
	dsn := "host=h password=abc"
	got := redactSecrets("failed "+dsn+" and abc", "abc", dsn)
	require.Equal(t, "failed [redacted] and [redacted]", got)
	require.False(t, strings.Contains(got, "abc"))
}
