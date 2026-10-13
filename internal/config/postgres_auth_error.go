package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresAuthError is the one startup error an operator sees when Postgres
// refuses the configured credentials. It names what to check (database user and
// password source) and the host:port, and never the password or the DSN. The
// driver's own error stays reachable through Unwrap (errors.Is / errors.As keep
// working) and Detail returns its text with secrets redacted, for debug logs.
type PostgresAuthError struct {
	// ClosedDuringStartup is true when the server (or a proxy in front of it)
	// dropped the connection while authenticating instead of sending an error
	// (see ClassifyPostgresConnectError for the heuristic); false when the server
	// answered with an authentication SQLSTATE.
	ClosedDuringStartup bool
	Host, Port, User    string

	cause  error
	detail string
}

const postgresAuthCheck = "Check the database user (storage.database.user, or the user in storage.database.dsn) " +
	"and the password source: KEYORIX_DB_PASSWORD, KEYORIX_DB_PASSWORD_FILE, storage.database.password, " +
	"or the password in storage.database.dsn"

func (e *PostgresAuthError) Error() string {
	target := net.JoinHostPort(e.Host, e.Port)
	if e.ClosedDuringStartup {
		return fmt.Sprintf("postgres at %s closed the connection while authenticating user %q: this is how Postgres, "+
			"or a proxy or pooler in front of it, usually reports rejected credentials or a missing pg_hba.conf entry. %s",
			target, e.User, postgresAuthCheck)
	}
	return fmt.Sprintf("postgres authentication failed for user %q at %s: the server rejected the credentials. %s",
		e.User, target, postgresAuthCheck)
}

func (e *PostgresAuthError) Unwrap() error { return e.cause }

// Detail is the driver's error text with the password and the DSN removed.
func (e *PostgresAuthError) Detail() string { return e.detail }

// ClassifyPostgresConnectError turns a Postgres connection failure into a
// *PostgresAuthError when it is an authentication failure, and returns err
// unchanged otherwise (including nil). dsn is the resolved DSN the connection
// used; it is only parsed for host, port, user and the secrets to redact, and
// never appears in the result.
//
// Two shapes count as an authentication failure:
//
//  1. The server answered with an ErrorResponse whose SQLSTATE is 28P01
//     (invalid_password) or 28000 (invalid_authorization_specification, which
//     includes "no pg_hba.conf entry"). Exact, by pgconn.PgError code.
//
//  2. Heuristic: the connection was established and then ended during the
//     startup/authentication exchange with a reset or EOF instead of an
//     ErrorResponse. Postgres itself sends an ErrorResponse before closing, but
//     proxies and poolers (and some TLS terminators) just drop the socket when a
//     login is refused, and the driver then reports "connection reset by peer".
//     pgconn does not export a type for the connection phase, so the phase is
//     read from the driver's message prefix ("failed to receive message" /
//     "failed to write startup message", both produced only after the TCP and TLS
//     setup succeeded) combined with the cause being ECONNRESET, EPIPE, EOF or
//     unexpected EOF. A dial failure ("dial error", connection refused, timeout)
//     and a TLS failure never match. The cost of a false positive is a message
//     that names the credentials as the likely cause of a connection the server
//     dropped at startup; the original error is kept either way.
func ClassifyPostgresConnectError(err error, dsn string) error {
	closed, ok := isPostgresAuthFailure(err)
	if !ok {
		return err
	}
	var host, port, user string
	var secrets []string
	if dsn != "" {
		secrets = append(secrets, dsn)
	}
	if pc, perr := pgconn.ParseConfig(dsn); perr == nil {
		host, user = pc.Host, pc.User
		if pc.Port != 0 {
			port = fmt.Sprint(pc.Port)
		}
		if pc.Password != "" {
			secrets = append(secrets, pc.Password)
		}
	}
	return newPostgresAuthError(err, closed, host, port, user, secrets)
}

// ClassifyPostgresConnectErrorConfig is ClassifyPostgresConnectError for a
// connection opened from a parsed config (ResolvePostgresConnConfig): host,
// port and user come from cc, and cc's password is redacted from Detail.
func ClassifyPostgresConnectErrorConfig(err error, cc *pgx.ConnConfig) error {
	closed, ok := isPostgresAuthFailure(err)
	if !ok {
		return err
	}
	var host, port, user string
	var secrets []string
	if cc != nil {
		host, user = cc.Host, cc.User
		if cc.Port != 0 {
			port = fmt.Sprint(cc.Port)
		}
		if cc.Password != "" {
			secrets = append(secrets, cc.Password)
		}
	}
	return newPostgresAuthError(err, closed, host, port, user, secrets)
}

// isPostgresAuthFailure reports whether err is one of the two authentication
// failure shapes ClassifyPostgresConnectError documents, and which one.
func isPostgresAuthFailure(err error) (closed, ok bool) {
	if err == nil {
		return false, false
	}
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		return false, pgErr.Code == "28P01" || pgErr.Code == "28000"
	case closedDuringStartup(err):
		return true, true
	default:
		return false, false
	}
}

func newPostgresAuthError(err error, closed bool, host, port, user string, secrets []string) *PostgresAuthError {
	out := &PostgresAuthError{ClosedDuringStartup: closed, Host: "the configured host", Port: "5432", User: user, cause: err}
	if host != "" {
		out.Host = host
	}
	if port != "" {
		out.Port = port
	}
	out.detail = redactSecrets(err.Error(), secrets...)
	return out
}

func closedDuringStartup(err error) bool {
	var ce *pgconn.ConnectError
	if !errors.As(err, &ce) {
		return false
	}
	msg := err.Error()
	if !strings.Contains(msg, "failed to receive message") && !strings.Contains(msg, "failed to write startup message") {
		return false
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// redactSecrets removes every occurrence of each non-empty secret from s,
// longest first so a password that is a substring of the DSN cannot leave part
// of the DSN behind.
func redactSecrets(s string, secrets ...string) string {
	for len(secrets) > 0 {
		longest := 0
		for i, v := range secrets {
			if len(v) > len(secrets[longest]) {
				longest = i
			}
		}
		if v := secrets[longest]; v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
		secrets = append(secrets[:longest], secrets[longest+1:]...)
	}
	return s
}
