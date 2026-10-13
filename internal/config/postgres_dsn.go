package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ResolvePostgresConnConfig returns the parsed PostgreSQL connection config,
// applying the password precedence documented in docs/CONFIGURATION.md
// ("storage"):
//
//   - storage.database.dsn empty: the connection is built from the host/port/
//     name/user/ssl_mode fields and the resolved password (KEYORIX_DB_PASSWORD,
//     or KEYORIX_DB_PASSWORD_FILE, or storage.database.password).
//   - dsn set and carrying no password: the resolved password is used with it.
//   - dsn set and already carrying a password, while a password is ALSO
//     configured through any of those three sources: an error. Keyorix does not
//     guess which of two credentials the operator meant (the same "no silent
//     precedence" rule as X vs X_FILE in resolveSecret).
//   - dsn set with a password and no other source: used as-is.
//
// The resolved password never becomes part of a connection string. The
// operator's DSN (or the field-built one, which carries no password) is parsed
// by pgx -- the parser the driver itself uses -- and the password is set on the
// parsed config. Host, port, sslmode, sslrootcert and every other setting are
// therefore exactly what pgx reads from the configured string, whatever bytes
// the password holds. Splicing the password into the string (#3159) let a
// password, or a DSN shape the splice read differently from pgx, move the host
// or turn TLS off (REVIEW-3162B). Callers open the connection from this config
// (stdlib.OpenDB), never from a re-serialised string.
//
// ValidateDatabaseTLS runs first and its error is returned instead of a config,
// so no caller can open a connection whose TLS trust the config does not name
// (verify-full with no CA, an unusable CA file). Then, as defence in depth,
// checkFinalPostgresTLS re-reads the FINAL config -- what the driver will
// actually use -- and refuses it unless its TLS (sslmode, CA, host name) is
// what the check validated. That catches any drift between the check's own
// DSN reader and pgx, the class REVIEW-3162B found.
//
// Error text names settings only and never contains the resolved password. A
// DSN pgx cannot parse is reported with pgx's own error, which redacts any
// password in the DSN on a best-effort basis (the same message the driver gave
// at connect time before).
func ResolvePostgresConnConfig(d *DatabaseConfig) (*pgx.ConnConfig, error) {
	if err := ValidateDatabaseTLS(d); err != nil {
		return nil, err
	}
	pw := d.GetPassword()
	dsn := d.DSN
	if dsn == "" {
		dsn = buildPostgresDSNFromFields(d)
	}
	// Parsed before the conflict check below, so that check only ever reads
	// a DSN pgx accepts. The resolved password is not in dsn, so a parse
	// error cannot quote it.
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("storage.database: invalid PostgreSQL connection settings: %w", err)
	}
	if d.DSN != "" && pw != "" && dsnHasPassword(d.DSN) {
		src := d.passwordSourceName()
		return nil, fmt.Errorf("storage.database.dsn already contains a password and %s is also set; "+
			"refusing to guess which one to use. Fix: remove the password from storage.database.dsn "+
			"(and keep %s), or unset %s", src, src, src)
	}
	if pw != "" {
		// Applies to every fallback host too: pgconn keeps one Password for
		// the primary and all Fallbacks. It also wins over a ~/.pgpass entry
		// pgx may have filled in, as an explicit password does in libpq.
		cc.Password = pw
	}
	if err := checkFinalPostgresTLS(d, cc); err != nil {
		return nil, err
	}
	return cc, nil
}

// passwordSourceName names the configured password source for error messages:
// the environment variable, its _FILE form, or the YAML key.
func (d *DatabaseConfig) passwordSourceName() string {
	switch {
	case envSet("KEYORIX_DB_PASSWORD_FILE"):
		return "KEYORIX_DB_PASSWORD_FILE"
	case envSet("KEYORIX_DB_PASSWORD"):
		return "KEYORIX_DB_PASSWORD"
	default:
		return "storage.database.password"
	}
}

func envSet(name string) bool { return os.Getenv(name) != "" }

// buildPostgresDSNFromFields builds the keyword/value DSN for the field form.
// It never carries the password: ResolvePostgresConnConfig sets that on the
// parsed config.
func buildPostgresDSNFromFields(d *DatabaseConfig) string {
	host := d.Host
	if host == "" {
		host = "localhost"
	}
	port := d.Port
	if port == "" {
		port = "5432"
	}
	sslMode := d.SSLMode
	if sslMode == "" {
		sslMode = "require"
	}
	// Every value is quoted: unquoted, a space in any field would start a new
	// keyword, and a later sslmode/sslrootcert/host overrides the one validated.
	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s sslmode=%s",
		quoteDSNValue(host), quoteDSNValue(port), quoteDSNValue(d.Name), quoteDSNValue(d.User), quoteDSNValue(sslMode))
	if d.SSLRootCert != "" {
		dsn += " sslrootcert=" + quoteDSNValue(d.SSLRootCert)
	}
	return dsn
}

func isURLDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// dsnHasPassword reports whether dsn, a connection string pgx accepts, sets a
// non-empty password itself (as opposed to pgx finding one in a passfile). It
// reads the password the way pgx's parseURLSettings / parseKeywordValueSettings
// (pgconn v5.11) do, with the same readers the TLS check uses
// (parseKeywordValueDSN, urlQuery);
// FuzzResolvePostgresConnConfig_PasswordCannotChangeConnection checks it
// against pgx. It only decides whether the DSN and a configured password
// conflict: the connection always uses pgx's own parse.
func dsnHasPassword(dsn string) bool {
	if isURLDSN(dsn) {
		return urlDSNPassword(dsn) != ""
	}
	settings, err := parseKeywordValueDSN(dsn)
	return err == nil && settings["password"] != ""
}

// urlDSNPassword returns the password a postgres:// URL sets: the userinfo
// password, overridden by a password query parameter. The userinfo ends at the
// first '@' found before any '/', even when a '?' or '#' comes first, so
// "postgres://u?x@h/db" has userinfo "u?x" (libpq's lookahead, which pgx
// copies); urlQuery finds the query the same way pgx does.
func urlDSNPassword(dsn string) string {
	p, ok := strings.CutPrefix(dsn, "postgresql://")
	if !ok {
		p, _ = strings.CutPrefix(dsn, "postgres://")
	}
	var pw string
	if i := strings.IndexAny(p, "@/"); i >= 0 && p[i] == '@' {
		if _, raw, ok := strings.Cut(p[:i], ":"); ok {
			pw = uriDecodeLoose(raw)
		}
	}
	query, err := urlQuery(dsn)
	if err != nil {
		return pw
	}
	for _, pair := range strings.Split(query, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if uriDecodeLoose(k) == "password" {
			pw = uriDecodeLoose(v)
		}
	}
	return pw
}

// uriDecodeLoose percent-decodes a URI component of a URL pgx has already
// accepted, as pgx's uriDecode does: leading and trailing spaces dropped,
// '+' literal.
func uriDecodeLoose(s string) string {
	s = strings.Trim(s, " ")
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

// checkFinalPostgresTLS is the defence-in-depth half of ResolvePostgresConnConfig:
// it reads the TLS settings off the FINAL pgx config -- the one the driver
// connects with -- and refuses it unless they are what ValidateDatabaseTLS
// validated from storage.database (its own reading of the dsn, or the fields):
//
//   - validated as verifying (verify-full, verify-ca, sslrootcert=system, or
//     require with a CA): the primary host and every fallback use TLS (no
//     plaintext fallback), verify the server's chain, trust exactly the
//     validated CA pool (the file, re-read now; or the OS pool for "system"),
//     and for verify-full check the host name against that same host;
//   - validated as require (no CA): every candidate uses TLS.
//
// In every mode, the host(s), port(s), database and user must be pgx's reading
// of the validated connection string alone (storage.database.dsn, or the
// field-built one): verify-full against sslrootcert=system checks the host
// name it is given, so a moved host would still "verify". Modes that
// verify nothing (prefer, allow, disable) make no TLS claim. A Unix-domain
// socket candidate (a host starting with '/') is not checked for TLS: it is
// local, and neither libpq nor pgx uses TLS on it. Errors name
// settings, never the DSN or the password.
func checkFinalPostgresTLS(d *DatabaseConfig, cc *pgx.ConnConfig) error {
	validated := d.DSN
	if validated == "" {
		validated = buildPostgresDSNFromFields(d)
	}
	ref, err := pgconn.ParseConfig(validated)
	if err != nil {
		return fmt.Errorf("storage.database: invalid PostgreSQL connection settings: %w", err)
	}
	if cc.Host != ref.Host || cc.Port != ref.Port || cc.Database != ref.Database || cc.User != ref.User ||
		len(cc.Fallbacks) != len(ref.Fallbacks) {
		return finalTLSMismatch("the host, port, database or user is not the configured one")
	}
	for i, fb := range ref.Fallbacks {
		if cc.Fallbacks[i].Host != fb.Host || cc.Fallbacks[i].Port != fb.Port {
			return finalTLSMismatch("a fallback host is not the configured one")
		}
	}
	mode, rootCert := d.effectiveSSLMode(), d.SSLRootCert
	if d.DSN != "" {
		var err error
		if mode, rootCert, err = dsnTLSSettings(d.DSN); err != nil {
			return fmt.Errorf("storage.database.dsn: %w", err)
		}
		if mode == "" {
			mode = os.Getenv("PGSSLMODE")
		}
	}
	if rootCert == SSLRootCertSystem {
		mode = "verify-full" // pgx, like libpq, upgrades any sslmode
	}
	verifies := sslModeVerifies(mode) || (mode == "require" && rootCert != "")
	if !verifies && mode != "require" {
		return nil
	}
	var wantPool *x509.CertPool
	if verifies && rootCert != SSLRootCertSystem {
		pool, _, err := LoadDatabaseCAPool(rootCert)
		if err != nil {
			return fmt.Errorf("storage.database: CA file re-check: %w", err)
		}
		wantPool = pool
	}
	type candidate struct {
		host string
		tls  *tls.Config
	}
	cands := []candidate{{cc.Host, cc.TLSConfig}}
	for _, fb := range cc.Fallbacks {
		cands = append(cands, candidate{fb.Host, fb.TLSConfig})
	}
	for _, c := range cands {
		if network, _ := pgconn.NetworkAddress(c.host, cc.Port); network == "unix" {
			continue // a Unix-domain socket: local, and never TLS (libpq and pgx alike)
		}
		switch {
		case c.tls == nil:
			return finalTLSMismatch("a connection attempt would not use TLS")
		case !verifies:
			continue
		case c.tls.InsecureSkipVerify && c.tls.VerifyPeerCertificate == nil:
			return finalTLSMismatch("the server certificate would not be verified")
		case c.tls.RootCAs == nil:
			return finalTLSMismatch("no CA pool is set")
		case wantPool != nil && !wantPool.Equal(c.tls.RootCAs):
			return finalTLSMismatch("the CA pool is not the validated CA file")
		case mode == "verify-full" && (c.tls.InsecureSkipVerify || c.tls.ServerName != c.host):
			return finalTLSMismatch("the host name would not be verified")
		}
	}
	return nil
}

func finalTLSMismatch(what string) error {
	return fmt.Errorf("storage.database: the PostgreSQL driver's connection settings differ from what the TLS "+
		"check validated (%s) -- refusing to start. Write sslmode and sslrootcert plainly in storage.database "+
		"(or the dsn) so both read them the same way", what)
}
