package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
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
// Error text names settings only and never contains the resolved password. A
// DSN pgx cannot parse is reported with pgx's own error, which redacts any
// password in the DSN on a best-effort basis (the same message the driver gave
// at connect time before).
func ResolvePostgresConnConfig(d *DatabaseConfig) (*pgx.ConnConfig, error) {
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
	return fmt.Sprintf("host=%s port=%s dbname=%s user=%s sslmode=%s",
		host, port, d.Name, d.User, sslMode)
}

func isURLDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// dsnHasPassword reports whether dsn, a connection string pgx accepts, sets a
// non-empty password itself (as opposed to pgx finding one in a passfile). It
// reads the password the way pgx's parseURLSettings / parseKeywordValueSettings
// (pgconn v5.11) do; FuzzResolvePostgresConnConfig_PasswordCannotChangeConnection
// checks it against pgx. It only decides whether the DSN and a configured
// password conflict: the connection always uses pgx's own parse.
func dsnHasPassword(dsn string) bool {
	if isURLDSN(dsn) {
		return urlDSNPassword(dsn) != ""
	}
	return keywordDSNSettings(dsn)["password"] != ""
}

// urlDSNPassword returns the password a postgres:// URL sets: the userinfo
// password, overridden by a password query parameter. The userinfo ends at the
// first '@' found before any '/', even when a '?' or '#' comes first, so
// "postgres://u?x@h/db" has userinfo "u?x" (libpq's lookahead, which pgx
// copies). The query starts at the first '?' after the host list, skipping a
// bracketed IPv6 host; pgx has no '#' fragment.
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
		p = p[i+1:]
	}
	for {
		if strings.HasPrefix(p, "[") {
			end := strings.IndexByte(p, ']')
			if end < 0 {
				return pw
			}
			p = p[end+1:]
		} else if i := strings.IndexAny(p, ":/?,"); i >= 0 {
			p = p[i:]
		} else {
			p = ""
		}
		if strings.HasPrefix(p, ":") {
			if i := strings.IndexAny(p, "/?,"); i >= 0 {
				p = p[i:]
			} else {
				p = ""
			}
		}
		if !strings.HasPrefix(p, ",") {
			break
		}
		p = p[1:]
	}
	if strings.HasPrefix(p, "/") {
		i := strings.IndexByte(p, '?')
		if i < 0 {
			return pw
		}
		p = p[i:]
	}
	query, ok := strings.CutPrefix(p, "?")
	if !ok {
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

const dsnSpace = " \t\n\r\v\f"

// keywordDSNSettings parses a libpq keyword/value connection string as pgx's
// parseKeywordValueSettings does: whitespace (space, \t, \n, \r, \v, \f)
// separates pairs, values are optionally single-quoted, a backslash escapes
// the next character (a trailing one is dropped), and the last occurrence of
// a key wins. Malformed input yields the settings parsed so far; callers only
// pass strings pgx accepted.
func keywordDSNSettings(s string) map[string]string {
	settings := map[string]string{}
	s = strings.TrimLeft(s, dsnSpace)
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return settings
		}
		key := strings.Trim(s[:eq], dsnSpace)
		s = strings.TrimLeft(s[eq+1:], dsnSpace)
		var val string
		switch {
		case len(s) == 0:
		case s[0] != '\'':
			end := 0
			for ; end < len(s); end++ {
				if strings.IndexByte(dsnSpace, s[end]) >= 0 {
					break
				}
				if s[end] == '\\' {
					end++
					if end == len(s) {
						break
					}
				}
			}
			val = unescapeDSNValue(s[:end])
			s = strings.TrimLeft(s[end:], dsnSpace)
		default:
			s = s[1:]
			end := 0
			for ; end < len(s); end++ {
				if s[end] == '\'' {
					break
				}
				if s[end] == '\\' {
					end++
				}
			}
			if end >= len(s) {
				return settings // unterminated quote
			}
			val = unescapeDSNValue(s[:end])
			s = strings.TrimLeft(s[end+1:], dsnSpace)
		}
		settings[key] = val
	}
	return settings
}

// unescapeDSNValue drops each backslash and keeps the character after it,
// as libpq does.
func unescapeDSNValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
