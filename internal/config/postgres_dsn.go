package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ResolvePostgresDSN returns the ready-to-use PostgreSQL DSN, applying the
// password precedence documented in docs/CONFIGURATION.md ("storage"):
//
//   - storage.database.dsn empty: the DSN is built from the host/port/name/user/
//     ssl_mode fields and the resolved password (KEYORIX_DB_PASSWORD, or
//     KEYORIX_DB_PASSWORD_FILE, or storage.database.password).
//   - dsn set and carrying no password: the resolved password is added to it.
//   - dsn set and already carrying a password, while a password is ALSO
//     configured through any of those three sources: an error. Keyorix does not
//     guess which of two credentials the operator meant (the same "no silent
//     precedence" rule as X vs X_FILE in resolveSecret).
//   - dsn set with a password and no other source: used as-is.
//
// Error text names settings only and never contains the password (nor the DSN,
// which may contain one).
func ResolvePostgresDSN(d *DatabaseConfig) (string, error) {
	pw := d.GetPassword()
	if d.DSN == "" {
		return buildPostgresDSNFromFields(d, pw), nil
	}
	if pw == "" {
		// Nothing to apply or conflict with: hand the DSN to the driver
		// untouched, without inspecting (or rejecting) it here.
		return d.DSN, nil
	}
	has, err := dsnHasPassword(d.DSN)
	if err != nil {
		return "", err
	}
	if has {
		src := d.passwordSourceName()
		return "", fmt.Errorf("storage.database.dsn already contains a password and %s is also set; "+
			"refusing to guess which one to use. Fix: remove the password from storage.database.dsn "+
			"(and keep %s), or unset %s", src, src, src)
	}
	return appendDSNPassword(d.DSN, pw)
}

// BuildPostgresDSN is ResolvePostgresDSN for callers that cannot report an
// error. It fails closed: on a conflicting password configuration it returns
// "", which every caller already treats as "no usable DSN". Production code
// should call ResolvePostgresDSN so the operator sees the reason.
func BuildPostgresDSN(d *DatabaseConfig) string {
	dsn, err := ResolvePostgresDSN(d)
	if err != nil {
		return ""
	}
	return dsn
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

func buildPostgresDSNFromFields(d *DatabaseConfig, pw string) string {
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
	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s sslmode=%s",
		host, port, d.Name, d.User, sslMode)
	if pw != "" {
		dsn += " password=" + quoteDSNValue(pw)
	}
	return dsn
}

func isURLDSN(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// urlDSNParts locates the authority of a postgres:// URL DSN without going
// through net/url, which rejects valid pgx forms (multi-host lists such as
// postgres://u@[::1]:5432,[::2]:5433/db) and would re-serialise the string.
// authStart/authEnd delimit the authority; userEnd is the index of the '@'
// that ends the userinfo, or -1 when there is none; query is the raw query
// string (without '?' and any fragment).
func urlDSNParts(dsn string) (authStart, authEnd, userEnd int, query string) {
	authStart = strings.Index(dsn, "://") + len("://")
	rest := dsn[authStart:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authEnd = authStart + end
	userEnd = -1
	if at := strings.LastIndex(dsn[authStart:authEnd], "@"); at >= 0 {
		userEnd = authStart + at
	}
	tail, _, _ := strings.Cut(dsn[authEnd:], "#")
	if _, q, ok := strings.Cut(tail, "?"); ok {
		query = q
	}
	return authStart, authEnd, userEnd, query
}

// dsnHasPassword reports whether dsn (URL or key=value form) carries a
// non-empty password. It never fails; the error result is kept for API
// stability.
func dsnHasPassword(dsn string) (bool, error) {
	if isURLDSN(dsn) {
		authStart, _, userEnd, query := urlDSNParts(dsn)
		if userEnd >= 0 {
			userinfo := dsn[authStart:userEnd]
			if i := strings.Index(userinfo, ":"); i >= 0 && userinfo[i+1:] != "" {
				return true, nil
			}
		}
		// Pairs net/url cannot parse (e.g. containing ';') are dropped by
		// ParseQuery, exactly as pgx drops them.
		vals, _ := url.ParseQuery(query)
		return vals.Get("password") != "", nil
	}
	for _, kv := range parseKeywordDSN(dsn) {
		if kv[0] == "password" && kv[1] != "" {
			return true, nil
		}
	}
	return false, nil
}

// appendDSNPassword adds pw to a DSN that has none. A URL DSN is spliced, not
// re-encoded: every byte except the inserted password is preserved, including
// the order and escaping of the query parameters. The password goes into the
// userinfo, escaped as net/url does for a password (space, @, :, /, ?, #, %
// all percent-encoded).
func appendDSNPassword(dsn, pw string) (string, error) {
	if isURLDSN(dsn) {
		authStart, _, userEnd, _ := urlDSNParts(dsn)
		escaped := url.UserPassword("x", pw).String()[len("x:"):]
		if userEnd < 0 {
			return dsn[:authStart] + ":" + escaped + "@" + dsn[authStart:], nil
		}
		sep := ":"
		if strings.Contains(dsn[authStart:userEnd], ":") {
			sep = "" // "user:" with an empty password
		}
		return dsn[:userEnd] + sep + escaped + dsn[userEnd:], nil
	}
	return strings.TrimRight(dsn, " \t\r\n") + " password=" + quoteDSNValue(pw), nil
}

// quoteDSNValue quotes a libpq key=value value when it needs it (spaces,
// quotes, backslashes, or empty); plain values are returned unchanged.
func quoteDSNValue(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\r\n'\\") {
		return v
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return "'" + v + "'"
}

// parseKeywordDSN splits a libpq key=value connection string into pairs,
// honouring single-quoted values and backslash escapes. Malformed input yields
// the pairs parsed so far; pgx reports the real syntax error at connect time.
func parseKeywordDSN(s string) [][2]string {
	var out [][2]string
	i, n := 0, len(s)
	skipSpace := func() {
		for i < n && strings.ContainsRune(" \t\r\n", rune(s[i])) {
			i++
		}
	}
	for {
		skipSpace()
		start := i
		for i < n && s[i] != '=' && !strings.ContainsRune(" \t\r\n", rune(s[i])) {
			i++
		}
		key := s[start:i]
		skipSpace()
		if key == "" || i >= n || s[i] != '=' {
			return out
		}
		i++ // '='
		skipSpace()
		var val strings.Builder
		if i < n && s[i] == '\'' {
			i++
			for i < n && s[i] != '\'' {
				if s[i] == '\\' && i+1 < n {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
			i++ // closing quote
		} else {
			for i < n && !strings.ContainsRune(" \t\r\n", rune(s[i])) {
				if s[i] == '\\' && i+1 < n {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
		}
		out = append(out, [2]string{key, val.String()})
	}
}
