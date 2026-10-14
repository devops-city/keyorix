package config

// database_tls.go -- server-to-PostgreSQL TLS trust (PG-VERIFYFULL-1).
//
// storage.database.ssl_mode had verify-full but no way to name the CA that
// signed the database server's certificate. pgx then trusts whatever it finds
// on its own -- PGSSLROOTCERT, ~/.postgresql/root.crt of whichever user runs
// the process, or the OS trust store -- so "verify-full" verified against a
// trust set the Keyorix config never stated. storage.database.ssl_root_cert
// names that CA explicitly, and a verifying mode without it refuses to start.

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// SSLRootCertSystem is the ssl_root_cert value that trusts the operating
// system's CA store (libpq's and pgx's own `sslrootcert=system`). It is an
// explicit choice, for a database whose certificate a public CA issued; an
// empty ssl_root_cert never means it.
const SSLRootCertSystem = "system"

// maxDatabaseCAFileBytes bounds how much of a CA file is read. A PEM bundle of
// every public root is well under 1 MiB; anything larger is not a CA file.
const maxDatabaseCAFileBytes = 1 << 20

// resolveConfigRelativeFile anchors a relative file path from the config to
// baseDir (the config file's directory), as resolveConfigRelativePath does for
// database.path, without that function's SQLite-DSN special cases ('?'
// suffixes, in-memory names) that a CA path does not have. A relative path
// containing ".." is refused rather than collapsed into a path outside baseDir.
func resolveConfigRelativeFile(baseDir, p string) (string, error) {
	if filepath.IsAbs(p) {
		return p, nil
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("%q must not contain \"..\"", p)
	}
	return filepath.Abs(filepath.Join(baseDir, p))
}

// effectiveSSLMode is the sslmode ResolvePostgresConnConfig uses for a field-built
// DSN: SSLMode, or "require" when unset.
func (d *DatabaseConfig) effectiveSSLMode() string {
	if d.SSLMode == "" {
		return "require"
	}
	return d.SSLMode
}

// sslModeVerifies reports whether mode makes the client verify the server's
// certificate chain (verify-ca) or chain and host name (verify-full).
func sslModeVerifies(mode string) bool {
	return mode == "verify-full" || mode == "verify-ca"
}

// validSSLModes is every sslmode pgx (and libpq) accepts, weakest first. pgx
// refuses any other value only when it connects ("sslmode is invalid");
// PG-TLS-2 refuses it at config validation instead, with this list in the
// message, so a typo never reaches the insecure-settings registry or the
// posture report as an unknown mode they cannot classify.
var validSSLModes = []string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}

func sslModeValid(mode string) bool {
	return slices.Contains(validSSLModes, mode)
}

// sslModeMayBePlaintext reports whether the driver can run the connection
// unencrypted under mode: disable never encrypts, allow tries plaintext
// first, prefer falls back to plaintext whenever the TLS attempt fails --
// including when anyone on the network path answers the SSLRequest with "no".
func sslModeMayBePlaintext(mode string) bool {
	return mode == "disable" || mode == "allow" || mode == "prefer"
}

func invalidSSLModeError(field string) error {
	return fmt.Errorf("%s is not a valid sslmode; use one of: %s", field, strings.Join(validSSLModes, ", "))
}

// databaseTLS is the TLS setting a PostgreSQL connection built from a
// DatabaseConfig actually runs with, resolved the way pgx resolves it.
type databaseTLS struct {
	// written is the sslmode as configured: ssl_mode (or its "require"
	// default), or the dsn's sslmode, PGSSLMODE, or pgx's "prefer" default.
	written string
	// mode is written after pgx's sslrootcert=system upgrade to verify-full:
	// what the connection really does.
	mode     string
	rootCert string
	fromDSN  bool
}

// resolveDatabaseTLS works out the sslmode and sslrootcert d's connection
// uses, the single reading shared by ValidateDatabaseTLS, DatabaseTLSPosture
// and the insecure-settings registry, so the three cannot disagree on what
// the connection does (before PG-TLS-2 the registry read ssl_mode even when
// a dsn was set, and the dsn is what pgx uses). It refuses:
//
//   - an sslmode outside validSSLModes, from ssl_mode, the dsn or PGSSLMODE;
//   - ssl_mode together with a dsn whose sslmode differs or is absent (the
//     dsn is used as-is, so ssl_mode would be silently ignored);
//   - a connection service (refuseConnectionService): pgx would take settings
//     from a service file Keyorix does not read.
//
// With a dsn and no sslmode in it, the mode is PGSSLMODE, else pgx's default
// "prefer" -- the same order pgx applies.
func resolveDatabaseTLS(d *DatabaseConfig) (databaseTLS, error) {
	var t databaseTLS
	if err := refuseConnectionService(d); err != nil {
		return t, err
	}
	if d.DSN == "" {
		t.written, t.rootCert = d.effectiveSSLMode(), d.SSLRootCert
		if !sslModeValid(t.written) {
			return t, invalidSSLModeError(fmt.Sprintf("storage.database.ssl_mode %q", d.SSLMode))
		}
	} else {
		t.fromDSN = true
		s, err := parseDSNTLS(d.DSN)
		if err != nil {
			// Never echo the DSN: it may carry a password.
			return t, fmt.Errorf("storage.database.dsn: %w", err)
		}
		t.written, t.rootCert = s.sslmode, s.sslrootcert
		if d.SSLMode != "" {
			if !sslModeValid(d.SSLMode) {
				return t, invalidSSLModeError(fmt.Sprintf("storage.database.ssl_mode %q", d.SSLMode))
			}
			if s.sslmode != d.SSLMode {
				dsnSays := "has no sslmode"
				if s.sslmode != "" {
					dsnSays = "has a different sslmode"
				}
				return t, fmt.Errorf("storage.database.ssl_mode is %s but storage.database.dsn %s: when dsn is set "+
					"it is used as-is and ssl_mode is ignored, so the connection would not use the mode ssl_mode "+
					"names -- refusing to start. Put sslmode=%s in the dsn, or remove ssl_mode", d.SSLMode, dsnSays, d.SSLMode)
			}
		}
		if t.written == "" {
			t.written = os.Getenv("PGSSLMODE")
			if t.written != "" && !sslModeValid(t.written) {
				return t, invalidSSLModeError("PGSSLMODE (used because storage.database.dsn has no sslmode)")
			}
			if t.written == "" {
				t.written = "prefer" // pgx's (and libpq's) default
			}
		} else if !sslModeValid(t.written) {
			// The dsn's value is not echoed: an operator who pasted a
			// password into the wrong key would see it in the log.
			return t, invalidSSLModeError("the sslmode in storage.database.dsn")
		}
	}
	t.mode = t.written
	if t.rootCert == SSLRootCertSystem {
		// pgx (like libpq) upgrades any sslmode to verify-full when
		// sslrootcert=system.
		t.mode = "verify-full"
	}
	return t, nil
}

// EffectiveDatabaseSSLMode is the sslmode d's PostgreSQL connection runs with
// (see resolveDatabaseTLS), or an error when ValidateDatabaseTLS would refuse
// the setting. The insecure-settings registry reads it.
func EffectiveDatabaseSSLMode(d *DatabaseConfig) (string, error) {
	t, err := resolveDatabaseTLS(d)
	return t.mode, err
}

// LoadDatabaseCAPool reads the PEM CA bundle path names into a new
// x509.CertPool holding only that file's certificates, and returns how many it
// holds. Same rules as the CLI's --ca-file (cli/internal/apiclient.LoadCAPool):
// it fails closed when the file is missing, not a regular file, larger than
// 1 MiB, holds no certificate, holds a private key (the wrong file), or is
// writable by group or others (anyone who can write it can make the server
// trust their database). Errors name the path, never file contents.
func LoadDatabaseCAPool(path string) (*x509.CertPool, int, error) {
	// OpenRegular opens non-blocking and fstats the same descriptor, so a FIFO
	// is refused at once instead of hanging boot in open(2).
	f, info, err := secretenv.OpenRegular(path, 0)
	if err != nil {
		if errors.Is(err, secretenv.ErrNotRegular) {
			return nil, 0, fmt.Errorf("CA file %s: not a regular file", path)
		}
		return nil, 0, fmt.Errorf("read CA file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, 0, fmt.Errorf("CA file %s has permissions %#o: writable by group or others, refusing to trust it; fix with chmod go-w %s", path, perm, path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxDatabaseCAFileBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read CA file: %w", err)
	}
	if len(data) > maxDatabaseCAFileBytes {
		return nil, 0, fmt.Errorf("CA file %s is larger than %d bytes", path, maxDatabaseCAFileBytes)
	}

	pool := x509.NewCertPool()
	certs := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, 0, fmt.Errorf("CA file %s contains a private key (%s): name the CA certificate only", path, block.Type)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("CA file %s: parse certificate: %w", path, err)
		}
		pool.AddCert(cert)
		certs++
	}
	if certs == 0 {
		return nil, 0, fmt.Errorf("CA file %s: no PEM certificate found", path)
	}
	return pool, certs, nil
}

// checkRootCert validates one sslrootcert value: "system", or a CA file
// LoadDatabaseCAPool accepts. field names where the value came from, for the
// error message.
func checkRootCert(field, value string) error {
	if value == SSLRootCertSystem {
		return nil
	}
	if _, _, err := LoadDatabaseCAPool(value); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

// missingRootCertError is the refusal for a verifying sslmode with no CA named
// in the Keyorix config. A constant-shaped message so the tests and the docs
// cannot drift from what an operator sees.
func missingRootCertError(modeField, mode, fix string) error {
	return fmt.Errorf("%s is %s but no CA certificate is configured, so the database server's certificate "+
		"would be checked against whatever trust store the process happens to find (PGSSLROOTCERT, "+
		"~/.postgresql/root.crt or the OS store) -- refusing to start. %s", modeField, mode, fix)
}

// ValidateDatabaseTLS checks storage.database's TLS trust settings and fails
// closed on every shape where the connection would verify against something
// the config does not name, or where the config names a CA that would be
// ignored:
//
//   - ssl_mode verify-full/verify-ca with no ssl_root_cert: refused.
//   - ssl_root_cert naming a missing, unreadable, empty, key-bearing or
//     group/world-writable file: refused (never a fallback to system roots).
//   - ssl_root_cert with ssl_mode disable: refused (the operator believes the
//     connection is verified; it is not even encrypted).
//   - ssl_root_cert together with dsn: refused (the dsn is used as-is, so the
//     key would be silently ignored); put sslrootcert inside the dsn instead.
//   - a dsn whose sslmode (or PGSSLMODE, when the dsn has none) is
//     verify-full/verify-ca: its sslrootcert must be set and pass the same
//     file checks.
//   - everything resolveDatabaseTLS refuses (PG-TLS-2): an sslmode outside
//     validSSLModes, ssl_mode disagreeing with the dsn's sslmode.
//
// Run by Config.Validate at startup and by ResolvePostgresConnConfig on every
// connection a process opens, so an entry point that never calls Validate
// (the admin subcommands) cannot connect around it.
func ValidateDatabaseTLS(d *DatabaseConfig) error {
	if err := refuseConnectionService(d); err != nil {
		return err
	}
	if d.DSN != "" && d.SSLRootCert != "" {
		return fmt.Errorf("storage.database.ssl_root_cert cannot be combined with storage.database.dsn: the dsn is " +
			"used as-is, so the key would be ignored; put sslrootcert=<path> in the dsn, or use host/name/user " +
			"fields instead of dsn")
	}
	t, err := resolveDatabaseTLS(d)
	if err != nil {
		return err
	}
	if !t.fromDSN {
		if t.rootCert == "" {
			if sslModeVerifies(t.mode) {
				return missingRootCertError("storage.database.ssl_mode", t.mode,
					"Set storage.database.ssl_root_cert to the PEM file of the CA that signed the database "+
						"server's certificate, or to \"system\" to trust the OS CA store.")
			}
			return nil
		}
		if t.written == "disable" {
			return fmt.Errorf("storage.database.ssl_root_cert is set but storage.database.ssl_mode is disable, " +
				"so the connection is neither encrypted nor verified; set ssl_mode to verify-full (or remove ssl_root_cert)")
		}
		return checkRootCert("storage.database.ssl_root_cert", t.rootCert)
	}
	if t.rootCert == "" {
		if sslModeVerifies(t.mode) {
			return missingRootCertError("the sslmode in storage.database.dsn", t.mode,
				"Add sslrootcert=<path to the PEM file of the CA that signed the database server's "+
					"certificate> (or sslrootcert=system to trust the OS CA store) to the dsn.")
		}
		return nil
	}
	return checkRootCert("sslrootcert in storage.database.dsn", t.rootCert)
}

// refuseConnectionService refuses a PostgreSQL connection that would take
// settings from a connection-service file: `service=` / `servicefile=` in the
// dsn, or the PGSERVICE environment variable (pgx reads both). The file is
// merged over the environment and under the dsn, so it can supply the sslmode,
// sslrootcert and host that the checks in this file never see: a service with
// sslmode=verify-full and no sslrootcert would make pgx verify against its
// implicit trust store, the fallback ssl_root_cert exists to close. Resolving
// the file the way pgx does would mean re-reading it at connect time too, so
// the config is refused instead. PGSERVICEFILE alone is inert -- pgx reads a
// service file only when a service is selected -- so it is not refused.
func refuseConnectionService(d *DatabaseConfig) error {
	const fix = "Put the connection settings (host, ssl_mode, ssl_root_cert, ...) in storage.database or " +
		"in the dsn itself instead of a service file; Keyorix does not read service files, so it " +
		"cannot check the TLS trust they would set"
	if d.DSN != "" {
		selects, err := dsnSelectsService(d.DSN)
		if err != nil {
			return fmt.Errorf("storage.database.dsn: %w", err)
		}
		if selects {
			return errors.New("storage.database.dsn selects a PostgreSQL connection service (service= or servicefile=), " +
				"whose file could set sslmode, sslrootcert or host behind the TLS checks -- refusing to start. " + fix)
		}
	}
	if os.Getenv("PGSERVICE") != "" {
		return errors.New("the PGSERVICE environment variable selects a PostgreSQL connection service, " +
			"whose file could set sslmode, sslrootcert or host behind the TLS checks -- refusing to start. " +
			"Unset PGSERVICE for the Keyorix server, or: " + fix)
	}
	return nil
}

// dsnTLS is what parseDSNTLS reads from a connection string.
type dsnTLS struct {
	sslmode, sslrootcert string
}

// dsnTLSSettings is parseDSNTLS's sslmode and sslrootcert.
func dsnTLSSettings(dsn string) (sslmode, sslrootcert string, err error) {
	s, err := parseDSNTLS(dsn)
	return s.sslmode, s.sslrootcert, err
}

// parseDSNTLS extracts sslmode and sslrootcert from a PostgreSQL connection string in either form pgx accepts: a
// postgres:// or postgresql:// URL, or libpq keyword/value pairs. The
// keyword/value grammar follows pgx's parseKeywordValueSettings
// (pgconn/config.go): whitespace separated key=value, values optionally
// single-quoted, backslash escapes. A string pgx itself would reject is
// reported as an error here too.
//
// Guarded against drift from pgx by TestDSNTLSSettings_AgreesWithPgx
// (database_tls_pgx_test.go), which runs the same connection strings through
// pgconn.ParseConfig; only that test links the driver into this package.
func parseDSNTLS(dsn string) (dsnTLS, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return urlTLSSettings(dsn)
	}
	settings, err := parseKeywordValueDSN(dsn)
	if err != nil {
		return dsnTLS{}, err
	}
	return dsnTLS{sslmode: settings["sslmode"], sslrootcert: settings["sslrootcert"]}, nil
}

// urlTLSSettings reads sslmode/sslrootcert from a connection URL's query the
// way pgx's parseURLQueryParams does (libpq's conninfo_uri_parse_params):
// '&'-separated key=value pairs, both halves percent-decoded with '+' kept
// literal, the LAST occurrence of a key winning. net/url's Query() keeps the
// first one, which would let "?sslmode=require&sslmode=verify-full" pass as
// require while pgx connects with verify-full.
//
// "ssl=true" is pgx's URI-only alias for sslmode=require, applied when the
// final ssl value is "true" and no sslmode key came after the last ssl key
// (parse_url.go's sslWasLast). It is modelled exactly rather than ignored:
// ignored, "?ssl=true" would read as no sslmode (prefer) and
// "?sslmode=verify-full&ssl=true" as verify-full, while pgx runs require.
func urlTLSSettings(dsn string) (dsnTLS, error) {
	var s dsnTLS
	pairs, err := urlParamPairs(dsn)
	if err != nil {
		return s, err
	}
	ssl, sslWasLast := "", false
	for _, kv := range pairs {
		switch kv[0] {
		case "sslmode":
			s.sslmode = kv[1]
			sslWasLast = false
		case "ssl":
			ssl = kv[1]
			sslWasLast = true
		case "sslrootcert":
			s.sslrootcert = kv[1]
		}
	}
	if ssl == "true" && sslWasLast {
		s.sslmode = "require"
	}
	return s, nil
}

// urlParams returns every key of a connection URL's query, read as described
// at urlTLSSettings (last occurrence wins; keys and values percent-decoded and
// space-trimmed). A key present with an empty value is present in the map, as
// it is to pgx.
func urlParams(dsn string) (map[string]string, error) {
	pairs, err := urlParamPairs(dsn)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, kv := range pairs {
		out[kv[0]] = kv[1]
	}
	return out, nil
}

// urlParamPairs returns a connection URL's query as decoded (key, value)
// pairs in order, for urlParams and urlTLSSettings (which needs the order for
// pgx's ssl/sslmode precedence).
func urlParamPairs(dsn string) ([][2]string, error) {
	params, err := urlQuery(dsn)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	// No '#' fragment is cut off: pgx has none, so "?#=&sslmode=verify-full"
	// is a verify-full connection to pgx and must be one here.
	for pair := range strings.SplitSeq(params, "&") {
		if pair == "" {
			continue
		}
		rawKey, rawValue, found := strings.Cut(pair, "=")
		if !found || strings.Contains(rawValue, "=") {
			return nil, errors.New("malformed query parameter in the connection URL")
		}
		key, kerr := url.PathUnescape(rawKey)
		value, verr := url.PathUnescape(rawValue)
		if kerr != nil || verr != nil {
			return nil, errors.New("malformed percent-encoding in the connection URL's query")
		}
		// pgx's uriDecode drops leading/trailing ASCII spaces only: a key
		// "sslrootcert\r" is a runtime parameter to pgx, not sslrootcert
		// (fuzz-found by FuzzResolvePostgresConnConfig_PasswordCannotChangeConnection
		// through checkFinalPostgresTLS).
		out = append(out, [2]string{strings.Trim(key, " "), strings.Trim(value, " ")})
	}
	return out, nil
}

// dsnSelectsService reports whether the connection string names a connection
// service (the `service` key, present even when empty, as pgx tests it) or a
// service file (`servicefile`, a pgx extension). pgx then merges that file's
// settings over the environment and under the string's own, so it can supply
// sslmode, sslrootcert or host -- settings the check reads only from the string.
func dsnSelectsService(dsn string) (bool, error) {
	var settings map[string]string
	var err error
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		settings, err = urlParams(dsn)
	} else {
		settings, err = parseKeywordValueDSN(dsn)
	}
	if err != nil {
		return false, err
	}
	_, svc := settings["service"]
	_, file := settings["servicefile"]
	return svc || file, nil
}

// urlQuery returns the query string of a postgres:// URL the way pgx's
// parseURLSettings (pgconn/parse_url.go) finds it, not at the first '?' in the
// string: a '?' in the userinfo (pgx looks ahead for '@' before any '/') or
// inside a bracketed IPv6 host (pgx does not validate bracket contents) is not
// the start of the query. Taking the first '?' there would read no sslmode
// while pgx reads verify-full from the real query and verifies against its
// implicit trust store.
func urlQuery(dsn string) (string, error) {
	p, ok := strings.CutPrefix(dsn, "postgresql://")
	if !ok {
		p, _ = strings.CutPrefix(dsn, "postgres://")
	}
	if i := strings.IndexAny(p, "@/"); i >= 0 && p[i] == '@' {
		p = p[i+1:]
	}
	for {
		if strings.HasPrefix(p, "[") {
			end := strings.IndexByte(p, ']')
			if end < 0 {
				return "", errors.New("unterminated IPv6 host in the connection URL")
			}
			p = p[end+1:]
			if p != "" && !strings.ContainsAny(p[:1], ":/?,") {
				return "", errors.New("unexpected character after the IPv6 host in the connection URL")
			}
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
			return "", nil
		}
		p = p[i:]
	}
	if q, ok := strings.CutPrefix(p, "?"); ok {
		return q, nil
	}
	return "", nil
}

const dsnSpace = " \t\n\r\v\f"

func parseKeywordValueDSN(s string) (map[string]string, error) {
	settings := map[string]string{}
	if strings.IndexByte(s, 0) >= 0 {
		return nil, errors.New("forbidden NUL byte in connection string")
	}
	s = strings.TrimLeft(s, dsnSpace)
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return nil, errors.New("invalid keyword/value connection string")
		}
		key := strings.Trim(s[:eq], dsnSpace)
		if strings.ContainsAny(key, dsnSpace) {
			return nil, errors.New("invalid keyword/value connection string: whitespace inside a keyword")
		}
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
					if end == len(s) {
						return nil, errors.New("unterminated quoted string in connection string")
					}
				}
			}
			if end == len(s) {
				return nil, errors.New("unterminated quoted string in connection string")
			}
			val = unescapeDSNValue(s[:end])
			s = strings.TrimLeft(s[end+1:], dsnSpace)
		}
		if key == "" {
			return nil, errors.New("invalid keyword/value connection string: empty keyword")
		}
		settings[key] = val
	}
	return settings, nil
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

// quoteDSNValue single-quotes v for a keyword/value DSN, escaping backslash
// and quote, so a path with spaces or quotes stays one value.
func quoteDSNValue(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// DatabaseTLSPosture describes, in one line, how the server's PostgreSQL
// connection is protected: what is encrypted, what is verified and against
// which CA. Used by `admin validate --posture` and `admin init`. The second
// result is an error from ValidateDatabaseTLS -- the same refusal the server
// boot gives -- so a caller reports it rather than a description.
func DatabaseTLSPosture(d *DatabaseConfig) (string, error) {
	if err := ValidateDatabaseTLS(d); err != nil {
		return "", err
	}
	t, err := resolveDatabaseTLS(d)
	if err != nil {
		return "", err
	}
	mode, rootCert := t.mode, t.rootCert
	source := "storage.database.ssl_mode"
	if t.fromDSN {
		source = "the dsn's sslmode"
	}
	trust := func() string {
		if rootCert == SSLRootCertSystem {
			return "the OS CA store (ssl_root_cert: system)"
		}
		_, n, _ := LoadDatabaseCAPool(rootCert) // validated above
		return fmt.Sprintf("CA file %s (%d certificate(s))", rootCert, n)
	}
	switch {
	case mode == "verify-full":
		return fmt.Sprintf("database TLS: %s=verify-full -- encrypted; certificate chain and host name verified against %s", source, trust()), nil
	case mode == "verify-ca" || (mode == "require" && rootCert != ""):
		return fmt.Sprintf("database TLS: %s=%s -- encrypted; certificate chain verified against %s, host name NOT verified", source, mode, trust()), nil
	case mode == "require":
		return fmt.Sprintf("database TLS: %s=require -- encrypted, server certificate NOT verified (set ssl_mode: verify-full and ssl_root_cert to verify it)", source), nil
	case mode == "disable":
		return fmt.Sprintf("database TLS: %s=disable -- connection is NOT encrypted", source), nil
	default:
		return fmt.Sprintf("database TLS: %s=%s -- may fall back to an unencrypted connection; server certificate NOT verified", source, mode), nil
	}
}
