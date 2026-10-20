// Package pgdsn builds schema- and database-scoped Postgres DSNs from either
// accepted DSN form (see PGSearchPathDSN, PGReplaceDBName) for tests that
// isolate themselves on a shared KEYORIX_TEST_PG_DSN server.
package pgdsn

import (
	"net/url"
	"strings"
)

// PGSearchPathDSN returns base with search_path pointed at schema, for either
// DSN form KEYORIX_TEST_PG_DSN is allowed to take:
//   - keyword/value ("host=localhost port=5432 dbname=x user=y sslmode=disable"):
//     append " search_path=<schema>", the libpq keyword/value syntax.
//   - URL ("postgres://user:pass@host:port/db?sslmode=disable"): append
//     "search_path=<schema>" as a query parameter — space-concatenating onto a
//     URL is invalid syntax and fails to parse (pgconn: "failed to configure
//     TLS (sslmode is invalid)"), since the trailing " search_path=x" gets
//     read as part of the query string's last value, not a new parameter.
func PGSearchPathDSN(base, schema string) string {
	if isURLDSN(base) {
		sep := "?"
		if strings.Contains(base, "?") {
			sep = "&"
		}
		return base + sep + "search_path=" + url.QueryEscape(schema)
	}
	return base + " search_path=" + schema
}

// PGReplaceDBName returns base with its target database swapped to newName,
// for either DSN form KEYORIX_TEST_PG_DSN is allowed to take:
//   - keyword/value ("host=localhost port=5432 dbname=x user=y sslmode=disable"):
//     replace the dbname= field in place (append one if base has none).
//   - URL ("postgres://user:pass@host:port/db?sslmode=disable"): replace the
//     URL path (the database name) via net/url — string-concatenating a
//     "dbname=" field onto a URL is not libpq keyword/value syntax and is
//     silently ignored, leaving every isolated test pointed at the same
//     shared base database instead of its own disposable one.
//
// Both forms keep every other field (sslmode, a quoted or percent-encoded
// password, search_path, ...) intact; see replace_dbname.go. An unparseable URL
// panics rather than returning base unchanged.
func PGReplaceDBName(base, newName string) string {
	if isURLDSN(base) {
		return replaceURLDBName(base, newName)
	}
	return replaceKeywordValueDBName(base, newName)
}
