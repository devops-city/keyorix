package dsn

import (
	"slices"
	"testing"
)

// TestParseDSNHosts_CoversWhatTheDriverDials pins ParseDSNHosts to the hosts the
// real drivers dial for shapes where the old first-match parser saw a different
// (public) host than the driver connects to (REVIEW-COVERAGE-1). Each case names
// the driver behaviour it mirrors, read from the driver source in go.mod:
// pgx v5.11.0 pgconn (parse_url.go, config.go parseKeywordValueSettings),
// go-sql-driver/mysql v1.10.1 (dsn.go ParseDSN), mongo-driver v2.9.1
// (x/mongo/driver/connstring). internal/dynamic's FuzzDSNHostsCoverDriverHosts
// checks the same property against the drivers themselves.
//
// The direction asserted is coverage only: every host the driver may dial must be
// among the returned candidates. Extra candidates are a safe failure (the
// validator checks them too); missing ones are a register-time SSRF bypass, with
// internal/dynamic's dial-time netutil.Dialer as the remaining guard.
func TestParseDSNHosts_CoversWhatTheDriverDials(t *testing.T) {
	const imds = "169.254.169.254"
	cases := []struct {
		name, dsn string
		want      []string
	}{
		// pgx keyword/value: last occurrence of a key wins.
		{"kv repeated host, last wins in pgx", "host=203.0.113.5 host=" + imds + " user=a", []string{imds}},
		// pgx keyword/value: single-quoted values.
		{"kv quoted host", "host='" + imds + "' user=a", []string{imds}},
		// pgx keyword/value: whitespace around '='.
		{"kv spaces around =", "host = " + imds + " user=a", []string{imds}},
		{"kv tab before =", "host\t=" + imds + " user=a", []string{imds}},
		// pgx keyword/value: a backslash escapes the next character.
		{"kv backslash escape", `host=169.254.169.25\4 user=a`, []string{imds}},
		// pgx picks URL vs keyword/value by the postgres:// prefix only; a "://"
		// inside a value does not make the string a URL.
		{"kv with :// in another value", "host=" + imds + " password=a://203.0.113.5", []string{imds}},
		// pgx URL: ?host= overrides the authority.
		{"url query host overrides authority", "postgres://203.0.113.5/db?host=" + imds, []string{imds}},
		{"url empty authority, query host", "postgres:///db?host=" + imds, []string{imds}},
		// pgx URL: the host list is percent-decoded (url.Parse rejects it).
		{"url percent-encoded host", "postgres://%31%36%39.254.169.254/db", []string{imds}},
		{"url percent-encoded comma splits", "postgres://203.0.113.5%2C" + imds + "/db", []string{imds}},
		// pgx URL: userinfo ends at the FIRST '@' before any '/' (url.Parse and the
		// old manual fallback take the last).
		{"url first @ ends userinfo", "postgres://u@" + imds + ",x@203.0.113.5/db", []string{imds}},
		{"url @ inside query ends userinfo", "postgres://203.0.113.5?a=b@" + imds + "/db", []string{imds}},
		// go-sql-driver: last '/', then last '@' before it, then the first '('.
		{"mysql @tcp( inside password", "u:x@tcp(203.0.113.5:1)y@tcp(" + imds + ":3306)/db", []string{imds}},
		{"mysql @( inside password", "u:p@(203.0.113.5)z@tcp(" + imds + ":3306)/db", []string{imds}},
		// mongo-driver: each host is query-unescaped.
		{"mongo percent-encoded host", "mongodb://%31%36%39.254.169.254:27017/", []string{imds}},
		// Kubernetes api_server: every host of the URL, not only the first.
		{"kubernetes multi-host api_server", `{"api_server":"https://203.0.113.5,` + imds + `"}`, []string{"203.0.113.5", imds}},
		// Shapes the old parser already handled; kept so the rewrite cannot lose them.
		{"url plain", "postgres://admin:pass@db.example.com:5432/app", []string{"db.example.com"}},
		{"url multi-host bracketed ipv6", "postgres://u@[64:ff9b::a9fe:a9fe]:5432,10.0.0.1:5432/db", []string{"64:ff9b::a9fe:a9fe", "10.0.0.1"}},
		{"url ipv6 zone", "postgres://[fe80::1%25eth0]:5432/db", []string{"fe80::1%eth0"}},
		{"kv multi-host", "host=h1,h2,h3 port=1,2,3", []string{"h1", "h2", "h3"}},
		{"mysql tcp", "admin:pass@tcp(db.internal:3306)/app", []string{"db.internal"}},
		{"mysql bare parens", "admin:pass@(db.internal:3306)/app", []string{"db.internal"}},
		{"redis url", "redis://user:pass@redis.internal:6379/0", []string{"redis.internal"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseDSNHosts(tc.dsn)
			for _, w := range tc.want {
				if !slices.Contains(got, w) {
					t.Errorf("ParseDSNHosts(%q) = %q: missing %q, which the driver dials", tc.dsn, got, w)
				}
			}
		})
	}
}

// TestParseDSNHosts_UnixSocketPathIsReturnedVerbatim documents, rather than
// changes, the unix-socket case: the path comes back as a candidate, the
// validator can neither parse nor resolve it and skips it, and the dial-time
// guard refuses it (netutil.Dialer.DialContext fails net.SplitHostPort on a
// socket path; redis refuses the unix scheme outright).
func TestParseDSNHosts_UnixSocketPathIsReturnedVerbatim(t *testing.T) {
	for dsn, want := range map[string]string{
		"host=/var/run/postgresql user=a":           "/var/run/postgresql",
		"postgres:///db?host=%2Fvar%2Frun%2Fpg":     "/var/run/pg",
		"user:pass@unix(/tmp/mysql.sock)/db":        "/tmp/mysql.sock",
		"host='/var/run/postgresql' dbname=keyorix": "/var/run/postgresql",
	} {
		if got := ParseDSNHosts(dsn); !slices.Contains(got, want) {
			t.Errorf("ParseDSNHosts(%q) = %q, want it to contain %q", dsn, got, want)
		}
	}
}

func TestParseDSNHosts_UnrecognisedStillNil(t *testing.T) {
	for _, dsn := range []string{"", "not-a-dsn", "   ", `{"token":"t"}`} {
		if got := ParseDSNHosts(dsn); got != nil {
			t.Errorf("ParseDSNHosts(%q) = %q, want nil", dsn, got)
		}
	}
}
