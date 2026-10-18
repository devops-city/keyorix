package dynamic

import (
	"net"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// FuzzDSNHostsCoverDriverHosts is the differential oracle for the register-time
// SSRF check (core.validateAdminDSNHost -> dsn.ParseDSNHosts): for any admin_dsn
// string that a real driver parses, every TCP host that driver would dial must be
// among the hosts dsn.ParseDSNHosts returns. A host the driver dials but the
// parser did not return is a register-time validation bypass (REVIEW-COVERAGE-1
// found fifteen such shapes; dsn_differential_test.go pins them). It lives here,
// not in internal/core/dsn, because it links the drivers, and dsn's own fuzz
// binary must stay stdlib-only (TestDSNStaysALeaf).
//
// Drivers and how their dial targets are read:
//   - pgx (pgconn.ParseConfig): Config.Host plus every Fallbacks[].Host;
//   - go-sql-driver/mysql (mysql.ParseDSN): Config.Addr when Net is "tcp";
//   - mongo (connstring.Parse, mongodb:// only: mongodb+srv:// does DNS): Hosts.
//
// What it does NOT check: unix-socket targets (a path; the dial-time
// netutil.Dialer refuses them), driver defaults the string never names (pgx's
// localhost / socket dirs, mysql's 127.0.0.1:3306 for an empty address: the
// dial-time guard refuses loopback), PG* environment variables (cleared below)
// and service files, redis (go-redis parses with net/url, the same parser
// ParseDSNHostsFromURL uses first) and the Kubernetes JSON form (encoding/json on
// both sides). It does not check the reverse direction: an extra candidate is a
// safe failure.
func FuzzDSNHostsCoverDriverHosts(f *testing.F) {
	for _, s := range []string{
		"host=203.0.113.5 host=169.254.169.254 user=a",
		"host='169.254.169.254' user=a",
		"host = 169.254.169.254 user=a",
		`host=169.254.169.25\4 user=a`,
		"host=169.254.169.254 password=a://203.0.113.5",
		"host=h1,h2,h3 port=1,2,3",
		"postgres://203.0.113.5/db?host=169.254.169.254",
		"postgres:///db?host=169.254.169.254",
		"postgres://%31%36%39.254.169.254/db",
		"postgres://203.0.113.5%2C169.254.169.254/db",
		"postgres://u@169.254.169.254,x@203.0.113.5/db",
		"postgres://203.0.113.5?a=b@169.254.169.254/db",
		"postgresql://u:p@[64:ff9b::a9fe:a9fe]:5432,10.0.0.1:5432/db?sslmode=disable",
		"postgres://[fe80::1%25eth0]:5432/db",
		"u:x@tcp(203.0.113.5:1)y@tcp(169.254.169.254:3306)/db",
		"admin:pass@tcp(db.internal:3306)/app",
		"admin:pass@(db.internal:3306)/app?tls=true",
		"mongodb://%31%36%39.254.169.254:27017/",
		"mongodb://u:p@h1:27017,h2:27017/db?replicaSet=rs0",
	} {
		f.Add(s)
	}
	for _, env := range []string{"PGHOST", "PGPORT", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGSSLMODE"} {
		f.Setenv(env, "")
	}
	f.Fuzz(func(t *testing.T, s string) {
		if strings.Contains(s, "service=") || strings.Contains(s, "servicefile=") || strings.Contains(s, "passfile=") ||
			strings.Contains(s, "sslrootcert=") || strings.Contains(s, "sslcert=") || strings.Contains(s, "sslkey=") {
			return // pgx would read local files; not a host-extraction question
		}
		got := dsn.ParseDSNHosts(s)
		covered := func(host string) bool {
			// Surrounding spaces: the parser trims them (SplitDSNHostList); a
			// resolver given " h" fails rather than dialing "h".
			want := strings.TrimSpace(stripBrackets(host))
			for _, g := range got {
				g = strings.TrimSpace(stripBrackets(g))
				if g == want {
					return true
				}
				if h, _, err := net.SplitHostPort(want); err == nil && g == h {
					return true // pgx keeps a key/value "host=h:5432" whole; the parser strips the port
				}
			}
			return false
		}
		check := func(driver, host string) {
			if strings.TrimSpace(host) == "" || strings.HasPrefix(host, "/") {
				return // whitespace-only (resolves to nothing) or a unix socket (refused at dial time)
			}
			if (host == "localhost" || host == "127.0.0.1") && !strings.Contains(s, host) {
				return // the driver's default (pgx localhost, mysql 127.0.0.1), not named by the string
			}
			if !covered(host) {
				t.Fatalf("%s dials %q for %q, but dsn.ParseDSNHosts returned %q", driver, host, s, got)
			}
		}

		if cfg, err := pgconn.ParseConfig(s); err == nil {
			check("pgx", cfg.Host)
			for _, fb := range cfg.Fallbacks {
				check("pgx fallback", fb.Host)
			}
		}
		if cfg, err := mysql.ParseDSN(s); err == nil && cfg.Net == "tcp" {
			// normalize() appends the default port with net.JoinHostPort, so an
			// address that is not host:port-shaped comes back as "<addr>:3306".
			host := strings.TrimSuffix(cfg.Addr, ":3306")
			if h, _, err := net.SplitHostPort(cfg.Addr); err == nil {
				host = h
			}
			check("go-sql-driver/mysql", host)
		}
		if strings.HasPrefix(s, "mongodb://") {
			if cs, err := connstring.Parse(s); err == nil {
				for _, h := range cs.Hosts {
					host := h
					if hh, _, err := net.SplitHostPort(h); err == nil {
						host = hh
					}
					check("mongo", host)
				}
			}
		}
	})
}

func stripBrackets(h string) string {
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}
