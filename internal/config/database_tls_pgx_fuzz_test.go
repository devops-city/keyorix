package config

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// FuzzDSNTLSSettings_NeverMissesPgxVerification is the open-ended form of
// TestDSNTLSSettings_AgreesWithPgx, in the one direction that fails open: for
// any connection string pgx accepts and builds a certificate-verifying TLS
// config from, dsnTLSSettings must either refuse the string or read a mode
// that verifies too. Otherwise ValidateDatabaseTLS sees no verification, needs
// no CA, and pgx then verifies against its implicit trust store -- the
// fallback PG-VERIFYFULL-1 closes. (The `?`-in-userinfo and `?`-in-IPv6-host
// URL shapes were such misses.) The other direction -- reading verification
// pgx does not do -- only refuses a config, so it is not checked here.
//
// It also fuzzes the password (REVIEW-3162B): each (DSN, password) pair goes
// through the full build path, ResolvePostgresConnConfig, and when that
// accepts it the FINAL config the driver gets must be what was validated and
// intended: the host(s) and port(s) pgx reads from the DSN alone, the
// configured password (or the DSN's own when none is configured), and, when
// the check's reading of the DSN verifies the server, TLS on every candidate
// with chain verification, a CA pool, and for verify-full the candidate's own
// host as the verified name. The splice #3159 shipped failed this for a
// keyword DSN ending in '\' and a URL with '?' in the userinfo.
//
// HOME, PGSSLMODE, PGSSLROOTCERT and PGPASSFILE are cleared so no implicit CA
// or password exists; a DSN naming an sslrootcert pgx cannot load is skipped
// by pgx's own error.
func FuzzDSNTLSSettings_NeverMissesPgxVerification(f *testing.F) {
	f.Setenv("HOME", f.TempDir())
	f.Setenv("PGSSLMODE", "")
	f.Setenv("PGSSLROOTCERT", "")
	f.Setenv("PGPASSFILE", "")
	f.Setenv("KEYORIX_DB_PASSWORD", "")
	f.Setenv("KEYORIX_DB_PASSWORD_FILE", "")
	// A service file that turns verification on with no CA: any string that
	// selects it (service=svc, in any spelling pgx accepts) must be refused by
	// dsnSelectsService, or the oracle below sees pgx verify and the check not.
	svcFile := filepath.Join(f.TempDir(), "pg_service.conf")
	if err := os.WriteFile(svcFile, []byte("[svc]\nhost=db\nsslmode=verify-full\n"), 0o600); err != nil {
		f.Fatal(err)
	}
	f.Setenv("PGSERVICEFILE", svcFile)
	f.Setenv("PGSERVICE", "")
	for _, s := range []string{
		"service=svc",
		"host=db service='svc'",
		"postgres://u@db/k?service=svc",
		"postgres://u@db/k?servic%65=svc",
		"host=db sslmode=verify-full",
		"host=db sslmode=require sslmode=verify-ca",
		"host=db password='x sslmode=disable' sslmode=verify-full",
		`host=db sslmode=verify\-full`,
		"postgres://u@db/k?sslmode=verify-full",
		"postgres://u:pa?ss@db/k?sslmode=verify-full",
		"postgres://u@[::1?x]/k?sslmode=verify-full",
		"postgres://u@h1,h2:5433/k?sslmode=verify-ca",
		"postgresql://u@db/k?ssl%6Dode=verify-full",
		"postgres://u@db/k?sslmode=disable&sslrootcert=system",
	} {
		f.Add(s, "")
	}
	for _, s := range [][2]string{
		{"host=db.internal sslmode=verify-full sslrootcert=system application_name=x\\", `a sslmode=disable host=evil x=\`},
		{"host=db.internal sslmode=verify-full sslrootcert=system application_name=x\\ ", `a sslmode=disable host=evil x=\`},
		{"postgres://u?x@db.internal/k?sslmode=verify-full&sslrootcert=system", "secret"},
		{"postgres://u?x@db.internal?sslmode=verify-full&sslrootcert=system", "secret"},
		{"postgres://u@a.internal,b.internal/k?sslmode=verify-full&sslrootcert=system", "x' host=evil sslmode=disable"},
		{"host=db.internal sslmode=require", "' sslmode=disable host=evil"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, dsn, pw string) {
		pc, perr := pgconn.ParseConfig(dsn)
		if perr != nil {
			return
		}
		checkFinalConfigIsTheValidatedOne(t, dsn, pw, pc)
		tlsCfg := pc.TLSConfig
		if tlsCfg == nil || (tlsCfg.InsecureSkipVerify && tlsCfg.VerifyPeerCertificate == nil) {
			return // pgx does not verify the server: nothing to miss.
		}
		if sel, serr := dsnSelectsService(dsn); serr != nil || sel {
			return // a connection service is refused: fails closed.
		}
		mode, root, err := dsnTLSSettings(dsn)
		if err != nil {
			return // refused: fails closed.
		}
		if !(sslModeVerifies(mode) || root == SSLRootCertSystem || (root != "" && mode == "require")) {
			t.Fatalf("pgx verifies the server certificate for %q, but the check read sslmode=%q sslrootcert=%q (no verification, so no CA required)", dsn, mode, root)
		}
	})
}

// checkFinalConfigIsTheValidatedOne is the full-build-path oracle described at
// FuzzDSNTLSSettings_NeverMissesPgxVerification. pc is pgx's parse of dsn alone.
func checkFinalConfigIsTheValidatedOne(t *testing.T, dsn, pw string, pc *pgconn.Config) {
	t.Helper()
	if dsn == "" {
		return // the field-built form (TestResolvePostgresConnConfig_FieldValuesCannotInjectKeywords)
	}
	cc, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: dsn, Password: pw})
	if err != nil {
		return // refused: fails closed
	}
	wantPw := pc.Password
	if pw != "" {
		wantPw = pw
	}
	if cc.Password != wantPw {
		t.Fatalf("final password is not the intended one (dsn %q)", dsn)
	}
	if cc.Host != pc.Host || cc.Port != pc.Port || len(cc.Fallbacks) != len(pc.Fallbacks) {
		t.Fatalf("final host %q:%d (+%d fallbacks) is not pgx's reading of the DSN alone %q:%d (+%d) for %q",
			cc.Host, cc.Port, len(cc.Fallbacks), pc.Host, pc.Port, len(pc.Fallbacks), dsn)
	}
	for i := range pc.Fallbacks {
		if cc.Fallbacks[i].Host != pc.Fallbacks[i].Host || cc.Fallbacks[i].Port != pc.Fallbacks[i].Port {
			t.Fatalf("final fallback %d moved for %q", i, dsn)
		}
	}
	mode, root, err := dsnTLSSettings(dsn)
	if err != nil {
		t.Fatalf("ResolvePostgresConnConfig accepted a DSN the TLS check cannot read: %q", dsn)
	}
	if root == SSLRootCertSystem {
		mode = "verify-full"
	}
	verifies := sslModeVerifies(mode) || (mode == "require" && root != "")
	if !verifies && mode != "require" {
		return
	}
	type cand struct {
		host string
		tls  *tls.Config
	}
	cands := []cand{{cc.Host, cc.TLSConfig}}
	for _, fb := range cc.Fallbacks {
		cands = append(cands, cand{fb.Host, fb.TLSConfig})
	}
	for _, c := range cands {
		if network, _ := pgconn.NetworkAddress(c.host, cc.Port); network == "unix" {
			continue // local socket, never TLS
		}
		switch {
		case c.tls == nil:
			t.Fatalf("validated sslmode=%q sslrootcert=%q, but a final candidate (%q) has no TLS: %q", mode, root, c.host, dsn)
		case !verifies:
		case c.tls.InsecureSkipVerify && c.tls.VerifyPeerCertificate == nil, c.tls.RootCAs == nil:
			t.Fatalf("validated sslmode=%q sslrootcert=%q, but the final config does not verify %q: %q", mode, root, c.host, dsn)
		case mode == "verify-full" && (c.tls.InsecureSkipVerify || c.tls.ServerName != c.host):
			t.Fatalf("validated verify-full, but the final config does not verify host name %q: %q", c.host, dsn)
		}
	}
}
