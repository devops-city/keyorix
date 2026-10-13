package config

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// FuzzResolvePostgresConnConfig_PasswordCannotChangeConnection fuzzes
// (DSN, password) pairs through ResolvePostgresConnConfig and checks, against
// pgx's own parse of the DSN alone:
//
//   - the resolved connection goes to the same host(s) and port(s), database
//     and user, with the same TLS for the primary and every fallback, and the
//     same runtime parameters: the password cannot move it or weaken it;
//   - the password is exactly the configured one (or the DSN's own when none
//     is configured);
//   - a DSN carrying a password plus a configured one is refused, and the
//     conflict check agrees with pgx about whether the DSN carries one.
//
// The class it guards: the TLS/host checks read one string while the driver
// is handed another (REVIEW-3162B). It does not cover the field-built form
// (TestResolvePostgresConnConfig_Fields) nor what a server does with the
// password.
func FuzzResolvePostgresConnConfig_PasswordCannotChangeConnection(f *testing.F) {
	for _, k := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
		"PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGSERVICE", "PGSERVICEFILE", "PGAPPNAME",
		"PGOPTIONS", "PGSSLNEGOTIATION", "PGSSLSNI", "PGTARGETSESSIONATTRS", "KEYORIX_DB_PASSWORD",
		"KEYORIX_DB_PASSWORD_FILE"} {
		f.Setenv(k, "")
	}
	f.Setenv("HOME", f.TempDir())
	for _, s := range [][2]string{
		{dsnNoPwKeyword, "secret"},
		{dsnNoPwURL, "p w+%@#:/?&=;'\"\\"},
		{"host=db.internal sslmode=verify-full sslrootcert=system application_name=x\\", `a sslmode=disable host=evil x=\`},
		{"host=db.internal sslmode=verify-full sslrootcert=system application_name=x\\ ", `a sslmode=disable host=evil x=\`},
		{"postgres://u?x@db.internal/k?sslmode=verify-full&sslrootcert=system", "secret"},
		{"postgres://u?x@db.internal?sslmode=verify-full&sslrootcert=system", "secret"},
		{"postgres://u:pa?ss@db.internal/k?sslmode=verify-full", "secret"},
		{"postgres://u@[::1]:5432,[::2]:5433/db?sslmode=verify-full&sslrootcert=system", "x' host=evil"},
		{dsnPwKeyword, "other"},
		{dsnPwURL, ""},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, dsn, pw string) {
		if dsn == "" {
			return // the field-built form, not this target
		}
		want, err := pgx.ParseConfig(dsn)
		if err != nil {
			return
		}
		got, err := ResolvePostgresConnConfig(&DatabaseConfig{DSN: dsn, Password: pw})
		dsnHasPw := want.Password != "" // no passfile: HOME is empty, PGPASSFILE unset
		if has := dsnHasPassword(dsn); has != dsnHasPw {
			t.Fatalf("dsnHasPassword=%v but pgx reads a password: %v (%q)", has, dsnHasPw, dsn)
		}
		switch {
		case pw != "" && dsnHasPw:
			if err == nil {
				t.Fatalf("DSN password plus configured password must be refused (%q)", dsn)
			}
			return
		case err != nil:
			t.Fatalf("ResolvePostgresConnConfig failed on a DSN pgx accepts: %v", err)
		}
		wantPw := want.Password
		if pw != "" {
			wantPw = pw
		}
		assertSameConnection(t, dsn, got, wantPw)
	})
}
