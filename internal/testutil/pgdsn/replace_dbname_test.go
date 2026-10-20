package pgdsn

import (
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// trickyPassword holds every character that breaks string splicing or URL
// parsing when unescaped: @ : / ? % plus a space and a quote.
const trickyPassword = "p@ss:w/rd?x%41 y'z"

func dsnForms(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"keyword":          "host=db.example port=5433 user=kx password=secret dbname=orig sslmode=disable",
		"keyword-quoted":   "host=db.example port=5433 user=kx password='p@ss:w/rd?x%41 y\\'z' dbname = 'orig' sslmode=require",
		"keyword-nodbname": "host=db.example port=5433 user=kx password=secret sslmode=disable",
		"url":              "postgres://kx:secret@db.example:5433/orig?sslmode=disable&application_name=a%20b",
		"postgresql-url":   "postgresql://kx:secret@db.example:5433/orig?sslmode=disable",
		"url-nodbname":     "postgres://kx:secret@db.example:5433?sslmode=disable",
		"url-encoded-pw": "postgres://" + url.UserPassword("kx", trickyPassword).String() +
			"@db.example:5433/orig?sslmode=disable",
	}
}

func TestPGReplaceDBName_BothFormsRetargetAndKeepFields(t *testing.T) {
	for name, base := range dsnForms(t) {
		t.Run(name, func(t *testing.T) {
			before, err := pgconn.ParseConfig(base)
			if err != nil {
				t.Fatalf("base %q does not parse: %v", base, err)
			}
			got := PGReplaceDBName(base, "iso_db")
			after, err := pgconn.ParseConfig(got)
			if err != nil {
				t.Fatalf("result %q does not parse: %v", got, err)
			}
			if after.Database != "iso_db" {
				t.Fatalf("Database = %q, want iso_db (dsn %q)", after.Database, got)
			}
			if after.Host != before.Host || after.Port != before.Port || after.User != before.User || after.Password != before.Password {
				t.Fatalf("connection fields changed: before %+v after %+v", before, after)
			}
			if (before.TLSConfig == nil) != (after.TLSConfig == nil) {
				t.Fatalf("sslmode not preserved (%q -> %q)", base, got)
			}
			for k, v := range before.RuntimeParams {
				if after.RuntimeParams[k] != v {
					t.Fatalf("runtime param %s = %q, want %q", k, after.RuntimeParams[k], v)
				}
			}
		})
	}
}

func TestPGReplaceDBName_SpecialCharPassword(t *testing.T) {
	forms := map[string]string{
		"keyword": "host=h user=kx password='p@ss:w/rd?x%41 y\\'z' dbname=orig sslmode=disable",
		"url":     "postgres://" + url.UserPassword("kx", trickyPassword).String() + "@h:5432/orig?sslmode=disable",
	}
	for name, base := range forms {
		t.Run(name, func(t *testing.T) {
			got := PGReplaceDBName(base, "iso_db")
			cfg, err := pgconn.ParseConfig(got)
			if err != nil {
				t.Fatalf("parse %q: %v", got, err)
			}
			if cfg.Password != trickyPassword {
				t.Fatalf("password = %q, want %q", cfg.Password, trickyPassword)
			}
			if cfg.Database != "iso_db" {
				t.Fatalf("database = %q", cfg.Database)
			}
		})
	}
}

func TestPGReplaceDBName_KeywordExactOutput(t *testing.T) {
	cases := []struct{ in, want string }{
		{"host=h dbname=x user=y", "host=h dbname=n user=y"},
		{"host=h user=y", "host=h user=y dbname=n"},
		{"dbname = 'x y' host=h", "dbname=n host=h"},
		{"host=h dbname=a dbname=b", "host=h dbname=n dbname=n"},
		{"host=h password='dbname=evil'", "host=h password='dbname=evil' dbname=n"},
	}
	for _, c := range cases {
		if got := PGReplaceDBName(c.in, "n"); got != c.want {
			t.Errorf("PGReplaceDBName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPGReplaceDBName_UnparseableURLPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for an unparseable URL DSN, not a silent no-op")
		}
	}()
	PGReplaceDBName("postgres://kx:p@ss@h:notaport/db", "n")
}
