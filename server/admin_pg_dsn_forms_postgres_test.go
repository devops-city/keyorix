package main

// admin_pg_dsn_forms_postgres_test.go is the product-path proof for
// PG-DSN-FORMS-1: operators hand the server a managed-Postgres connection
// string (postgres://...) as often as a libpq "key=value" one, so the admin
// commands must give identical results for the same database whichever form
// names it. Covers `admin verify-audit --pg-dsn`, `admin backup`, and the
// read-only part of `admin migrate` (the migration-state check of `admin
// diagnose`, plus `migrate` itself, which is an idempotent no-op on an
// already-migrated database). Gated on KEYORIX_TEST_PG_DSN (either form).
//
// Not covered here: `admin restore` (RESTORE-POPULATED-PG-1 owns it).

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
)

// dsnFormsPassword holds every character that is special in a URL userinfo
// (@ : / ? %) plus a space and a quote, which are special in key=value.
const dsnFormsPassword = "p@ss:w/rd?x%41 y'z"

var dsnFormsRoleCounter int64

type dsnForm struct {
	name string
	dsn  string
}

// kvQuote quotes a libpq key=value value.
func kvQuote(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// dsnFormsOf builds, for the database base points at, the key=value form and
// the URL forms the task lists. cfg comes from pgx's own parse of the
// KEYORIX_TEST_PG_DSN-derived DSN, so either input form works.
func dsnFormsOf(t *testing.T, base, user, password string) []dsnForm {
	t.Helper()
	cfg, err := pgconn.ParseConfig(base)
	require.NoError(t, err)
	hostport := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	u := func(q string) string {
		s := "postgres://" + url.UserPassword(user, password).String() + "@" + hostport + "/" + cfg.Database
		if q != "" {
			s += "?" + q
		}
		return s
	}
	return []dsnForm{
		{"keyvalue", fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			cfg.Host, cfg.Port, user, kvQuote(password), cfg.Database)},
		{"url", u("")},
		{"url-sslmode-disable", u("sslmode=disable")},
		{"postgresql-scheme", strings.Replace(u("sslmode=disable"), "postgres://", "postgresql://", 1)},
	}
}

// createDSNFormsRole creates a login role whose password is dsnFormsPassword
// and makes it own every table of the database, so the admin commands run as
// it. Dropped on cleanup.
func createDSNFormsRole(t *testing.T, base, isolated string) string {
	t.Helper()
	role := fmt.Sprintf("kx_dsn_forms_%d_%d", os.Getpid(), atomic.AddInt64(&dsnFormsRoleCounter, 1))
	open := func(dsn string) *gorm.DB {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { _ = sqlDB.Close() })
		return db
	}
	admin := open(base)
	lit := strings.ReplaceAll(dsnFormsPassword, "'", "''")
	require.NoError(t, admin.Exec(fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, lit)).Error)
	t.Cleanup(func() {
		_ = admin.Exec(fmt.Sprintf("DROP OWNED BY %s", role)).Error
		_ = admin.Exec(fmt.Sprintf("DROP ROLE IF EXISTS %s", role)).Error
	})

	iso := open(isolated)
	require.NoError(t, iso.Exec(fmt.Sprintf("GRANT ALL ON SCHEMA public TO %s", role)).Error)
	require.NoError(t, iso.Exec(fmt.Sprintf(`DO $$ DECLARE r record; BEGIN
		FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
			EXECUTE format('ALTER TABLE public.%%I OWNER TO %s', r.tablename);
		END LOOP;
		FOR r IN SELECT p.oid::regprocedure::text AS sig FROM pg_proc p
			JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = 'public'
			AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e') LOOP
			EXECUTE format('ALTER FUNCTION %%s OWNER TO %s', r.sig);
		END LOOP; END $$`, role, role)).Error)
	return role
}

func writeAdminPGConfig(t *testing.T, dir, dsn string) {
	t.Helper()
	cfg := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: "8080"
  grpc:
    enabled: false
`, dsn)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(cfg), 0o600))
}

func readBackupManifest(t *testing.T, path string) backupfmt.Manifest {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test-created path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, "MANIFEST.json", hdr.Name)
	var m backupfmt.Manifest
	require.NoError(t, json.NewDecoder(tr).Decode(&m))
	return m
}

var generatedAtLine = regexp.MustCompile(`(?m)^Generated at \S+ `)

var migrationStateLine = regexp.MustCompile(`(?m)^\[\s*\w+\s*\] migration state.*$`)

func TestAdminPostgres_DSNForms_ProductPath(t *testing.T) {
	base := adminPgTestDSN(t)
	isolated := adminPgIsolatedDatabaseDSN(t, base)
	baseCfg, err := pgconn.ParseConfig(isolated)
	require.NoError(t, err)

	bin := buildServerBinary(t)
	dir, env := setupVerifyAuditPostgresDB(t, bin, isolated)
	seedAuditChainPG(t, isolated, 10)

	role := createDSNFormsRole(t, base, isolated)
	forms := dsnFormsOf(t, isolated, baseCfg.User, baseCfg.Password)
	// Same database, other principal: a percent-encoded password in URL form
	// and the same password quoted in key=value form.
	for _, f := range dsnFormsOf(t, isolated, role, dsnFormsPassword) {
		if f.name == "keyvalue" || f.name == "url" {
			forms = append(forms, dsnForm{"role-" + f.name + "-special-password", f.dsn})
		}
	}

	// 1. verify-audit --pg-dsn is read-only, so run it for every form before
	// any config-based command appends audit rows: the reports must be
	// byte-identical.
	var refOut string
	for i, f := range forms {
		out, code := verifyAuditExitCode(t, bin, dir, env, "--pg-dsn", f.dsn)
		require.Equal(t, 0, code, "verify-audit --pg-dsn (%s):\n%s", f.name, out)
		out = generatedAtLine.ReplaceAllString(out, "Generated at <ts> ")
		require.Contains(t, out, "chained events:   ", f.name)
		if i == 0 {
			refOut = out
			continue
		}
		require.Equal(t, refOut, out, "verify-audit report differs between %s and %s", forms[0].name, f.name)
	}

	// 2. diagnose's migration-state check, migrate (a no-op here) and backup,
	// each through a config file carrying the DSN in that form.
	var refManifest *backupfmt.Manifest
	var refState string
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			writeAdminPGConfig(t, dir, f.dsn)

			out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
			require.NoError(t, err, "diagnose:\n%s", out)
			state := migrationStateLine.FindString(out)
			require.NotEmpty(t, state, "no migration-state line in diagnose output:\n%s", out)
			require.Contains(t, state, "[ OK ]", "migration state not OK:\n%s", out)
			if refState == "" {
				refState = state
			}
			require.Equal(t, refState, state)

			out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
			require.NoError(t, err, "migrate:\n%s", out)

			archive := filepath.Join(dir, "backup-"+f.name+".tar.gz")
			out, err = runAdmin(t, bin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", archive)
			require.NoError(t, err, "backup:\n%s", out)
			require.Contains(t, out, "Backup written to")

			m := readBackupManifest(t, archive)
			if refManifest == nil {
				refManifest = &m
				return
			}
			require.Equal(t, refManifest.SchemaEpoch, m.SchemaEpoch)
			require.Equal(t, len(refManifest.KeyFiles), len(m.KeyFiles))
			require.Equal(t, len(refManifest.Tables), len(m.Tables))
			for i, want := range refManifest.Tables {
				got := m.Tables[i]
				require.Equal(t, want.Name, got.Name)
				require.Equal(t, want.Columns, got.Columns, "table %s columns", want.Name)
				if got.Name == "audit_events" {
					// each admin command records its own audit event
					require.GreaterOrEqual(t, got.RowCount, want.RowCount)
					continue
				}
				require.Equal(t, want.RowCount, got.RowCount, "table %s row count", want.Name)
			}
		})
	}
}

// TestAdminPostgres_DSNForms_IsolatedDatabaseIsNotTheSharedOne is the
// regression test for #3346: with a URL KEYORIX_TEST_PG_DSN the "isolated"
// database used to be the shared one.
func TestAdminPostgres_DSNForms_IsolatedDatabaseIsNotTheSharedOne(t *testing.T) {
	base := adminPgTestDSN(t)
	isolated := adminPgIsolatedDatabaseDSN(t, base)

	baseCfg, err := pgconn.ParseConfig(base)
	require.NoError(t, err)
	isoCfg, err := pgconn.ParseConfig(isolated)
	require.NoError(t, err)
	require.NotEqual(t, baseCfg.Database, isoCfg.Database)
	require.True(t, strings.HasPrefix(isoCfg.Database, "admin_pr11_"), isoCfg.Database)
	require.Equal(t, baseCfg.Password, isoCfg.Password)
	require.Equal(t, replaceAdminDBName(base, isoCfg.Database), isolated)
}
