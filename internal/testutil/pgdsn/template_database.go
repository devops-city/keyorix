package pgdsn

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TemplateEnv switches template cloning off when set to "0": MigratedDatabase
// then creates an empty database and runs the migration in it, as every test
// did before templates. Use it to debug a migration or a template problem.
const TemplateEnv = "KEYORIX_TEST_PG_TEMPLATE"

const (
	// templateLockKey is the fixed advisory lock key ("kxtpl") that serializes
	// template creation, cloning and clean-up on one server, across test
	// processes and sessions. Postgres refuses CREATE DATABASE ... TEMPLATE
	// while any other session is connected to the template, which includes
	// another CREATE DATABASE cloning it, so clones take the lock too.
	templateLockKey int64 = 0x6b78_7470_6c

	// templateMarker prefixes the database comment that records when a
	// template (or an unfinished build of one) was created: Postgres keeps no
	// creation time for a database.
	templateMarker = "kxtpl:"

	// StaleTemplateAge is how old a template of a non-current fingerprint must
	// be before the first use in a process drops it.
	StaleTemplateAge = 24 * time.Hour

	maxTemplatePrefix = 40 // identifiers are 63 bytes: prefix + "_tpl_" + 12 hex + "_b<pid>"
)

// Migrator brings an empty database to the schema the tests need. The caller
// passes it in because this package cannot import internal/storage (package
// storage's own tests import pgdsn).
type Migrator func(db *gorm.DB) error

var (
	templateMu      sync.Mutex
	templateReady   = map[string]string{} // base|fingerprint -> template database name
	templateCleaned = map[string]bool{}   // base -> stale templates already dropped by this process
)

// MigratedDatabase returns base pointed at a fresh database that already holds
// the schema migrate builds, and drops it on test cleanup.
//
// The first call per (server, fingerprint) builds a template database once
// (under an advisory lock, so parallel test processes and sessions sharing the
// server build it once); every call then clones it with CREATE DATABASE ...
// TEMPLATE, which copies files instead of replaying the migration. Change the
// fingerprint when the migration's inputs change (see SourceFingerprint) and a
// new template is built. Tests never connect to a template.
//
// Tests of the migration itself (empty or old schemas, upgrade paths) must use
// IsolatedDatabase, not this.
func MigratedDatabase(tb testing.TB, base, prefix, fingerprint string, migrate Migrator) string {
	tb.Helper()
	if os.Getenv(TemplateEnv) == "0" || fingerprint == "" {
		return migratedWithoutTemplate(tb, base, prefix, migrate)
	}
	ctx := context.Background()
	tpl, err := templateFor(ctx, base, fingerprint, migrate)
	if err != nil {
		tb.Fatalf("template database for %s: %v", fingerprint, err)
	}
	name := fmt.Sprintf("%s_%d_%d", prefix, os.Getpid(), isolatedDBCounter.Add(1))
	if err := cloneDatabase(ctx, base, tpl, name); err != nil {
		tb.Fatalf("clone template %s into %s: %v", tpl, name, err)
	}
	tb.Cleanup(func() { _ = execOn(ctx, base, "DROP DATABASE IF EXISTS "+quoteIdent(name)+" WITH (FORCE)") })
	return PGReplaceDBName(base, name)
}

func migratedWithoutTemplate(tb testing.TB, base, prefix string, migrate Migrator) string {
	tb.Helper()
	dsn := IsolatedDatabase(tb, base, prefix)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open %s: %v", DatabaseName(dsn), err)
	}
	defer closeGorm(db)
	if err := migrate(db); err != nil {
		tb.Fatalf("migrate %s: %v", DatabaseName(dsn), err)
	}
	return dsn
}

// templateFor returns the name of the template for fingerprint, building it on
// first use in this process and dropping stale templates once per server.
func templateFor(ctx context.Context, base, fingerprint string, migrate Migrator) (string, error) {
	templateMu.Lock()
	defer templateMu.Unlock()
	key := base + "|" + fingerprint
	if name, ok := templateReady[key]; ok {
		return name, nil
	}
	name, err := ensureTemplate(ctx, base, fingerprint, migrate)
	if err != nil {
		return "", err
	}
	templateReady[key] = name
	if !templateCleaned[base] {
		templateCleaned[base] = true
		_ = dropStaleTemplates(ctx, base, fingerprint, StaleTemplateAge) // best effort: never fails a test
	}
	return name, nil
}

// TemplateName is the template database name for fingerprint on the server at
// base. It starts with base's own database name, so a role that may only
// create databases carrying its tag slug (kpg) may create it.
func TemplateName(base, fingerprint string) string {
	return templatePrefix(base) + "_tpl_" + shortFingerprint(fingerprint)
}

func templatePrefix(base string) string {
	p := DatabaseName(base)
	if p == "" {
		p = "keyorix_test"
	}
	if len(p) > maxTemplatePrefix {
		p = p[:maxTemplatePrefix]
	}
	return p
}

// shortFingerprint maps any fingerprint to 12 hex characters of its SHA-256,
// so two fingerprints never share a template name just because they share a
// prefix, and the name is always a safe identifier.
func shortFingerprint(fp string) string {
	if fp == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(sum[:])[:12]
}

// ensureTemplate builds the template for fingerprint unless it exists
// ("IF NOT EXISTS" under the advisory lock). It builds under a temporary name
// and renames only after the migration succeeded, so a process killed
// half-way leaves nothing another process could clone.
func ensureTemplate(ctx context.Context, base, fingerprint string, migrate Migrator) (string, error) {
	name := TemplateName(base, fingerprint)
	if fingerprint == "" {
		return "", errors.New("empty fingerprint")
	}
	return name, withLock(ctx, base, func(conn *sql.Conn) error {
		var isTemplate sql.NullBool
		err := conn.QueryRowContext(ctx, "SELECT datistemplate FROM pg_database WHERE datname = $1", name).Scan(&isTemplate)
		switch {
		case err == nil && isTemplate.Bool:
			return nil
		case err == nil:
			// Renamed but never marked: a builder died between the two statements.
			if _, e := conn.ExecContext(ctx, "DROP DATABASE "+quoteIdent(name)+" WITH (FORCE)"); e != nil {
				return e
			}
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}

		build := fmt.Sprintf("%s_b%d", name, os.Getpid())
		_, _ = conn.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(build)+" WITH (FORCE)")
		if _, err := conn.ExecContext(ctx, "CREATE DATABASE "+quoteIdent(build)); err != nil {
			return fmt.Errorf("create %s: %w", build, err)
		}
		ok := false
		defer func() {
			if !ok {
				_, _ = conn.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(build)+" WITH (FORCE)")
			}
		}()
		if err := setCreatedComment(ctx, conn, build, time.Now()); err != nil {
			return err
		}
		if err := migrateInto(PGReplaceDBName(base, build), migrate); err != nil {
			return fmt.Errorf("migrate %s: %w", build, err)
		}
		if _, err := conn.ExecContext(ctx, "ALTER DATABASE "+quoteIdent(build)+" RENAME TO "+quoteIdent(name)); err != nil {
			return err
		}
		ok = true // the name is final from here; a half-marked template is repaired above
		_, err = conn.ExecContext(ctx, "ALTER DATABASE "+quoteIdent(name)+" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false")
		return err
	})
}

func migrateInto(dsn string, migrate Migrator) error {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	defer closeGorm(db) // CREATE/RENAME need every connection gone
	return migrate(db)
}

// cloneDatabase creates name from template tpl, under the advisory lock.
func cloneDatabase(ctx context.Context, base, tpl, name string) error {
	return withLock(ctx, base, func(conn *sql.Conn) error {
		stmt := "CREATE DATABASE " + quoteIdent(name) + " TEMPLATE " + quoteIdent(tpl) // #nosec G202 -- both names go through pgx.Identifier.Sanitize; DDL cannot take bind parameters
		var err error
		for range 20 {
			if _, err = conn.ExecContext(ctx, stmt); err == nil {
				return nil
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55006" { // object_in_use: someone connected to the template
				return err
			}
			time.Sleep(100 * time.Millisecond)
		}
		return err
	})
}

// dropStaleTemplates drops templates (and abandoned builds) of this server
// whose fingerprint is not current and which are older than maxAge. It holds
// the advisory lock, so no process is cloning one while it is dropped; a
// template that is still in use fails to drop and is left for the next run.
func dropStaleTemplates(ctx context.Context, base, currentFingerprint string, maxAge time.Duration) error {
	current := TemplateName(base, currentFingerprint)
	prefix := templatePrefix(base) + "_tpl_"
	return withLock(ctx, base, func(conn *sql.Conn) error {
		rows, err := conn.QueryContext(ctx,
			"SELECT datname, COALESCE(shobj_description(oid, 'pg_database'), '') FROM pg_database WHERE starts_with(datname, $1)", prefix)
		if err != nil {
			return err
		}
		type cand struct{ name, comment string }
		var cands []cand
		for rows.Next() {
			var c cand
			if err := rows.Scan(&c.name, &c.comment); err != nil {
				_ = rows.Close()
				return err
			}
			cands = append(cands, c)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		_ = rows.Close()
		for _, c := range cands {
			if c.name == current || strings.HasPrefix(c.name, current+"_b") {
				continue
			}
			created, ok := parseCreatedComment(c.comment)
			if !ok || time.Since(created) < maxAge {
				continue // not one of ours, or too young
			}
			_, _ = conn.ExecContext(ctx, "ALTER DATABASE "+quoteIdent(c.name)+" WITH IS_TEMPLATE false")
			_, _ = conn.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(c.name))
		}
		return nil
	})
}

func setCreatedComment(ctx context.Context, conn *sql.Conn, db string, at time.Time) error {
	_, err := conn.ExecContext(ctx, "COMMENT ON DATABASE "+quoteIdent(db)+" IS '"+templateMarker+strconv.FormatInt(at.Unix(), 10)+"'")
	return err
}

func parseCreatedComment(c string) (time.Time, bool) {
	s, ok := strings.CutPrefix(c, templateMarker)
	if !ok {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// withLock runs f on one pinned connection to base holding the template
// advisory lock. Closing the connection releases the lock even if f panics.
func withLock(ctx context.Context, base string, f func(conn *sql.Conn) error) error {
	db, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	defer closeGorm(db)
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", templateLockKey); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", templateLockKey)
	}()
	return f(conn)
}

func execOn(ctx context.Context, base, stmt string) error {
	db, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	defer closeGorm(db)
	return db.WithContext(ctx).Exec(stmt).Error
}

func closeGorm(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

func quoteIdent(name string) string { return pgx.Identifier{name}.Sanitize() }

// DatabaseName returns the database a DSN of either accepted form points at,
// or "" when it names none.
func DatabaseName(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(u.Path, "/")
	}
	for f := range strings.FieldsSeq(dsn) {
		if v, ok := strings.CutPrefix(f, "dbname="); ok {
			return v
		}
	}
	return ""
}

// SchemaFingerprint is SourceFingerprint() computed once per process: the
// sources do not change while a test binary runs.
var SchemaFingerprint = sync.OnceValue(func() string { return SourceFingerprint() })

// SourceFingerprint hashes the inputs of the production schema migration: the
// non-test Go and SQL sources under internal/storage (models, store, migration
// code and SQL) and go.mod/go.sum (the module versions of gorm, pgx and the
// rest), plus extra. A schema change therefore changes the fingerprint and
// builds a new template. It returns "" when the sources cannot be read (a test
// binary run away from the checkout), which makes MigratedDatabase migrate
// without a template.
func SourceFingerprint(extra ...string) string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	root := filepath.Join(filepath.Dir(self), "..", "..", "..") // internal/testutil/pgdsn -> repo root
	var files []string
	err := filepath.WalkDir(filepath.Join(root, "internal", "storage"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		n := d.Name()
		if (strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go")) || strings.HasSuffix(n, ".sql") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil || len(files) == 0 {
		return ""
	}
	files = append(files, filepath.Join(root, "go.mod"), filepath.Join(root, "go.sum"))
	sort.Strings(files)
	h := sha256.New()
	for _, p := range files {
		b, err := os.ReadFile(p) // #nosec G304 -- paths come from walking this repo's own tree
		if err != nil {
			return ""
		}
		rel, _ := filepath.Rel(root, p)
		h.Write([]byte(filepath.ToSlash(rel) + "\x00" + strconv.Itoa(len(b)) + "\x00")) //nolint:errcheck // hash.Hash.Write never fails
		h.Write(b)                                                                      //nolint:errcheck // hash.Hash.Write never fails
	}
	for _, e := range extra {
		h.Write([]byte("extra\x00" + e + "\x00")) //nolint:errcheck // hash.Hash.Write never fails
	}
	return hex.EncodeToString(h.Sum(nil))
}
