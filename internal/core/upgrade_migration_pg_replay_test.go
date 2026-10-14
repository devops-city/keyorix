//go:build !windows

package core

// upgrade_migration_pg_replay_test.go -- E4: PostgreSQL path for
// FuzzUpgradeMigration (see upgrade_migration_fuzz_test.go's package doc for
// the harness's own scope note: "PostgreSQL is explicitly NOT implemented
// here -- a real Postgres replay-and-migrate mechanism would need to be
// built and verified against a live instance, and no local PostgreSQL was
// available in this environment to do that safely").
//
// Each fixture.db is a REAL SQLite database in its own pre-migration (old
// tag) schema shape. There is no equivalent Postgres fixture -- one was
// never captured -- so this file builds one MECHANICALLY at test time: it
// reads the fixture's OWN sqlite_master table definitions and row data (not
// a hand-maintained duplicate of the schema, which would drift the moment a
// model gains a field) and replays both onto a fresh, isolated Postgres
// schema. storagefactory.NewStorageFactory().CreateStorage then runs HEAD's
// real migration path against that replayed pre-migration state, exactly as
// the SQLite side already does against the fixture file directly. The same
// 4 oracles from upgrade_migration_fuzz_test.go are reused unchanged -- see
// runUpgradeOracles, factored out of FuzzUpgradeMigration for this purpose --
// so there is no separate, potentially-diverging copy of the oracle logic
// for each backend.
//
// Type mapping SQLite -> Postgres is derived from the actual declared
// storage-class token in the fixture's own CREATE TABLE SQL (integer,
// numeric, real, text, blob, datetime -- confirmed the complete set via
// `sqlite3 fixture.db ".schema"` across all 3 fixtures before writing this),
// not assumed. `numeric` is GORM's sqlite dialect's affinity for Go bool
// fields throughout this schema (checked: every `numeric` column here is
// boolean-named -- is_active, enabled, revoked, etc. -- with a true/false or
// no default, never used for an actual numeric quantity), so it maps to
// Postgres boolean, converting the underlying 0/1 integer storage value
// explicitly rather than relying on an implicit driver cast.
import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var upgradePGSchemaSeq atomic.Int64

// runUpgradeOracles asserts the same 4 invariants FuzzUpgradeMigration checks
// on SQLite, against an already-migrated backend (st/c) plus a raw *gorm.DB
// (orphanDB) opened on the SAME migrated database for oracle 4's raw-SQL
// orphan check. Factored out so SQLite and Postgres share one oracle
// implementation -- see this file's package doc.
func runUpgradeOracles(t *testing.T, c *KeyorixCore, orphanDB *gorm.DB, manifest upgradeFuzzManifest) {
	t.Helper()
	ctx := t.Context()

	// Oracle 1: every secret decrypts to its recorded plaintext.
	for idStr, want := range manifest.SecretValues {
		var id uint
		if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
			t.Fatalf("manifest secret id %q: %v", idStr, err)
		}
		got, err := c.GetSecretValue(ctx, id)
		if err != nil {
			t.Fatalf("GetSecretValue(%d) after migrating a %s-vintage database: %v", id, manifest.SourceTag, err)
		}
		if string(got) != want {
			t.Errorf("secret %d decrypted to %q after migration, want %q (source=%s)", id, got, want, manifest.SourceTag)
		}
	}

	// Oracle 2: the fixed authz probe gives the same verdict the OLD tag's
	// own core.Authorize recorded at seed time.
	allowRead, err := c.Authorize(ctx, manifest.ProbeUserID, "secrets.read", Scope{ProjectID: manifest.ProbeProjectID})
	if err != nil {
		t.Fatalf("Authorize(read) after migration: %v", err)
	}
	if allowRead != manifest.ProbeAllowRead {
		t.Errorf("secrets.read verdict changed after migrating a %s-vintage database: was %v, now %v",
			manifest.SourceTag, manifest.ProbeAllowRead, allowRead)
	}
	allowWrite, err := c.Authorize(ctx, manifest.ProbeUserID, "secrets.write", Scope{ProjectID: manifest.ProbeProjectID})
	if err != nil {
		t.Fatalf("Authorize(write) after migration: %v", err)
	}
	if allowWrite != manifest.ProbeAllowWrite {
		t.Errorf("secrets.write verdict changed after migrating a %s-vintage database: was %v, now %v",
			manifest.SourceTag, manifest.ProbeAllowWrite, allowWrite)
	}

	// Oracle 3: the audit hash chain still verifies.
	verification, err := c.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain after migration: %v", err)
	}
	if !verification.Valid {
		t.Errorf("audit chain failed to verify after migrating a %s-vintage database: first broken id=%v (chained=%d, unchained=%d)",
			manifest.SourceTag, verification.FirstBrokenID, verification.ChainedEvents, verification.UnchainedEvents)
	}

	// Oracle 4: no orphan rows introduced by migration -- same raw-SQL
	// checks as assertNoOrphans, against whichever *gorm.DB the caller
	// opened (sqlite file or Postgres schema).
	checks := []struct {
		desc  string
		query string
	}{
		{"SecretVersion with no parent SecretNode",
			"SELECT COUNT(*) FROM secret_versions sv LEFT JOIN secret_nodes sn ON sv.secret_node_id = sn.id WHERE sn.id IS NULL"},
		{"UserRole with no parent User",
			"SELECT COUNT(*) FROM user_roles ur LEFT JOIN users u ON ur.user_id = u.id WHERE u.id IS NULL"},
		{"UserRole with no parent Role",
			"SELECT COUNT(*) FROM user_roles ur LEFT JOIN roles r ON ur.role_id = r.id WHERE r.id IS NULL"},
		{"RolePermission with no parent Role",
			"SELECT COUNT(*) FROM role_permissions rp LEFT JOIN roles r ON rp.role_id = r.id WHERE r.id IS NULL"},
	}
	for _, chk := range checks {
		var count int64
		if err := orphanDB.Raw(chk.query).Scan(&count).Error; err != nil {
			t.Fatalf("orphan check %q: %v", chk.desc, err)
		}
		if count > 0 {
			t.Errorf("%d orphan row(s) after migrating a %s-vintage database: %s", count, manifest.SourceTag, chk.desc)
		}
	}
}

// pgColumnDef is one parsed SQLite column: its Postgres-translated DDL
// fragment plus the ORIGINAL sqlite storage-class token, needed later to
// convert scanned row values correctly (in particular, numeric -> bool).
type pgColumnDef struct {
	name       string
	pgDDL      string // "<name> <pgtype> <constraints...>"
	sqliteType string // lowercase: integer|numeric|real|text|blob|datetime
	isSerialPK bool
}

var ddlColRe = regexp.MustCompile("^`([a-zA-Z0-9_]+)`\\s+([a-zA-Z]+)(.*)$")

// splitTopLevel splits s on commas at paren-depth 0 -- a plain strings.Split
// would break composite PRIMARY KEY/UNIQUE clauses like
// "PRIMARY KEY (`a`,`b`)", whose internal comma is not a field separator.
func splitTopLevel(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// translateCreateTable converts one sqlite_master CREATE TABLE statement
// (GORM's sqlite dialect output) into Postgres DDL, returning the translated
// statement and each column's original sqlite type for later row-value
// conversion. See this file's package doc for the derivation of the type map
// and the confirmed-complete token set (integer/numeric/real/text/blob/datetime).
func translateCreateTable(createSQL string) (pgDDL string, cols map[string]pgColumnDef, err error) {
	open := strings.IndexByte(createSQL, '(')
	close := strings.LastIndexByte(createSQL, ')')
	if open < 0 || close < 0 || close < open {
		return "", nil, fmt.Errorf("unrecognized CREATE TABLE shape: %s", createSQL)
	}
	header := createSQL[:open] // "CREATE TABLE `name` "
	body := createSQL[open+1 : close]

	header = strings.ReplaceAll(header, "`", "")

	cols = make(map[string]pgColumnDef)
	var outParts []string
	for _, raw := range splitTopLevel(body) {
		seg := strings.TrimSpace(raw)
		if seg == "" {
			continue
		}
		if !strings.HasPrefix(seg, "`") {
			// Table-level constraint (PRIMARY KEY(...)/CONSTRAINT ... UNIQUE(...)):
			// backtick-quoted lowercase snake_case identifiers are valid,
			// unquoted Postgres identifiers, so stripping backticks is sufficient.
			outParts = append(outParts, strings.ReplaceAll(seg, "`", ""))
			continue
		}
		m := ddlColRe.FindStringSubmatch(seg)
		if m == nil {
			return "", nil, fmt.Errorf("unrecognized column def: %s", seg)
		}
		name := m[1]
		sqliteType := strings.ToLower(m[2])
		rest := strings.TrimSpace(m[3])

		def := pgColumnDef{name: name, sqliteType: sqliteType}
		var pgType string
		switch sqliteType {
		case "integer":
			if strings.Contains(rest, "PRIMARY KEY") && strings.Contains(rest, "AUTOINCREMENT") {
				outParts = append(outParts, name+" SERIAL PRIMARY KEY")
				def.pgDDL = name + " SERIAL PRIMARY KEY"
				def.isSerialPK = true
				cols[name] = def
				continue
			}
			pgType = "integer"
		case "numeric":
			pgType = "boolean"
		case "datetime":
			pgType = "timestamptz"
		case "real":
			pgType = "double precision"
		case "blob":
			pgType = "bytea"
		case "text":
			pgType = "text"
		default:
			pgType = sqliteType
		}
		rest = strings.ReplaceAll(rest, `DEFAULT "`, "DEFAULT '")
		rest = regexp.MustCompile(`DEFAULT '([^"]*)"`).ReplaceAllString(rest, "DEFAULT '$1'")
		colDDL := strings.TrimSpace(name + " " + pgType + " " + rest)
		def.pgDDL = colDDL
		cols[name] = def
		outParts = append(outParts, colDDL)
	}
	pgDDL = header + "(" + strings.Join(outParts, ", ") + ")"
	return pgDDL, cols, nil
}

// pgValueFor converts one value scanned from the SQLite fixture into the
// Go value Postgres' driver should receive for that column, based on the
// column's ORIGINAL sqlite storage-class token (not the scanned Go type
// alone, which for a `numeric` column is an ambiguous 0/1 integer that must
// become a real bool to satisfy the boolean column this DDL now declares).
func pgValueFor(sqliteType string, v any) any {
	if v == nil {
		return nil
	}
	switch sqliteType {
	case "numeric":
		switch t := v.(type) {
		case int64:
			return t != 0
		case float64:
			return t != 0
		case []byte:
			s := string(t)
			return s == "1" || strings.EqualFold(s, "true")
		case string:
			return t == "1" || strings.EqualFold(t, "true")
		case bool:
			return t
		default:
			return v
		}
	case "datetime":
		var s string
		switch t := v.(type) {
		case string:
			s = t
		case []byte:
			s = string(t)
		default:
			return v
		}
		for _, layout := range []string{
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999Z07:00",
			time.RFC3339Nano,
			time.RFC3339,
		} {
			if pt, perr := time.Parse(layout, s); perr == nil {
				return pt
			}
		}
		return s
	case "blob":
		switch t := v.(type) {
		case []byte:
			return t
		case string:
			return []byte(t)
		default:
			return v
		}
	default:
		return v
	}
}

// replayFixtureIntoPostgres mechanically rebuilds sqliteDBPath's OWN
// pre-migration schema and row data inside a fresh, isolated Postgres schema
// on pgAdminDSN, and returns a schema-scoped DSN pointing at it -- ready for
// storagefactory.NewStorageFactory().CreateStorage to run the real migration
// path against, exactly mirroring what happens natively when the SQLite side
// copies the fixture file and migrates it in place.
func replayFixtureIntoPostgres(t *testing.T, sqliteDBPath, pgAdminDSN string) string {
	t.Helper()

	schema := fmt.Sprintf("upgradefuzz_%d_%d", os.Getpid(), upgradePGSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgAdminDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open pg admin: %v", err)
	}
	adminDB, err := admin.DB()
	if err != nil {
		t.Fatalf("pg admin DB(): %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		t.Fatalf("pg drop schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("pg create schema: %v", err)
	}
	_ = adminDB.Close()
	t.Cleanup(func() {
		if c, e := gorm.Open(postgres.Open(pgAdminDSN), &gorm.Config{Logger: logger.Discard}); e == nil {
			_ = c.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
			if cdb, e2 := c.DB(); e2 == nil {
				_ = cdb.Close()
			}
		}
	})
	pgTargetDSN := pgdsn.PGSearchPathDSN(pgAdminDSN, schema)

	pgGorm, err := gorm.Open(postgres.Open(pgTargetDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open pg target: %v", err)
	}
	pgDB, err := pgGorm.DB()
	if err != nil {
		t.Fatalf("pg target DB(): %v", err)
	}
	// Closed once the replay below finishes -- CreateStorage (called by the
	// caller right after this function returns) opens its own connection to
	// the same DSN. Leaving this one open too would leak a connection per
	// fuzz iteration and exhaust Postgres' max_connections under sustained
	// fuzzing (confirmed: a 60s/-parallel=2 burst hit "sorry, too many
	// clients already" within ~10s before this fix).
	defer func() { _ = pgDB.Close() }()

	sqliteGorm, err := gorm.Open(sqlite.Open(sqliteDBPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite fixture %s: %v", sqliteDBPath, err)
	}
	sqliteDB, err := sqliteGorm.DB()
	if err != nil {
		t.Fatalf("sqlite fixture DB(): %v", err)
	}
	defer func() { _ = sqliteDB.Close() }()

	type tableDef struct {
		name string
		sql  string
	}
	var tables []tableDef
	rows, err := sqliteDB.Query(`SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("listing sqlite tables: %v", err)
	}
	for rows.Next() {
		var td tableDef
		if err := rows.Scan(&td.name, &td.sql); err != nil {
			t.Fatalf("scanning sqlite_master row: %v", err)
		}
		tables = append(tables, td)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating sqlite_master: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("closing sqlite_master rows: %v", err)
	}
	if len(tables) == 0 {
		t.Fatalf("no tables found in fixture %s -- sqlite_master query returned nothing", sqliteDBPath)
	}

	for _, td := range tables {
		pgDDL, cols, terr := translateCreateTable(td.sql)
		if terr != nil {
			t.Fatalf("translating DDL for table %s: %v", td.name, terr)
		}
		if _, err := pgDB.Exec(pgDDL); err != nil {
			t.Fatalf("creating postgres table %s (DDL: %s): %v", td.name, pgDDL, err)
		}
		replayTableRows(t, sqliteDB, pgDB, td.name, cols)
	}

	return pgTargetDSN
}

// replayTableRows copies every row of one table from sqlite to postgres,
// converting each value per its ORIGINAL sqlite column type.
func replayTableRows(t *testing.T, sqliteDB, pgDB *sql.DB, table string, cols map[string]pgColumnDef) {
	t.Helper()
	rows, err := sqliteDB.Query("SELECT * FROM " + table) //nolint:gosec // table name is sqlite_master-derived, not user input
	if err != nil {
		t.Fatalf("reading rows from sqlite table %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	colNames, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}

	var insertedAny bool
	for rows.Next() {
		dest := make([]any, len(colNames))
		ptrs := make([]any, len(colNames))
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scanning row from %s: %v", table, err)
		}

		placeholders := make([]string, len(colNames))
		vals := make([]any, len(colNames))
		for i, cn := range colNames {
			placeholders[i] = "$" + strconv.Itoa(i+1)
			def, ok := cols[cn]
			if !ok {
				vals[i] = dest[i]
				continue
			}
			vals[i] = pgValueFor(def.sqliteType, dest[i])
		}
		insertSQL := "INSERT INTO " + table + " (" + strings.Join(colNames, ",") + ") VALUES (" + strings.Join(placeholders, ",") + ")" //nolint:gosec
		if _, err := pgDB.Exec(insertSQL, vals...); err != nil {
			t.Fatalf("replaying row into postgres table %s: %v (sql=%s vals=%v)", table, err, insertSQL, vals)
		}
		insertedAny = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating rows of %s: %v", table, err)
	}
	_ = insertedAny
}

// FuzzUpgradeMigrationPostgres is E4: the same FuzzUpgradeMigration oracles
// (see runUpgradeOracles), run against a Postgres database mechanically
// replayed from the same 3 real historical fixtures FuzzUpgradeMigration
// uses for SQLite. Skips cleanly without KEYORIX_TEST_PG_DSN, matching every
// other PG-gated harness in this repo (e.g.
// internal/storage/store/backend_differential_fuzz_test.go).
func FuzzUpgradeMigrationPostgres(f *testing.F) {
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		f.Skip("KEYORIX_TEST_PG_DSN not set -- Postgres upgrade-migration fuzzing needs a real Postgres (rig-only)")
	}
	for i := range upgradeFuzzFixtures {
		f.Add(uint8(i))
	}

	f.Fuzz(func(t *testing.T, sel uint8) {
		name := upgradeFuzzFixtures[int(sel)%len(upgradeFuzzFixtures)]
		srcDir := filepath.Join("testdata", "upgrade-fixtures", name)
		if _, err := os.Stat(srcDir); err != nil {
			t.Skipf("fixture %s not present: %v", name, err)
		}
		manifest := loadUpgradeFuzzManifest(t, filepath.Join(srcDir, "manifest.json"))

		pgTargetDSN := replayFixtureIntoPostgres(t, filepath.Join(srcDir, "fixture.db"), pgDSN)

		workDir := t.TempDir()
		copyFileT(t, filepath.Join(srcDir, "dek.key"), filepath.Join(workDir, "dek.key"))
		copyFileT(t, filepath.Join(srcDir, "kek.salt"), filepath.Join(workDir, "kek.salt"))

		cfg := &config.Config{
			Storage: config.StorageConfig{
				Type:     "postgres",
				Database: config.DatabaseConfig{DSN: pgTargetDSN},
				Encryption: config.EncryptionConfig{
					Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt",
				},
			},
		}

		// The real production migration path, targeting the replayed
		// pre-migration Postgres schema -- exactly what
		// FuzzUpgradeMigration does for the SQLite fixture file directly.
		st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
		if err != nil {
			t.Fatalf("CreateStorage (real migration path, postgres) failed on a %s-vintage database: %v", manifest.SourceTag, err)
		}
		// CreateStorage opens its OWN *sql.DB connection pool, separate from
		// orphanDB's below -- unlike the SQLite path (a file, closed by the OS
		// when the process/temp dir goes away), a Postgres connection is a
		// live server-side resource that outlives this function unless closed
		// explicitly. Confirmed by reproducing it: a fresh 60s/-parallel=2
		// burst without this close hit "sorry, too many clients already"
		// (Postgres' max_connections) after ~99 iterations -- one leaked
		// connection per iteration, never released.
		// Close releases every pool the factory opened (request, lock and
		// native read pools), not only the request pool.
		if closer, ok := st.(interface{ Close() error }); ok {
			defer func() { _ = closer.Close() }()
		}

		enc := encryption.NewService(&cfg.Storage.Encryption, workDir)
		if err := enc.Initialize(manifest.Passphrase); err != nil {
			t.Fatalf("re-opening the encryption service with the fixture's own passphrase: %v", err)
		}

		c := NewKeyorixCore(st)
		c.SetAuthEncryptor(enc)
		c.SetSecretValueEncryptor(enc)

		orphanDB, err := gorm.Open(postgres.Open(pgTargetDSN), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("reopening postgres target for orphan check: %v", err)
		}
		if sqlDB, e := orphanDB.DB(); e == nil {
			defer func() { _ = sqlDB.Close() }()
		}

		runUpgradeOracles(t, c, orphanDB, manifest)
	})
}
