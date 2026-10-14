// all_models_migration_guard_test.go -- SESSION U, guard U1: "every model
// gets a table". Found 2026-09-28/29: models with live, wired handler code
// but no production migration -- 7 tables (#2258), then 6 more (#2264) --
// each found late, by an e2e run or a release check, not by CI. The only
// guard that existed was TestMigrateDatabase_CreatesAllSevenPreviouslyUnmigratedTables
// (factory_seven_unmigrated_models_test.go), which names exactly the seven
// tables #2258 fixed and nothing else -- a new model added tomorrow gets no
// coverage from it at all.
//
// This file adds two guards instead of one more hand-picked list:
//
//  1. TestAllTestModels_MatchesModelsGoStructSet: models.AllTestModels() is
//     itself a hand-maintained slice literal (see its own doc comment --
//     "append it here and nowhere else"). A hand list is exactly the kind of
//     thing this campaign keeps finding stale (see the CLAUDE.md "opt-in
//     correctness" note). This test derives the REAL set of model structs
//     from internal/storage/models/models.go's own AST -- the same technique
//     g1619_beforesave_bypass_guard_test.go already uses in this package for
//     the same reason -- and fails, by name, the moment the two sets diverge
//     in either direction. Storage.AllModels() (design-b3-backup-v2.md,
//     #2261) will eventually be the single source of truth this test could
//     defer to instead of the AST derivation; it had not merged as of this
//     writing (no such function exists in internal/storage), so this is the
//     strongest self-checking option available today.
//
//     Running this the first time found the fallible list was ALREADY stale
//     by 15 models: APICallLog, APIClient, APIToken, AuditCheckpoint,
//     ConnectorProjectBinding, ExternalIdentity, GRPCService,
//     IdentityProvider, MFAStepUpGrant, PasswordReset, RateLimit,
//     RecoveryKeyRecord, SecretAccessLog, SecretMetadataHistory, Setting --
//     every one of them already has a production migration (migrateDatabase
//     AutoMigrates all of them; see the full-repo grep in the PR body), so
//     this was a test-coverage gap, not a live "no such table" bug: fixed in
//     the same PR by adding the 15 to all_models.go, restoring
//     AllTestModels() to what its own doc comment already claimed it was.
//
//  2. TestMigrateDatabase_EveryModelGetsATable_*: runs the REAL production
//     migration path (DefaultStorageFactory.migrateDatabase -- the same
//     function createLocalStorage/createPostgresStorage call, and the same
//     one FuzzUpgradeMigration and TestCreateStorage_Postgres_Success drive;
//     never a hand-picked AutoMigrate subset) against (a) a brand-new empty
//     database and (b) a database first migrated by an older schema (reusing
//     the v0.95.0 real fixture FuzzUpgradeMigration already carries in
//     testdata/upgrade-fixtures/v095 -- no
//     TestMigrateDatabase_SessionI_SixMissingTables_UpgradedInstall exists in
//     this tree to reuse instead), then asserts db.Migrator().HasTable AND
//     that every one of that model's own schema fields resolved to a real
//     column, for every model models.AllTestModels() names. Gated onto
//     Postgres too when KEYORIX_TEST_PG_DSN is set (fresh-DB case only: no
//     Postgres-vintage upgrade fixture exists to reuse).
//
// Red-proof (not committed -- see the PR description for the exact diff and
// failure text): commenting out the `&models.AuditCheckpoint{}}` migration
// call in migrateDatabase's dedicated block makes
// TestMigrateDatabase_EveryModelGetsATable_Fresh fail with "AuditCheckpoint:
// migrateDatabase did not create a table for this model ... add an
// AutoMigrate(&models.AuditCheckpoint{}) call to migrateDatabase
// (internal/storage/factory.go)" -- names the model and the file to fix, per
// GUARD RULES #1.
package storage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// copyFileU1 copies a fixture database file into a scratch path so the test
// never mutates the checked-in fixture.
func copyFileU1(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	require.NoError(t, err)
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	require.NoError(t, err)
}

// repoRootU1 locates the repository root relative to this file's own
// location on disk, matching repoRootG1619's approach in this same package's
// sibling guard test -- works regardless of the test runner's working
// directory.
func repoRootU1() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// modelsGoStructNamesU1 derives, from internal/storage/models/models.go's own
// AST, the name of every exported top-level struct type declared there --
// the real universe of GORM models this codebase defines, independent of any
// hand-maintained enumeration of them.
func modelsGoStructNamesU1(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join(repoRootU1(), "internal", "storage", "models", "models.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err, "parsing models.go")

	names := map[string]bool{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if _, ok := ts.Type.(*ast.StructType); !ok {
				continue
			}
			if ts.Name.IsExported() {
				names[ts.Name.Name] = true
			}
		}
	}
	return names
}

// allTestModelsNamesU1 returns the type name of every model
// models.AllTestModels() lists, via reflection -- no hand-mapping from name
// to type is needed since AllTestModels() already gives concrete typed
// pointers.
func allTestModelsNamesU1() map[string]bool {
	names := map[string]bool{}
	for _, m := range models.AllTestModels() {
		names[reflect.TypeOf(m).Elem().Name()] = true
	}
	return names
}

// TestAllTestModels_MatchesModelsGoStructSet guards against
// models.AllTestModels() silently drifting from the models it is documented
// to enumerate -- see this file's package doc comment for why this check
// exists and what it already found.
func TestAllTestModels_MatchesModelsGoStructSet(t *testing.T) {
	fromAST := modelsGoStructNamesU1(t)
	fromList := allTestModelsNamesU1()

	var missing []string // declared in models.go, absent from AllTestModels()
	for name := range fromAST {
		if !fromList[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	var extra []string // listed in AllTestModels(), no longer in models.go
	for name := range fromList {
		if !fromAST[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("models.go defines %d struct(s) that models.AllTestModels() does not list: %v -- "+
			"add &models.<Name>{} to internal/storage/models/all_models.go for each, or if it is not "+
			"a real GORM model, this test's struct-vs-non-struct heuristic needs updating", len(missing), missing)
	}
	if len(extra) > 0 {
		t.Errorf("models.AllTestModels() lists %d type(s) with no matching struct in models.go: %v -- "+
			"remove the stale entry from internal/storage/models/all_models.go", len(extra), extra)
	}
}

// assertModelMigratedU1 asserts db has a table for model and a real column
// for every one of the model's own schema fields (via gorm's own schema.Parse
// -- so association-only fields and gorm:"-" fields are correctly excluded,
// not hand-filtered).
func assertModelMigratedU1(t *testing.T, db *gorm.DB, model any) {
	t.Helper()
	typeName := reflect.TypeOf(model).Elem().Name()

	if !db.Migrator().HasTable(model) {
		t.Errorf("%s: migrateDatabase did not create a table for this model -- add an "+
			"AutoMigrate(&models.%s{}) call to migrateDatabase (internal/storage/factory.go)", typeName, typeName)
		return
	}

	sch, err := schema.Parse(model, &sync.Map{}, db.NamingStrategy)
	require.NoErrorf(t, err, "%s: schema.Parse", typeName)
	for _, f := range sch.Fields {
		if f.DBName == "" {
			continue // association-only / gorm:"-" field, not a real column
		}
		if !db.Migrator().HasColumn(model, f.Name) {
			t.Errorf("%s: migrateDatabase created the table but column %q (field %s) is missing -- "+
				"the model's schema and migrateDatabase have drifted", typeName, f.DBName, f.Name)
		}
	}
}

// TestMigrateDatabase_EveryModelGetsATable_Fresh runs the real production
// migration path against a brand-new empty database and asserts every model
// models.AllTestModels() lists gets a table with every schema column.
func TestMigrateDatabase_EveryModelGetsATable_Fresh(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "every-model-fresh.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	for _, m := range models.AllTestModels() {
		t.Run(reflect.TypeOf(m).Elem().Name(), func(t *testing.T) {
			assertModelMigratedU1(t, db, m)
		})
	}
}

// TestMigrateDatabase_EveryModelGetsATable_UpgradedInstall runs the real
// production migration path against a database first migrated by an older
// schema -- reusing the same real v0.95.0 fixture FuzzUpgradeMigration
// carries in internal/core/testdata/upgrade-fixtures/v095 (the closest
// vintage to HEAD of the three) -- and asserts the same per-model coverage
// as the fresh-DB case, matching the "upgrade" shape
// TestCompanionIndexes_CreatedOnUpgrade and
// TestMigrateDatabase_SevenPreviouslyUnmigratedTables_SurviveUpgradeRerun
// already exercise for narrower cases.
func TestMigrateDatabase_EveryModelGetsATable_UpgradedInstall(t *testing.T) {
	srcDB := filepath.Join(repoRootU1(), "internal", "core", "testdata", "upgrade-fixtures", "v095", "fixture.db")
	if _, err := os.Stat(srcDB); err != nil {
		t.Skipf("v095 fixture not present: %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "every-model-upgraded.db")
	copyFileU1(t, srcDB, dbPath)

	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db), "re-running migrateDatabase against a v0.95.0-vintage database")

	for _, m := range models.AllTestModels() {
		t.Run(reflect.TypeOf(m).Elem().Name(), func(t *testing.T) {
			assertModelMigratedU1(t, db, m)
		})
	}
}

// TestMigrateDatabase_EveryModelGetsATable_Postgres_Fresh is the Postgres
// counterpart of the fresh-DB case, gated on KEYORIX_TEST_PG_DSN exactly like
// TestCreateStorage_Postgres_Success -- go test ./... still passes cleanly
// with no Postgres available. No Postgres-vintage upgrade fixture exists in
// this tree, so there is no upgraded-install counterpart here.
func TestMigrateDatabase_EveryModelGetsATable_Postgres_Fresh(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsn
	cfg.Storage.Database.MaxOpenConns = 5
	cfg.Storage.Database.MaxIdleConns = 2
	cfg.Storage.Database.ConnMaxLifetimeMinutes = 10

	// The real production migration path -- same factory call
	// TestCreateStorage_Postgres_Success drives.
	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	require.NotNil(t, st)

	db := pgRawOpen(t, dsn)
	for _, m := range models.AllTestModels() {
		t.Run(reflect.TypeOf(m).Elem().Name(), func(t *testing.T) {
			assertModelMigratedU1(t, db, m)
		})
	}
}
