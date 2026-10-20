package pgdsn

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func templateTestBase(t *testing.T) string {
	t.Helper()
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping live Postgres template test")
	}
	return base
}

// uniqueFingerprint is distinct per test run, so tests neither reuse a
// template left by an earlier run nor collide with each other.
func uniqueFingerprint(tag string) string {
	return fmt.Sprintf("%x%x", os.Getpid(), time.Now().UnixNano()) + tag
}

func dropTemplateOnCleanup(t *testing.T, base, name string) {
	t.Helper()
	t.Cleanup(func() {
		_ = execOn(context.Background(), base, "ALTER DATABASE "+quoteIdent(name)+" WITH IS_TEMPLATE false")
		_ = execOn(context.Background(), base, "DROP DATABASE IF EXISTS "+quoteIdent(name)+" WITH (FORCE)")
	})
}

func templateState(t *testing.T, base, name string) (exists, isTemplate, allowsConn bool) {
	t.Helper()
	db, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer closeGorm(db)
	var rows []struct{ Datistemplate, Datallowconn bool }
	if err := db.Raw("SELECT datistemplate, datallowconn FROM pg_database WHERE datname = ?", name).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return false, false, false
	}
	return true, rows[0].Datistemplate, rows[0].Datallowconn
}

func probeMigrator(calls *atomic.Int64) Migrator {
	return func(db *gorm.DB) error {
		calls.Add(1)
		return db.Exec("CREATE TABLE template_probe (id int)").Error
	}
}

func tableExists(t *testing.T, dsn string) bool {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer closeGorm(db)
	var n int
	if err := db.Raw("SELECT count(*) FROM information_schema.tables WHERE table_name = 'template_probe'").Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func TestDatabaseName_BothDSNForms(t *testing.T) {
	cases := map[string]string{
		"postgres://u:p@h:1/kpg_x?sslmode=disable": "kpg_x",
		"host=h port=1 dbname=kpg_y user=u":        "kpg_y",
		"host=h port=1 user=u":                     "",
	}
	for dsn, want := range cases {
		if got := DatabaseName(dsn); got != want {
			t.Errorf("DatabaseName(%q) = %q, want %q", dsn, got, want)
		}
	}
}

// The template name must start with the base database's name so a session role
// limited to databases carrying its tag slug (kpg) may create it.
func TestTemplateName_FollowsBaseDatabasePrefix(t *testing.T) {
	got := TemplateName("postgres://u:p@h:1/pg_template_db_1?sslmode=disable", "fp-one")
	if want := "pg_template_db_1_tpl_" + shortFingerprint("fp-one"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got == TemplateName("postgres://u:p@h:1/pg_template_db_1?sslmode=disable", "fp-two") {
		t.Fatal("different fingerprints share a template name")
	}
	if long := TemplateName("host=h dbname="+strings.Repeat("x", 60), "abc"); len(long) > 63 {
		t.Fatalf("template name %q is %d bytes, over the 63-byte identifier limit", long, len(long))
	}
}

func TestSourceFingerprint_StableAndSensitive(t *testing.T) {
	a := SourceFingerprint()
	if a == "" {
		t.Fatal("fingerprint empty inside the checkout")
	}
	if b := SourceFingerprint(); a != b {
		t.Fatalf("fingerprint not stable: %s vs %s", a, b)
	}
	if c := SourceFingerprint("extra input"); a == c {
		t.Fatal("extra input did not change the fingerprint")
	}
}

// A new fingerprint (a schema change) builds a new template; the same
// fingerprint reuses the one built.
func TestMigratedDatabase_FingerprintChangeBuildsNewTemplate(t *testing.T) {
	base := templateTestBase(t)
	t.Setenv(TemplateEnv, "1")
	var calls atomic.Int64
	m := probeMigrator(&calls)
	fp1, fp2 := uniqueFingerprint("a"), uniqueFingerprint("b")
	tpl1, tpl2 := TemplateName(base, fp1), TemplateName(base, fp2)
	dropTemplateOnCleanup(t, base, tpl1)
	dropTemplateOnCleanup(t, base, tpl2)

	d1 := MigratedDatabase(t, base, "tpl_unit", fp1, m)
	d2 := MigratedDatabase(t, base, "tpl_unit", fp1, m)
	if got := calls.Load(); got != 1 {
		t.Fatalf("migration ran %d times for one fingerprint, want 1", got)
	}
	if d1 == d2 {
		t.Fatalf("two clones share one database: %s", d1)
	}
	if !tableExists(t, d1) || !tableExists(t, d2) {
		t.Fatal("clone lacks the migrated table")
	}
	if ex, tmpl, conn := templateState(t, base, tpl1); !ex || !tmpl || conn {
		t.Fatalf("template 1 state exists=%v datistemplate=%v allowconn=%v, want true true false", ex, tmpl, conn)
	}

	d3 := MigratedDatabase(t, base, "tpl_unit", fp2, m)
	if got := calls.Load(); got != 2 {
		t.Fatalf("changed fingerprint did not rebuild: migration ran %d times, want 2", got)
	}
	if !tableExists(t, d3) {
		t.Fatal("clone of template 2 lacks the migrated table")
	}
	if ex, _, _ := templateState(t, base, tpl2); !ex || tpl1 == tpl2 {
		t.Fatalf("template 2 missing or not distinct (%s vs %s)", tpl1, tpl2)
	}
}

// Parallel first use of one fingerprint (processes sharing a server are
// modelled by bypassing the per-process cache) builds the template once, and
// concurrent clones all succeed.
func TestEnsureTemplate_ConcurrentFirstUseBuildsOnce(t *testing.T) {
	base := templateTestBase(t)
	var calls atomic.Int64
	m := probeMigrator(&calls)
	fp := uniqueFingerprint("c")
	tpl := TemplateName(base, fp)
	dropTemplateOnCleanup(t, base, tpl)

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for i := range workers {
		wg.Go(func() {
			ctx := context.Background()
			name, err := ensureTemplate(ctx, base, fp, m)
			if err != nil {
				errs <- err
				return
			}
			clone := fmt.Sprintf("tpl_conc_%d_%d_%d", os.Getpid(), i, time.Now().UnixNano()%1e9)
			if err := cloneDatabase(ctx, base, name, clone); err != nil {
				errs <- err
				return
			}
			_ = execOn(ctx, base, "DROP DATABASE IF EXISTS "+quoteIdent(clone)+" WITH (FORCE)")
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("migration ran %d times across %d concurrent first uses, want 1", got, workers)
	}
	if ex, tmpl, _ := templateState(t, base, tpl); !ex || !tmpl {
		t.Fatalf("template state exists=%v datistemplate=%v", ex, tmpl)
	}
}

// Stale templates (non-current fingerprint, older than the age) are dropped;
// the current one and young non-current ones stay.
func TestDropStaleTemplates_KeepsCurrentAndYoung(t *testing.T) {
	base := templateTestBase(t)
	var calls atomic.Int64
	m := probeMigrator(&calls)
	ctx := context.Background()
	old, young, cur := uniqueFingerprint("o"), uniqueFingerprint("y"), uniqueFingerprint("n")
	names := map[string]string{}
	for k, fp := range map[string]string{"old": old, "young": young, "cur": cur} {
		n, err := ensureTemplate(ctx, base, fp, m)
		if err != nil {
			t.Fatal(err)
		}
		names[k] = n
		dropTemplateOnCleanup(t, base, n)
	}
	backdate := time.Now().Add(-48 * time.Hour).Unix()
	if err := execOn(ctx, base, fmt.Sprintf("COMMENT ON DATABASE %s IS '%s%d'", quoteIdent(names["old"]), templateMarker, backdate)); err != nil {
		t.Fatal(err)
	}
	if err := execOn(ctx, base, fmt.Sprintf("COMMENT ON DATABASE %s IS '%s%d'", quoteIdent(names["cur"]), templateMarker, backdate)); err != nil {
		t.Fatal(err)
	}

	if err := dropStaleTemplates(ctx, base, cur, StaleTemplateAge); err != nil {
		t.Fatal(err)
	}
	if ex, _, _ := templateState(t, base, names["old"]); ex {
		t.Error("old non-current template was not dropped")
	}
	if ex, _, _ := templateState(t, base, names["young"]); !ex {
		t.Error("young non-current template was dropped")
	}
	if ex, _, _ := templateState(t, base, names["cur"]); !ex {
		t.Error("current template was dropped even though it is old")
	}
}

// KEYORIX_TEST_PG_TEMPLATE=0 restores create-empty-then-migrate: the migration
// runs for every database and no template is built.
func TestMigratedDatabase_TemplateDisabledMigratesEveryTime(t *testing.T) {
	base := templateTestBase(t)
	t.Setenv(TemplateEnv, "0")
	var calls atomic.Int64
	m := probeMigrator(&calls)
	fp := uniqueFingerprint("d")

	d1 := MigratedDatabase(t, base, "tpl_off", fp, m)
	d2 := MigratedDatabase(t, base, "tpl_off", fp, m)
	if got := calls.Load(); got != 2 {
		t.Fatalf("migration ran %d times, want 2 (once per database)", got)
	}
	if !tableExists(t, d1) || !tableExists(t, d2) {
		t.Fatal("database lacks the migrated table")
	}
	if ex, _, _ := templateState(t, base, TemplateName(base, fp)); ex {
		t.Fatal("a template was built although templates are disabled")
	}
}
