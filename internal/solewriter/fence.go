package solewriter

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// FencedTable is one security table the fence covers.
type FencedTable struct {
	Name string
	// UpdateIgnores lists bookkeeping columns: an UPDATE that changes only
	// these is neither fenced nor counted (a deny-list, so a column added
	// later is fenced by default).
	UpdateIgnores []string
	// Key, when set, fences only rows whose "key" column equals it
	// (system_metadata holds unrelated rows too).
	Key string
}

// FencedTables are the tables whose rows the machine-token read path's
// authoritative caches are derived from (docs/specs/single-writer-cache.md
// §1.4): the credential and its identity, the identity's roles at a scope,
// the roles' permissions and the generation that versions them, the
// project/environment scope, and the secret's node, versions and schedule.
var FencedTables = []FencedTable{
	{Name: "machine_identity_credentials", UpdateIgnores: []string{"last_used_at"}},
	{Name: "machine_identities"},
	{Name: "machine_identity_roles"},
	{Name: "roles"},
	{Name: "role_permissions"},
	{Name: "permissions"},
	{Name: "projects"},
	{Name: "environments"},
	{Name: "secret_nodes"},
	{Name: "secret_versions"},
	{Name: "secret_access_schedules"},
	{Name: "system_metadata", Key: "role_permissions_generation"},
}

// FencedTableNames lists FencedTables' names.
func FencedTableNames() []string {
	out := make([]string, len(FencedTables))
	for i, t := range FencedTables {
		out[i] = t.Name
	}
	return out
}

// coveredTableNames are the tables whose rows the fence protects: the fenced
// tables and this package's own two.
func coveredTableNames() []string {
	return append(FencedTableNames(), HolderTable, EpochTable)
}

// ensureOwnTables creates the holder and epoch tables (not GORM models: only
// this package reads or writes them).
func ensureOwnTables(ctx context.Context, conn *sql.Conn, schema string) error {
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS ` + qualify(schema, HolderTable) + ` (id integer PRIMARY KEY CHECK (id = 1), holder_pid integer, nonce_hash text, since timestamptz, boot_id text)`,
		`CREATE TABLE IF NOT EXISTS ` + qualify(schema, EpochTable) + ` (id integer PRIMARY KEY CHECK (id = 1), incarnation text NOT NULL, n bigint NOT NULL)`,
	} {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("single_writer: create %s: %w", strings.Fields(s)[5], err)
		}
	}
	return nil
}

// funcSearchPath is every fence function's own search_path (CREATE FUNCTION
// ... SET). pg_catalog first and pg_temp named last: a temp table cannot
// shadow a catalog, and functions and operators are never looked up in
// pg_temp. The bodies qualify every relation and function as well; the
// setting is what also pins the operators (=, +, &, ...) and type names.
const funcSearchPath = "pg_catalog, pg_temp"

// checkFuncBody raises when a live holder exists and the session is not one
// of its own. Shared by the guard and fence-only trigger functions.
func checkFuncBody() string {
	return `
DECLARE
  hpid integer;
  hhash text;
  hsince timestamptz;
BEGIN
  EXECUTE pg_catalog.format('SELECT holder_pid, nonce_hash, since FROM %I.` + HolderTable + ` WHERE id = 1', sch) INTO hpid, hhash, hsince;
  IF hpid IS NULL THEN
    RETURN;
  END IF;
  IF hhash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(coalesce(pg_catalog.current_setting('` + config.SoleWriterSessionSetting + `', true), ''), 'UTF8')), 'hex') THEN
    RETURN;
  END IF;
  IF NOT ` + lockHeldExpr("hpid", "sch") + ` THEN
    RETURN;
  END IF;
  RAISE EXCEPTION 'keyorix single_writer: the Keyorix server holding the single-writer lock (backend pid %, since %) is the only permitted writer of the security tables while it runs', hpid, hsince
    USING ERRCODE = 'insufficient_privilege',
          HINT = 'Write through the server''s API, or stop the server first. Emergency: SELECT pg_terminate_backend(holder_pid) FROM ` + HolderTable + `; then run the change (docs/single-writer.md "Emergency SQL").';
END;
`
}

// The function bodies, exactly as installed (the census compares their md5).
// Every Keyorix object they touch is qualified with the fired table's schema,
// never resolved through the writer's search_path: an operator's session on
// another search_path must meet this schema's fence and epoch. Every catalog
// object and function is qualified with pg_catalog (and funcSearchPath pins
// the rest).
//
// The guard runs per row (see triggerSpecs), so it bumps the epoch once per
// transaction rather than once per row: the UPDATE skips the row when this
// transaction already wrote it (its xmin is ours). A bump inside a
// subtransaction carries the subtransaction's xid, so the next row bumps again,
// which is only an extra bump.
func guardFuncBody() string {
	return `
BEGIN
  EXECUTE pg_catalog.format('SELECT %I.` + checkFunc + `($1)', TG_TABLE_SCHEMA) USING TG_TABLE_SCHEMA::text;
  EXECUTE pg_catalog.format('UPDATE %I.` + EpochTable + ` SET n = n + 1 WHERE id = 1 AND xmin <> pg_catalog.xid(pg_catalog.pg_current_xact_id())', TG_TABLE_SCHEMA);
  RETURN NULL;
END;
`
}

func fenceOnlyFuncBody() string {
	return `
BEGIN
  EXECUTE pg_catalog.format('SELECT %I.` + checkFunc + `($1)', TG_TABLE_SCHEMA) USING TG_TABLE_SCHEMA::text;
  RETURN NULL;
END;
`
}

// triggerSpec is one fence trigger: its name, table and the rest of its
// CREATE TRIGGER text after "ON <table>".
type triggerSpec struct {
	name, table, events, rest string
}

func (t triggerSpec) create(schema string) string {
	return "CREATE TRIGGER " + t.name + " AFTER " + t.events + " ON " + qualify(schema, t.table) + " " + t.rest
}

// triggerSpecs derives every fence trigger from FencedTables, for the tables
// and functions in schema.
//
// INSERT, UPDATE and DELETE are guarded FOR EACH ROW, never only per
// statement: a statement-level trigger fires only for the table the statement
// names, so a write that reaches a fenced table's rows through a parent
// (ALTER TABLE ... INHERIT, ATTACH PARTITION) would fire none
// (REVIEW-SINGLE-WRITER-2 N2). Row triggers fire on the table that holds the
// row, whichever table the statement named. TRUNCATE has no row form; a
// TRUNCATE of a parent fires the statement-level TRUNCATE trigger of every
// child it truncates. The census also refuses any inheritance involving a
// fenced table (fingerprintSQL, InstallFence).
func triggerSpecs(schema string) []triggerSpec {
	var out []triggerSpec
	exec := func(fn string) string { return "EXECUTE PROCEDURE " + qualify(schema, fn) + "()" }
	stmt := "FOR EACH STATEMENT " + exec(guardFunc)
	row := func(when string) string {
		if when == "" {
			return "FOR EACH ROW " + exec(guardFunc)
		}
		return "FOR EACH ROW WHEN (" + when + ") " + exec(guardFunc)
	}
	for _, t := range FencedTables {
		out = append(out, triggerSpec{TriggerPrefix + "guard", t.Name, "TRUNCATE", stmt})
		switch {
		case t.Key != "":
			k := "'" + t.Key + "'"
			out = append(out,
				triggerSpec{TriggerPrefix + "guard_ins", t.Name, "INSERT", row("NEW.key = " + k)},
				triggerSpec{TriggerPrefix + "guard_upd", t.Name, "UPDATE", row("OLD.key = " + k + " OR NEW.key = " + k)},
				triggerSpec{TriggerPrefix + "guard_del", t.Name, "DELETE", row("OLD.key = " + k)})
		case len(t.UpdateIgnores) > 0:
			minus := ""
			for _, c := range t.UpdateIgnores {
				minus += " - '" + c + "'"
			}
			out = append(out,
				triggerSpec{TriggerPrefix + "guard_row", t.Name, "INSERT OR DELETE", row("")},
				triggerSpec{TriggerPrefix + "guard_upd", t.Name, "UPDATE", row("(pg_catalog.to_jsonb(OLD)" + minus + ") IS DISTINCT FROM (pg_catalog.to_jsonb(NEW)" + minus + ")")})
		default:
			out = append(out, triggerSpec{TriggerPrefix + "guard_row", t.Name, "INSERT OR UPDATE OR DELETE", row("")})
		}
	}
	for _, own := range []string{HolderTable, EpochTable} {
		out = append(out,
			triggerSpec{TriggerPrefix + "fence", own, "TRUNCATE", "FOR EACH STATEMENT " + exec(fenceOnlyFunc)},
			triggerSpec{TriggerPrefix + "fence_row", own, "INSERT OR UPDATE OR DELETE", "FOR EACH ROW " + exec(fenceOnlyFunc)})
	}
	return out
}

// fingerprintSQL fingerprints, in schema $1 (covered tables $2, see
// coveredTableNames): every fence trigger (its full definition, enabled state
// and catalog row version), the three functions (body, settings and row
// version), every inheritance or partition link with a covered table on
// either side, and every column of a covered table (name, type and row
// version). Every name is qualified; run it on a session whose search_path is
// pinned (pinSessionSchema), which also fixes pg_get_triggerdef's output.
//
// The row version (xmin) is what catches a change that is undone before
// anyone looks: DISABLE TRIGGER; write; ENABLE ALWAYS TRIGGER in one
// transaction (or across two between polls), DROP and re-CREATE of an
// identical trigger, CREATE OR REPLACE with the same body. Every one of them
// rewrites the pg_trigger / pg_proc row, so its xmin is the tampering
// transaction's id even though the definition reads as before. No SQL
// statement can set a row's xmin back. Nothing the server does after
// InstallFence rewrites these rows; something else that does (a manual
// ALTER, a pg_upgrade) is a false alarm that fails closed.
//
// A child table (CREATE TABLE ... INHERITS, ALTER TABLE ... INHERIT) is read
// through its parent, but the parent's triggers do not fire for writes to the
// child, so a child of a fenced table is tampering too. So is a fenced table
// made the child or partition of a new parent: the row-level guards still
// fire through it, but nothing the server does needs it.
//
// The columns catch DDL that changes stored or read values with no DML
// trigger firing: ALTER COLUMN ... TYPE ... USING rewrites every row, RENAME
// COLUMN swaps what a name reads. Each rewrites the pg_attribute row. VACUUM
// FULL, CLUSTER, CREATE INDEX and ANALYZE do not touch pg_attribute.
const fingerprintSQL = `SELECT pg_catalog.md5(
  coalesce((SELECT pg_catalog.string_agg(c.relname || ':' || pg_catalog.pg_get_triggerdef(t.oid) || ':' || t.tgenabled::text || ':' || t.xmin::text, E'\n' ORDER BY c.relname, t.tgname)
    FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = $1 AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%'), '')
  || '|' ||
  coalesce((SELECT pg_catalog.string_agg(p.proname || ':' || pg_catalog.md5(p.prosrc) || ':' || coalesce(pg_catalog.array_to_string(p.proconfig, ';'), '') || ':' || p.prosecdef::text || ':' || p.xmin::text, ',' ORDER BY p.proname)
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = $1 AND p.proname LIKE 'keyorix\_sole\_writer\_%'), '')
  || '|' ||
  coalesce((SELECT pg_catalog.string_agg(i.inhparent::text || '<' || i.inhrelid::text, ',' ORDER BY i.inhparent, i.inhrelid)
    FROM pg_catalog.pg_inherits i WHERE i.inhparent IN (` + coveredOIDsSQL + `) OR i.inhrelid IN (` + coveredOIDsSQL + `)), '')
  || '|' ||
  coalesce((SELECT pg_catalog.string_agg(a.attrelid::text || '.' || a.attnum::text || ':' || a.attname || ':' || a.atttypid::text || ':' || a.xmin::text, ',' ORDER BY a.attrelid, a.attnum)
    FROM pg_catalog.pg_attribute a WHERE a.attnum > 0 AND a.attrelid IN (` + coveredOIDsSQL + `)), ''))`

// coveredOIDsSQL selects the oids of the covered tables ($2) in schema $1.
const coveredOIDsSQL = `SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relname = ANY ($2::text[])`

// InstallFence installs (or converges) the fence and epoch triggers on every
// fenced table and records the fingerprint the poller will compare against.
// One transaction; it never drops a trigger. Every fenced table must exist
// (run after migrations). A failure here means the server must not start.
func (g *Guard) InstallFence(ctx context.Context) error {
	tx, err := g.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("single_writer: install the fence: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) error {
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	sch := g.schema
	for _, t := range FencedTables {
		var ok bool
		if err := tx.QueryRowContext(ctx, "SELECT pg_catalog.to_regclass($1) IS NOT NULL", qualify(sch, t.Name)).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("single_writer: security table %s does not exist; the fence cannot be installed", t.Name)
		}
	}
	fns := []struct{ name, sig, ret, body string }{
		{checkFunc, "(sch text)", "void", checkFuncBody()},
		{guardFunc, "()", "trigger", guardFuncBody()},
		{fenceOnlyFunc, "()", "trigger", fenceOnlyFuncBody()},
	}
	for _, f := range fns {
		if err := exec("CREATE OR REPLACE FUNCTION " + qualify(sch, f.name) + f.sig + " RETURNS " + f.ret + " LANGUAGE plpgsql SET search_path = " + funcSearchPath + " AS $keyorix$" + f.body + "$keyorix$"); err != nil {
			return fmt.Errorf("single_writer: create %s: %w", f.name, err)
		}
	}
	specs := triggerSpecs(sch)
	for _, s := range specs {
		var state sql.NullString
		err := tx.QueryRowContext(ctx, "SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE NOT tgisinternal AND tgrelid = pg_catalog.to_regclass($1) AND tgname = $2", qualify(sch, s.table), s.name).Scan(&state)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if !state.Valid {
			if err := exec(s.create(sch)); err != nil {
				return fmt.Errorf("single_writer: create %s on %s: %w", s.name, s.table, err)
			}
		}
		if state.String != "A" {
			if err := exec("ALTER TABLE " + qualify(sch, s.table) + " ENABLE ALWAYS TRIGGER " + s.name); err != nil {
				return fmt.Errorf("single_writer: enable %s on %s: %w", s.name, s.table, err)
			}
		}
	}
	incarnation, err := randomHex(16)
	if err != nil {
		return err
	}
	if err := exec(`INSERT INTO `+qualify(sch, EpochTable)+` (id, incarnation, n) VALUES (1, $1, 0) ON CONFLICT (id) DO UPDATE SET incarnation = EXCLUDED.incarnation`, incarnation); err != nil {
		return fmt.Errorf("single_writer: initialise the write epoch: %w", err)
	}
	// Verify what is now installed, inside the same transaction: every
	// expected trigger present and ENABLE ALWAYS, and no stray one. A trigger
	// with the right name but a different definition (from an older build)
	// would show up in the fingerprint only, so recreate-on-mismatch is not
	// attempted: refuse, and the operator drops it (the message says how).
	var n, always int
	if err := tx.QueryRowContext(ctx, fenceCountSQL, sch).Scan(&n, &always); err != nil {
		return err
	}
	if n != len(specs) || always != len(specs) {
		return fmt.Errorf("single_writer: fence verification failed: %d fence triggers present (%d ENABLE ALWAYS), want %d", n, always, len(specs))
	}
	for _, s := range specs {
		var def string
		if err := tx.QueryRowContext(ctx, "SELECT pg_catalog.pg_get_triggerdef(oid) FROM pg_catalog.pg_trigger WHERE tgrelid = pg_catalog.to_regclass($1) AND tgname = $2", qualify(sch, s.table), s.name).Scan(&def); err != nil {
			return err
		}
		if !triggerDefMatches(def, s) {
			return fmt.Errorf("single_writer: fence trigger %s on %s has an unexpected definition (%s); drop it (DROP TRIGGER %s ON %s) and restart", s.name, s.table, def, s.name, s.table)
		}
	}
	// A table inheriting from a fenced one takes writes the fence never sees,
	// and a fenced table with a parent has no business having one (see
	// fingerprintSQL); the fingerprint only notices a link added later.
	var links string
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(pg_catalog.string_agg(ch.relname || ' INHERITS ' || pa.relname, ', ' ORDER BY ch.relname, pa.relname), '')
FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class ch ON ch.oid = i.inhrelid JOIN pg_catalog.pg_class pa ON pa.oid = i.inhparent
WHERE i.inhparent IN (`+coveredOIDsSQL+`) OR i.inhrelid IN (`+coveredOIDsSQL+`)`, sch, coveredTableNames()).Scan(&links); err != nil {
		return err
	}
	if links != "" {
		return fmt.Errorf("single_writer: a fenced table has a child or a parent table (%s): writes through it bypass statement-level checks and a child's rows bypass the fence; remove the inheritance and restart", links)
	}
	var fp string
	if err := tx.QueryRowContext(ctx, fingerprintSQL, sch, coveredTableNames()).Scan(&fp); err != nil {
		return err
	}
	var epoch int64
	var epochXmin string
	if err := tx.QueryRowContext(ctx, "SELECT n, xmin::text FROM "+qualify(sch, EpochTable)+" WHERE id = 1").Scan(&epoch, &epochXmin); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("single_writer: install the fence: %w", err)
	}
	g.mu.Lock()
	g.fingerprint, g.incarnation, g.epoch, g.epochXmin = fp, incarnation, epoch, epochXmin
	g.mu.Unlock()
	return nil
}

// triggerDefMatches compares pg_get_triggerdef's text with the spec loosely
// enough to absorb PostgreSQL's normalisation (schema qualification, WHEN
// parenthesisation, EXECUTE FUNCTION vs PROCEDURE): same name, timing,
// events, level and function.
func triggerDefMatches(def string, s triggerSpec) bool {
	d := strings.ToUpper(def)
	prefix := "TRIGGER " + strings.ToUpper(s.name) + " AFTER "
	_, rest, ok := strings.Cut(d, prefix)
	if !ok {
		return false
	}
	events, _, ok := strings.Cut(rest, " ON ")
	if !ok || !sameEvents(events, strings.ToUpper(s.events)) {
		return false
	}
	fn := guardFunc
	if strings.Contains(s.rest, fenceOnlyFunc) {
		fn = fenceOnlyFunc
	}
	level := "FOR EACH STATEMENT"
	if strings.Contains(s.rest, "FOR EACH ROW") {
		level = "FOR EACH ROW"
	}
	return strings.Contains(d, level) && strings.Contains(d, strings.ToUpper(fn)+"()")
}

// sameEvents compares two "A OR B OR C" event lists as sets (PostgreSQL
// prints them in its own order).
func sameEvents(a, b string) bool {
	as, bs := strings.Split(a, " OR "), strings.Split(b, " OR ")
	if len(as) != len(bs) {
		return false
	}
	seen := map[string]bool{}
	for _, e := range as {
		seen[strings.TrimSpace(e)] = true
	}
	for _, e := range bs {
		if !seen[strings.TrimSpace(e)] {
			return false
		}
	}
	return true
}

// HolderLive reports whether a single-writer server currently holds the lock
// for cfg's database (and its pid). For the admin --force refusal and the
// normal-mode boot check. Not PostgreSQL: false.
func HolderLive(ctx context.Context, cfg *config.Config) (bool, int, error) {
	if st := cfg.Storage.Type; st != "postgres" && st != "postgresql" {
		return false, 0, nil
	}
	db, conn, schema, err := openOne(ctx, cfg)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = conn.Close(); _ = db.Close() }()
	pid, err := holderPID(ctx, conn, schema)
	return pid != 0, pid, err
}

// CheckOff is the boot step of a server WITHOUT single_writer on PostgreSQL:
// refuse while a single-writer server holds the database, and otherwise remove
// a fence a previous single-writer boot left behind (with no live holder it
// lets everything through, but its epoch row would still serialise writes to
// the security tables). The tables are dropped too.
func CheckOff(ctx context.Context, cfg *config.Config) error {
	if st := cfg.Storage.Type; st != "postgres" && st != "postgresql" {
		return nil
	}
	db, conn, schema, err := openOne(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(); _ = db.Close() }()
	pid, err := holderPID(ctx, conn, schema)
	if err != nil {
		return fmt.Errorf("single_writer: check for a single-writer server: %w", err)
	}
	if pid != 0 {
		return fmt.Errorf("a Keyorix server running with storage.database.single_writer holds this database (backend pid %d); it must be the only server. Stop it first, or remove this server", pid)
	}
	return removeFence(ctx, conn, schema)
}

// removeFence drops every fence trigger, the functions and the two tables, in
// one transaction, only if any exist.
func removeFence(ctx context.Context, conn *sql.Conn, schema string) error {
	rows, err := conn.QueryContext(ctx, `SELECT c.relname, t.tgname FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%'`, schema)
	if err != nil {
		return err
	}
	var drops []string
	for rows.Next() {
		var rel, name string
		if err := rows.Scan(&rel, &name); err != nil {
			_ = rows.Close()
			return err
		}
		drops = append(drops, "DROP TRIGGER "+quoteIdent(name)+" ON "+qualify(schema, rel))
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var tables int
	if err := conn.QueryRowContext(ctx, "SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname IN ("+quoteList([]string{HolderTable, EpochTable})+")", schema).Scan(&tables); err != nil {
		return err
	}
	if len(drops) == 0 && tables == 0 {
		return nil
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	drops = append(drops,
		"DROP FUNCTION IF EXISTS "+qualify(schema, guardFunc)+"()", "DROP FUNCTION IF EXISTS "+qualify(schema, fenceOnlyFunc)+"()",
		"DROP FUNCTION IF EXISTS "+qualify(schema, checkFunc)+"(text)",
		"DROP TABLE IF EXISTS "+qualify(schema, HolderTable), "DROP TABLE IF EXISTS "+qualify(schema, EpochTable))
	for _, d := range drops {
		if _, err := tx.ExecContext(ctx, d); err != nil {
			return fmt.Errorf("single_writer: remove the fence left by an earlier single-writer boot (%s): %w", d, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	logf("removed the write fence left by an earlier single_writer boot (single_writer is off)")
	return nil
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// openOne opens a one-connection pool for a short check, with its
// search_path pinned (pinSessionSchema), and returns the schema.
func openOne(ctx context.Context, cfg *config.Config) (*sql.DB, *sql.Conn, string, error) {
	cc, err := config.ResolvePostgresConnConfig(&cfg.Storage.Database)
	if err != nil {
		return nil, nil, "", err
	}
	db := stdlibOpen(cc)
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, nil, "", err
	}
	schema, err := pinSessionSchema(ctx, conn)
	if err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, nil, "", err
	}
	return db, conn, schema, nil
}

// FenceReport is the installed fence as seen from outside the server (the
// posture report).
type FenceReport struct {
	HolderLive bool
	HolderPID  int
	Triggers   int // fence triggers present in the current schema
	Always     int // of which ENABLE ALWAYS
	Expected   int // triggers a complete fence has
	// BelowSQL: the role this configuration connects as is a superuser, or
	// may run server-side programs or write server files. Such a session can
	// change the security tables below SQL (native code, the data directory)
	// with no trigger firing and no catalog row changing, which neither the
	// fence nor the fingerprint can see.
	BelowSQL bool
}

// Complete reports whether every expected trigger is present and ENABLE ALWAYS.
func (r FenceReport) Complete() bool {
	return r.Triggers == r.Expected && r.Always == r.Expected
}

// InspectFence reads the fence's state without changing anything.
func InspectFence(ctx context.Context, cfg *config.Config) (FenceReport, error) {
	rep := FenceReport{Expected: len(triggerSpecs(""))}
	if st := cfg.Storage.Type; st != "postgres" && st != "postgresql" {
		return rep, nil
	}
	db, conn, schema, err := openOne(ctx, cfg)
	if err != nil {
		return rep, err
	}
	defer func() { _ = conn.Close(); _ = db.Close() }()
	if rep.HolderPID, err = holderPID(ctx, conn, schema); err != nil {
		return rep, err
	}
	rep.HolderLive = rep.HolderPID != 0
	err = conn.QueryRowContext(ctx, fenceCountSQL, schema).Scan(&rep.Triggers, &rep.Always)
	if err != nil {
		return rep, err
	}
	err = conn.QueryRowContext(ctx, belowSQLQuery).Scan(&rep.BelowSQL)
	return rep, err
}

// fenceCountSQL counts the fence triggers in schema $1, and those ENABLE ALWAYS.
const fenceCountSQL = `SELECT pg_catalog.count(*), pg_catalog.count(*) FILTER (WHERE t.tgenabled = 'A')
FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid JOIN pg_catalog.pg_namespace ns ON ns.oid = c.relnamespace
WHERE ns.nspname = $1 AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%'`

// belowSQLQuery reports whether the session's role can reach below SQL.
const belowSQLQuery = `SELECT r.rolsuper OR pg_catalog.pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER')
  OR pg_catalog.pg_has_role(current_user, 'pg_write_server_files', 'MEMBER')
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`
