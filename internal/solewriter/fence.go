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

// ensureOwnTables creates the holder and epoch tables (not GORM models: only
// this package reads or writes them).
func ensureOwnTables(ctx context.Context, conn *sql.Conn) error {
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS ` + HolderTable + ` (id integer PRIMARY KEY CHECK (id = 1), holder_pid integer, nonce_hash text, since timestamptz, boot_id text)`,
		`CREATE TABLE IF NOT EXISTS ` + EpochTable + ` (id integer PRIMARY KEY CHECK (id = 1), incarnation text NOT NULL, n bigint NOT NULL)`,
	} {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("single_writer: create %s: %w", strings.Fields(s)[5], err)
		}
	}
	return nil
}

// checkFuncBody raises when a live holder exists and the session is not one
// of its own. Shared by the guard and fence-only trigger functions.
func checkFuncBody() string {
	return `
DECLARE
  hpid integer;
  hhash text;
  hsince timestamptz;
BEGIN
  EXECUTE format('SELECT holder_pid, nonce_hash, since FROM %I.` + HolderTable + ` WHERE id = 1', sch) INTO hpid, hhash, hsince;
  IF hpid IS NULL THEN
    RETURN;
  END IF;
  IF hhash = encode(sha256(convert_to(coalesce(current_setting('` + config.SoleWriterSessionSetting + `', true), ''), 'UTF8')), 'hex') THEN
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
// Every object they touch is qualified with the fired table's schema, never
// resolved through the writer's search_path: an operator's session on another
// search_path must meet this schema's fence and epoch.
func guardFuncBody() string {
	return `
BEGIN
  EXECUTE format('SELECT %I.` + checkFunc + `($1)', TG_TABLE_SCHEMA) USING TG_TABLE_SCHEMA::text;
  EXECUTE format('UPDATE %I.` + EpochTable + ` SET n = n + 1 WHERE id = 1', TG_TABLE_SCHEMA);
  RETURN NULL;
END;
`
}

func fenceOnlyFuncBody() string {
	return `
BEGIN
  EXECUTE format('SELECT %I.` + checkFunc + `($1)', TG_TABLE_SCHEMA) USING TG_TABLE_SCHEMA::text;
  RETURN NULL;
END;
`
}

// triggerSpec is one fence trigger: its name, table and the rest of its
// CREATE TRIGGER text after "ON <table>".
type triggerSpec struct {
	name, table, events, rest string
}

func (t triggerSpec) create() string {
	return "CREATE TRIGGER " + t.name + " AFTER " + t.events + " ON " + t.table + " " + t.rest
}

// triggerSpecs derives every fence trigger from FencedTables.
func triggerSpecs() []triggerSpec {
	var out []triggerSpec
	stmt := "FOR EACH STATEMENT EXECUTE PROCEDURE " + guardFunc + "()"
	row := func(when string) string {
		return "FOR EACH ROW WHEN (" + when + ") EXECUTE PROCEDURE " + guardFunc + "()"
	}
	for _, t := range FencedTables {
		switch {
		case t.Key != "":
			k := "'" + t.Key + "'"
			out = append(out,
				triggerSpec{TriggerPrefix + "guard", t.Name, "TRUNCATE", stmt},
				triggerSpec{TriggerPrefix + "guard_ins", t.Name, "INSERT", row("NEW.key = " + k)},
				triggerSpec{TriggerPrefix + "guard_upd", t.Name, "UPDATE", row("OLD.key = " + k + " OR NEW.key = " + k)},
				triggerSpec{TriggerPrefix + "guard_del", t.Name, "DELETE", row("OLD.key = " + k)})
		case len(t.UpdateIgnores) > 0:
			minus := ""
			for _, c := range t.UpdateIgnores {
				minus += " - '" + c + "'"
			}
			out = append(out,
				triggerSpec{TriggerPrefix + "guard", t.Name, "INSERT OR DELETE OR TRUNCATE", stmt},
				triggerSpec{TriggerPrefix + "guard_upd", t.Name, "UPDATE", row("(to_jsonb(OLD)" + minus + ") IS DISTINCT FROM (to_jsonb(NEW)" + minus + ")")})
		default:
			out = append(out, triggerSpec{TriggerPrefix + "guard", t.Name, "INSERT OR UPDATE OR DELETE OR TRUNCATE", stmt})
		}
	}
	for _, own := range []string{HolderTable, EpochTable} {
		out = append(out, triggerSpec{TriggerPrefix + "fence", own, "INSERT OR UPDATE OR DELETE OR TRUNCATE",
			"FOR EACH STATEMENT EXECUTE PROCEDURE " + fenceOnlyFunc + "()"})
	}
	return out
}

// fingerprintSQL fingerprints every fence trigger in the current schema (its
// full definition, enabled state and catalog row version), the three
// functions (body and row version), and every table that inherits from a
// fenced table.
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
// child, so a child of a fenced table is tampering too.
const fingerprintSQL = `SELECT md5(
  coalesce((SELECT string_agg(c.relname || ':' || pg_get_triggerdef(t.oid) || ':' || t.tgenabled::text || ':' || t.xmin::text, E'\n' ORDER BY c.relname, t.tgname)
    FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema() AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%'), '')
  || '|' ||
  coalesce((SELECT string_agg(p.proname || ':' || md5(p.prosrc) || ':' || p.xmin::text, ',' ORDER BY p.proname)
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = current_schema() AND p.proname LIKE 'keyorix\_sole\_writer\_%'), '')
  || '|' ||
  coalesce((SELECT string_agg(i.inhparent::text || '<' || i.inhrelid::text, ',' ORDER BY i.inhparent, i.inhrelid)
    FROM pg_inherits i WHERE i.inhparent IN (
      SELECT t.tgrelid FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = current_schema() AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%')), ''))`

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
	for _, t := range FencedTables {
		var ok bool
		if err := tx.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", t.Name).Scan(&ok); err != nil {
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
		if err := exec("CREATE OR REPLACE FUNCTION " + f.name + f.sig + " RETURNS " + f.ret + " LANGUAGE plpgsql AS $keyorix$" + f.body + "$keyorix$"); err != nil {
			return fmt.Errorf("single_writer: create %s: %w", f.name, err)
		}
	}
	specs := triggerSpecs()
	for _, s := range specs {
		var state sql.NullString
		err := tx.QueryRowContext(ctx, "SELECT tgenabled::text FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = to_regclass($1) AND tgname = $2", s.table, s.name).Scan(&state)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if !state.Valid {
			if err := exec(s.create()); err != nil {
				return fmt.Errorf("single_writer: create %s on %s: %w", s.name, s.table, err)
			}
		}
		if state.String != "A" {
			if err := exec("ALTER TABLE " + s.table + " ENABLE ALWAYS TRIGGER " + s.name); err != nil {
				return fmt.Errorf("single_writer: enable %s on %s: %w", s.name, s.table, err)
			}
		}
	}
	incarnation, err := randomHex(16)
	if err != nil {
		return err
	}
	if err := exec(`INSERT INTO `+EpochTable+` (id, incarnation, n) VALUES (1, $1, 0) ON CONFLICT (id) DO UPDATE SET incarnation = EXCLUDED.incarnation`, incarnation); err != nil {
		return fmt.Errorf("single_writer: initialise the write epoch: %w", err)
	}
	// Verify what is now installed, inside the same transaction: every
	// expected trigger present and ENABLE ALWAYS, and no stray one. A trigger
	// with the right name but a different definition (from an older build)
	// would show up in the fingerprint only, so recreate-on-mismatch is not
	// attempted: refuse, and the operator drops it (the message says how).
	var n, always int
	if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE t.tgenabled = 'A')
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace ns ON ns.oid = c.relnamespace
WHERE ns.nspname = current_schema() AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%'`).Scan(&n, &always); err != nil {
		return err
	}
	if n != len(specs) || always != len(specs) {
		return fmt.Errorf("single_writer: fence verification failed: %d fence triggers present (%d ENABLE ALWAYS), want %d", n, always, len(specs))
	}
	for _, s := range specs {
		var def string
		if err := tx.QueryRowContext(ctx, "SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid = to_regclass($1) AND tgname = $2", s.table, s.name).Scan(&def); err != nil {
			return err
		}
		if !triggerDefMatches(def, s) {
			return fmt.Errorf("single_writer: fence trigger %s on %s has an unexpected definition (%s); drop it (DROP TRIGGER %s ON %s) and restart", s.name, s.table, def, s.name, s.table)
		}
	}
	// A table inheriting from a fenced one takes writes the fence never sees
	// (see fingerprintSQL); the fingerprint only notices one added later.
	var children string
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(string_agg(i.inhrelid::regclass::text || ' INHERITS ' || i.inhparent::regclass::text, ', '), '')
FROM pg_inherits i WHERE i.inhparent IN (SELECT to_regclass(x) FROM unnest($1::text[]) AS x)`, FencedTableNames()).Scan(&children); err != nil {
		return err
	}
	if children != "" {
		return fmt.Errorf("single_writer: a fenced table has a child table (%s): writes to it bypass the fence; remove the inheritance and restart", children)
	}
	var fp string
	if err := tx.QueryRowContext(ctx, fingerprintSQL).Scan(&fp); err != nil {
		return err
	}
	var epoch int64
	if err := tx.QueryRowContext(ctx, "SELECT n FROM "+EpochTable+" WHERE id = 1").Scan(&epoch); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("single_writer: install the fence: %w", err)
	}
	g.mu.Lock()
	g.fingerprint, g.incarnation, g.epoch = fp, incarnation, epoch
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
	db, conn, err := openOne(ctx, cfg)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = conn.Close(); _ = db.Close() }()
	pid, err := holderPID(ctx, conn)
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
	db, conn, err := openOne(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(); _ = db.Close() }()
	pid, err := holderPID(ctx, conn)
	if err != nil {
		return fmt.Errorf("single_writer: check for a single-writer server: %w", err)
	}
	if pid != 0 {
		return fmt.Errorf("a Keyorix server running with storage.database.single_writer holds this database (backend pid %d); it must be the only server. Stop it first, or remove this server", pid)
	}
	return removeFence(ctx, conn)
}

// removeFence drops every fence trigger, the functions and the two tables, in
// one transaction, only if any exist.
func removeFence(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, `SELECT c.relname, t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%'`)
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
		drops = append(drops, "DROP TRIGGER "+quoteIdent(name)+" ON "+quoteIdent(rel))
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var tables int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relname IN ("+quoteList([]string{HolderTable, EpochTable})+")").Scan(&tables); err != nil {
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
		"DROP FUNCTION IF EXISTS "+guardFunc+"()", "DROP FUNCTION IF EXISTS "+fenceOnlyFunc+"()", "DROP FUNCTION IF EXISTS "+checkFunc+"(text)",
		"DROP TABLE IF EXISTS "+HolderTable, "DROP TABLE IF EXISTS "+EpochTable)
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

// openOne opens a one-connection pool for a short check.
func openOne(ctx context.Context, cfg *config.Config) (*sql.DB, *sql.Conn, error) {
	cc, err := config.ResolvePostgresConnConfig(&cfg.Storage.Database)
	if err != nil {
		return nil, nil, err
	}
	db := stdlibOpen(cc)
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return db, conn, nil
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
	rep := FenceReport{Expected: len(triggerSpecs())}
	if st := cfg.Storage.Type; st != "postgres" && st != "postgresql" {
		return rep, nil
	}
	db, conn, err := openOne(ctx, cfg)
	if err != nil {
		return rep, err
	}
	defer func() { _ = conn.Close(); _ = db.Close() }()
	if rep.HolderPID, err = holderPID(ctx, conn); err != nil {
		return rep, err
	}
	rep.HolderLive = rep.HolderPID != 0
	err = conn.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE t.tgenabled = 'A')
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace ns ON ns.oid = c.relnamespace
WHERE ns.nspname = current_schema() AND NOT t.tgisinternal AND t.tgname LIKE 'trg\_ksw\_%'`).Scan(&rep.Triggers, &rep.Always)
	if err != nil {
		return rep, err
	}
	err = conn.QueryRowContext(ctx, belowSQLQuery).Scan(&rep.BelowSQL)
	return rep, err
}

// belowSQLQuery reports whether the session's role can reach below SQL.
const belowSQLQuery = `SELECT r.rolsuper OR pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER')
  OR pg_has_role(current_user, 'pg_write_server_files', 'MEMBER')
FROM pg_roles r WHERE r.rolname = current_user`
