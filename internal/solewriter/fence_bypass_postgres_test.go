package solewriter

// fence_bypass_postgres_test.go — SQL-level ways around the fence and the
// epoch that need no trigger change (REVIEW-SINGLE-WRITER-2 N1–N3): name
// resolution through the writer's search_path, a fenced table made the child
// of a new parent, and an epoch moved back to its old value. pg-gated.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
)

// foreignTx runs stmts in one foreign transaction. %SCHEMA% is the world's
// schema, %d the credential id.
func (w *swWorld) foreignTx(stmts ...string) error {
	return w.foreign.Transaction(func(tx *gorm.DB) error {
		for _, s := range stmts {
			s = strings.ReplaceAll(s, "%SCHEMA%", w.schema)
			if strings.Contains(s, "%d") {
				s = fmt.Sprintf(s, w.credID)
			}
			if err := tx.Exec(s).Error; err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	})
}

// dmlRole creates a role with only DML grants on the world's schema (and the
// TEMP every role has by default): no ownership, no CREATE, no superuser.
func (w *swWorld) dmlRole() string {
	w.t.Helper()
	role := "swdml_" + w.schema
	for _, s := range []string{
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE",
		"GRANT USAGE ON SCHEMA " + w.schema + " TO " + role,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA " + w.schema + " TO " + role,
	} {
		require.NoError(w.t, w.foreign.Exec(s).Error, s)
	}
	w.t.Cleanup(func() {
		_ = w.foreign.Exec("DROP OWNED BY " + role).Error
		_ = w.foreign.Exec("DROP ROLE IF EXISTS " + role).Error
	})
	return role
}

// TestFence_NameResolutionCannotBeHijacked: the fence functions resolve
// nothing through the writer's search_path. A temp table named like a
// catalog (pg_temp is searched before pg_catalog for relations unless
// pg_catalog is listed), or a function or operator of the same name and
// argument types in a schema the writer puts first, must not change what the
// fence checks or counts (REVIEW-SINGLE-WRITER-2 N1). Every case is a foreign
// write while the holder lives, so every case must be refused.
func TestFence_NameResolutionCannotBeHijacked(t *testing.T) {
	revoke := "UPDATE machine_identity_credentials SET revoked = true WHERE id = %d"
	evil := "swevil_%SCHEMA%"
	shadowPath := "SET LOCAL search_path = " + evil + ", pg_catalog, %SCHEMA%"
	cases := []struct {
		name  string
		setup []string // committed first (CREATE SCHEMA and its objects)
		stmts []string
		asDML bool
	}{
		// Needs nothing but TEMP and DML, which roles get by default; the
		// same transaction moves the epoch back (N1 + N3).
		{name: "dml-role-temp-pg_database-and-epoch-rewind", asDML: true, stmts: []string{
			"CREATE TEMP TABLE pg_database (oid oid, datname name)",
			revoke,
			"UPDATE " + EpochTable + " SET n = n - 1 WHERE id = 1",
		}},
		{name: "temp-pg_database", stmts: []string{"CREATE TEMP TABLE pg_database (oid oid, datname name)", revoke}},
		{name: "temp-pg_locks", stmts: []string{"CREATE TEMP TABLE pg_locks (locktype text, granted boolean, pid integer, database oid, classid oid, objid oid, objsubid smallint)", revoke}},
		{name: "function-format", setup: []string{
			"CREATE SCHEMA " + evil,
			"CREATE FUNCTION " + evil + ".format(text, name) RETURNS text LANGUAGE sql AS $$ SELECT 'SELECT 1'::text $$",
		}, stmts: []string{shadowPath, revoke}},
		{name: "function-encode", setup: []string{
			"CREATE SCHEMA " + evil,
			"CREATE FUNCTION " + evil + ".encode(bytea, text) RETURNS text LANGUAGE sql AS $$ SELECT nonce_hash FROM %SCHEMA%." + HolderTable + " $$",
		}, stmts: []string{shadowPath, revoke}},
		{name: "function-hashtext", setup: []string{
			"CREATE SCHEMA " + evil,
			"CREATE FUNCTION " + evil + ".hashtext(text) RETURNS integer LANGUAGE sql AS $$ SELECT 0 $$",
		}, stmts: []string{shadowPath, revoke}},
		{name: "operator-text-equals", setup: []string{
			"CREATE SCHEMA " + evil,
			"CREATE FUNCTION " + evil + ".yes(text, text) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$",
			"CREATE OPERATOR " + evil + ".= (LEFTARG = text, RIGHTARG = text, FUNCTION = " + evil + ".yes)",
		}, stmts: []string{shadowPath, revoke}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newSWWorld(t)
			t.Cleanup(func() {
				_ = w.foreign.Exec("DROP SCHEMA IF EXISTS " + strings.ReplaceAll(evil, "%SCHEMA%", w.schema) + " CASCADE").Error
			})
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			stmts := tc.stmts
			if tc.asDML {
				stmts = append([]string{"SET LOCAL ROLE " + w.dmlRole()}, stmts...)
			}
			if len(tc.setup) > 0 {
				require.NoError(t, w.foreignTx(tc.setup...))
			}
			e0 := w.epoch(w.foreign)
			requireFenced(t, w.foreignTx(stmts...), tc.name)
			require.False(t, w.revoked(), "the refused revocation must not have been applied")
			require.Equal(t, e0, w.epoch(w.foreign))
		})
	}
}

// TestFence_FencedTableAsAChild: a write that reaches a fenced table's rows
// through a new parent (ALTER TABLE ... INHERIT, ATTACH PARTITION) fires no
// statement-level trigger of the fenced table, so the fence must be per row;
// and the inheritance itself is tampering the census sees, even with no write
// (REVIEW-SINGLE-WRITER-2 N2).
func TestFence_FencedTableAsAChild(t *testing.T) {
	refused := []struct {
		name  string
		stmts []string
	}{
		{"inherit-delete-then-restore", []string{
			"CREATE TABLE sw_parent (id bigint)",
			"ALTER TABLE machine_identity_credentials INHERIT sw_parent",
			"DELETE FROM sw_parent WHERE id = %d",
			"ALTER TABLE machine_identity_credentials NO INHERIT sw_parent",
			"DROP TABLE sw_parent",
		}},
		{"inherit-update-then-restore", []string{
			"CREATE TABLE sw_parent (state text)",
			"ALTER TABLE machine_identities INHERIT sw_parent",
			"UPDATE sw_parent SET state = 'revoked'",
			"ALTER TABLE machine_identities NO INHERIT sw_parent",
			"DROP TABLE sw_parent",
		}},
		{"inherit-update-left-in-place", []string{
			"CREATE TABLE sw_parent (state text)",
			"ALTER TABLE machine_identities INHERIT sw_parent",
			"UPDATE sw_parent SET state = 'revoked'",
		}},
		{"attach-partition-update-then-detach", []string{
			"CREATE TABLE sw_root (LIKE machine_identities) PARTITION BY LIST (id)",
			"ALTER TABLE sw_root ATTACH PARTITION machine_identities DEFAULT",
			"UPDATE sw_root SET state = 'revoked'",
			"ALTER TABLE sw_root DETACH PARTITION machine_identities",
			"DROP TABLE sw_root",
		}},
		{"holder-row-through-a-parent", []string{
			"CREATE TABLE sw_parent (nonce_hash text)",
			"ALTER TABLE " + HolderTable + " INHERIT sw_parent",
			"UPDATE sw_parent SET nonce_hash = 'x'",
		}},
		{"epoch-row-through-a-parent", []string{
			"CREATE TABLE sw_parent (n bigint)",
			"ALTER TABLE " + EpochTable + " INHERIT sw_parent",
			"UPDATE sw_parent SET n = n - 1",
		}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			requireFenced(t, w.foreignTx(tc.stmts...), tc.name)
			var state string
			require.NoError(t, w.foreign.Raw("SELECT state FROM machine_identities LIMIT 1").Scan(&state).Error)
			require.Equal(t, "active", state)
			require.False(t, w.revoked())
		})
	}
	// The inheritance alone (no write yet), in either direction, and a column
	// rewritten by ALTER ... TYPE ... USING (no DML trigger fires for a
	// table rewrite): seen at the next poll.
	seen := []struct {
		name  string
		stmts []string
	}{
		{"fenced-table-becomes-a-child", []string{"CREATE TABLE sw_parent (state text)", "ALTER TABLE machine_identities INHERIT sw_parent"}},
		{"fenced-table-becomes-a-partition", []string{
			"CREATE TABLE sw_root (LIKE machine_identities) PARTITION BY LIST (id)",
			"ALTER TABLE sw_root ATTACH PARTITION machine_identities DEFAULT",
		}},
		{"epoch-table-becomes-a-child", []string{"CREATE TABLE sw_parent (n bigint)", "ALTER TABLE " + EpochTable + " INHERIT sw_parent"}},
		{"column-rewritten-by-alter-type", []string{"ALTER TABLE machine_identity_credentials ALTER COLUMN revoked TYPE boolean USING true"}},
		{"column-renamed", []string{"ALTER TABLE machine_identities RENAME COLUMN state TO state_was"}},
	}
	for _, tc := range seen {
		t.Run(tc.name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			require.NoError(t, w.foreignTx(tc.stmts...))
			d := waitFor(t, 2*time.Second, func() bool { return !g.Authoritative() })
			require.GreaterOrEqual(t, d, time.Duration(0), "the census did not see %s", tc.name)
			require.LessOrEqual(t, d, PollInterval+pollTimeout)
			require.Contains(t, g.Status().Reason, "write fence changed")
		})
	}
}

// TestInstallFence_RefusesAFencedTableThatIsAChild: the boot-time half of
// TestFence_FencedTableAsAChild.
func TestInstallFence_RefusesAFencedTableThatIsAChild(t *testing.T) {
	w := newSWWorld(t)
	require.NoError(t, w.foreignTx("CREATE TABLE sw_parent (state text)", "ALTER TABLE machine_identities INHERIT sw_parent"))
	g, err := Start(t.Context(), w.cfg, Options{LockWait: 500 * time.Millisecond, SkipPresenceCensus: true})
	require.NoError(t, err)
	t.Cleanup(g.Close)
	err = g.InstallFence(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "machine_identities INHERITS sw_parent")
}

// TestPoll_EpochRewindIsSeen: a session that passes the fence (here one that
// copied the server's tag, the documented residual) and moves the epoch back
// in the same transaction leaves n where it was. The poller must still see
// the write and flush (REVIEW-SINGLE-WRITER-2 N3).
func TestPoll_EpochRewindIsSeen(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	var flushes atomic.Int64
	g.OnEpochChange(func(int64) { flushes.Add(1) })
	e0 := w.epoch(w.foreign)
	require.NoError(t, w.foreignTx(
		"SELECT set_config('"+config.SoleWriterSessionSetting+"', '"+g.nonce+"', true)",
		"UPDATE machine_identity_credentials SET revoked = true WHERE id = %d",
		"UPDATE "+EpochTable+" SET n = n - 1 WHERE id = 1",
	))
	require.True(t, w.revoked())
	require.Equal(t, e0, w.epoch(w.foreign), "the test needs a net-zero epoch")
	d := waitFor(t, 2*time.Second, func() bool { return flushes.Load() > 0 })
	require.GreaterOrEqual(t, d, time.Duration(0), "a net-zero epoch write must still flush")
	require.LessOrEqual(t, d, PollInterval+pollTimeout)
}
