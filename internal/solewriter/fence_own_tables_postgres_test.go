package solewriter

// fence_own_tables_postgres_test.go — the holder and epoch tables against a
// role that holds only table privileges (REVIEW-SINGLE-WRITER-3): N5, a write
// to the holder row itself must not open the fence; N6, a lock on the guard's
// own tables must not cost the guard its lock session; and the trigger census
// over every trigger on a covered table. pg-gated.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// privRole creates a NOSUPERUSER, non-owner role with privs on every table of
// the world's schema.
func (w *swWorld) privRole(tag, privs string) string {
	w.t.Helper()
	role := "swp" + tag + "_" + w.schema
	for _, s := range []string{
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE",
		"GRANT USAGE ON SCHEMA " + w.schema + " TO " + role,
		"GRANT " + privs + " ON ALL TABLES IN SCHEMA " + w.schema + " TO " + role,
	} {
		require.NoError(w.t, w.foreign.Exec(s).Error, s)
	}
	w.t.Cleanup(func() {
		_ = w.foreign.Exec("DROP OWNED BY " + role).Error
		_ = w.foreign.Exec("DROP ROLE IF EXISTS " + role).Error
	})
	return role
}

// asRole runs stmts in one foreign transaction as role.
func (w *swWorld) asRole(role string, stmts ...string) error {
	return w.foreign.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL ROLE " + role).Error; err != nil {
			return err
		}
		for _, s := range stmts {
			if err := tx.Exec(s).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ownRows is every column and the row version of both own tables, as text.
func (w *swWorld) ownRows() string {
	w.t.Helper()
	var h, e sql.NullString
	require.NoError(w.t, w.foreign.Raw("SELECT (SELECT h::text || ':' || h.xmin::text FROM "+HolderTable+" h WHERE id = 1), (SELECT e::text || ':' || e.xmin::text FROM "+EpochTable+" e WHERE id = 1)").Row().Scan(&h, &e))
	return h.String + " | " + e.String
}

// TestFence_OwnTablesRefuseATablePrivilegedRole (REVIEW-SINGLE-WRITER-3 N5):
// a role with table privileges only writes every column of both own tables,
// deletes their rows, upserts and truncates them. Every write must be refused
// by the fence, leave both rows (values and row version) as they were, and
// leave the fence closed: the holder still holds the lock and a foreign write
// to a fenced table is still refused.
func TestFence_OwnTablesRefuseATablePrivilegedRole(t *testing.T) {
	h, e := HolderTable, EpochTable
	cases := map[string]string{
		"holder-id":                "UPDATE " + h + " SET id = id",
		"holder-holder_pid":        "UPDATE " + h + " SET holder_pid = pg_backend_pid()",
		"holder-holder_pid-null":   "UPDATE " + h + " SET holder_pid = NULL",
		"holder-nonce_hash":        "UPDATE " + h + " SET nonce_hash = encode(sha256(convert_to('', 'UTF8')), 'hex')",
		"holder-since":             "UPDATE " + h + " SET since = now()",
		"holder-boot_id":           "UPDATE " + h + " SET boot_id = 'x'",
		"holder-delete":            "DELETE FROM " + h,
		"holder-upsert":            "INSERT INTO " + h + " (id, holder_pid) VALUES (1, pg_backend_pid()) ON CONFLICT (id) DO UPDATE SET holder_pid = EXCLUDED.holder_pid",
		"holder-merge":             "MERGE INTO " + h + " t USING (SELECT 1 AS id) s ON t.id = s.id WHEN MATCHED THEN UPDATE SET holder_pid = NULL",
		"holder-truncate":          "TRUNCATE " + h,
		"holder-delete-then-write": "DELETE FROM " + h + "; UPDATE machine_identity_credentials SET revoked = true",
		"epoch-id":                 "UPDATE " + e + " SET id = id",
		"epoch-incarnation":        "UPDATE " + e + " SET incarnation = 'x'",
		"epoch-n":                  "UPDATE " + e + " SET n = n + 1",
		"epoch-delete":             "DELETE FROM " + e,
		"epoch-upsert":             "INSERT INTO " + e + " (id, incarnation, n) VALUES (1, 'x', 0) ON CONFLICT (id) DO UPDATE SET n = 0",
		"epoch-truncate":           "TRUNCATE " + e,
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			role := w.privRole("o", "SELECT, INSERT, UPDATE, DELETE, TRUNCATE")
			before := w.ownRows()
			err := w.asRole(role, strings.Split(stmt, "; ")...)
			requireFenced(t, err, name)
			require.Equal(t, before, w.ownRows(), "%s: an own-table row changed", name)
			pid, err := holderPID(context.Background(), mustSQLConn(t, w), w.schema)
			require.NoError(t, err)
			require.Equal(t, g.PID(), pid)
			requireFenced(t, w.asRole(role, "UPDATE machine_identity_credentials SET revoked = true"), name+" then a fenced write")
			require.False(t, w.revoked())
			time.Sleep(2 * PollInterval)
			require.True(t, g.Authoritative(), "%s: a refused write must not cost the guard its state", name)
		})
	}
}

func mustSQLConn(t *testing.T, w *swWorld) *sql.DB {
	t.Helper()
	d, err := w.foreign.DB()
	require.NoError(t, err)
	return d
}

// TestPoll_HolderRowChangeLeavesAuthoritative (N5, second half): a session
// that passes the fence (here one carrying the holder's tag, as a copied tag
// would) rewrites the holder row. The poller compares holder_pid, nonce_hash
// and the row version with its own, so even a rewrite to the same values is
// seen.
func TestPoll_HolderRowChangeLeavesAuthoritative(t *testing.T) {
	for name, stmt := range map[string]string{
		"other-pid":   "UPDATE " + HolderTable + " SET holder_pid = holder_pid + 1",
		"other-hash":  "UPDATE " + HolderTable + " SET nonce_hash = 'x'",
		"same-values": "UPDATE " + HolderTable + " SET holder_pid = holder_pid, nonce_hash = nonce_hash",
		"deleted":     "DELETE FROM " + HolderTable,
	} {
		t.Run(name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			require.NoError(t, w.own().Exec(stmt).Error)
			d := waitFor(t, 2*time.Second, func() bool { return g.Status().State == StateConfirming })
			require.GreaterOrEqual(t, d, time.Duration(0), "the poller did not see the holder row change")
			require.Contains(t, g.Status().Reason, "holder row")
			time.Sleep(2 * PollInterval)
			require.False(t, g.Authoritative(), "a changed holder row leaves authoritative until restart")
		})
	}
}

// TestPoll_OwnTableLockKeepsTheHolderLock (REVIEW-SINGLE-WRITER-3 N6): a role
// with UPDATE on an own table locks it for longer than pollTimeout. The poll
// blocks; the lease runs out (fail closed). It must not cost the guard its
// lock session: once the lock is released the holder pid still holds the
// lock and the guard is authoritative again.
func TestPoll_OwnTableLockKeepsTheHolderLock(t *testing.T) {
	for _, table := range []string{EpochTable, HolderTable} {
		t.Run(table, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			role := w.privRole("l", "SELECT, INSERT, UPDATE, DELETE")
			done := make(chan error, 1)
			go func() {
				done <- w.asRole(role, "LOCK TABLE "+table+" IN ACCESS EXCLUSIVE MODE", "SELECT pg_sleep(2.5)")
			}()
			d := waitFor(t, 2500*time.Millisecond, func() bool { return !g.Authoritative() })
			require.GreaterOrEqual(t, d, time.Duration(0), "a blocked poll must let the lease run out")
			require.NoError(t, <-done)
			d = waitFor(t, 2*time.Second, g.Authoritative)
			st := g.Status()
			require.GreaterOrEqual(t, d, time.Duration(0), "not authoritative again after the lock cleared: state=%s reason=%q lastErr=%q", st.State, st.Reason, st.LastPollError)
			pid, err := holderPID(context.Background(), mustSQLConn(t, w), w.schema)
			require.NoError(t, err)
			require.Equal(t, g.PID(), pid, "the holder lost its lock session")
		})
	}
}

// TestFence_ForeignTriggerOnACoveredTable (TRIGGER-privilege hardening): a
// trigger that is not one of the fence's on a covered table can rewrite or
// suppress rows around the fence. One present at install keeps the guard out
// of the authoritative state and is reported by InspectFence; one added later
// is a fingerprint change.
func TestFence_ForeignTriggerOnACoveredTable(t *testing.T) {
	fn := "CREATE FUNCTION sw_foreign_trg() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
	trg := "CREATE TRIGGER zz_foreign BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION sw_foreign_trg()"
	t.Run("at-install", func(t *testing.T) {
		w := newSWWorld(t)
		require.NoError(t, w.foreignTx(fn, trg))
		g := w.start(Options{})
		time.Sleep(2 * PollInterval)
		require.False(t, g.Authoritative())
		require.Equal(t, StateConfirming, g.Status().State)
		require.Contains(t, g.Status().Reason, "zz_foreign")
		rep, err := InspectFence(context.Background(), w.cfg)
		require.NoError(t, err)
		require.Equal(t, []string{"roles.zz_foreign"}, rep.ForeignTriggers)
	})
	t.Run("added-later", func(t *testing.T) {
		w := newSWWorld(t)
		g := w.start(Options{})
		require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
		require.NoError(t, w.foreignTx(fn, trg))
		d := waitFor(t, 2*time.Second, func() bool { return g.Status().State == StateConfirming })
		require.GreaterOrEqual(t, d, time.Duration(0))
		require.Contains(t, g.Status().Reason, "write fence changed")
	})
}

// TestInstallFence_RefusesAFenceTriggerThatDiffers: a trigger with a fence
// trigger's name, timing, events, level and function name, but another WHEN
// clause or a function of that name in another schema, is not the fence.
// InstallFence compares the full definition and refuses.
func TestInstallFence_RefusesAFenceTriggerThatDiffers(t *testing.T) {
	upd := TriggerPrefix + "guard_upd"
	cases := map[string][]string{
		"when-false": {
			"DROP TRIGGER " + upd + " ON machine_identity_credentials",
			"CREATE TRIGGER " + upd + " AFTER UPDATE ON machine_identity_credentials FOR EACH ROW WHEN (false) EXECUTE PROCEDURE " + guardFunc + "()",
		},
		"function-in-another-schema": {
			"CREATE SCHEMA %SCHEMA%_evil",
			"CREATE FUNCTION %SCHEMA%_evil." + guardFunc + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$",
			"DROP TRIGGER " + upd + " ON machine_identity_credentials",
			"CREATE TRIGGER " + upd + " AFTER UPDATE ON machine_identity_credentials FOR EACH ROW WHEN ((to_jsonb(OLD) - 'last_used_at') IS DISTINCT FROM (to_jsonb(NEW) - 'last_used_at')) EXECUTE PROCEDURE %SCHEMA%_evil." + guardFunc + "()",
		},
	}
	for name, stmts := range cases {
		t.Run(name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			g.Close()
			t.Cleanup(func() { _ = w.foreign.Exec("DROP SCHEMA IF EXISTS " + w.schema + "_evil CASCADE").Error })
			require.NoError(t, w.foreignTx(stmts...))
			g2, err := Start(context.Background(), w.cfg, Options{SkipPresenceCensus: true, LockWait: 500 * time.Millisecond})
			require.NoError(t, err)
			t.Cleanup(g2.Close)
			err = g2.InstallFence(context.Background())
			require.Error(t, err, "a differing fence trigger was accepted")
			require.Contains(t, err.Error(), "unexpected definition")
		})
	}
}
