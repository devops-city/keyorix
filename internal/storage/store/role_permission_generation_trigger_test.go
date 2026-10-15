// role_permission_generation_trigger_test.go — #3259: a direct database
// change to role_permissions / permissions is seen by a warm store on its next
// decision, and a database without the triggers never serves the cache.
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// rpgWorld is a warm reader (ls), a second store on its own connection that
// makes the direct change (writer), a user and a machine holding one role
// with one permission at one scope.
type rpgWorld struct {
	ls, writer *LocalStorage
	sc         storage.Scope
	uid, mid   uint
	role       *models.Role
	perm       *models.Permission
}

func newRPGWorld(t *testing.T, backend string) rpgWorld {
	t.Helper()
	ls, reopen := newPrincipalPermStorage(t, backend)
	w := ppWorld{t: t, ls: ls}
	ctx := context.Background()
	p := w.project()
	sc := storage.Scope{ProjectID: p}
	perm := w.perm()
	role := w.role(false, perm)
	uid := w.user()
	require.NoError(t, ls.AssignRole(ctx, uid, role.ID, sc))
	mid := w.machine(p)
	require.NoError(t, ls.AssignMachineRole(ctx, mid, role.ID, sc))
	return rpgWorld{ls: ls, writer: reopen(), sc: sc, uid: uid, mid: mid, role: role, perm: perm}
}

// decide asks all three cached decision paths for w.perm: the machine and user
// one-statement resolutions and RoleSetHasPermission. They must agree.
func (w rpgWorld) decide(t *testing.T, name string) bool {
	t.Helper()
	ctx := context.Background()
	m, err := w.ls.ResolveMachinePermissionAt(ctx, w.mid, w.sc, name)
	require.NoError(t, err)
	u, err := w.ls.ResolveUserPermissionAt(ctx, w.uid, w.sc, name)
	require.NoError(t, err)
	r, err := w.ls.RoleSetHasPermission(ctx, []uint{w.role.ID}, name)
	require.NoError(t, err)
	require.Equal(t, m.HasPermission, u.HasPermission, "machine and user paths disagree")
	require.Equal(t, m.HasPermission, r, "resolution and RoleSetHasPermission disagree")
	return r
}

type rpgCase struct {
	name     string
	pgOnly   bool
	before   bool // the decision the warm cache holds
	change   func(t *testing.T, w rpgWorld)
	nameRead func(w rpgWorld) string
}

func rpgCases() []rpgCase {
	permName := func(w rpgWorld) string { return w.perm.Name }
	return []rpgCase{
		{name: "edge-deleted", before: true, nameRead: permName, change: func(t *testing.T, w rpgWorld) {
			require.NoError(t, w.writer.db.Exec("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?", w.role.ID, w.perm.ID).Error)
		}},
		{name: "permission-renamed", before: true, nameRead: permName, change: func(t *testing.T, w rpgWorld) {
			require.NoError(t, w.writer.db.Exec("UPDATE permissions SET name = name || '.renamed' WHERE id = ?", w.perm.ID).Error)
		}},
		{name: "edge-inserted", before: false, nameRead: func(w rpgWorld) string { return w.perm.Name + ".granted" }, change: func(t *testing.T, w rpgWorld) {
			p := &models.Permission{Name: w.perm.Name + ".granted", Resource: "pp", Action: w.perm.Name + ".granted"}
			require.NoError(t, w.writer.db.Exec("INSERT INTO permissions (name, resource, action) VALUES (?, ?, ?)", p.Name, p.Resource, p.Action).Error)
			require.NoError(t, w.writer.db.Exec("INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = ?", w.role.ID, p.Name).Error)
		}},
		{name: "truncate", pgOnly: true, before: true, nameRead: permName, change: func(t *testing.T, w rpgWorld) {
			require.NoError(t, w.writer.db.Exec("TRUNCATE role_permissions").Error)
		}},
		{name: "replica-role-session", pgOnly: true, before: true, nameRead: permName, change: func(t *testing.T, w rpgWorld) {
			// session_replication_role = replica skips ordinary triggers (what
			// pg_restore and logical replication run under); the triggers are
			// ENABLE ALWAYS so they still fire. One transaction, so SET LOCAL
			// and the DELETE share a connection. Needs a superuser (the test DSN's
			// role is one, as in CI).
			require.NoError(t, w.writer.db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Exec("SET LOCAL session_replication_role = replica").Error; err != nil {
					return err
				}
				return tx.Exec("DELETE FROM role_permissions WHERE role_id = ?", w.role.ID).Error
			}))
		}},
	}
}

// TestRolePermissionGeneration_DirectSQLSeenOnNextDecision: warm every cached
// path, change the tables directly on another connection, and the very next
// decision must reflect it. Red without the triggers (#3259).
func TestRolePermissionGeneration_DirectSQLSeenOnNextDecision(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		for _, tc := range rpgCases() {
			if tc.pgOnly && backend != "postgres" {
				continue
			}
			t.Run(backend+"/"+tc.name, func(t *testing.T) {
				w := newRPGWorld(t, backend)
				name := tc.nameRead(w)
				require.Equal(t, tc.before, w.decide(t, name), "warm")
				require.Equal(t, tc.before, w.decide(t, name), "warm, from the cache")
				tc.change(t, w)
				require.Equal(t, !tc.before, w.decide(t, name), "the very next decision after a direct change must reflect it")
			})
		}
	}
}

// TestRolePermissionGeneration_MissingTriggerBypassesCache: a database whose
// triggers are gone (a restore that skipped them, an operator's DROP) or, on
// Postgres, disabled, must never answer from the cache: the generation would
// no longer move on a direct change. The direct change is then seen anyway,
// because the live join answers. Red-proof: make rolePermGenerationExpr skip
// the proof and the post-change decision is the stale cached one.
func TestRolePermissionGeneration_MissingTriggerBypassesCache(t *testing.T) {
	type removal struct {
		name   string
		pgOnly bool
		sql    func(backend string) string
	}
	removals := []removal{
		{name: "dropped", sql: func(backend string) string {
			if backend == "postgres" {
				return "DROP TRIGGER " + RolePermissionsGenerationTrigger + " ON role_permissions"
			}
			return "DROP TRIGGER " + sqliteRolePermGenerationTriggerName(RolePermissionsGenerationTrigger, "DELETE")
		}},
		{name: "disabled", pgOnly: true, sql: func(string) string {
			return "ALTER TABLE role_permissions DISABLE TRIGGER " + RolePermissionsGenerationTrigger
		}},
	}
	for _, backend := range principalPermBackends(t) {
		for _, rm := range removals {
			if rm.pgOnly && backend != "postgres" {
				continue
			}
			t.Run(backend+"/"+rm.name, func(t *testing.T) {
				w := newRPGWorld(t, backend)
				require.True(t, w.decide(t, w.perm.Name), "warm")
				require.NoError(t, w.writer.db.Exec(rm.sql(backend)).Error)
				_, trusted, err := liveRolePermissionsGeneration(context.Background(), w.ls)
				require.NoError(t, err)
				require.False(t, trusted, "the generation must read as untrusted once a trigger is %s", rm.name)
				// A DELETE the remaining triggers (if any) do not see.
				require.NoError(t, w.writer.db.Exec("DELETE FROM role_permissions WHERE role_id = ?", w.role.ID).Error)
				require.False(t, w.decide(t, w.perm.Name), "a store must not serve its cache while the generation triggers are %s", rm.name)

				// Reinstalled (the next boot's migration): the cache is used again.
				require.NoError(t, EnsureRolePermissionsGenerationTriggers(w.writer.db))
				_, trusted, err = liveRolePermissionsGeneration(context.Background(), w.ls)
				require.NoError(t, err)
				require.True(t, trusted, "reinstalled triggers must be trusted again")
			})
		}
	}
}

// TestRolePermissionGeneration_EnsureIsIdempotentAndConverges: a second run
// changes nothing; on SQLite a trigger with a different body is replaced, on
// Postgres a trigger left as an ordinary trigger (pg_restore re-enables that
// way) is turned back into ENABLE ALWAYS.
func TestRolePermissionGeneration_EnsureIsIdempotentAndConverges(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newRPGWorld(t, backend)
			db := w.writer.db
			require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
			if backend == "postgres" {
				require.NoError(t, db.Exec("ALTER TABLE permissions ENABLE TRIGGER "+PermissionsGenerationTrigger).Error)
				require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
				var state string
				require.NoError(t, db.Raw("SELECT tgenabled::text FROM pg_trigger WHERE tgrelid = 'permissions'::regclass AND tgname = ?",
					PermissionsGenerationTrigger).Scan(&state).Error)
				require.Equal(t, "A", state)
			} else {
				name := sqliteRolePermGenerationTriggerName(PermissionsGenerationTrigger, "UPDATE")
				require.NoError(t, db.Exec("DROP TRIGGER "+name).Error)
				require.NoError(t, db.Exec("CREATE TRIGGER "+name+" AFTER UPDATE ON permissions FOR EACH ROW BEGIN SELECT 1; END").Error)
				require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
				var body string
				require.NoError(t, db.Raw("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?", name).Scan(&body).Error)
				require.Equal(t, sqliteRolePermGenerationTriggerSQL("permissions", PermissionsGenerationTrigger, "UPDATE"), body)
			}
			// Still correct afterwards.
			require.True(t, w.decide(t, w.perm.Name))
			require.NoError(t, db.Exec("UPDATE permissions SET name = name || '.x' WHERE id = ?", w.perm.ID).Error)
			require.False(t, w.decide(t, w.perm.Name))
		})
	}
}
