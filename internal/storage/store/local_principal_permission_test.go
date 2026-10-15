package store

// PERF-FIX-6: ResolveUserPermissionAt / ResolveMachinePermissionAt must answer
// exactly what the classic per-statement methods answer (GetUserRoleIDsAt ∪
// GetUserGroupRoleIDsAt, RoleSetBypassesPermissionChecks, RoleSetHasPermission;
// GetMachineRoleIDsAt + RoleSetHasPermission), in one statement on a warm
// role->permission cache, with that cache's rules unchanged.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var principalPermModels = []any{
	&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
	&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	&models.Project{}, &models.Environment{}, &models.MachineIdentity{}, &models.MachineIdentityRole{},
	&models.SystemMetadata{},
}

// newPrincipalPermStorage returns a caching LocalStorage on backend and a
// function opening another, independent LocalStorage (own pool, own cache) on
// the same database.
func newPrincipalPermStorage(t *testing.T, backend string) (*LocalStorage, func() *LocalStorage) {
	t.Helper()
	var open func() *gorm.DB
	if backend == "sqlite" {
		path := filepath.Join(t.TempDir(), "pp.db")
		open = func() *gorm.DB {
			db, err := gorm.Open(sqlite.Open("file:"+path+"?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL"), &gorm.Config{Logger: logger.Discard})
			require.NoError(t, err)
			t.Cleanup(func() {
				if sqlDB, err := db.DB(); err == nil {
					_ = sqlDB.Close()
				}
			})
			return db
		}
	} else {
		dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
		open = func() *gorm.DB { return pgOpen(t, dsn) }
	}
	db := open()
	require.NoError(t, db.AutoMigrate(principalPermModels...))
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db)) // #3259, see newRolePermCacheTestStorage
	// On Postgres the stores read their hot statements on a native pool, as the
	// factory-built storage does (native_reads.go).
	mk := func(db *gorm.DB) *LocalStorage {
		ls := NewLocalStorage(db)
		if backend != "sqlite" {
			attachNativeReadPool(t, ls)
		}
		return ls
	}
	return mk(db), func() *LocalStorage { return mk(open()) }
}

func principalPermBackends(t *testing.T) []string {
	if os.Getenv("KEYORIX_TEST_PG_DSN") != "" {
		return []string{"sqlite", "postgres"}
	}
	t.Log("KEYORIX_TEST_PG_DSN not set: Postgres leg skipped")
	return []string{"sqlite"}
}

var ppSeq atomic.Int64

type ppWorld struct {
	t  *testing.T
	ls *LocalStorage
}

func (w ppWorld) name(p string) string { return fmt.Sprintf("%s-%d", p, ppSeq.Add(1)) }

func (w ppWorld) perm() *models.Permission {
	n := w.name("pp.perm")
	p, err := w.ls.CreatePermission(context.Background(), &models.Permission{Name: n, Resource: "pp", Action: n})
	require.NoError(w.t, err)
	return p
}

func (w ppWorld) role(bypass bool, perms ...*models.Permission) *models.Role {
	ctx := context.Background()
	n, err := identity.NewFoldedName(w.name("pp-role"))
	require.NoError(w.t, err)
	r, err := w.ls.CreateRole(ctx, n, "")
	require.NoError(w.t, err)
	for _, p := range perms {
		require.NoError(w.t, w.ls.AssignPermissionToRole(ctx, r.ID, p.ID))
	}
	if bypass {
		require.NoError(w.t, w.ls.SetRoleBypassesPermissionChecks(ctx, r.ID, true))
	}
	return r
}

func (w ppWorld) user() uint {
	n := w.name("pp-user")
	u, err := w.ls.CreateUser(context.Background(), &models.User{Username: n, UsernameFolded: n, Email: n + "@x.io", EmailFolded: n + "@x.io"})
	require.NoError(w.t, err)
	return u.ID
}

func (w ppWorld) group() uint {
	n := w.name("pp-group")
	g, err := w.ls.CreateGroup(context.Background(), &models.Group{Name: n, NameFolded: n})
	require.NoError(w.t, err)
	return g.ID
}

func (w ppWorld) project() uint {
	p, err := w.ls.CreateProject(context.Background(), &models.Project{Name: w.name("pp-project")})
	require.NoError(w.t, err)
	return p.ID
}

func (w ppWorld) env(projectID uint) uint {
	e, err := w.ls.CreateEnvironment(context.Background(), &models.Environment{ProjectID: projectID, Name: w.name("pp-env")})
	require.NoError(w.t, err)
	return e.ID
}

func (w ppWorld) machine(projectID uint) uint {
	m, err := w.ls.CreateMachineIdentity(context.Background(), &models.MachineIdentity{ProjectID: projectID, Name: w.name("pp-m"), State: "active"})
	require.NoError(w.t, err)
	return m.ID
}

// classicUser is what core.Authorize read before PERF-FIX-6, one statement at a time.
func classicUser(t *testing.T, ls *LocalStorage, userID uint, scope storage.Scope, perm string) storage.PrincipalPermission {
	ctx := context.Background()
	direct, err := ls.GetUserRoleIDsAt(ctx, userID, scope)
	require.NoError(t, err)
	viaGroups, err := ls.GetUserGroupRoleIDsAt(ctx, userID, scope)
	require.NoError(t, err)
	var out storage.PrincipalPermission
	for _, id := range append(direct, viaGroups...) {
		if !slices.Contains(out.RoleIDs, id) {
			out.RoleIDs = append(out.RoleIDs, id)
		}
	}
	if len(out.RoleIDs) == 0 {
		return out
	}
	out.BypassesPermissionChecks, err = ls.RoleSetBypassesPermissionChecks(ctx, out.RoleIDs)
	require.NoError(t, err)
	if !out.BypassesPermissionChecks {
		out.HasPermission, err = ls.RoleSetHasPermission(ctx, out.RoleIDs, perm)
		require.NoError(t, err)
	}
	return out
}

func classicMachine(t *testing.T, ls *LocalStorage, machineID uint, scope storage.Scope, perm string) storage.PrincipalPermission {
	ctx := context.Background()
	ids, err := ls.GetMachineRoleIDsAt(ctx, machineID, scope)
	require.NoError(t, err)
	out := storage.PrincipalPermission{RoleIDs: ids}
	if len(ids) > 0 {
		out.HasPermission, err = ls.RoleSetHasPermission(ctx, ids, perm)
		require.NoError(t, err)
	}
	return out
}

func requireSamePrincipalPermission(t *testing.T, want storage.PrincipalPermission, got *storage.PrincipalPermission, msg string) {
	t.Helper()
	require.NotNil(t, got, msg)
	require.ElementsMatch(t, want.RoleIDs, got.RoleIDs, "%s: role ids", msg)
	require.Len(t, got.RoleIDs, len(want.RoleIDs), "%s: role ids de-duplicated", msg)
	require.Equal(t, want.BypassesPermissionChecks, got.BypassesPermissionChecks, "%s: bypass", msg)
	require.Equal(t, want.HasPermission, got.HasPermission, "%s: has permission", msg)
}

func TestResolvePrincipalPermission_EquivalentToClassicMethods(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, reopen := newPrincipalPermStorage(t, backend)
			classic := reopen() // own cache: the classic answers never share an entry with ls
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			pR, pW, pO := w.perm(), w.perm(), w.perm()
			rR, rW, rB, rRW := w.role(false, pR), w.role(false, pW), w.role(true), w.role(false, pR, pW)
			p1, p2, pDel := w.project(), w.project(), w.project()
			e1, e2, eDel := w.env(p1), w.env(p1), w.env(p1)
			past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

			g1, gScoped, gDel, gExp, gAdm := w.group(), w.group(), w.group(), w.group(), w.group()
			require.NoError(t, ls.AssignRoleToGroup(ctx, g1, rW.ID, storage.Scope{ProjectID: p1}))
			require.NoError(t, ls.AssignRoleToGroup(ctx, gScoped, rR.ID, storage.Scope{ProjectID: p2}))
			require.NoError(t, ls.AssignRoleToGroup(ctx, gDel, rB.ID, storage.Scope{}))
			require.NoError(t, ls.AssignRoleToGroupWithExpiry(ctx, gExp, rR.ID, storage.Scope{ProjectID: p1}, past))
			require.NoError(t, ls.AssignRoleToGroup(ctx, gAdm, rB.ID, storage.Scope{ProjectID: p1, EnvironmentID: e1}))
			require.NoError(t, ls.AssignRoleToGroup(ctx, g1, rR.ID, storage.Scope{ProjectID: pDel}))

			var users []uint
			u := func(grant func(id uint)) {
				id := w.user()
				grant(id)
				users = append(users, id)
			}
			u(func(id uint) {}) // no roles
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{})) })
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rB.ID, storage.Scope{ProjectID: p1})) })
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rR.ID, storage.Scope{ProjectID: p1})) })
			u(func(id uint) {
				require.NoError(t, ls.AssignRole(ctx, id, rR.ID, storage.Scope{ProjectID: p1, EnvironmentID: e1}))
			})
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rRW.ID, storage.Scope{})) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, g1, 0)) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, g1, p2)) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gScoped, p2)) })
			u(func(id uint) {
				require.NoError(t, ls.AssignRole(ctx, id, rR.ID, storage.Scope{ProjectID: p1}))
				require.NoError(t, ls.AddUserToGroup(ctx, id, g1, 0))
			})
			u(func(id uint) {
				require.NoError(t, ls.AssignRole(ctx, id, rW.ID, storage.Scope{ProjectID: p1}))
				require.NoError(t, ls.AddUserToGroup(ctx, id, g1, 0)) // same role both ways
			})
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gDel, 0)) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gExp, 0)) })
			u(func(id uint) { require.NoError(t, ls.AddUserToGroup(ctx, id, gAdm, 0)) })
			u(func(id uint) {
				require.NoError(t, ls.AssignRoleWithExpiry(ctx, id, rB.ID, storage.Scope{}, past))
				require.NoError(t, ls.AssignRoleWithExpiry(ctx, id, rR.ID, storage.Scope{ProjectID: p1}, future))
			})
			u(func(id uint) { require.NoError(t, ls.AssignRole(ctx, id, rR.ID, storage.Scope{ProjectID: pDel})) })
			u(func(id uint) {
				require.NoError(t, ls.AssignRole(ctx, id, rR.ID, storage.Scope{ProjectID: p1, EnvironmentID: eDel}))
			})

			var machines []uint
			m := func(grant func(id uint)) {
				id := w.machine(p1)
				grant(id)
				machines = append(machines, id)
			}
			m(func(id uint) {})
			m(func(id uint) { require.NoError(t, ls.AssignMachineRole(ctx, id, rR.ID, storage.Scope{ProjectID: p1})) })
			m(func(id uint) { require.NoError(t, ls.AssignMachineRole(ctx, id, rB.ID, storage.Scope{ProjectID: p1})) })
			m(func(id uint) {
				require.NoError(t, ls.AssignMachineRole(ctx, id, rB.ID, storage.Scope{ProjectID: p1}))
				require.NoError(t, ls.AssignMachineRole(ctx, id, rRW.ID, storage.Scope{ProjectID: p1, EnvironmentID: e1}))
			})
			m(func(id uint) {
				require.NoError(t, ls.AssignMachineRole(ctx, id, rR.ID, storage.Scope{ProjectID: pDel}))
			})
			m(func(id uint) {
				require.NoError(t, ls.AssignMachineRole(ctx, id, rR.ID, storage.Scope{ProjectID: p1, EnvironmentID: eDel}))
			})

			require.NoError(t, ls.DeleteGroup(ctx, gDel))
			// Soft-delete the rows (role resolution reads only deleted_at; the full
			// DeleteProject cascade is not what this test is about).
			require.NoError(t, ls.db.Delete(&models.Project{ID: pDel}).Error)
			require.NoError(t, ls.db.Delete(&models.Environment{ID: eDel}).Error)

			scopes := []storage.Scope{{}, {ProjectID: p1}, {ProjectID: p2}, {ProjectID: pDel},
				{ProjectID: p1, EnvironmentID: e1}, {ProjectID: p1, EnvironmentID: e2}, {ProjectID: p1, EnvironmentID: eDel}}
			perms := []string{pR.Name, pW.Name, pO.Name}
			n := 0
			for pass := range 2 { // cold, then warm
				for _, sc := range scopes {
					for _, perm := range perms {
						for _, id := range users {
							msg := fmt.Sprintf("user %d scope %+v perm %s pass %d", id, sc, perm, pass)
							got, err := ls.ResolveUserPermissionAt(ctx, id, sc, perm)
							require.NoError(t, err, msg)
							requireSamePrincipalPermission(t, classicUser(t, classic, id, sc, perm), got, msg)
							n++
						}
						for _, id := range machines {
							msg := fmt.Sprintf("machine %d scope %+v perm %s pass %d", id, sc, perm, pass)
							got, err := ls.ResolveMachinePermissionAt(ctx, id, sc, perm)
							require.NoError(t, err, msg)
							requireSamePrincipalPermission(t, classicMachine(t, classic, id, sc, perm), got, msg)
							n++
						}
					}
				}
			}
			t.Logf("%d decisions compared", n)
		})
	}
}

// ppCountStatements is countStatements (local_secret_schedule_and_version_test.go)
// with a unique callback name per call.
func ppCountStatements(t *testing.T, db *gorm.DB) *stmtCounter {
	return countStatements(t, db, fmt.Sprintf("pp%d", ppSeq.Add(1)))
}

// TestResolvePrincipalPermission_OneStatementAndSharedCache: warm = one
// statement; cold = that statement + the live join; the cache entry is the
// same one RoleSetHasPermission reads and writes (same key, same generation),
// in both directions; a never-bumped install (no generation row) caches under "".
func TestResolvePrincipalPermission_OneStatementAndSharedCache(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newPrincipalPermStorage(t, backend)
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			p := w.project()
			sc := storage.Scope{ProjectID: p}
			// Create permission rows and roles WITHOUT bumping: a never-bumped install.
			pR := w.perm()
			n, err := identity.NewFoldedName(w.name("pp-role"))
			require.NoError(t, err)
			r, err := ls.CreateRole(ctx, n, "")
			require.NoError(t, err)
			require.NoError(t, ls.db.Create(&models.RolePermission{RoleID: r.ID, PermissionID: pR.ID}).Error)
			// The #3259 triggers created the generation row on those writes; remove
			// it to get back to an install that has none.
			require.NoError(t, ls.db.Where("key = ?", rolePermissionsGenerationKey).Delete(&models.SystemMetadata{}).Error)
			var gens int64
			require.NoError(t, ls.db.Model(&models.SystemMetadata{}).Where("key = ?", rolePermissionsGenerationKey).Count(&gens).Error)
			require.Zero(t, gens, "precondition: never-bumped install")
			uid := w.user()
			require.NoError(t, ls.AssignRole(ctx, uid, r.ID, sc))
			mid := w.machine(p)
			require.NoError(t, ls.AssignMachineRole(ctx, mid, r.ID, sc))

			counter := ppCountStatements(t, ls.db)
			resolve := func(machine bool) (*storage.PrincipalPermission, []string) {
				var got *storage.PrincipalPermission
				var err error
				stmts := counter.during(func() {
					if machine {
						got, err = ls.ResolveMachinePermissionAt(ctx, mid, sc, pR.Name)
					} else {
						got, err = ls.ResolveUserPermissionAt(ctx, uid, sc, pR.Name)
					}
				})
				require.NoError(t, err)
				return got, stmts
			}
			got, stmts := resolve(false)
			require.True(t, got.HasPermission)
			require.Len(t, stmts, 2, "cold: combined statement + live join:\n%s", strings.Join(stmts, "\n"))
			got, stmts = resolve(false)
			require.True(t, got.HasPermission)
			require.Len(t, stmts, 1, "warm under the never-bumped generation \"\":\n%s", strings.Join(stmts, "\n"))
			got, stmts = resolve(true) // same role set, same key: the user's entry serves the machine
			require.True(t, got.HasPermission)
			require.Len(t, stmts, 1, "machine, same role set:\n%s", strings.Join(stmts, "\n"))

			// A bump (any role_permissions write) invalidates it.
			pX := w.perm()
			require.NoError(t, ls.AssignPermissionToRole(ctx, r.ID, pX.ID))
			got, stmts = resolve(true)
			require.True(t, got.HasPermission)
			require.Len(t, stmts, 2, "after a bump the entry must miss:\n%s", strings.Join(stmts, "\n"))

			// Classic RoleSetHasPermission finds the entry the new method published...
			stmts = counter.during(func() {
				ok, err := ls.RoleSetHasPermission(ctx, []uint{r.ID}, pR.Name)
				require.NoError(t, err)
				require.True(t, ok)
			})
			require.Len(t, stmts, 1, "classic hit = its generation probe only:\n%s", strings.Join(stmts, "\n"))
			// ...and the new method finds one the classic method published.
			stmts = counter.during(func() {
				ok, err := ls.RoleSetHasPermission(ctx, []uint{r.ID}, pX.Name)
				require.NoError(t, err)
				require.True(t, ok)
			})
			require.Len(t, stmts, 2, "classic cold (no entry, so no hit probe): probe + join:\n%s", strings.Join(stmts, "\n"))
			stmts = counter.during(func() {
				got, err := ls.ResolveUserPermissionAt(ctx, uid, sc, pX.Name)
				require.NoError(t, err)
				require.True(t, got.HasPermission)
			})
			require.Len(t, stmts, 1, "new method hits the classic entry:\n%s", strings.Join(stmts, "\n"))
		})
	}
}

// TestResolvePrincipalPermission_GenerationReadBeforeTheJoin: a permission
// removal committing between the live join and the publish must not leave the
// pre-removal answer servable. The generation used to publish is the one read
// with the role ids, BEFORE the join, so the entry is stale on arrival and the
// next decision misses and denies. (Publishing under a generation read after
// the join would serve the revoked permission until an unrelated bump.)
func TestResolvePrincipalPermission_GenerationReadBeforeTheJoin(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		for _, kind := range []string{"user", "machine"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				ls, reopen := newPrincipalPermStorage(t, backend)
				writer := reopen()
				w := ppWorld{t: t, ls: ls}
				ctx := context.Background()
				p := w.project()
				sc := storage.Scope{ProjectID: p}
				pR := w.perm()
				r := w.role(false, pR)
				uid := w.user()
				require.NoError(t, ls.AssignRole(ctx, uid, r.ID, sc))
				mid := w.machine(p)
				require.NoError(t, ls.AssignMachineRole(ctx, mid, r.ID, sc))
				resolve := func() bool {
					var got *storage.PrincipalPermission
					var err error
					if kind == "machine" {
						got, err = ls.ResolveMachinePermissionAt(ctx, mid, sc, pR.Name)
					} else {
						got, err = ls.ResolveUserPermissionAt(ctx, uid, sc, pR.Name)
					}
					require.NoError(t, err)
					return got.HasPermission
				}

				// One-shot hook: right after the live join (the only statement
				// joining role_permissions; the principal statement only names the
				// table in its #3259 trigger proof), another replica removes the
				// permission.
				var once sync.Once
				fired := false
				hook := func(db *gorm.DB) {
					if !strings.Contains(db.Statement.SQL.String(), sqlJoinRolePerms) {
						return
					}
					once.Do(func() {
						fired = true
						require.NoError(t, writer.RemovePermissionFromRole(ctx, r.ID, pR.ID))
					})
				}
				cb := ls.db.Callback()
				name := fmt.Sprintf("pp-hook-%d", ppSeq.Add(1))
				require.NoError(t, cb.Query().After("gorm:query").Register(name+":q", hook))
				require.NoError(t, cb.Row().After("gorm:row").Register(name+":row", hook))

				require.True(t, resolve(), "the join ran before the removal: allowed at that snapshot")
				require.True(t, fired, "harness: the removal must land between the join and the publish")
				require.False(t, resolve(), "the very next decision after the removal committed must deny")
				require.False(t, resolve(), "and keep denying")
			})
		}
	}
}

// TestResolvePrincipalPermission_TransactionScopedStoreNeverUsesTheCache: a
// tx-scoped store neither reads the shared cache (a poisoned entry under the
// live generation is ignored) nor publishes into it.
func TestResolvePrincipalPermission_TransactionScopedStoreNeverUsesTheCache(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ls, _ := newPrincipalPermStorage(t, backend)
			w := ppWorld{t: t, ls: ls}
			ctx := context.Background()
			p := w.project()
			sc := storage.Scope{ProjectID: p}
			pR, pW := w.perm(), w.perm()
			r := w.role(false, pR)
			uid := w.user()
			require.NoError(t, ls.AssignRole(ctx, uid, r.ID, sc))
			mid := w.machine(p)
			require.NoError(t, ls.AssignMachineRole(ctx, mid, r.ID, sc))

			gen, trusted, err := liveRolePermissionsGeneration(ctx, ls)
			require.NoError(t, err)
			require.True(t, trusted, "precondition: the generation triggers are installed")
			poisoned := rolePermKey([]uint{r.ID}, pW.Name)
			ls.rolePermCache.set(poisoned, rolePermCacheEntry{generation: gen, allowed: true})
			// Calibration: the non-tx store DOES serve the poisoned entry.
			got, err := ls.ResolveUserPermissionAt(ctx, uid, sc, pW.Name)
			require.NoError(t, err)
			require.True(t, got.HasPermission, "calibration: the poisoned entry is live for a caching store")

			before := len(ls.rolePermCache.entries)
			require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
				got, err := tx.ResolveUserPermissionAt(ctx, uid, sc, pW.Name)
				require.NoError(t, err)
				require.False(t, got.HasPermission, "tx-scoped user read must go live, not to the cache")
				got, err = tx.ResolveMachinePermissionAt(ctx, mid, sc, pW.Name)
				require.NoError(t, err)
				require.False(t, got.HasPermission, "tx-scoped machine read must go live, not to the cache")
				got, err = tx.ResolveUserPermissionAt(ctx, uid, sc, pR.Name)
				require.NoError(t, err)
				require.True(t, got.HasPermission)
				return nil
			}))
			require.Equal(t, before, len(ls.rolePermCache.entries), "a tx-scoped store must publish nothing")
			_, published := ls.rolePermCache.get(rolePermKey([]uint{r.ID}, pR.Name))
			require.False(t, published, "a tx-scoped store must publish nothing")
		})
	}
}
