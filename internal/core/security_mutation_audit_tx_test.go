package core

// security_mutation_audit_tx_test.go — AUDIT-TX-2: every grant-shaped security
// mutation commits its audit row in its own transaction, on SQLite and on
// PostgreSQL (set KEYORIX_TEST_PG_DSN; the Postgres leg skips without it).
//
// For every kind below:
//   - success: the change is visible AND one more row of its audit type exists
//     the moment the call returns;
//   - the audit append fails (faultstorage on LogAuditEvent, the
//     transaction-scoped call): the call returns ErrMutationAuditUnavailable and
//     nothing changed, audit rows included;
//   - effect-then-error: the append really inserts, then reports an error. Still
//     nothing may remain, which proves the row was written INSIDE the mutation's
//     transaction (a separate append would have committed it);
//   - panic: same as an error;
//   - crash: the goroutine running the mutation dies (runtime.Goexit) at the
//     audit append, the in-process stand-in for kill -9 there. The mutation must
//     not survive without its row. On main the grant had already committed when
//     the append ran, so it survived unaudited.
//
// Red on main: the mutations committed first and appended afterwards through
// c.storage, so every failure kind left a committed grant behind.

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// crashAtAuditStorage ends the calling goroutine (runtime.Goexit: deferred
// calls run, nothing after them does) at the first LogAuditEvent while armed —
// the point a process killed at the audit append would stop. A transaction
// still open there rolls back from its deferred handler, exactly as the
// database rolls back the transaction of a killed process.
type crashAtAuditStorage struct {
	inner storage.Storage
	armed *atomic.Bool
}

func (s crashAtAuditStorage) LogAuditEvent(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
	if s.armed.CompareAndSwap(true, false) {
		runtime.Goexit()
	}
	return next.LogAuditEvent(ctx, e)
}

// wrap returns inner decorated with crashAtAuditStorage's overrides.
func (s *crashAtAuditStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx:        true,
		LogAuditEvent: s.LogAuditEvent,
	})
}

// store returns s.inner decorated with crashAtAuditStorage's overrides.
func (s *crashAtAuditStorage) store() storage.Storage { return s.wrap(s.inner) }

// satWorld is smaWorld (secret_mutation_audit_tx_test.go) plus a second core
// whose storage can crash at the audit append, and the fixtures the grant
// kinds need.
type satWorld struct {
	*smaWorld
	crash      *atomic.Bool
	crashCore  *KeyorixCore
	member     *models.User // a project member, the target of grants and shares
	devRole    *models.Role
	viewerRole *models.Role
	permID     uint
	group      *models.Group
	secretID   uint
	machine    *models.MachineIdentity
	seq        int
}

func newSATWorld(t *testing.T, f *ctaReview) *satWorld {
	t.Helper()
	w := &satWorld{smaWorld: newSMAWorld(t, f), crash: &atomic.Bool{}}
	w.crashCore = NewKeyorixCore((&crashAtAuditStorage{inner: w.fs, armed: w.crash}).store())
	for _, c := range []*KeyorixCore{w.c, w.crashCore} {
		c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour})
	}
	ctx := context.Background()
	w.member = f.user("sat-member", "project_viewer")
	var err error
	w.devRole, err = f.setup.Storage().GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	w.viewerRole, err = f.setup.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	perm, err := f.setup.Storage().CreatePermission(ctx, &models.Permission{Name: "sat.custom", Description: "sat"})
	require.NoError(t, err)
	w.permID = perm.ID
	w.group, err = f.setup.CreateGroup(ctx, f.adminID, &CreateGroupRequest{Name: "sat-group"})
	require.NoError(t, err)
	// Owned by a project member: share authority needs live membership.
	w.secretID = f.secret("sat-secret", w.member.ID).ID
	w.machine, err = f.setup.CreateMachineIdentity(ctx, f.projectID, "sat-machine", "service", "", "", f.adminID, 0)
	require.NoError(t, err)
	return w
}

func (w *satWorld) tag(prefix string) string {
	w.seq++
	return fmt.Sprintf("%s%d", prefix, w.seq)
}

// fingerprint counts every table a grant-shaped mutation may touch, audit rows
// included.
func (w *satWorld) fingerprint() string {
	w.t.Helper()
	out := ""
	for _, m := range []any{
		&models.UserRole{}, &models.GroupRole{}, &models.RolePermission{}, &models.Role{}, &models.UserGroup{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.PersonalAccessToken{}, &models.User{}, &models.Project{},
		&models.Environment{}, &models.BreakGlassActivation{}, &models.SoDPolicy{}, &models.AuditEvent{},
	} {
		var n int64
		require.NoError(w.t, w.db.Model(m).Count(&n).Error)
		out += fmt.Sprintf("%T=%d ", m, n)
	}
	var perms []string
	require.NoError(w.t, w.db.Model(&models.ShareRecord{}).Order("id").Pluck("permission", &perms).Error)
	return out + fmt.Sprint(perms)
}

func (w *satWorld) eventRows(eventType string) int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

// satKind is one mutation. prepare runs unfaulted; mutate runs the mutation
// through c (the plain or the crashing core) and returns its error.
type satKind struct {
	name      string
	eventType string
	prepare   func(w *satWorld) any
	mutate    func(w *satWorld, c *KeyorixCore, state any) error
}

func satKinds() []satKind {
	none := func(*satWorld) any { return nil }
	freshUser := func(w *satWorld) any { return w.f.user(w.tag("sat-u"), "project_viewer") }
	share := func(w *satWorld) any {
		u := w.f.user(w.tag("sat-s"), "project_viewer")
		s, err := w.c.ShareSecret(context.Background(), &ShareSecretRequest{SecretID: w.secretID, RecipientID: u.ID, Permission: "read", SharedBy: w.member.ID})
		require.NoError(w.t, err)
		return s
	}
	adminCtx := func(w *satWorld) context.Context { return context.Background() }
	return []satKind{
		{name: "assign-user-role", eventType: EventRoleAssigned, prepare: freshUser,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.AssignUserRole(adminCtx(w), w.f.adminID, s.(*models.User).ID, w.devRole.ID, Scope{ProjectID: w.f.projectID}, false)
			}},
		{name: "assign-user-role-expiry", eventType: EventRoleAssigned, prepare: freshUser,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.AssignUserRoleWithExpiry(adminCtx(w), w.f.adminID, s.(*models.User).ID, w.devRole.ID, Scope{ProjectID: w.f.projectID}, time.Now().Add(time.Hour), false)
			}},
		{name: "assign-group-role", eventType: EventRoleGroupAssigned,
			prepare: func(w *satWorld) any {
				g, err := w.c.CreateGroup(context.Background(), w.f.adminID, &CreateGroupRequest{Name: w.tag("sat-g")})
				require.NoError(w.t, err)
				return g
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.AssignRoleToGroup(adminCtx(w), w.f.adminID, s.(*models.Group).ID, w.devRole.ID, Scope{ProjectID: w.f.projectID}, false)
			}},
		{name: "assign-permission", eventType: EventPermissionAdded,
			prepare: func(w *satWorld) any {
				r, _, err := w.c.CreateRole(context.Background(), w.f.adminID, w.tag("sat-r"), "", nil)
				require.NoError(w.t, err)
				return r
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.AssignPermissionToRole(adminCtx(w), w.f.adminID, s.(*models.Role).ID, w.permID, false)
			}},
		{name: "create-role", eventType: EventRoleCreated, prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, _, err := c.CreateRole(adminCtx(w), w.f.adminID, w.tag("sat-cr"), "", []uint{w.permID})
				return err
			}},
		{name: "update-role", eventType: EventRoleUpdated,
			prepare: func(w *satWorld) any {
				r, _, err := w.c.CreateRole(context.Background(), w.f.adminID, w.tag("sat-ur"), "", nil)
				require.NoError(w.t, err)
				return r
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				r := *s.(*models.Role)
				r.Description = "changed"
				_, _, err := c.UpdateRole(adminCtx(w), w.f.adminID, &r, &[]uint{w.permID})
				return err
			}},
		{name: "add-group-member", eventType: EventGroupMemberAdded, prepare: freshUser,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.AddUserToGroup(adminCtx(w), w.f.adminID, false, s.(*models.User).ID, w.group.ID, 0)
			}},
		{name: "share-secret", eventType: string(ShareAuditEventCreated), prepare: freshUser,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.ShareSecret(adminCtx(w), &ShareSecretRequest{SecretID: w.secretID, RecipientID: s.(*models.User).ID, Permission: "read", SharedBy: w.member.ID})
				return err
			}},
		{name: "update-share", eventType: string(ShareAuditEventUpdated), prepare: share,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.UpdateSharePermission(adminCtx(w), &UpdateShareRequest{ShareID: s.(*models.ShareRecord).ID, Permission: "write", UpdatedBy: w.member.ID})
				return err
			}},
		{name: "grant-secret-acl", eventType: EventSecretACLGranted, prepare: freshUser,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.GrantSecretACL(adminCtx(w), w.f.adminID, w.secretID, s.(*models.User).ID, []string{"secrets.read"})
			}},
		{name: "create-machine-identity", eventType: "machine_identity.created", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateMachineIdentity(adminCtx(w), w.f.projectID, w.tag("sat-m"), "service", "", "", w.f.adminID, 0)
				return err
			}},
		{name: "issue-machine-token", eventType: "machine_identity.token_issued", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.IssueMachineToken(adminCtx(w), w.f.projectID, w.machine.ID, w.f.adminID, IssueMachineTokenParams{Name: w.tag("sat-t")})
				return err
			}},
		{name: "assign-machine-role", eventType: "machine_identity.role_granted",
			prepare: func(w *satWorld) any {
				m, err := w.c.CreateMachineIdentity(context.Background(), w.f.projectID, w.tag("sat-mr"), "service", "", "", w.f.adminID, 0)
				require.NoError(w.t, err)
				return m
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.AssignMachineRole(adminCtx(w), s.(*models.MachineIdentity).ID, w.viewerRole.ID, Scope{ProjectID: w.f.projectID}, w.f.adminID, false)
			}},
		{name: "create-pat", eventType: EventPATCreated, prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateOwnPAT(adminCtx(w), w.member.ID, w.tag("sat-p"), nil, nil, 0, 0, nil)
				return err
			}},
		{name: "create-user-with-assignments", eventType: EventUserCreated, prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				n := w.tag("sat-cu")
				_, err := c.CreateUserWithAssignments(adminCtx(w), &CreateUserRequest{Username: n, Email: n + "@example.com", DisplayName: n, Password: "UserPass123!xyz-long-enough"},
					"", []ProjectAssignment{{ProjectID: w.f.projectID, Role: "project_viewer"}}, w.f.adminID, false)
				return err
			}},
		{name: "create-user-audited", eventType: EventUserCreated, prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				n := w.tag("sat-pu")
				_, err := c.CreateUserAudited(adminCtx(w), &CreateUserRequest{Username: n, Email: n + "@example.com", DisplayName: n, Password: "UserPass123!xyz-long-enough"}, w.f.adminID)
				return err
			}},
		{name: "create-project", eventType: EventProjectCreated, prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateProject(WithMutationAuditActor(adminCtx(w), w.f.adminID), w.tag("sat-proj"), "")
				return err
			}},
		{name: "create-environment", eventType: EventEnvironmentCreated, prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateEnvironment(WithMutationAuditActor(adminCtx(w), w.f.adminID), w.f.projectID, w.tag("sat-env"))
				return err
			}},
		{name: "activate-break-glass", eventType: EventBreakGlassActivated, prepare: freshUser,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.ActivateBreakGlass(adminCtx(w), w.f.projectID, s.(*models.User).ID, "production outage, paging incident commander now", "")
				return err
			}},
		{name: "create-sod-policy", eventType: EventSoDPolicyCreated, prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateSoDPolicy(adminCtx(w), w.f.adminID, w.tag("sat-sod"), "", "secrets.read", "audit.read")
				return err
			}},
		{name: "delete-sod-policy", eventType: EventSoDPolicyDeleted,
			prepare: func(w *satWorld) any {
				p, err := w.c.CreateSoDPolicy(context.Background(), w.f.adminID, w.tag("sat-sodd"), "", "secrets.write", "audit.read")
				require.NoError(w.t, err)
				return p
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeleteSoDPolicy(adminCtx(w), w.f.adminID, s.(*models.SoDPolicy).ID)
			}},
	}
}

// runCrashing runs fn on its own goroutine and reports whether it returned
// (false: it ended inside runtime.Goexit).
func runCrashing(fn func() error) (returned bool, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		err = fn()
		returned = true
	}()
	<-done
	return returned, err
}

func TestSecurityMutationAudit_RowExistsIffMutationCommitted(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		for _, k := range satKinds() {
			t.Run(k.name+"/success", func(t *testing.T) {
				state := k.prepare(w)
				before, rows := w.fingerprint(), w.eventRows(k.eventType)
				require.NoError(t, k.mutate(w, w.c, state))
				require.NotEqual(t, before, w.fingerprint(), "precondition: the mutation must have changed state")
				require.Equal(t, rows+1, w.eventRows(k.eventType),
					"%s committed, so its %s row must exist when the call returns", k.name, k.eventType)
			})
			for _, fk := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError, faultstorage.KindPanic} {
				t.Run(k.name+"/audit-"+fk.String(), func(t *testing.T) {
					state := k.prepare(w)
					before := w.fingerprint()
					w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: fk, Err: errors.New("injected audit failure")})
					err := func() (err error) {
						defer func() {
							if r := recover(); r != nil {
								err = fmt.Errorf("panic escaped the mutation: %v", r)
							}
						}()
						return k.mutate(w, w.c, state)
					}()
					fired := w.fs.Fired()
					w.fs.Arm(nil)
					require.True(t, fired, "%s never appended its audit row through storage", k.name)
					require.ErrorIs(t, err, ErrMutationAuditUnavailable, "a failed audit append must fail the mutation")
					require.Equal(t, before, w.fingerprint(),
						"%s failed its audit append but changed state anyway: the mutation committed without its audit row", k.name)
				})
			}
			t.Run(k.name+"/crash-at-audit", func(t *testing.T) {
				state := k.prepare(w)
				before := w.fingerprint()
				w.crash.Store(true)
				returned, err := runCrashing(func() error { return k.mutate(w, w.crashCore, state) })
				armed := w.crash.Swap(false)
				require.False(t, armed, "%s never reached an audit append", k.name)
				require.False(t, returned, "precondition: the goroutine must have died at the append (returned err=%v)", err)
				require.Equal(t, before, w.fingerprint(),
					"%s: a crash at the audit append left the mutation committed without its audit row", k.name)
			})
		}
		v, err := w.c.Storage().VerifyAuditChain(context.Background(), nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "the audit chain must verify after every success and every rolled-back attempt: %s", v.Reason)
	})
}

// TestSecurityMutationAudit_UntaggedCreateWritesNoRow: CreateProject /
// CreateEnvironment / CreateUser called without an audit actor (internal and
// self-service callers that audit separately) write no row from core, so this
// change adds no duplicates for them.
func TestSecurityMutationAudit_UntaggedCreateWritesNoRow(t *testing.T) {
	w := newSATWorld(t, newCTAReviewSQLite(t))
	ctx := context.Background()
	p0, e0, u0 := w.eventRows(EventProjectCreated), w.eventRows(EventEnvironmentCreated), w.eventRows(EventUserCreated)
	_, err := w.c.CreateProject(ctx, "sat-untagged", "")
	require.NoError(t, err)
	_, err = w.c.CreateEnvironment(ctx, w.f.projectID, "sat-untagged-env")
	require.NoError(t, err)
	_, err = w.c.CreateUser(ctx, &CreateUserRequest{Username: "sat-untagged", Email: "sat-untagged@example.com", DisplayName: "u", Password: "UserPass123!xyz-long-enough"})
	require.NoError(t, err)
	require.Equal(t, p0, w.eventRows(EventProjectCreated))
	require.Equal(t, e0, w.eventRows(EventEnvironmentCreated))
	require.Equal(t, u0, w.eventRows(EventUserCreated))
}

// TestWithAuditedMutation_NoRowFailsClosed: a mutation run through
// withAuditedMutation that writes no audit row at all (a refactor that dropped
// the call) is refused and rolled back, not committed unaudited.
func TestWithAuditedMutation_NoRowFailsClosed(t *testing.T) {
	w := newSATWorld(t, newCTAReviewSQLite(t))
	before := w.fingerprint()
	err := w.c.withAuditedMutation(context.Background(), func(tx storage.Storage, _ auditTarget) error {
		_, err := tx.CreateSoDPolicy(context.Background(), &models.SoDPolicy{Name: "sat-unaudited", PermissionA: "a.b", PermissionB: "c.d", CreatedBy: w.f.adminID, CreatedAt: time.Now()})
		return err
	})
	require.ErrorIs(t, err, ErrMutationAuditUnavailable)
	require.ErrorIs(t, err, errMutationWroteNoAudit)
	require.Equal(t, before, w.fingerprint())
}
