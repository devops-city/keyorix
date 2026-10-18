package core

// revocation_owed_audit_test.go — AUDIT-TX-3: a revocation is never blocked by the
// audit log (Andrei 2026-10-14) and its audit row is never lost either (#3345's
// owed-audit record plus backfill), on SQLite and on PostgreSQL (set
// KEYORIX_TEST_PG_DSN; the Postgres leg skips without it).
//
// For every revocation kind below:
//   - success: the revocation took effect and its audit row(s) exist the moment the
//     call returns, with nothing left pending;
//   - the audit append fails (faultstorage on LogAuditEvent, the post-commit
//     append): the call still returns nil and the revocation still took effect, and
//     every owed row is either appended or queued (rows + pending == the success
//     count). BackfillPendingAuditEvents then writes exactly the missing rows;
//   - effect-then-error: the append really inserts, then reports an error. The
//     append's own transaction rolls back, so the row is queued, never doubled;
//   - panic: same as an error;
//   - crash: the goroutine running the revocation dies (runtime.Goexit) at the
//     post-commit append, the in-process stand-in for kill -9 there. The
//     revocation is committed and its row is queued: the record of what was owed
//     committed with the effect, so a crash cannot lose it;
//   - the owed-audit record cannot be written (error or panic on
//     CreatePendingAuditEvent): the revocation still goes through and its row is
//     appended directly.
//
// Red on main: the revocations wrote their row best-effort after the commit with
// no record, so every failure kind left a committed revocation with a missing row
// and nothing to backfill it from (rows + pending < the success count).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// effectFP fingerprints every table except the audit log and the owed-audit
// queue: what a revocation changes, nothing the audit machinery touches.
func (w *satWorld) effectFP() string {
	w.t.Helper()
	h := sha256.New()
	for _, m := range kxstorage.AllModels() {
		stmt := &gorm.Statement{DB: w.db}
		require.NoError(w.t, stmt.Parse(m))
		tn := stmt.Schema.Table
		if strings.HasPrefix(tn, "audit") || tn == "pending_audit_events" {
			continue
		}
		var rows []map[string]any
		require.NoError(w.t, w.db.Table(tn).Find(&rows).Error)
		lines := make([]string, len(rows))
		for i, r := range rows {
			lines[i] = fmt.Sprint(r)
		}
		sort.Strings(lines)
		_, _ = fmt.Fprintf(h, "%s:%d\n%s\n", tn, len(lines), strings.Join(lines, "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (w *satWorld) auditTotal() int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.AuditEvent{}).Count(&n).Error)
	return n
}

func (w *satWorld) pendingTotal() int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.PendingAuditEvent{}).Count(&n).Error)
	return n
}

// revKind is one revocation. prepare runs unfaulted; mutate runs the revocation
// through c (the plain or the crashing core).
type revKind struct {
	name    string
	prepare func(w *satWorld) any
	mutate  func(w *satWorld, c *KeyorixCore, state any) error
}

func (w *satWorld) newUser(prefix, role string) *models.User {
	return w.f.user(w.tag(prefix), role)
}

func (w *satWorld) newSession(userID uint) *models.Session {
	w.t.Helper()
	s := &models.Session{UserID: userID, SessionToken: w.tag("rev-sess"), CreatedAt: time.Now()}
	require.NoError(w.t, w.db.Create(s).Error)
	return s
}

func (w *satWorld) adminRoleID() uint {
	w.t.Helper()
	roles, err := w.f.setup.Storage().GetUserRoles(context.Background(), w.f.adminID)
	require.NoError(w.t, err)
	for _, r := range roles {
		if r.BypassesPermissionChecks {
			return r.ID
		}
	}
	require.FailNow(w.t, "the bootstrap admin holds no admin-bypass role")
	return 0
}

func revKinds() []revKind {
	ctx := context.Background()
	project := func(w *satWorld) Scope { return Scope{ProjectID: w.f.projectID} }
	viewer := func(w *satWorld) any { return w.newUser("rev-u", "project_viewer") }
	userID := func(s any) uint { return s.(*models.User).ID }
	share := func(w *satWorld) any {
		u := w.newUser("rev-s", "project_viewer")
		s, err := w.c.ShareSecret(ctx, &ShareSecretRequest{SecretID: w.secretID, RecipientID: u.ID, Permission: "read", SharedBy: w.member.ID})
		require.NoError(w.t, err)
		return [2]any{u, s}
	}
	group := func(w *satWorld) any {
		g, err := w.c.CreateGroup(ctx, w.f.adminID, &CreateGroupRequest{Name: w.tag("rev-g")})
		require.NoError(w.t, err)
		return g
	}
	machine := func(w *satWorld) any {
		m, err := w.c.CreateMachineIdentity(ctx, w.f.projectID, w.tag("rev-m"), "service", "", "", w.f.adminID, 0)
		require.NoError(w.t, err)
		return m
	}
	future := time.Now().Add(24 * time.Hour)
	return []revKind{
		{name: "remove-user-role", prepare: viewer,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemoveUserRole(ctx, w.f.adminID, userID(s), w.viewerRole.ID, project(w))
			}},
		{name: "remove-global-admin-role",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-adm", "")
				require.NoError(w.t, w.c.AssignUserRole(ctx, w.f.adminID, u.ID, w.adminRoleID(), Scope{}, false))
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemoveUserRole(ctx, w.f.adminID, userID(s), w.adminRoleID(), Scope{})
			}},
		{name: "remove-group-role",
			prepare: func(w *satWorld) any {
				g := group(w).(*models.Group)
				require.NoError(w.t, w.c.AssignRoleToGroup(ctx, w.f.adminID, g.ID, w.devRole.ID, project(w), false))
				return g
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemoveRoleFromGroup(ctx, w.f.adminID, s.(*models.Group).ID, w.devRole.ID, project(w))
			}},
		{name: "remove-permission",
			prepare: func(w *satWorld) any {
				r, _, err := w.c.CreateRole(ctx, w.f.adminID, w.tag("rev-r"), "", []uint{w.permID})
				require.NoError(w.t, err)
				return r
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemovePermissionFromRole(ctx, w.f.adminID, s.(*models.Role).ID, w.permID)
			}},
		{name: "delete-role",
			prepare: func(w *satWorld) any {
				r, _, err := w.c.CreateRole(ctx, w.f.adminID, w.tag("rev-dr"), "", []uint{w.permID})
				require.NoError(w.t, err)
				return r
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeleteRole(ctx, w.f.adminID, s.(*models.Role).ID)
			}},
		{name: "remove-group-member",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-gm", "project_viewer")
				require.NoError(w.t, w.c.AddUserToGroup(ctx, w.f.adminID, false, u.ID, w.group.ID, 0))
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemoveUserFromGroup(ctx, w.f.adminID, userID(s), w.group.ID, 0)
			}},
		{name: "delete-group", prepare: group,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeleteGroup(ctx, w.f.adminID, s.(*models.Group).ID)
			}},
		{name: "remove-project-member", prepare: viewer,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemoveProjectMember(ctx, w.f.adminID, w.f.projectID, userID(s))
			}},
		{name: "revoke-share", prepare: share,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RevokeShare(ctx, s.([2]any)[1].(*models.ShareRecord).ID, w.member.ID)
			}},
		{name: "remove-self-from-share", prepare: share,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemoveSelfFromShare(ctx, w.secretID, s.([2]any)[0].(*models.User).ID)
			}},
		{name: "expire-shares",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-se", "project_viewer")
				exp := time.Now().Add(time.Hour)
				_, err := w.c.ShareSecret(ctx, &ShareSecretRequest{SecretID: w.secretID, RecipientID: u.ID, Permission: "read", SharedBy: w.member.ID, ExpiresAt: &exp})
				require.NoError(w.t, err)
				return nil
			},
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				n, err := c.RemoveExpiredShares(ctx, time.Now().Add(2*time.Hour))
				if err == nil && n == 0 {
					return errors.New("the sweep removed nothing")
				}
				return err
			}},
		{name: "expire-role-grants",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-re", "")
				require.NoError(w.t, w.c.AssignUserRoleWithExpiry(ctx, w.f.adminID, u.ID, w.devRole.ID, project(w), time.Now().Add(time.Hour), false))
				return nil
			},
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				n, err := c.RemoveExpiredRoleGrants(ctx, time.Now().Add(2*time.Hour))
				if err == nil && n == 0 {
					return errors.New("the sweep removed nothing")
				}
				return err
			}},
		{name: "revoke-secret-acl",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-acl", "project_viewer")
				require.NoError(w.t, w.c.GrantSecretACL(ctx, w.f.adminID, w.secretID, u.ID, []string{"secrets.read"}))
				acls, err := w.c.ListSecretACLs(ctx, w.secretID)
				require.NoError(w.t, err)
				for _, a := range acls {
					if a.UserID == u.ID {
						return a.ID
					}
				}
				require.FailNow(w.t, "granted ACL not found")
				return nil
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RevokeSecretACL(ctx, w.f.adminID, w.secretID, s.(uint))
			}},
		{name: "suspend-machine-identity", prepare: machine,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.TransitionMachineIdentity(ctx, w.f.projectID, s.(*models.MachineIdentity).ID, MachineSuspended, w.f.adminID)
				return err
			}},
		{name: "revoke-machine-token",
			prepare: func(w *satWorld) any {
				m := machine(w).(*models.MachineIdentity)
				res, err := w.c.IssueMachineToken(ctx, w.f.projectID, m.ID, w.f.adminID, IssueMachineTokenParams{Name: w.tag("rev-t")})
				require.NoError(w.t, err)
				return [2]uint{m.ID, res.Credential.ID}
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				ids := s.([2]uint)
				_, err := c.RevokeMachineToken(ctx, w.f.projectID, ids[0], ids[1], w.f.adminID)
				return err
			}},
		{name: "remove-machine-role",
			prepare: func(w *satWorld) any {
				m := machine(w).(*models.MachineIdentity)
				require.NoError(w.t, w.c.AssignMachineRole(ctx, m.ID, w.viewerRole.ID, project(w), w.f.adminID, false))
				return m
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RemoveMachineRole(ctx, s.(*models.MachineIdentity).ID, w.viewerRole.ID, project(w), w.f.adminID)
			}},
		{name: "revoke-own-pat",
			prepare: func(w *satWorld) any {
				res, err := w.c.CreateOwnPAT(ctx, w.member.ID, w.tag("rev-pat"), nil, nil, 0, 0, nil)
				require.NoError(w.t, err)
				return res.Token.ID
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.RevokeOwnPAT(ctx, w.member.ID, s.(uint))
				return err
			}},
		{name: "revoke-own-session",
			prepare: func(w *satWorld) any { return w.newSession(w.member.ID) },
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RevokeOwnSession(ctx, w.member.ID, s.(*models.Session).ID)
			}},
		{name: "revoke-user-sessions",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-us", "project_viewer")
				w.newSession(u.ID)
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				n, err := c.RevokeUserSessions(ctx, w.f.adminID, userID(s))
				if err == nil && n == 0 {
					return errors.New("no session was revoked")
				}
				return err
			}},
		{name: "revoke-all-pats",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-ap", "project_viewer")
				_, err := w.c.CreateOwnPAT(ctx, u.ID, w.tag("rev-pat"), nil, nil, 0, 0, nil)
				require.NoError(w.t, err)
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.RevokeAllPersonalAccessTokensForUser(ctx, "user", w.f.adminID, userID(s))
				return err
			}},
		{name: "delete-sessions-for-user",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-ds", "project_viewer")
				w.newSession(u.ID)
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeleteSessionsForUserExcept(ctx, "user", w.f.adminID, userID(s), 0)
			}},
		{name: "suspend-user", prepare: viewer,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error { return c.SuspendUser(ctx, w.f.adminID, userID(s)) }},
		{name: "deactivate-user", prepare: viewer,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				off := false
				_, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: userID(s), ActorID: w.f.adminID, IsActive: &off})
				return err
			}},
		{name: "delete-user", prepare: viewer,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error { return c.DeleteUser(ctx, w.f.adminID, userID(s)) }},
		{name: "revoke-break-glass",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-bg", "project_viewer")
				a, err := w.c.ActivateBreakGlass(ctx, w.f.projectID, u.ID, "production outage, paging incident commander now", "")
				require.NoError(w.t, err)
				return a
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RevokeBreakGlass(ctx, w.f.adminID, 0, w.f.projectID, s.(*models.BreakGlassActivation).ID)
			}},
		{name: "revoke-invitation",
			prepare: func(w *satWorld) any {
				inv, err := w.c.InviteToProject(ctx, w.f.projectID, w.tag("rev-inv")+"@example.com", "project_viewer", w.f.adminID, 0)
				require.NoError(w.t, err)
				return inv
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RevokeInvitation(ctx, w.f.projectID, s.(*models.ProjectInvitation).ID, w.f.adminID)
			}},
		{name: "withdraw-access-request",
			prepare: func(w *satWorld) any {
				u := w.newUser("rev-ar", "")
				r, err := w.c.RequestProjectAccess(ctx, w.f.projectID, u.ID, "", "need it")
				require.NoError(w.t, err)
				return [2]uint{r.ID, u.ID}
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				ids := s.([2]uint)
				return c.WithdrawAccessRequest(ctx, ids[0], ids[1])
			}},
		{name: "revoke-risk-exception",
			prepare: func(w *satWorld) any {
				e, err := w.c.CreateRiskException(ctx, w.f.adminID, false, "accepted gap", "other", "", "reviewed", future)
				require.NoError(w.t, err)
				return e
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RevokeRiskException(ctx, w.f.adminID, s.(*models.RiskException).ID)
			}},
		{name: "scim-deprovision-user",
			prepare: func(w *satWorld) any {
				n := w.tag("rev-scim")
				u, err := w.c.ProvisionSCIMUser(ctx, 0, n, n, n+"@example.com", "ext-"+n, true)
				require.NoError(w.t, err)
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error { return c.DeprovisionSCIMUser(ctx, 0, userID(s)) }},
		{name: "scim-deactivate-user",
			prepare: func(w *satWorld) any {
				n := w.tag("rev-scimd")
				u, err := w.c.ProvisionSCIMUser(ctx, 0, n, n, n+"@example.com", "ext-"+n, true)
				require.NoError(w.t, err)
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				off := false
				_, err := c.UpdateSCIMUser(ctx, 0, userID(s), nil, nil, &off)
				return err
			}},
		{name: "scim-deprovision-group",
			prepare: func(w *satWorld) any {
				g, err := w.c.ProvisionSCIMGroup(ctx, 0, w.tag("rev-sg"), nil)
				require.NoError(w.t, err)
				return g
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeprovisionSCIMGroup(ctx, 0, s.(*models.Group).ID)
			}},
	}
}

// callContained runs fn and turns a panic that escapes it into an error: a
// revocation must never let an audit-log failure unwind through its caller.
func callContained(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic escaped the revocation: %v", r)
		}
	}()
	return fn()
}

func TestRevocationAudit_EffectCommitsAndRowIsOwedNeverLost(t *testing.T) {
	ctx := context.Background()
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		for _, k := range revKinds() {
			var expected int64 // audit rows one successful run writes; set by the success case
			t.Run(k.name+"/success", func(t *testing.T) {
				state := k.prepare(w)
				before, auditBefore, pendingBefore := w.effectFP(), w.auditTotal(), w.pendingTotal()
				require.NoError(t, k.mutate(w, w.c, state))
				require.NotEqual(t, before, w.effectFP(), "precondition: the revocation must have changed state")
				expected = w.auditTotal() - auditBefore
				require.Positive(t, expected, "%s committed, so its audit row must exist when the call returns", k.name)
				require.Equal(t, pendingBefore, w.pendingTotal(), "a row appended at once leaves nothing queued")
			})
			for _, fk := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError, faultstorage.KindPanic} {
				t.Run(k.name+"/audit-"+fk.String(), func(t *testing.T) {
					require.Positive(t, expected, "the success case must run first")
					state := k.prepare(w)
					before, auditBefore, pendingBefore := w.effectFP(), w.auditTotal(), w.pendingTotal()
					w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: fk, Err: errors.New("injected audit failure")})
					err := callContained(func() error { return k.mutate(w, w.c, state) })
					fired := w.fs.Fired()
					w.fs.Arm(nil)
					require.True(t, fired, "%s never appended its audit row through storage", k.name)
					require.NoError(t, err, "a revocation is never failed by the audit log")
					afterEffect := w.effectFP()
					require.NotEqual(t, before, afterEffect, "%s: the revocation must have taken effect", k.name)
					rows, pending := w.auditTotal()-auditBefore, w.pendingTotal()-pendingBefore
					require.Equal(t, expected, rows+pending,
						"%s: every owed row is either appended or queued (rows=%d pending=%d)", k.name, rows, pending)
					require.Positive(t, pending, "%s: a refused append must leave the row queued", k.name)

					written, berr := w.c.BackfillPendingAuditEvents(ctx)
					require.NoError(t, berr)
					require.EqualValues(t, pending, written)
					require.Equal(t, expected, w.auditTotal()-auditBefore, "%s: the backfill must complete the trail exactly once", k.name)
					require.Equal(t, pendingBefore, w.pendingTotal())
					require.Equal(t, afterEffect, w.effectFP(), "the backfill writes audit rows only")
				})
			}
			t.Run(k.name+"/crash-at-audit", func(t *testing.T) {
				require.Positive(t, expected, "the success case must run first")
				state := k.prepare(w)
				before, auditBefore, pendingBefore := w.effectFP(), w.auditTotal(), w.pendingTotal()
				w.crash.Store(true)
				returned, err := runCrashing(func() error { return k.mutate(w, w.crashCore, state) })
				armed := w.crash.Swap(false)
				require.False(t, armed, "%s never reached an audit append", k.name)
				require.False(t, returned, "precondition: the goroutine must have died at the append (returned err=%v)", err)
				afterEffect := w.effectFP()
				require.NotEqual(t, before, afterEffect, "%s: the revocation committed before the append, so it must have taken effect", k.name)
				rows, pending := w.auditTotal()-auditBefore, w.pendingTotal()-pendingBefore
				require.Equal(t, expected, rows+pending,
					"%s: a crash at the append lost an owed row (rows=%d pending=%d)", k.name, rows, pending)
				require.Positive(t, pending)

				written, berr := w.c.BackfillPendingAuditEvents(ctx)
				require.NoError(t, berr)
				require.EqualValues(t, pending, written)
				require.Equal(t, expected, w.auditTotal()-auditBefore)
				require.Equal(t, pendingBefore, w.pendingTotal())
			})
			for _, fk := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
				t.Run(k.name+"/pending-record-"+fk.String(), func(t *testing.T) {
					require.Positive(t, expected, "the success case must run first")
					state := k.prepare(w)
					before, auditBefore, pendingBefore := w.effectFP(), w.auditTotal(), w.pendingTotal()
					w.fs.Arm(&faultstorage.FaultSpec{Method: "CreatePendingAuditEvent", NthCall: 1, Kind: fk, Err: errors.New("injected pending-record failure")})
					err := callContained(func() error { return k.mutate(w, w.c, state) })
					fired := w.fs.Fired()
					w.fs.Arm(nil)
					require.True(t, fired, "%s never recorded its owed row", k.name)
					require.NoError(t, err, "a revocation is never failed by the owed-audit record")
					require.NotEqual(t, before, w.effectFP(), "%s: the revocation must have taken effect", k.name)
					require.Equal(t, expected, w.auditTotal()-auditBefore,
						"%s: without a record the row is appended at once", k.name)
					require.Equal(t, pendingBefore, w.pendingTotal())
				})
			}
		}
		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "the audit chain must verify after every append and every backfill: %s", v.Reason)
	})
}
