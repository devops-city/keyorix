package core

// security_mutation_audit_tx3_test.go — AUDIT-TX-3: the mutations #3367's inventory
// listed as "not covered yet" write their audit row in their own transaction, on
// SQLite and on PostgreSQL (set KEYORIX_TEST_PG_DSN; the Postgres leg skips
// without it). Same matrix as security_mutation_audit_tx_test.go: for every kind
//   - success: the change is visible AND its audit row exists the moment the call
//     returns;
//   - the audit append fails (error, effect-then-error, panic): the call returns
//     ErrMutationAuditUnavailable and NOTHING changed (every table but the audit
//     log is byte-identical, the audit log and the owed-audit queue unchanged);
//   - crash: the goroutine dies (runtime.Goexit) at the audit append; the
//     mutation must not survive without its row.
//
// Revocations are not in this file: they are never blocked by the audit log and
// have their own matrix, revocation_owed_audit_test.go.
//
// Red on main: these mutations committed first and appended afterwards (or, for
// project/environment delete/update and the alert escalation policies, the
// transport appended), so every failure kind left a committed change behind.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// grantKind is one fail-closed mutation. prepare runs unfaulted.
type grantKind struct {
	name    string
	prepare func(w *satWorld) any
	mutate  func(w *satWorld, c *KeyorixCore, state any) error
}

func tx3Kinds() []grantKind {
	ctx := context.Background()
	tagged := func(w *satWorld) context.Context { return WithMutationAuditActor(ctx, w.f.adminID) }
	none := func(*satWorld) any { return nil }
	user := func(role string) func(w *satWorld) any {
		return func(w *satWorld) any { return w.newUser("g3-u", role) }
	}
	uid := func(s any) uint { return s.(*models.User).ID }
	future := time.Now().Add(24 * time.Hour)
	group := func(w *satWorld) any {
		g, err := w.c.CreateGroup(ctx, w.f.adminID, &CreateGroupRequest{Name: w.tag("g3-g")})
		require.NoError(w.t, err)
		return g
	}
	scimUser := func(w *satWorld) any {
		n := w.tag("g3-scim")
		u, err := w.c.ProvisionSCIMUser(ctx, 0, n, n, n+"@example.com", "ext-"+n, true)
		require.NoError(w.t, err)
		return u
	}
	scimGroup := func(w *satWorld) any {
		u := scimUser(w).(*models.User)
		g, err := w.c.ProvisionSCIMGroup(ctx, 0, w.tag("g3-sg"), nil)
		require.NoError(w.t, err)
		return [2]any{g, u}
	}
	channel := func(w *satWorld) any {
		ch, err := w.c.CreateNotificationChannel(ctx, &models.NotificationChannel{
			Name: w.tag("g3-ch"), Type: "email", Email: "alerts@example.com", Enabled: true,
		}, "admin", w.f.adminID)
		require.NoError(w.t, err)
		return ch
	}
	rotation := func(w *satWorld) any {
		pid := w.f.projectID
		p, err := w.c.CreateRotationPolicy(ctx, w.f.adminID, &CreateRotationPolicyRequest{
			Name: w.tag("g3-rp"), Scope: "project", ProjectID: &pid, IntervalDays: 90, AlertDaysBefore: 7, NotifyOnBreach: true, CreatedBy: "admin",
		})
		require.NoError(w.t, err)
		return p
	}
	escalation := func(w *satWorld) any {
		p, err := w.c.CreateAlertEscalationPolicy(tagged(w), &models.AlertEscalationPolicy{
			Name: w.tag("g3-ae"), MinSeverity: "high", EscalateAfterMinutes: 30, Enabled: true, CreatedBy: w.f.adminID,
		})
		require.NoError(w.t, err)
		return p
	}
	riskException := func(w *satWorld) any {
		e, err := w.c.CreateRiskException(ctx, w.f.adminID, false, "accepted gap", "other", "", "reviewed", future)
		require.NoError(w.t, err)
		return e
	}
	holdPlaced := func(w *satWorld) any { // an active hold, whatever state the previous case left
		if h, _ := w.c.GetActiveLegalHold(ctx); h != nil {
			require.NoError(w.t, w.c.LiftLegalHold(ctx, w.f.adminID, "reset between cases"))
		}
		_, err := w.c.PlaceLegalHold(ctx, w.f.adminID, "litigation hold")
		require.NoError(w.t, err)
		return nil
	}
	return []grantKind{
		// users
		{name: "update-user-email", prepare: user("project_viewer"),
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: uid(s), ActorID: w.f.adminID, Email: w.tag("g3-new") + "@example.com"})
				return err
			}},
		{name: "reactivate-user",
			prepare: func(w *satWorld) any {
				u := w.newUser("g3-ru", "project_viewer")
				require.NoError(w.t, w.c.SuspendUser(ctx, w.f.adminID, u.ID))
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error { return c.ReactivateUser(ctx, w.f.adminID, uid(s)) }},
		{name: "restore-user",
			prepare: func(w *satWorld) any {
				u := w.newUser("g3-rs", "project_viewer")
				require.NoError(w.t, w.c.DeleteUser(ctx, w.f.adminID, u.ID))
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error { return c.RestoreUser(ctx, w.f.adminID, uid(s)) }},
		// reissue-one-time-password narrows (sessions end) and widens (a new credential):
		// split into two commits, covered by audit_split_test.go (MERGE-FIX-3482G).
		// groups
		{name: "create-group", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateGroup(ctx, w.f.adminID, &CreateGroupRequest{Name: w.tag("g3-cg")})
				return err
			}},
		{name: "update-group", prepare: group,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.UpdateGroup(ctx, w.f.adminID, &UpdateGroupRequest{ID: s.(*models.Group).ID, Name: w.tag("g3-ug")})
				return err
			}},
		{name: "restore-group",
			prepare: func(w *satWorld) any {
				g := group(w).(*models.Group)
				require.NoError(w.t, w.c.DeleteGroup(ctx, w.f.adminID, g.ID))
				return g
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.RestoreGroup(ctx, w.f.adminID, s.(*models.Group).ID)
				return err
			}},
		// SCIM
		{name: "scim-provision-user", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				n := w.tag("g3-sp")
				_, err := c.ProvisionSCIMUser(ctx, 0, n, n, n+"@example.com", "ext-"+n, true)
				return err
			}},
		{name: "scim-update-user", prepare: scimUser,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				name := w.tag("g3-dn")
				_, err := c.UpdateSCIMUser(ctx, 0, uid(s), &name, nil, nil)
				return err
			}},
		// A deactivation is a revocation; a request that also changes the email or the
		// username is split (deactivation owed, identity change fail closed):
		// audit_split_test.go (MERGE-FIX-3482G). A user who is already inactive revokes
		// nothing, so that request stays fail closed as a whole.
		{name: "scim-update-user-already-inactive-deactivate",
			prepare: func(w *satWorld) any {
				u := scimUser(w).(*models.User)
				off := false
				_, err := w.c.UpdateSCIMUser(ctx, 0, u.ID, nil, nil, &off)
				require.NoError(w.t, err)
				return u
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				off, name := false, w.tag("g3-ai")
				_, err := c.UpdateSCIMUser(ctx, 0, uid(s), &name, nil, &off)
				return err
			}},
		{name: "scim-provision-group",
			prepare: func(w *satWorld) any { return scimUser(w) },
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.ProvisionSCIMGroup(ctx, 0, w.tag("g3-spg"), []uint{uid(s)})
				return err
			}},
		{name: "scim-patch-group-add", prepare: scimGroup,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				p := s.([2]any)
				_, err := c.PatchSCIMGroup(ctx, 0, p[0].(*models.Group).ID, nil, []uint{p[1].(*models.User).ID}, nil)
				return err
			}},
		{name: "scim-replace-group", prepare: scimGroup,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				p := s.([2]any)
				_, err := c.ReplaceSCIMGroup(ctx, 0, p[0].(*models.Group).ID, w.tag("g3-rg"), []uint{p[1].(*models.User).ID})
				return err
			}},
		// invitations and access requests
		{name: "invite-to-project", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.InviteToProject(ctx, w.f.projectID, w.tag("g3-inv")+"@example.com", "project_viewer", w.f.adminID, 0)
				return err
			}},
		{name: "invite-global", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.InviteGlobal(ctx, w.tag("g3-ig")+"@example.com", "", nil, w.f.adminID, 0)
				return err
			}},
		{name: "request-project-access", prepare: user(""),
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.RequestProjectAccess(ctx, w.f.projectID, uid(s), "", "need it")
				return err
			}},
		// reject-access-request is a narrowing decision (owed, never blocked by the audit
		// log): revocation_owed_audit_test.go (ask 3482-reject-access-request-direction).
		{name: "request-secret-access", prepare: user("project_viewer"),
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.RequestSecretAccess(ctx, w.secretID, uid(s), "need it")
				return err
			}},
		{name: "approve-secret-access-request",
			prepare: func(w *satWorld) any {
				u := w.newUser("g3-sa", "project_viewer")
				r, err := w.c.RequestSecretAccess(ctx, w.secretID, u.ID, "need it")
				require.NoError(w.t, err)
				return r
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.ApproveSecretAccessRequest(ctx, s.(*models.AccessRequest).ID, w.f.adminID)
				return err
			}},
		// projects and environments
		{name: "update-project", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.UpdateProject(tagged(w), w.f.projectID, w.tag("g3-pn"), "", nil)
				return err
			}},
		{name: "update-project-mfa-requirement", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				on := true
				_, err := c.UpdateProject(tagged(w), w.f.projectID, "cta-review-project", "", &on)
				return err
			}},
		// delete-project / delete-environment are revocations (owed row, never blocked by the
		// audit log): covered by revocation_owed_audit_test.go, not this fail-closed matrix.
		{name: "restore-project",
			prepare: func(w *satWorld) any {
				p, err := w.c.CreateProject(ctx, w.tag("g3-rp"), "")
				require.NoError(w.t, err)
				require.NoError(w.t, w.c.DeleteProject(tagged(w), w.f.adminID, p.ID, true))
				return p
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RestoreProject(ctx, w.f.adminID, s.(*models.Project).ID)
			}},
		{name: "restore-environment",
			prepare: func(w *satWorld) any {
				e, err := w.c.CreateEnvironment(ctx, w.f.projectID, w.tag("g3-re"))
				require.NoError(w.t, err)
				require.NoError(w.t, w.c.DeleteEnvironment(tagged(w), e.ID))
				return e
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.RestoreEnvironment(ctx, w.f.adminID, w.f.projectID, s.(*models.Environment).ID)
			}},
		// configuration
		{name: "create-notification-channel", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateNotificationChannel(ctx, &models.NotificationChannel{
					Name: w.tag("g3-cnc"), Type: "email", Email: "alerts@example.com", Enabled: true,
				}, "admin", w.f.adminID)
				return err
			}},
		{name: "update-notification-channel", prepare: channel,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.UpdateNotificationChannel(ctx, s.(*models.NotificationChannel).ID, map[string]any{"enabled": false}, w.f.adminID)
				return err
			}},
		{name: "delete-notification-channel", prepare: channel,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeleteNotificationChannel(ctx, s.(*models.NotificationChannel).ID, w.f.adminID)
			}},
		{name: "set-notification-retry-policy", prepare: channel,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.SetNotificationRetryPolicy(ctx, w.f.adminID, s.(*models.NotificationChannel).ID, NotificationRetryConfig{MaxRetries: 2, RetryBackoffMs: 500})
			}},
		{name: "update-anomaly-config", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				cfg, err := c.GetAnomalyConfig(ctx)
				if err != nil {
					return err
				}
				next := *cfg
				next.MLEnabled = !cfg.MLEnabled
				return c.UpdateAnomalyConfig(ctx, &next, "admin", w.f.adminID)
			}},
		{name: "create-rotation-policy", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				pid := w.f.projectID
				_, err := c.CreateRotationPolicy(ctx, w.f.adminID, &CreateRotationPolicyRequest{
					Name: w.tag("g3-crp"), Scope: "project", ProjectID: &pid, IntervalDays: 90, AlertDaysBefore: 7, NotifyOnBreach: true, CreatedBy: "admin",
				})
				return err
			}},
		{name: "update-rotation-policy", prepare: rotation,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.UpdateRotationPolicy(ctx, w.f.adminID, &UpdateRotationPolicyRequest{
					ID: s.(*models.RotationPolicy).ID, Name: w.tag("g3-urp"), IntervalDays: 365, AlertDaysBefore: 1, IsActive: false,
				})
				return err
			}},
		{name: "delete-rotation-policy", prepare: rotation,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeleteRotationPolicy(ctx, w.f.adminID, s.(*models.RotationPolicy).ID)
			}},
		{name: "create-alert-escalation-policy", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateAlertEscalationPolicy(tagged(w), &models.AlertEscalationPolicy{
					Name: w.tag("g3-cae"), MinSeverity: "high", EscalateAfterMinutes: 30, Enabled: true, CreatedBy: w.f.adminID,
				})
				return err
			}},
		{name: "update-alert-escalation-policy", prepare: escalation,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.UpdateAlertEscalationPolicy(tagged(w), s.(*models.AlertEscalationPolicy).ID, map[string]any{"enabled": false})
				return err
			}},
		{name: "delete-alert-escalation-policy", prepare: escalation,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.DeleteAlertEscalationPolicy(tagged(w), s.(*models.AlertEscalationPolicy).ID)
			}},
		{name: "create-risk-exception", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.CreateRiskException(ctx, w.f.adminID, false, "accepted gap", "other", "", "reviewed", future)
				return err
			}},
		{name: "approve-risk-exception", prepare: riskException,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				return c.ApproveRiskException(ctx, w.member.ID, false, s.(*models.RiskException).ID)
			}},
		{name: "place-legal-hold", prepare: func(w *satWorld) any {
			if h, _ := w.c.GetActiveLegalHold(ctx); h != nil {
				require.NoError(w.t, w.c.LiftLegalHold(ctx, w.f.adminID, "reset between cases"))
			}
			return nil
		},
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.PlaceLegalHold(ctx, w.f.adminID, "litigation hold")
				return err
			}},
		{name: "lift-legal-hold", prepare: holdPlaced,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				return c.LiftLegalHold(ctx, w.f.adminID, "matter closed")
			}},
		// machine identities
		{name: "classify-machine-identity",
			prepare: func(w *satWorld) any {
				m, err := w.c.CreateMachineIdentity(ctx, w.f.projectID, w.tag("g3-mc"), "service", "", "", w.f.adminID, 0)
				require.NoError(w.t, err)
				return m
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.ClassifyMachineIdentity(ctx, w.f.projectID, s.(*models.MachineIdentity).ID, "restricted", w.f.adminID)
				return err
			}},
		{name: "classify-machine-token",
			prepare: func(w *satWorld) any {
				m, err := w.c.CreateMachineIdentity(ctx, w.f.projectID, w.tag("g3-mt"), "service", "", "", w.f.adminID, 0)
				require.NoError(w.t, err)
				res, err := w.c.IssueMachineToken(ctx, w.f.projectID, m.ID, w.f.adminID, IssueMachineTokenParams{Name: w.tag("g3-t")})
				require.NoError(w.t, err)
				return [2]uint{m.ID, res.Credential.ID}
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				ids := s.([2]uint)
				_, err := c.ClassifyMachineToken(ctx, w.f.projectID, ids[0], ids[1], "restricted", w.f.adminID)
				return err
			}},
		// access review campaigns
		{name: "open-access-review-campaign", prepare: none,
			mutate: func(w *satWorld, c *KeyorixCore, _ any) error {
				_, err := c.OpenAccessReviewCampaign(ctx, w.f.adminID, 0, w.f.projectID, w.tag("g3-camp"))
				return err
			}},
		{name: "close-access-review-campaign",
			prepare: func(w *satWorld) any {
				c, err := w.c.OpenAccessReviewCampaign(ctx, w.f.adminID, 0, w.f.projectID, w.tag("g3-cc"))
				require.NoError(w.t, err)
				return c.Campaign
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.CloseAccessReviewCampaign(ctx, w.f.adminID, 0, w.f.projectID, s.(*models.AccessReviewCampaign).ID, true)
				return err
			}},
	}
}

// TestSecurityMutationAudit3_RowExistsIffMutationCommitted: see the file comment.
func TestSecurityMutationAudit3_RowExistsIffMutationCommitted(t *testing.T) {
	ctx := context.Background()
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		for _, k := range tx3Kinds() {
			t.Run(k.name+"/success", func(t *testing.T) {
				state := k.prepare(w)
				before, audit, pending := w.effectFP(), w.auditTotal(), w.pendingTotal()
				require.NoError(t, k.mutate(w, w.c, state))
				require.NotEqual(t, before, w.effectFP(), "precondition: the mutation must have changed state")
				require.Positive(t, w.auditTotal()-audit, "%s committed, so its audit row must exist when the call returns", k.name)
				require.Equal(t, pending, w.pendingTotal(), "a fail-closed mutation queues nothing")
			})
			for _, fk := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError, faultstorage.KindPanic} {
				t.Run(k.name+"/audit-"+fk.String(), func(t *testing.T) {
					state := k.prepare(w)
					before, audit, pending := w.effectFP(), w.auditTotal(), w.pendingTotal()
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
					require.Equal(t, before, w.effectFP(),
						"%s failed its audit append but changed state anyway: the mutation committed without its audit row", k.name)
					require.Equal(t, audit, w.auditTotal())
					require.Equal(t, pending, w.pendingTotal())
				})
			}
			t.Run(k.name+"/crash-at-audit", func(t *testing.T) {
				state := k.prepare(w)
				before, audit := w.effectFP(), w.auditTotal()
				w.crash.Store(true)
				returned, err := runCrashing(func() error { return k.mutate(w, w.crashCore, state) })
				armed := w.crash.Swap(false)
				require.False(t, armed, "%s never reached an audit append", k.name)
				require.False(t, returned, "precondition: the goroutine must have died at the append (returned err=%v)", err)
				require.Equal(t, before, w.effectFP(),
					"%s: a crash at the audit append left the mutation committed without its audit row", k.name)
				require.Equal(t, audit, w.auditTotal())
			})
		}
		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "the audit chain must verify after every success and every rolled-back attempt: %s", v.Reason)
	})
}
