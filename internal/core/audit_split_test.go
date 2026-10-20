package core

// audit_split_test.go — MERGE-FIX-3482G (Andrei 2026-10-20, ask
// 3482-mixed-request-rule (a)): a request that narrows access AND widens it is
// applied as two commits, the narrowing first and owed (never blocked by the audit
// log), the rest fail closed. On SQLite and on PostgreSQL (KEYORIX_TEST_PG_DSN; the
// Postgres leg skips without it), for every split site:
//
//   - success: both halves applied, both rows written, nothing pending;
//   - audit outage (every append refused): the call fails with a
//     PartialMutationError whose details say revocation_applied=true,
//     remainder_applied=false. The DATABASE then shows the narrowing applied and its
//     owed row queued in pending_audit_events, and commit 2's effect and row both
//     absent. The backfill writes the owed row once; a retry of the same request
//     then completes the rest (commit 1 is idempotent);
//   - commit 2's own append refused (error, effect-then-error, panic) while the
//     audit log otherwise works: the same partial outcome, the owed row appended
//     at once;
//   - crash (runtime.Goexit) at the first append after commit 1: the narrowing is
//     committed and its row queued, commit 2 never ran;
//   - the owed record refused (CreatePendingAuditEvent) with a working audit log:
//     everything applies, the owed row is appended directly;
//   - BOTH the owed record and every append refused: the narrowing still applies
//     (a revocation is never blocked) but its row is neither written nor queued.
//     That is the loud "NOT queued for backfill" gap, which stays a violation
//     (Andrei 2026-10-20): this test pins that it is counted (audit_owed_failures)
//     and that the backfill cannot heal it, it never accepts it as complete.
//
// Red before the split (a675a36c): every mixed request failed closed as a whole, so
// the outage, commit-2-refused and crash cases found the narrowing NOT applied (the
// user still active, the member still in the group, MFA still off, the sessions
// still alive), and Reject/the deactivation half had nothing queued.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// splitRow names one audit row by event type and a description fragment.
type splitRow struct{ eventType, desc string }

// splitKind is one mixed request. narrowed / remainder read the DATABASE, never the
// call's return value.
type splitKind struct {
	name      string
	prepare   func(w *satWorld) any
	mutate    func(w *satWorld, c *KeyorixCore, state any) error
	narrowed  func(w *satWorld, state any) bool
	remainder func(w *satWorld, state any) bool
	owed      splitRow // commit 1's row
	rest      splitRow // commit 2's row
}

// splitAuditFaults is a core whose audit appends and owed records can be refused by
// predicate, the test-side stand-in for an audit outage.
type splitAuditFaults struct {
	refuseAppend func(e *models.AuditEvent) (refuse bool, mode string) // mode: error | effect-then-error | panic
	refuseRecord bool
}

func (f *splitAuditFaults) core(inner storage.Storage) *KeyorixCore {
	return NewKeyorixCore(hooked(inner, &storeHooks{
		WrapTx: true,
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			if f.refuseAppend != nil {
				if refuse, mode := f.refuseAppend(e); refuse {
					switch mode {
					case "panic":
						panic("injected audit append panic")
					case "effect-then-error":
						if err := next.LogAuditEvent(ctx, e); err != nil {
							return err
						}
					}
					return errors.New("injected: the audit log refuses the append")
				}
			}
			return next.LogAuditEvent(ctx, e)
		},
		CreatePendingAuditEvent: func(next storage.Storage, ctx context.Context, p *models.PendingAuditEvent) error {
			if f.refuseRecord {
				return errors.New("injected: the owed-audit record cannot be written")
			}
			return next.CreatePendingAuditEvent(ctx, p)
		},
	}))
}

func (w *satWorld) splitAudit(r splitRow) int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.AuditEvent{}).
		Where("event_type = ? AND description LIKE ?", r.eventType, "%"+r.desc+"%").Count(&n).Error)
	return n
}

func (w *satWorld) splitPending(r splitRow) int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.PendingAuditEvent{}).
		Where("event_type = ? AND event LIKE ?", r.eventType, "%"+r.desc+"%").Count(&n).Error)
	return n
}

func (w *satWorld) reloadUser(id uint) *models.User {
	w.t.Helper()
	var u models.User
	require.NoError(w.t, w.db.Unscoped().First(&u, id).Error)
	return &u
}

func (w *satWorld) inGroup(userID, groupID uint) bool {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", userID, groupID).Count(&n).Error)
	return n > 0
}

func splitKinds() []splitKind {
	ctx := context.Background()
	type userAndNew struct {
		u     *models.User
		value string
	}
	type groupCase struct {
		g      *models.Group
		a, b   *models.User
		rename string
	}
	user := func(w *satWorld) any {
		u := w.newUser("sp-u", "project_viewer")
		return &userAndNew{u: u, value: w.tag("sp-new")}
	}
	scimUser := func(w *satWorld) *models.User {
		n := w.tag("sp-scim")
		u, err := w.c.ProvisionSCIMUser(ctx, 0, n, n, n+"@example.com", "ext-"+n, true)
		require.NoError(w.t, err)
		return u
	}
	scimGroup := func(w *satWorld) any {
		a, b := scimUser(w), scimUser(w)
		g, err := w.c.ProvisionSCIMGroup(ctx, 0, w.tag("sp-g"), []uint{a.ID})
		require.NoError(w.t, err)
		return &groupCase{g: g, a: a, b: b, rename: w.tag("sp-gr")}
	}
	inactive := func(w *satWorld, s any) bool { return !w.reloadUser(s.(*userAndNew).u.ID).IsActive }
	gc := func(s any) *groupCase { return s.(*groupCase) }
	removed := func(w *satWorld, s any) bool { return !w.inGroup(gc(s).a.ID, gc(s).g.ID) }
	added := func(w *satWorld, s any) bool { return w.inGroup(gc(s).b.ID, gc(s).g.ID) }
	renamed := func(w *satWorld, s any) bool {
		var g models.Group
		require.NoError(w.t, w.db.First(&g, gc(s).g.ID).Error)
		return g.Name == gc(s).rename
	}
	return []splitKind{
		{name: "update-user-deactivate-and-email", prepare: user,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				off, st := false, s.(*userAndNew)
				_, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: st.u.ID, ActorID: w.f.adminID, IsActive: &off, Email: st.value + "@example.com"})
				return err
			},
			narrowed: inactive,
			remainder: func(w *satWorld, s any) bool {
				return w.reloadUser(s.(*userAndNew).u.ID).Email == s.(*userAndNew).value+"@example.com"
			},
			owed: splitRow{EventUserUpdated, "deactivated user"}, rest: splitRow{EventUserUpdated, "updated user"}},
		{name: "update-user-deactivate-and-username", prepare: user,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				off, st := false, s.(*userAndNew)
				_, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: st.u.ID, ActorID: w.f.adminID, IsActive: &off, Username: st.value})
				return err
			},
			narrowed: inactive,
			remainder: func(w *satWorld, s any) bool {
				return w.reloadUser(s.(*userAndNew).u.ID).Username == s.(*userAndNew).value
			},
			owed: splitRow{EventUserUpdated, "deactivated user"}, rest: splitRow{EventUserUpdated, "updated user"}},
		{name: "scim-update-user-deactivate-and-email",
			prepare: func(w *satWorld) any { return &userAndNew{u: scimUser(w), value: w.tag("sp-se")} },
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				off, st := false, s.(*userAndNew)
				email := st.value + "@example.com"
				_, err := c.UpdateSCIMUser(ctx, 0, st.u.ID, nil, &email, &off)
				return err
			},
			narrowed: inactive,
			remainder: func(w *satWorld, s any) bool {
				return w.reloadUser(s.(*userAndNew).u.ID).Email == s.(*userAndNew).value+"@example.com"
			},
			owed: splitRow{EventSCIMUserUpdated, "SCIM deactivated user"}, rest: splitRow{EventSCIMUserUpdated, "SCIM updated user"}},
		{name: "scim-patch-group-remove-and-add", prepare: scimGroup,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.PatchSCIMGroup(ctx, 0, gc(s).g.ID, nil, []uint{gc(s).b.ID}, []uint{gc(s).a.ID})
				return err
			},
			narrowed: removed, remainder: added,
			owed: splitRow{EventSCIMGroupUpdated, "(-1 members)"}, rest: splitRow{EventSCIMGroupUpdated, "(+1"}},
		{name: "scim-patch-group-remove-and-rename", prepare: scimGroup,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				name := gc(s).rename
				_, err := c.PatchSCIMGroup(ctx, 0, gc(s).g.ID, &name, nil, []uint{gc(s).a.ID})
				return err
			},
			narrowed: removed, remainder: renamed,
			owed: splitRow{EventSCIMGroupUpdated, "(-1 members)"}, rest: splitRow{EventSCIMGroupUpdated, "(+0"}},
		{name: "scim-replace-group-remove-and-add", prepare: scimGroup,
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.ReplaceSCIMGroup(ctx, 0, gc(s).g.ID, gc(s).rename, []uint{gc(s).b.ID})
				return err
			},
			narrowed:  removed,
			remainder: func(w *satWorld, s any) bool { return added(w, s) && renamed(w, s) },
			owed:      splitRow{EventSCIMGroupUpdated, "removed the members not in the new set"}, rest: splitRow{EventSCIMGroupUpdated, "(members=1)"}},
		{name: "update-project-mfa-on-and-rename",
			prepare: func(w *satWorld) any {
				p, err := w.c.CreateProject(ctx, w.tag("sp-p"), "")
				require.NoError(w.t, err)
				return &userAndNew{value: w.tag("sp-pr"), u: &models.User{ID: p.ID}} // u.ID carries the project id
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				on, st := true, s.(*userAndNew)
				_, err := c.UpdateProject(WithMutationAuditActor(ctx, w.f.adminID), st.u.ID, st.value, "", &on)
				return err
			},
			narrowed: func(w *satWorld, s any) bool {
				var p models.Project
				require.NoError(w.t, w.db.First(&p, s.(*userAndNew).u.ID).Error)
				return p.RequireMFA
			},
			remainder: func(w *satWorld, s any) bool {
				var p models.Project
				require.NoError(w.t, w.db.First(&p, s.(*userAndNew).u.ID).Error)
				return p.Name == s.(*userAndNew).value
			},
			owed: splitRow{"project.mfa_requirement_enabled", "per-project MFA requirement enabled"}, rest: splitRow{"project.updated", ""}},
		{name: "reissue-one-time-password",
			prepare: func(w *satWorld) any {
				u := w.newUser("sp-otp", "project_viewer")
				w.newSession(u.ID)
				return &userAndNew{u: u}
			},
			mutate: func(w *satWorld, c *KeyorixCore, s any) error {
				_, err := c.ReissueOneTimePassword(ctx, w.f.adminID, s.(*userAndNew).u.ID)
				return err
			},
			narrowed: func(w *satWorld, s any) bool {
				id := s.(*userAndNew).u.ID
				var n int64
				require.NoError(w.t, w.db.Model(&models.Session{}).Where("user_id = ?", id).Count(&n).Error)
				return n == 0 && w.reloadUser(id).AccountState == AccountPasswordResetRequired
			},
			remainder: func(w *satWorld, s any) bool {
				return w.reloadUser(s.(*userAndNew).u.ID).OneTimePasswordExpiresAt != nil
			},
			owed: splitRow{EventUserOneTimePasswordReissueRestricted, "account restricted"}, rest: splitRow{EventUserOneTimePasswordReissued, "reissued"}},
	}
}

// splitCounts is the audit/pending state of a kind's two rows.
type splitCounts struct{ owedAudit, owedPending, restAudit, restPending int64 }

func (w *satWorld) splitCounts(k splitKind) splitCounts {
	return splitCounts{w.splitAudit(k.owed), w.splitPending(k.owed), w.splitAudit(k.rest), w.splitPending(k.rest)}
}

func (s splitCounts) minus(b splitCounts) splitCounts {
	return splitCounts{s.owedAudit - b.owedAudit, s.owedPending - b.owedPending, s.restAudit - b.restAudit, s.restPending - b.restPending}
}

// requirePartial checks the machine-readable outcome of a failed commit 2.
func requirePartial(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, ErrMutationPartiallyApplied, "commit 2 failed after commit 1: the call must say which half was applied")
	pe, ok := AsPartialMutationError(err)
	require.True(t, ok)
	d := pe.Details()
	require.Equal(t, PartialMutationErrorCode, d["code"])
	require.Equal(t, true, d["revocation_applied"])
	require.Equal(t, false, d["remainder_applied"])
	require.Equal(t, true, d["retry_safe"])
	require.NotEmpty(t, d["applied"])
	require.NotEmpty(t, d["not_applied"])
}

func TestMixedRequestSplit_NarrowingNeverBlockedRemainderFailsClosed(t *testing.T) {
	ctx := context.Background()
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		faults := &splitAuditFaults{}
		fc := faults.core(w.fs)
		for _, k := range splitKinds() {
			rest := k.rest
			isRest := func(e *models.AuditEvent) bool {
				return e.EventType == rest.eventType && (rest.desc == "" || strings.Contains(e.Description, rest.desc)) &&
					!(k.owed.eventType == rest.eventType && strings.Contains(e.Description, k.owed.desc))
			}
			t.Run(k.name+"/success", func(t *testing.T) {
				s := k.prepare(w)
				before := w.splitCounts(k)
				require.NoError(t, k.mutate(w, fc, s))
				require.True(t, k.narrowed(w, s), "the narrowing must be applied")
				require.True(t, k.remainder(w, s), "the rest must be applied")
				d := w.splitCounts(k).minus(before)
				require.Equal(t, splitCounts{owedAudit: 1, restAudit: 1}, d, "both rows written, nothing queued")
			})
			t.Run(k.name+"/audit-outage", func(t *testing.T) {
				s := k.prepare(w)
				before, pendingBefore := w.splitCounts(k), w.pendingTotal()
				failuresBefore := owedAuditFailures.Load()
				faults.refuseAppend = func(*models.AuditEvent) (bool, string) { return true, "error" }
				err := callContained(func() error { return k.mutate(w, fc, s) })
				faults.refuseAppend = nil
				requirePartial(t, err)
				require.ErrorIs(t, err, ErrMutationAuditUnavailable, "commit 2 failed closed on the audit log")
				require.True(t, k.narrowed(w, s), "an audit outage must not block the narrowing")
				require.False(t, k.remainder(w, s), "commit 2 failed closed: its effect must be absent")
				d := w.splitCounts(k).minus(before)
				require.Equal(t, splitCounts{owedPending: 1}, d, "the owed row is queued, commit 2's row is absent")
				require.Greater(t, owedAuditFailures.Load(), failuresBefore, "the refused owed row is counted")

				written, berr := fc.BackfillPendingAuditEvents(ctx)
				require.NoError(t, berr)
				require.GreaterOrEqual(t, written, 1)
				require.Equal(t, splitCounts{owedAudit: 1}, w.splitCounts(k).minus(before), "the backfill writes the owed row once")
				require.Equal(t, pendingBefore, w.pendingTotal())

				// Retry of the same request: safe, completes the rest.
				require.NoError(t, k.mutate(w, fc, s), "a retry of the same request must be safe")
				require.True(t, k.narrowed(w, s))
				require.True(t, k.remainder(w, s), "the retry applies the rest")
				d = w.splitCounts(k).minus(before)
				require.Equal(t, int64(1), d.restAudit, "the rest's row is written by the retry")
				require.Zero(t, d.restPending)
				require.Equal(t, pendingBefore, w.pendingTotal(), "the retry leaves nothing queued")
			})
			for _, mode := range []string{"error", "effect-then-error", "panic"} {
				t.Run(k.name+"/remainder-append-"+mode, func(t *testing.T) {
					s := k.prepare(w)
					before, pendingBefore := w.splitCounts(k), w.pendingTotal()
					faults.refuseAppend = func(e *models.AuditEvent) (bool, string) { return isRest(e), mode }
					err := callContained(func() error { return k.mutate(w, fc, s) })
					faults.refuseAppend = nil
					requirePartial(t, err)
					require.True(t, k.narrowed(w, s))
					require.False(t, k.remainder(w, s), "commit 2's append failed: its effect must be absent")
					require.Equal(t, splitCounts{owedAudit: 1}, w.splitCounts(k).minus(before), "owed row appended, commit 2's row absent")
					require.Equal(t, pendingBefore, w.pendingTotal())
				})
			}
			t.Run(k.name+"/crash-after-narrowing", func(t *testing.T) {
				s := k.prepare(w)
				before := w.splitCounts(k)
				w.crash.Store(true)
				returned, err := runCrashing(func() error { return k.mutate(w, w.crashCore, s) })
				armed := w.crash.Swap(false)
				require.False(t, armed, "%s never reached an audit append", k.name)
				require.False(t, returned, "precondition: the goroutine died at the append (err=%v)", err)
				require.True(t, k.narrowed(w, s), "the narrowing committed before the first append")
				require.False(t, k.remainder(w, s), "commit 2 never ran")
				require.Equal(t, splitCounts{owedPending: 1}, w.splitCounts(k).minus(before), "a crash never loses the owed row")
				_, berr := w.c.BackfillPendingAuditEvents(ctx)
				require.NoError(t, berr)
				require.Equal(t, splitCounts{owedAudit: 1}, w.splitCounts(k).minus(before))
			})
			t.Run(k.name+"/owed-record-refused", func(t *testing.T) {
				s := k.prepare(w)
				before, pendingBefore := w.splitCounts(k), w.pendingTotal()
				faults.refuseRecord = true
				err := callContained(func() error { return k.mutate(w, fc, s) })
				faults.refuseRecord = false
				require.NoError(t, err, "a refused owed record never blocks the change")
				require.True(t, k.narrowed(w, s))
				require.True(t, k.remainder(w, s))
				require.Equal(t, splitCounts{owedAudit: 1, restAudit: 1}, w.splitCounts(k).minus(before), "the owed row is appended directly")
				require.Equal(t, pendingBefore, w.pendingTotal())
			})
			t.Run(k.name+"/record-and-append-refused-is-a-gap", func(t *testing.T) {
				s := k.prepare(w)
				before, pendingBefore := w.splitCounts(k), w.pendingTotal()
				failuresBefore := owedAuditFailures.Load()
				faults.refuseRecord = true
				faults.refuseAppend = func(*models.AuditEvent) (bool, string) { return true, "error" }
				err := callContained(func() error { return k.mutate(w, fc, s) })
				faults.refuseRecord, faults.refuseAppend = false, nil
				requirePartial(t, err)
				require.True(t, k.narrowed(w, s), "a revocation is never blocked, even with both audit writes failing")
				require.False(t, k.remainder(w, s), "a widening never commits without its row")
				require.Equal(t, splitCounts{}, w.splitCounts(k).minus(before),
					"the owed row is neither written nor queued: the NOT-queued gap (a violation, never accepted as complete)")
				require.Greater(t, owedAuditFailures.Load(), failuresBefore, "the gap must be loud (audit_owed_failures)")
				_, berr := fc.BackfillPendingAuditEvents(ctx)
				require.NoError(t, berr)
				require.Equal(t, splitCounts{}, w.splitCounts(k).minus(before), "nothing was queued, so the backfill cannot heal the gap")
				require.Equal(t, pendingBefore, w.pendingTotal())
			})
		}
		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "the audit chain must verify after every split, refusal and backfill: %s", v.Reason)
	})
}

// TestMixedRequestSplit_RetryAfterPartialIsIdempotent: after a partial apply, the
// same request retried twice completes the rest once and never undoes the
// narrowing; the first attempt's owed row stays queued until the backfill.
func TestMixedRequestSplit_RetryAfterPartialIsIdempotent(t *testing.T) {
	ctx := context.Background()
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		faults := &splitAuditFaults{}
		fc := faults.core(w.fs)
		for _, k := range splitKinds() {
			t.Run(k.name, func(t *testing.T) {
				s := k.prepare(w)
				before := w.splitCounts(k)
				faults.refuseAppend = func(*models.AuditEvent) (bool, string) { return true, "error" }
				requirePartial(t, k.mutate(w, fc, s))
				faults.refuseAppend = nil
				// Two retries: the first completes the rest, the second finds it done; neither
				// undoes the narrowing.
				require.NoError(t, k.mutate(w, fc, s))
				require.True(t, k.narrowed(w, s))
				require.True(t, k.remainder(w, s))
				require.NoError(t, k.mutate(w, fc, s))
				require.True(t, k.narrowed(w, s))
				require.True(t, k.remainder(w, s))
				d := w.splitCounts(k).minus(before)
				require.Equal(t, int64(1), d.owedPending, "the first attempt's owed row is still queued (no backfill ran)")
				_, berr := fc.BackfillPendingAuditEvents(ctx)
				require.NoError(t, berr)
				require.Zero(t, w.splitCounts(k).minus(before).owedPending)
			})
		}
	})
}
