package core

// owed_audit_settle_outside_lock_test.go -- MERGE-FIX-3482F item 5 (REVIEW-3482 F6): the
// owed audit row of a revocation is appended AFTER the named lock the revocation held is
// released. settle waits up to owedAuditWait per refused row during an audit outage, and
// spending that inside lastAdminGuardLockKey / a project-admin lock serialises every
// last-admin operation of the cluster behind the audit log.
//
// The probe wraps the core's storage (transactions included) and records, for every
// audit append, how many WithNamedLock sections are open. Red before the fix: DeleteUser,
// DeleteGroup, RemoveUserFromGroup, RemoveProjectMember, RemoveRoleFromGroup,
// RemoveMachineRole and RemoveUserRole (project scope) appended their owed row with the
// lock still held.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type lockDepthProbe struct {
	depth atomic.Int32
	mu    sync.Mutex
	calls []lockDepthCall
}

type lockDepthCall struct {
	eventType string
	depth     int32
}

func (p *lockDepthProbe) store(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		WithNamedLock: func(next storage.Storage, ctx context.Context, key string, fn func(ctx context.Context) error) error {
			p.depth.Add(1)
			defer p.depth.Add(-1)
			return next.WithNamedLock(ctx, key, fn)
		},
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			p.mu.Lock()
			p.calls = append(p.calls, lockDepthCall{eventType: e.EventType, depth: p.depth.Load()})
			p.mu.Unlock()
			return next.LogAuditEvent(ctx, e)
		},
	})
}

func (p *lockDepthProbe) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = nil
}

func (p *lockDepthProbe) snapshot() []lockDepthCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]lockDepthCall(nil), p.calls...)
}

func TestOwedAuditSettle_RunsAfterNamedLockIsReleased(t *testing.T) {
	ctx := context.Background()
	sites := map[string]bool{
		"delete-user":            true, // DeleteUser: lastAdminGuardLockKey
		"delete-group":           true, // deleteGroupGuarded: withGroupProjectAdminGuardLocks
		"scim-deprovision-group": true, // deleteGroupGuarded via DeprovisionSCIMGroup
		"remove-group-member":    true, // RemoveUserFromGroup
		"remove-project-member":  true, // RemoveProjectMember: projectAdminGuardLockKey
		"remove-group-role":      true, // RemoveRoleFromGroup: withGroupRoleRemovalGuards
		"remove-machine-role":    true, // RemoveMachineRole: sodGrantLockKey
		"remove-user-role":       true, // RemoveUserRole (project scope): withUserRoleRemovalGuards
	}
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		probe := &lockDepthProbe{}
		pc := NewKeyorixCore(probe.store(w.fs))
		matched := 0
		for _, k := range revKinds() {
			if !sites[k.name] {
				continue
			}
			matched++
			t.Run(k.name, func(t *testing.T) {
				state := k.prepare(w)
				probe.reset()
				require.NoError(t, k.mutate(w, pc, state))
				calls := probe.snapshot()
				require.NotEmpty(t, calls, "%s: the owed row was never appended through storage", k.name)
				for _, c := range calls {
					require.Zero(t, c.depth, "%s: audit append %q ran inside %d named lock section(s): settle must run after the lock is released", k.name, c.eventType, c.depth)
				}
			})
		}
		require.Equal(t, len(sites), matched, "every F6 site must exist as a revocation kind")

		// SetProjectMemberRole's removal loop calls removeUserRoleUnguarded under the project
		// admin lock: its role.removed row is settled after the lock. (The new role's
		// role.assigned row is a grant, written fail closed inside the transaction, so it is
		// legitimately inside the lock and not checked here.)
		t.Run("set-project-member-role-swap", func(t *testing.T) {
			u := w.newUser("f6-swap", "project_viewer")
			probe.reset()
			require.NoError(t, pc.SetProjectMemberRole(ctx, w.f.adminID, w.f.projectID, u.ID, "project_developer", false))
			removed := 0
			for _, c := range probe.snapshot() {
				if c.eventType == EventRoleRemoved {
					removed++
					require.Zero(t, c.depth, "role.removed was appended inside the project admin lock")
				}
			}
			require.Positive(t, removed, "the swap must have removed the old role through an owed row")
		})
	})
}
