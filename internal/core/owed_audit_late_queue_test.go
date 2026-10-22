package core

// owed_audit_late_queue_test.go — SUPERFAN-1022 note 1: an owed revocation whose
// pending record could not be written in its own transaction (the collect-only
// fallback) commits without one. Its rows were then only appended once, and the ones
// the audit log refused (or that were not attempted after the first refusal) were
// logged "NOT queued" and lost. They are now recorded as pending rows after the commit
// (queueOwedAuditLate), so the backfill writes them, also after a restart.
//
// The fault: CreatePendingAuditEvent refused ONCE (the record write inside the
// revocation's transaction) and every audit append refused while the log is down.
// The revocation owes two rows (two role grants removed). "Restart" is a new core over
// a new storage handle on the same database: nothing in memory carries over.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestOwedAudit_RecordAndAppendRefused_RowsSurviveARestart(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		st := w.f.setup.Storage()
		scope := Scope{ProjectID: w.f.projectID}
		envScope := Scope{ProjectID: w.f.projectID, EnvironmentID: w.f.envID}

		for _, tc := range []struct {
			name          string
			recordRefusal int32 // CreatePendingAuditEvent calls refused (0 = every call)
			queued        int64 // pending rows the call must leave
		}{
			{name: "record-refused-once/queued-late", recordRefusal: 1, queued: 2},
			// The pending table stays unwritable: the rows are the loud NOT-queued gap,
			// and the revocation still applies.
			{name: "record-refused-always/gap-but-revoked", recordRefusal: 0, queued: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				u := w.newUser("late-q", "project_viewer")
				require.NoError(t, st.AssignRole(ctx, u.ID, w.devRole.ID, envScope))
				var records atomic.Int32
				var auditDown atomic.Bool
				c := NewKeyorixCore(hooked(w.fs, &storeHooks{
					WrapTx: true,
					CreatePendingAuditEvent: func(next storage.Storage, ctx context.Context, p *models.PendingAuditEvent) error {
						if n := records.Add(1); tc.recordRefusal == 0 || n <= tc.recordRefusal {
							return errors.New("injected fault: pending_audit_events refuses writes")
						}
						return next.CreatePendingAuditEvent(ctx, p)
					},
					LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
						if auditDown.Load() {
							return errors.New("audit log refuses writes")
						}
						return next.LogAuditEvent(ctx, e)
					},
				}))
				pending, removed := w.pendingTotal(), w.eventRows(EventRoleRemoved)
				failures := owedAuditFailures.Load()

				auditDown.Store(true)
				err := c.RemoveProjectMember(ctx, w.f.adminID, w.f.projectID, u.ID)
				auditDown.Store(false)
				require.NoError(t, err, "a revocation is never blocked by the audit log")
				require.Empty(t, lateQueueRoles(t, st, u.ID, scope))
				require.Empty(t, lateQueueRoles(t, st, u.ID, envScope))
				require.Equal(t, removed, w.eventRows(EventRoleRemoved), "the audit log was down: nothing appended")
				require.Equal(t, pending+tc.queued, w.pendingTotal(), "the owed rows queued after the commit")
				require.Greater(t, owedAuditFailures.Load(), failures, "loud either way (audit_owed_failures)")

				// Restart: a fresh core on a fresh storage handle over the same database.
				restarted := NewKeyorixCore(localstore.NewLocalStorage(w.db))
				n, berr := restarted.BackfillPendingAuditEvents(ctx)
				require.NoError(t, berr)
				require.Equal(t, int(tc.queued), n)
				require.Equal(t, removed+tc.queued, w.eventRows(EventRoleRemoved), "every queued row is in the chain after the restart")
				require.Equal(t, pending, w.pendingTotal())
			})
		}

		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, v.Reason)
	})
}

func lateQueueRoles(t *testing.T, st storage.Storage, userID uint, scope Scope) []uint {
	t.Helper()
	got, err := st.GetUserRoleIDsExact(context.Background(), userID, scope)
	require.NoError(t, err)
	return got
}
