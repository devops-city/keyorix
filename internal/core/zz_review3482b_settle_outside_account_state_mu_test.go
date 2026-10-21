package core

// REVIEW-3482B: F6 moved settle out of the NAMED locks, but two revocations still
// append their owed row while holding c.accountStateMu (process-wide): setAccountState
// (SuspendUser, RequirePasswordReset, ...) and ReissueOneTimePassword's commit 1. settle
// waits up to owedAuditWait per refused row, so during a slow audit log every other
// account-state change of the process (SuspendUser, SCIM active=false, DeprovisionSCIMUser,
// another reissue) waits behind it BEFORE its own commit: a revocation delayed by the
// audit log.
//
// The probe records, for every audit append through storage, whether accountStateMu is
// held at that moment (TryLock from the same, single-threaded test).

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type accountStateMuProbe struct {
	core  *KeyorixCore
	depth atomic.Int32
	mu    sync.Mutex
	held  map[string]int
	total int
}

func (p *accountStateMuProbe) store(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		WithNamedLock: func(next storage.Storage, ctx context.Context, key string, fn func(ctx context.Context) error) error {
			p.depth.Add(1)
			defer p.depth.Add(-1)
			return next.WithNamedLock(ctx, key, fn)
		},
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			locked := !p.core.accountStateMu.TryLock()
			if !locked {
				p.core.accountStateMu.Unlock()
			}
			locked = locked || p.depth.Load() > 0
			p.mu.Lock()
			p.total++
			if locked {
				p.held[e.EventType]++
			}
			p.mu.Unlock()
			return next.LogAuditEvent(ctx, e)
		},
	})
}

func TestReview3482B_OwedSettleRunsAfterAccountStateMuIsReleased(t *testing.T) {
	ctx := context.Background()
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		probe := &accountStateMuProbe{held: map[string]int{}}
		pc := NewKeyorixCore(probe.store(w.fs))
		probe.core = pc
		check := func(t *testing.T, name string, owedType string, mutate func() error) {
			probe.mu.Lock()
			probe.held, probe.total = map[string]int{}, 0
			probe.mu.Unlock()
			require.NoError(t, mutate())
			require.Positive(t, probe.total, "%s: nothing was appended through storage", name)
			require.Zero(t, probe.held[owedType], "%s: the owed %q row was appended while accountStateMu or a named lock was held", name, owedType)
		}
		// Every revocation kind and every split kind: no audit append through storage
		// (owed rows are only ever appended by settle, after the commit) may run while
		// accountStateMu or a named lock is held.
		for _, k := range revKinds() {
			t.Run("rev/"+k.name, func(t *testing.T) {
				s := k.prepare(w)
				probe.mu.Lock()
				probe.held, probe.total = map[string]int{}, 0
				probe.mu.Unlock()
				require.NoError(t, k.mutate(w, pc, s))
				probe.mu.Lock()
				defer probe.mu.Unlock()
				require.Empty(t, probe.held, "%s: audit append(s) while accountStateMu or a named lock was held", k.name)
			})
		}
		t.Run("suspend-user", func(t *testing.T) {
			u := w.newUser("rv-mu-s", "project_viewer")
			check(t, "SuspendUser", "account.suspended", func() error { return pc.SuspendUser(ctx, w.f.adminID, u.ID) })
		})
		t.Run("reissue-one-time-password", func(t *testing.T) {
			u := w.newUser("rv-mu-o", "project_viewer")
			check(t, "ReissueOneTimePassword", EventUserOneTimePasswordReissueRestricted, func() error {
				_, err := pc.ReissueOneTimePassword(ctx, w.f.adminID, u.ID)
				return err
			})
		})
	})
}
