// concurrency_scim_account_state_race_postgres_test.go — C-RACE-FIX-B2: a SCIM
// lifecycle write (UpdateSCIMUser deactivate/reactivate, DeprovisionSCIMUser)
// derives its new account_state from the one it read, so a SuspendUser that
// commits between that read and the write must not be reverted.
//
// What the interleaving models, and what it does not: on Postgres, the SCIM
// paths read the row with LockUserForUpdate (SELECT ... FOR UPDATE) inside the
// same transaction as the write, and SuspendUser takes the same row lock, so
// on Postgres with that lock intact B would simply block until A commits and
// the suspension lands after A — this interleaving cannot happen there. It
// CAN happen wherever the read does not hold a row lock: SQLite's deferred
// transaction takes no write lock until the first write (the #G42 window
// scimUpdateUserTx's own comment documents), and any backend or future caller
// whose "locked read" is a plain read. This test reproduces exactly that
// window on real Postgres, with two replicas on independent connection pools:
// replica A's storage is wrapped so LockUserForUpdate is a plain GetUser (no
// row lock), and the ctaReview beforeA hook runs replica B's real, complete
// SuspendUser — committing on B's own connection — immediately before A's
// first UPDATE on users. That proves the conditional account_state write
// (SetAccountStateIfMatches) is what keeps the suspension, independent of the
// row lock. It does not test the row lock itself.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// noRowLockStorage turns LockUserForUpdate into a plain read, on the outer
// storage and on every transaction handle WithTransaction hands out — the
// #G42 SQLite deferred-transaction shape. Every other method is the real one.
// bInterleaveWait is how long the hook waits for replica B before concluding
// that a named lock is serializing B behind A.
const bInterleaveWait = 3 * time.Second

// WithNamedLock is also bypassed on replica A: main now serializes the SCIM
// and suspension paths with the same named lock as well as the row lock, and
// this test exists to prove the conditional account_state write holds even
// when BOTH are missing (a future caller that skips them, or SQLite's #G42
// window). Replica B keeps the real lock.
func noRowLockStorage(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		LockUserForUpdate: func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
			return next.GetUser(ctx, id)
		},
		WithNamedLock: func(_ storage.Storage, ctx context.Context, _ string, fn func(ctx context.Context) error) error {
			return fn(ctx)
		},
	})
}

// TestCTAReview_SCIM_vs_SuspendUser_WithoutRowLock_CrossReplicaPostgres: an
// admin suspension that commits after a SCIM write read the row must survive
// that write. Before C-RACE-FIX-B2 the SCIM paths wrote account_state with the
// blind SetAccountState (WHERE id = ?), so the suspension was overwritten:
// reactivation turned it into active (login unblocked), deactivation and
// DELETE into deprovisioned (so a later SCIM reactivation would unblock it).
func TestCTAReview_SCIM_vs_SuspendUser_WithoutRowLock_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	cases := []struct {
		name      string
		initState string
		initAct   bool
		scim      func(c *KeyorixCore, ctx context.Context, actor, id uint) error
	}{
		{"reactivate", AccountDeprovisioned, false, func(c *KeyorixCore, ctx context.Context, actor, id uint) error {
			_, err := c.UpdateSCIMUser(ctx, actor, id, nil, nil, &yes)
			return err
		}},
		{"deactivate", AccountActive, true, func(c *KeyorixCore, ctx context.Context, actor, id uint) error {
			_, err := c.UpdateSCIMUser(ctx, actor, id, nil, nil, &no)
			return err
		}},
		{"deprovision", AccountActive, true, func(c *KeyorixCore, ctx context.Context, actor, id uint) error {
			return c.DeprovisionSCIMUser(ctx, actor, id)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newCTAReview(t)
			target := f.user("cta-scim-"+tc.name, "project_viewer")
			require.NoError(t, f.setupDB.Model(&models.User{}).Where("id = ?", target.ID).Updates(map[string]any{
				"external_id": "okta|" + tc.name, "account_state": tc.initState, "is_active": tc.initAct,
			}).Error)

			coreA := NewKeyorixCore(noRowLockStorage(localstore.NewLocalStorage(f.dbA)))
			coreA.SetAuthEncryptor(f.enc)

			// B runs in its own goroutine. On current main both paths also hold the
			// same storage.WithNamedLock, so B may be unable to start until A
			// commits: running it synchronously inside A's hook would deadlock
			// (A waits for B, B waits for A's lock). If B has not finished after
			// bInterleaveWait, the named lock has serialized the two operations and
			// the stale-write interleaving cannot happen; A proceeds, then B runs.
			// Either way the invariant is the same: the suspension survives.
			var errB error
			bDone := make(chan struct{})
			interleaved := false
			fired := f.beforeA("update", "users", func() {
				go func() { errB = f.coreB.SuspendUser(f.ctx, f.adminID, target.ID); close(bDone) }()
				select {
				case <-bDone:
					interleaved = true
				case <-time.After(bInterleaveWait):
				}
			})
			errA := tc.scim(coreA, f.ctx, f.adminID, target.ID)
			require.True(t, fired(), "the hook must have fired before A's user UPDATE")
			select {
			case <-bDone:
			case <-time.After(30 * time.Second):
				t.Fatal("replica B's SuspendUser never completed after replica A finished")
			}
			t.Logf("SCIM %s (A) err=%v, SuspendUser (B) err=%v, interleaved=%v", tc.name, errA, errB, interleaved)
			if interleaved {
				require.NoError(t, errB, "the suspension itself reported success")
			}
			if errB != nil {
				// Serialized after A: B may legitimately fail (e.g. A deprovisioned
				// and removed the user). Nothing reported success, so nothing was lost.
				return
			}

			var got models.User
			require.NoError(t, f.setupDB.Unscoped().First(&got, target.ID).Error)
			assert.Equal(t, AccountSuspended, got.AccountState, "a suspension that reported success was silently overwritten by a stale SCIM write")
			if interleaved {
				assert.ErrorIs(t, errA, ErrUserAccountStateConflict, "the stale SCIM write must fail closed, not report success")
			}
		})
	}
}
