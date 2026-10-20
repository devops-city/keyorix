package core

// REVIEW-3482B B3: a split site must decide what each part changes against the row it
// read under the lock, never against the read before it. At ccb52906 UpdateUser (a
// deactivation whose request names no username/email change on the early read) and
// UpdateSCIMUser (active=false whose email equals the early read) wrote the request's
// identity fields on the OWED commit. If the row's username/email changed in between
// (another admin, another replica), the owed commit changes it back: an identity change
// (a widening: a reset link goes to the address) committed on the owed path, without
// its row during an audit outage. The concurrent change is injected right after the
// early read.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestReview3482B_SplitDirectionDecidedOnTheLockedRow(t *testing.T) {
	ctx := context.Background()
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		var refuseAppends bool
		var afterEarlyRead func(id uint)
		mk := func(withSessionsHook bool) *KeyorixCore {
			h := &storeHooks{
				WrapTx: true,
				LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
					if refuseAppends {
						return errors.New("injected: the audit log refuses the append")
					}
					return next.LogAuditEvent(ctx, e)
				},
			}
			if withSessionsHook {
				// UpdateUser's deactivating path reads the user, then lists its sessions,
				// then opens the transaction.
				h.ListSessionTokenHashesForUser = func(next storage.Storage, ctx context.Context, id uint) ([]string, error) {
					if f := afterEarlyRead; f != nil {
						afterEarlyRead = nil
						f(id)
					}
					return next.ListSessionTokenHashesForUser(ctx, id)
				}
			} else {
				// UpdateSCIMUser reads the user up front (scimOwned), then again under the
				// named lock for the direction (GetUser #2), then opens the transaction.
				calls := 0
				h.GetUser = func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
					u, err := next.GetUser(ctx, id)
					if afterEarlyRead != nil {
						calls++
					}
					if f := afterEarlyRead; f != nil && err == nil && calls == 2 {
						afterEarlyRead = nil
						f(id)
					}
					return u, err
				}
			}
			return NewKeyorixCore(hooked(w.fs, h))
		}

		t.Run("update-user-deactivate-keeps-a-concurrent-rename", func(t *testing.T) {
			c := mk(true)
			u := w.newUser("rv-b3-u", "project_viewer")
			renamed := w.tag("rv-b3-renamed")
			afterEarlyRead = func(id uint) {
				require.NoError(t, w.db.Model(&models.User{}).Where("id = ?", id).
					Updates(map[string]any{"username": renamed, "username_folded": renamed}).Error)
			}
			off := false
			_, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, ActorID: w.f.adminID, IsActive: &off})
			require.NoError(t, err)
			got := w.reloadUser(u.ID)
			require.False(t, got.IsActive)
			require.Equal(t, renamed, got.Username, "the owed deactivation commit must not write back the username the early read saw")
		})

		t.Run("scim-deactivate-same-email-early-read-email-changed-since", func(t *testing.T) {
			c := mk(false)
			n := w.tag("rv-b3-s")
			u, err := w.c.ProvisionSCIMUser(ctx, 0, n, n, n+"@example.com", "ext-"+n, true)
			require.NoError(t, err)
			oldEmail, newer := u.Email, w.tag("rv-b3-new")+"@example.com"
			afterEarlyRead = func(id uint) {
				require.NoError(t, w.db.Model(&models.User{}).Where("id = ?", id).
					Updates(map[string]any{"email": newer, "email_folded": newer}).Error)
			}
			off := false
			refuseAppends = true
			_, err = c.UpdateSCIMUser(ctx, 0, u.ID, nil, &oldEmail, &off)
			refuseAppends = false
			got := w.reloadUser(u.ID)
			require.False(t, got.IsActive, "the deactivation is never blocked by the audit log")
			require.Equal(t, newer, got.Email,
				"during an audit outage the email change back to %q is a widening and must fail closed (err=%v)", oldEmail, err)
			require.ErrorIs(t, err, ErrMutationPartiallyApplied)
		})
	})
}
