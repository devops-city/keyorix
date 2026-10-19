package core

// security_mutation_audit_direction_test.go — REVIEW-2 on #3367: UpdateRole and
// UpdateSharePermission are classified per call. An update that only narrows
// access (removes permissions, write→read, a shorter expiry) or changes no
// access is a revocation or neutral: it is never blocked by the audit log
// (Andrei 2026-10-14) and keeps its audit rows best-effort after the commit. An
// update that widens access in any way, including a mixed one that also
// narrows, stays fail-closed: it commits with its audit rows or not at all.
//
// The outage is total (every LogAuditEvent refused, inside and outside the
// transaction), which is what an operator sees when the audit log is down. On
// SQLite and on PostgreSQL (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditOutageStorage refuses every audit append while down is set, in a
// transaction or not.
type auditOutageStorage struct {
	inner storage.Storage
	down  *atomic.Bool
}

func (s auditOutageStorage) LogAuditEvent(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
	if s.down.Load() {
		return errors.New("audit log refuses writes")
	}
	return next.LogAuditEvent(ctx, e)
}

// wrap returns inner decorated with auditOutageStorage's overrides.
func (s *auditOutageStorage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx:        true,
		LogAuditEvent: s.LogAuditEvent,
	})
}

// store returns s.inner decorated with auditOutageStorage's overrides.
func (s *auditOutageStorage) store() storage.Storage { return s.wrap(s.inner) }

func (w *satWorld) rolePermIDs(roleID uint) []uint {
	w.t.Helper()
	ids := []uint{}
	require.NoError(w.t, w.db.Model(&models.RolePermission{}).Where("role_id = ?", roleID).Pluck("permission_id", &ids).Error)
	slices.Sort(ids)
	return ids
}

func TestSecurityMutationAudit_UpdateRole_ByDirection(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		p2, err := w.f.setup.Storage().CreatePermission(ctx, &models.Permission{Name: "sat.dir2", Description: "sat"})
		require.NoError(t, err)
		a, b := w.permID, p2.ID
		down := &atomic.Bool{}
		c := NewKeyorixCore((&auditOutageStorage{inner: w.fs, down: down}).store())

		for _, tc := range []struct {
			name      string
			have      []uint
			want      *[]uint
			widens    bool
			finalPerm []uint
		}{
			{name: "narrow", have: []uint{a, b}, want: &[]uint{a}, finalPerm: []uint{a}},
			{name: "narrow-to-none", have: []uint{a, b}, want: &[]uint{}, finalPerm: []uint{}},
			{name: "no-op-same-set", have: []uint{a}, want: &[]uint{a}, finalPerm: []uint{a}},
			{name: "no-op-description-only", have: []uint{a}, want: nil, finalPerm: []uint{a}},
			{name: "widen", have: []uint{a}, want: &[]uint{a, b}, widens: true},
			{name: "mixed", have: []uint{a}, want: &[]uint{b}, widens: true},
		} {
			t.Run(tc.name+"/audit-down", func(t *testing.T) {
				r, _, err := w.c.CreateRole(ctx, w.f.adminID, w.tag("sat-dir"), "before", tc.have)
				require.NoError(t, err)
				before := w.fingerprint()
				upd := *r
				upd.Description = "after"
				down.Store(true)
				_, _, err = c.UpdateRole(ctx, w.f.adminID, &upd, tc.want)
				down.Store(false)
				if tc.widens {
					require.ErrorIs(t, err, ErrMutationAuditUnavailable, "a widening update must fail closed while the audit log is down")
					require.Equal(t, before, w.fingerprint(), "a refused widening changed state")
					return
				}
				require.NoError(t, err, "a narrowing or neutral role update was blocked by the audit log")
				require.Equal(t, tc.finalPerm, w.rolePermIDs(r.ID))
				got, err := w.f.setup.Storage().GetRole(ctx, r.ID)
				require.NoError(t, err)
				require.Equal(t, "after", got.Description)
			})
		}

		// Audit up: a narrowing update still writes its rows (after the commit),
		// and a widening one writes them in its transaction.
		t.Run("narrow/audit-up-rows-written", func(t *testing.T) {
			r, _, err := w.c.CreateRole(ctx, w.f.adminID, w.tag("sat-dir"), "", []uint{a, b})
			require.NoError(t, err)
			upd, rem := w.eventRows(EventRoleUpdated), w.eventRows(EventPermissionRemoved)
			_, _, err = c.UpdateRole(ctx, w.f.adminID, r, &[]uint{a})
			require.NoError(t, err)
			require.Equal(t, upd+1, w.eventRows(EventRoleUpdated))
			require.Equal(t, rem+1, w.eventRows(EventPermissionRemoved))
		})
		t.Run("mixed/audit-up-rows-written", func(t *testing.T) {
			r, _, err := w.c.CreateRole(ctx, w.f.adminID, w.tag("sat-dir"), "", []uint{a})
			require.NoError(t, err)
			upd, rem, add := w.eventRows(EventRoleUpdated), w.eventRows(EventPermissionRemoved), w.eventRows(EventPermissionAdded)
			_, _, err = c.UpdateRole(ctx, w.f.adminID, r, &[]uint{b})
			require.NoError(t, err)
			require.Equal(t, []uint{b}, w.rolePermIDs(r.ID))
			require.Equal(t, upd+1, w.eventRows(EventRoleUpdated))
			require.Equal(t, rem+1, w.eventRows(EventPermissionRemoved))
			require.Equal(t, add+1, w.eventRows(EventPermissionAdded))
		})

		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, v.Reason)
	})
}

func TestSecurityMutationAudit_UpdateSharePermission_ByDirection(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		down := &atomic.Bool{}
		c := NewKeyorixCore((&auditOutageStorage{inner: w.fs, down: down}).store())
		in := func(d time.Duration) *time.Time { x := time.Now().Add(d); return &x }

		for _, tc := range []struct {
			name    string
			perm    string     // the share's permission before
			expires *time.Time // the share's expiry before (nil = permanent)
			req     UpdateShareRequest
			widens  bool
		}{
			{name: "narrow-write-to-read", perm: "write", req: UpdateShareRequest{Permission: "read"}},
			{name: "narrow-set-expiry", perm: "read", req: UpdateShareRequest{Permission: "read", ExpiresAt: in(time.Hour)}},
			{name: "narrow-shorten-expiry", perm: "read", expires: in(48 * time.Hour), req: UpdateShareRequest{Permission: "read", ExpiresAt: in(time.Hour)}},
			{name: "narrow-both", perm: "write", expires: in(48 * time.Hour), req: UpdateShareRequest{Permission: "read", ExpiresAt: in(time.Hour)}},
			{name: "no-op", perm: "read", req: UpdateShareRequest{Permission: "read"}},
			{name: "no-op-keeps-expiry", perm: "write", expires: in(48 * time.Hour), req: UpdateShareRequest{Permission: "write"}},
			{name: "widen-read-to-write", perm: "read", req: UpdateShareRequest{Permission: "write"}, widens: true},
			{name: "widen-extend-expiry", perm: "read", expires: in(time.Hour), req: UpdateShareRequest{Permission: "read", ExpiresAt: in(48 * time.Hour)}, widens: true},
			{name: "widen-clear-expiry", perm: "read", expires: in(time.Hour), req: UpdateShareRequest{Permission: "read", ClearExpiry: true}, widens: true},
			{name: "mixed-narrow-perm-clear-expiry", perm: "write", expires: in(time.Hour), req: UpdateShareRequest{Permission: "read", ClearExpiry: true}, widens: true},
			{name: "mixed-widen-perm-shorten-expiry", perm: "read", expires: in(48 * time.Hour), req: UpdateShareRequest{Permission: "write", ExpiresAt: in(time.Hour)}, widens: true},
		} {
			t.Run(tc.name+"/audit-down", func(t *testing.T) {
				u := w.f.user(w.tag("sat-dirs"), "project_viewer")
				s, err := w.c.ShareSecret(ctx, &ShareSecretRequest{SecretID: w.secretID, RecipientID: u.ID, Permission: tc.perm, SharedBy: w.member.ID, ExpiresAt: tc.expires})
				require.NoError(t, err)
				before := w.fingerprint()
				req := tc.req
				req.ShareID, req.UpdatedBy = s.ID, w.member.ID
				down.Store(true)
				_, err = c.UpdateSharePermission(ctx, &req)
				down.Store(false)
				if tc.widens {
					require.ErrorIs(t, err, ErrMutationAuditUnavailable, "a widening share update must fail closed while the audit log is down")
					require.Equal(t, before, w.fingerprint(), "a refused widening changed state")
					return
				}
				require.NoError(t, err, "a narrowing or neutral share update was blocked by the audit log")
				got, err := w.f.setup.Storage().GetShareRecord(ctx, s.ID)
				require.NoError(t, err)
				require.Equal(t, req.Permission, got.Permission)
				switch {
				case req.ExpiresAt != nil:
					require.NotNil(t, got.ExpiresAt)
					require.WithinDuration(t, *req.ExpiresAt, *got.ExpiresAt, time.Second)
				case tc.expires != nil:
					require.NotNil(t, got.ExpiresAt, "the expiry was dropped")
				}
			})
		}

		t.Run("narrow/audit-up-row-written", func(t *testing.T) {
			u := w.f.user(w.tag("sat-dirs"), "project_viewer")
			s, err := w.c.ShareSecret(ctx, &ShareSecretRequest{SecretID: w.secretID, RecipientID: u.ID, Permission: "write", SharedBy: w.member.ID})
			require.NoError(t, err)
			rows := w.eventRows(string(ShareAuditEventUpdated))
			_, err = c.UpdateSharePermission(ctx, &UpdateShareRequest{ShareID: s.ID, Permission: "read", UpdatedBy: w.member.ID})
			require.NoError(t, err)
			require.Equal(t, rows+1, w.eventRows(string(ShareAuditEventUpdated)))
		})

		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, v.Reason)
	})
}
