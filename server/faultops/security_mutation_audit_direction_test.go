// security_mutation_audit_direction_test.go -- REVIEW-2 on #3367.
//
// The web role editor saves a role with PUT /api/v1/roles/{id} and the role's
// whole permission set; gRPC RoleService.UpdateRole carries the same set. A save
// that only removes permissions (or changes none) is a revocation or neutral and
// must commit even when the audit append fails (Andrei 2026-10-14: a revocation
// is never blocked by the audit log), its rows owed (queued). A save that only
// adds stays fail-closed: refused, nothing changed. A mixed save (MERGE-FIX-3482K,
// ask 3482-mixed-update-role-share (a)) is two commits: the removals first, owed,
// then the additions, fail closed. Same for a share update (PUT
// /api/v1/shares/{id}, gRPC ShareService.UpdateSharePermission): write->read
// commits, read->write is refused, write->read plus a later expiry is split.
//
// The fault is one audit append of the request (LogAuditEvent#n), over the real
// router and gRPC server: #1 is the first row (a mixed save's owed row: queued,
// the save completes), #2 is a mixed save's second commit (partial: 503 /
// Unavailable, the narrowing alone applied). TestOwedAuditSplit_SweepEverySplitOp
// sweeps every #n of the mixed saves through the split rule.
package faultops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func rolePermissionNames(t *testing.T, w *faultWorld, roleID uint) []string {
	t.Helper()
	names := []string{}
	require.NoError(t, w.db.Model(&models.Permission{}).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ?", roleID).Pluck("permissions.name", &names).Error)
	sort.Strings(names)
	return names
}

// pendingAuditRows counts the owed rows of eventType queued for the backfill.
func pendingAuditRows(t *testing.T, w *faultWorld, eventType string) int {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(&models.PendingAuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return int(n)
}

func TestRoleEditorUpdate_AuditFailure_ByDirection(t *testing.T) {
	ctx := context.Background()
	type save func(w *faultWorld, roleID uint, perms []string) (opResult, error)
	transports := map[string]save{
		"REST PUT /api/v1/roles/{id}": func(w *faultWorld, roleID uint, perms []string) (opResult, error) {
			st, body, err := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", roleID), map[string]any{"permissions": perms})
			if err != nil {
				return opResult{}, err
			}
			return httpResult(st, body), nil
		},
		"GRPC keyorix.v1.RoleService.UpdateRole": func(w *faultWorld, roleID uint, perms []string) (opResult, error) {
			_, err := pb.NewRoleServiceClient(w.grpcConn).UpdateRole(w.grpcCtx, &pb.UpdateRoleRequest{Id: uint32(roleID), Permissions: perms})
			if err != nil {
				return opResult{Success: false, Detail: status.Convert(err).Code().String() + ": " + err.Error()}, nil
			}
			return opResult{Success: true, Detail: codes.OK.String()}, nil
		},
	}
	for transport, doSave := range transports {
		for _, tc := range []struct {
			name    string
			have    []string
			want    []string
			nth     int    // the refused LogAuditEvent call (0 = 1)
			widens  bool   // refused as a whole, nothing changed
			partial bool   // refused after the narrowing: 503 / Unavailable
			final   []string // the permission set after the call (default: want)
			owed    string // the event type queued by the refusal, if any
		}{
			{name: "narrow", have: []string{"secrets.read", "secrets.write"}, want: []string{"secrets.read"}, owed: "role.updated"},
			{name: "no-op", have: []string{"secrets.read"}, want: []string{"secrets.read"}, owed: "role.updated"},
			{name: "widen", have: []string{"secrets.read"}, want: []string{"secrets.read", "secrets.write"}, widens: true},
			{name: "mixed/owed-row-refused", have: []string{"secrets.read"}, want: []string{"secrets.write"}, owed: "permission.removed"},
			{name: "mixed/second-commit-refused", have: []string{"secrets.read"}, want: []string{"secrets.write"}, nth: 2, partial: true, final: []string{}},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				w := newFaultWorld(t, nil)
				st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/roles/", map[string]any{
					"name": "editor-role", "description": "editor role", "permissions": tc.have,
				})
				require.NoError(t, err)
				require.Equal(t, 2, st/100, "setup CreateRole: %s", body)
				var role models.Role
				require.NoError(t, w.db.Where("name = ?", "editor-role").First(&role).Error)
				drainAllBackgroundGoroutines()
				before, err := snapshotDB(w.db)
				require.NoError(t, err)

				w.faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: max(tc.nth, 1), Kind: faultstorage.KindError, Err: errFuzzInjected})
				result, execErr := doSave(w, role.ID, tc.want)
				fired := w.faulty.Fired()
				w.faulty.Arm(nil)
				drainAllBackgroundGoroutines()
				require.NoError(t, execErr, "transport error")
				require.True(t, fired, "the role save never appended an audit row #%d: the premise of this test is gone", max(tc.nth, 1))

				if tc.widens {
					require.False(t, result.Success, "a widening role save reported success without its audit row: %s", result.Detail)
					after, err := snapshotDB(w.db)
					require.NoError(t, err)
					require.Empty(t, diffTables(before, after), "a refused widening role save changed state")
					return
				}
				want := append([]string{}, tc.want...)
				if tc.final != nil {
					want = append([]string{}, tc.final...)
				}
				sort.Strings(want)
				require.Equal(t, want, rolePermissionNames(t, w, role.ID))
				if tc.partial {
					require.False(t, result.Success, "the second commit was refused, the save must not report success")
					require.Regexp(t, `HTTP 503|Unavailable`, result.Detail, "a partial apply answers 503 / Unavailable")
					require.Contains(t, result.Detail, "permission removal was applied", "the answer says which half was applied")
					return
				}
				require.True(t, result.Success, "a narrowing or neutral role save was blocked by the audit log: %s", result.Detail)
				require.Equal(t, 1, pendingAuditRows(t, w, tc.owed), "the refused row is owed: queued for the backfill")
			})
		}
	}
}

func TestShareUpdate_AuditFailure_ByDirection(t *testing.T) {
	ctx := context.Background()
	later := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		name, from, to string
		expires        bool   // the setup share expires in an hour
		body           any    // extra request fields
		nth            int    // the refused LogAuditEvent call (0 = 1)
		widens         bool   // refused as a whole, nothing changed
		partial        bool   // refused after the narrowing: 503
		final          string // the permission after the call (default: to)
	}{
		{name: "narrow", from: "write", to: "read"},
		{name: "no-op", from: "read", to: "read"},
		{name: "widen", from: "read", to: "write", widens: true},
		// write->read with a later expiry: commit 1 lowers the permission (owed), commit
		// 2 extends the expiry (fail closed).
		{name: "mixed/owed-row-refused", from: "write", to: "read", expires: true, body: later},
		{name: "mixed/second-commit-refused", from: "write", to: "read", expires: true, body: later, nth: 2, partial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newFaultWorld(t, nil)
			var shareID uint
			var err error
			if tc.expires {
				shareID, err = createExpiringShareForFuzz(ctx, w, tc.from, time.Hour)
			} else {
				shareID, err = createShareForFuzz(ctx, w, tc.from)
			}
			require.NoError(t, err)
			var start models.ShareRecord
			require.NoError(t, w.db.First(&start, shareID).Error)
			drainAllBackgroundGoroutines()
			before, err := snapshotDB(w.db)
			require.NoError(t, err)

			req := map[string]any{"permission": tc.to}
			if tc.body != nil {
				req["expires_at"] = tc.body
			}
			w.faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: max(tc.nth, 1), Kind: faultstorage.KindError, Err: errFuzzInjected})
			st, body, execErr := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/shares/%d", shareID), req)
			fired := w.faulty.Fired()
			w.faulty.Arm(nil)
			drainAllBackgroundGoroutines()
			require.NoError(t, execErr, "transport error")
			require.True(t, fired, "the share update never appended audit row #%d: the premise of this test is gone", max(tc.nth, 1))

			var share models.ShareRecord
			require.NoError(t, w.db.First(&share, shareID).Error)
			if tc.widens {
				require.NotEqual(t, 2, st/100, "a widening share update reported success without its audit row: %s", body)
				after, err := snapshotDB(w.db)
				require.NoError(t, err)
				require.Empty(t, diffTables(before, after), "a refused widening share update changed state")
				return
			}
			require.Equal(t, tc.to, share.Permission, "the narrowing must apply")
			if tc.partial {
				require.Equal(t, http.StatusServiceUnavailable, st, "a partial apply answers 503: %s", body)
				require.Contains(t, string(body), "MutationPartiallyApplied")
				require.NotNil(t, share.ExpiresAt)
				require.WithinDuration(t, *start.ExpiresAt, *share.ExpiresAt, time.Second, "commit 2 (the later expiry) was refused")
				return
			}
			require.Equal(t, 2, st/100, "a narrowing or neutral share update was blocked by the audit log: %s", body)
			require.Equal(t, 1, pendingAuditRows(t, w, "share_updated"), "the refused row is owed: queued for the backfill")
			if tc.expires {
				require.NotNil(t, share.ExpiresAt)
				require.True(t, share.ExpiresAt.After(start.ExpiresAt.Add(time.Hour)), "commit 2 extended the expiry")
			}
		})
	}
}

// createExpiringShareForFuzz is createShareForFuzz for a share that expires after ttl.
func createExpiringShareForFuzz(ctx context.Context, w *faultWorld, permission string, ttl time.Duration) (uint, error) {
	id, err := createShareForFuzz(ctx, w, permission)
	if err != nil {
		return 0, err
	}
	exp := time.Now().Add(ttl).UTC()
	return id, w.db.Model(&models.ShareRecord{}).Where("id = ?", id).Update("expires_at", exp).Error
}

// createShareForFuzz is the "REST PUT /api/v1/shares/{id}" catalog setup with
// the share's starting permission as a parameter.
func createShareForFuzz(ctx context.Context, w *faultWorld, permission string) (uint, error) {
	secretID, err := createSecretForFuzz(ctx, w)
	if err != nil {
		return 0, err
	}
	if err := addAdminAsProjectMemberForFuzz(ctx, w, 1); err != nil {
		return 0, err
	}
	userID, err := createUserForFuzz(ctx, w, "direction-share-recipient")
	if err != nil {
		return 0, err
	}
	if err := addProjectMemberForFuzz(ctx, w, 1, userID); err != nil {
		return 0, err
	}
	st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secretID), map[string]any{
		"recipient_id": userID, "permission": permission,
	})
	if err != nil {
		return 0, err
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("setup ShareSecret: HTTP %d: %s", st, body)
	}
	var decoded struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Data.ID == 0 {
		return 0, fmt.Errorf("decoding ShareSecret response: %w (body=%s)", err, body)
	}
	return decoded.Data.ID, nil
}
