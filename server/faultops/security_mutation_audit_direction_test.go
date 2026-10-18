// security_mutation_audit_direction_test.go -- REVIEW-2 on #3367.
//
// The web role editor saves a role with PUT /api/v1/roles/{id} and the role's
// whole permission set; gRPC RoleService.UpdateRole carries the same set. A save
// that only removes permissions (or changes none) is a revocation or neutral and
// must commit even when the audit append fails (Andrei 2026-10-14: a revocation
// is never blocked by the audit log). A save that adds any permission, mixed
// included, stays fail-closed: refused, nothing changed. Same for a share
// update (PUT /api/v1/shares/{id}): write->read commits, read->write is refused.
//
// The fault is the first audit append of the request (LogAuditEvent#1), over
// the real router and gRPC server.
package faultops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

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
			name   string
			have   []string
			want   []string
			widens bool
		}{
			{name: "narrow", have: []string{"secrets.read", "secrets.write"}, want: []string{"secrets.read"}},
			{name: "no-op", have: []string{"secrets.read"}, want: []string{"secrets.read"}},
			{name: "widen", have: []string{"secrets.read"}, want: []string{"secrets.read", "secrets.write"}, widens: true},
			{name: "mixed", have: []string{"secrets.read"}, want: []string{"secrets.write"}, widens: true},
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

				w.faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected})
				result, execErr := doSave(w, role.ID, tc.want)
				fired := w.faulty.Fired()
				w.faulty.Arm(nil)
				drainAllBackgroundGoroutines()
				require.NoError(t, execErr, "transport error")
				require.True(t, fired, "the role save never appended an audit row: the premise of this test is gone")

				if tc.widens {
					require.False(t, result.Success, "a widening role save reported success without its audit row: %s", result.Detail)
					after, err := snapshotDB(w.db)
					require.NoError(t, err)
					require.Empty(t, diffTables(before, after), "a refused widening role save changed state")
					return
				}
				require.True(t, result.Success, "a narrowing or neutral role save was blocked by the audit log: %s", result.Detail)
				want := append([]string{}, tc.want...)
				sort.Strings(want)
				require.Equal(t, want, rolePermissionNames(t, w, role.ID))
			})
		}
	}
}

func TestShareUpdate_AuditFailure_ByDirection(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, from, to string
		widens         bool
	}{
		{name: "narrow", from: "write", to: "read"},
		{name: "no-op", from: "read", to: "read"},
		{name: "widen", from: "read", to: "write", widens: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newFaultWorld(t, nil)
			shareID, err := createShareForFuzz(ctx, w, tc.from)
			require.NoError(t, err)
			drainAllBackgroundGoroutines()
			before, err := snapshotDB(w.db)
			require.NoError(t, err)

			w.faulty.Arm(&faultstorage.FaultSpec{Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected})
			st, body, execErr := httpJSON(ctx, w, http.MethodPut, fmt.Sprintf("/api/v1/shares/%d", shareID), map[string]any{"permission": tc.to})
			fired := w.faulty.Fired()
			w.faulty.Arm(nil)
			drainAllBackgroundGoroutines()
			require.NoError(t, execErr, "transport error")
			require.True(t, fired, "the share update never appended an audit row: the premise of this test is gone")

			var share models.ShareRecord
			require.NoError(t, w.db.First(&share, shareID).Error)
			if tc.widens {
				require.NotEqual(t, 2, st/100, "a widening share update reported success without its audit row: %s", body)
				after, err := snapshotDB(w.db)
				require.NoError(t, err)
				require.Empty(t, diffTables(before, after), "a refused widening share update changed state")
				return
			}
			require.Equal(t, 2, st/100, "a narrowing or neutral share update was blocked by the audit log: %s", body)
			require.Equal(t, tc.to, share.Permission)
		})
	}
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
