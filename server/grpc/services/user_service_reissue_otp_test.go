package services

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/keyorixhq/keyorix/server/proto/pb"
)

// REISSUE-1: UserService.ReissueOneTimePassword.

func TestReissueOneTimePassword_ReturnsPasswordOnceWithExpiry(t *testing.T) {
	svc := newUserService(t)
	target := svc.mustCreate(t, "reissue_grpc", "reissue_grpc@example.com")

	before := time.Now()
	resp, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
	require.NoError(t, err)
	assert.Equal(t, target.GetId(), resp.GetUserId())
	assert.Equal(t, "reissue_grpc@example.com", resp.GetEmail())
	require.NotEmpty(t, resp.GetOneTimePassword())
	exp, err := time.Parse(time.RFC3339, resp.GetOneTimePasswordExpiresAt())
	require.NoError(t, err)
	assert.Equal(t, time.UTC, exp.Location())
	assert.WithinDuration(t, before.Add(72*time.Hour), exp, time.Minute, "default one-time-password lifetime is 72h")
}

func TestReissueOneTimePassword_RequiresUsersWrite(t *testing.T) {
	svc := newUserService(t)
	target := svc.mustCreate(t, "reissue_denied", "reissue_denied@example.com")

	// A caller with users.read only, and one with nothing, are both refused -- the same
	// gate as CreateUser with generate_one_time_password.
	for _, ctx := range []struct {
		name string
		ctx  func() error
	}{
		{"ungranted user", func() error {
			_, err := svc.ReissueOneTimePassword(authCtx(7, "reader"), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
			return err
		}},
		{"no user at all", func() error {
			_, err := svc.ReissueOneTimePassword(t.Context(), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
			return err
		}},
	} {
		t.Run(ctx.name, func(t *testing.T) {
			err := ctx.ctx()
			require.Error(t, err)
			assert.Contains(t, []codes.Code{codes.PermissionDenied, codes.Unauthenticated}, status.Code(err))
		})
	}
}

func TestReissueOneTimePassword_RefusesOwnAccount(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.True(t, strings.Contains(status.Convert(err).Message(), "recover-admin"), "points at recover-admin: %q", status.Convert(err).Message())
}

func TestReissueOneTimePassword_InvalidAndMissingIDs(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: 99999})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestReissueOneTimePassword_RefusesSuspendedUser(t *testing.T) {
	svc := newUserService(t)
	target := svc.mustCreate(t, "reissue_susp_grpc", "reissue_susp_grpc@example.com")
	require.NoError(t, svc.core.SuspendUser(t.Context(), 1, uint(target.GetId())))

	_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: target.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// Each refusal sends its fixed client text, never err.Error().
func TestReissueOneTimePassword_RefusalMessagesAreFixed(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	svc := NewUserService(h.CoreService)
	sso := svc.mustCreate(t, "reissue_sso_grpc", "reissue_sso_grpc@example.com")
	require.NoError(t, h.DB.Exec("UPDATE users SET external_id = ? WHERE id = ?", "sso:corp:corp|7", sso.GetId()).Error)
	susp := svc.mustCreate(t, "reissue_susp_msg", "reissue_susp_msg@example.com")
	require.NoError(t, svc.core.SuspendUser(t.Context(), 1, uint(susp.GetId())))

	for name, tc := range map[string]struct {
		id   uint32
		want string
	}{
		"sso only":  {sso.GetId(), core.ReissueExternalIdentityMessage},
		"suspended": {susp.GetId(), core.ReissueAccountBlockedMessage},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: tc.id})
			require.Error(t, err)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Equal(t, tc.want, status.Convert(err).Message())
		})
	}
}

// A storage fault on the reissue's row lock is Internal, not the NotFound a
// missing user gets, and its text never reaches the client.
func TestReissueOneTimePassword_LockFaultIsInternalNotNotFound(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	target := h.CreateTestUser(t, "reissue_fault_grpc", 2)
	faulty := faultstorage.NewFaultyStorage(h.Storage, &faultstorage.FaultSpec{
		Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: LockUserForUpdate"),
	})
	svc := NewUserService(core.NewKeyorixCore(faulty))

	_, err := svc.ReissueOneTimePassword(adminCtx(), &pb.ReissueOneTimePasswordRequest{Id: uint32(target.ID)})
	require.True(t, faulty.Fired(), "the reissue's row lock must have been reached")
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.NotContains(t, status.Convert(err).Message(), "injected")
}
