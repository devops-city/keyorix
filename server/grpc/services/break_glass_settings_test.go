package services

// The "break-glass disabled" refusal carries a typed reason (google.rpc.ErrorInfo
// BreakGlassDisabled) on the same PermissionDenied status and text, and the list answer
// carries the server's break-glass limits. Not t.Parallel(): the locale test flips the
// process-global localizer.

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func errorInfoOf(err error) *errdetails.ErrorInfo {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info
		}
	}
	return nil
}

func TestBreakGlassGRPC_DisabledCarriesTypedReason(t *testing.T) {
	for _, translated := range []bool{false, true} {
		svc := newBreakGlassService(t)
		if translated {
			translateBreakGlassErrorPrefixes(t)
		}
		svc.core.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: false})
		_, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 1, Justification: "prod incident #42"})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
		assert.Equal(t, "access denied", status.Convert(err).Message())
		info := errorInfoOf(err)
		require.NotNil(t, info, "disabled must carry an ErrorInfo detail")
		assert.Equal(t, "BreakGlassDisabled", info.GetReason())
		assert.Equal(t, core.BreakGlassDisabledCode, info.GetReason())
	}
}

// Every other PermissionDenied of break-glass stays code-less: only "disabled" is typed.
func TestBreakGlassGRPC_NotMemberAndOtherRefusalsHaveNoReason(t *testing.T) {
	svc := newBreakGlassService(t)
	// user 1 is a member of project 1 only.
	_, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 2, Justification: "prod incident #42"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
	assert.Nil(t, errorInfoOf(err))
	assert.Empty(t, status.Convert(err).Details())
}

func TestBreakGlassGRPC_ListCarriesSettings(t *testing.T) {
	svc := newBreakGlassService(t)
	svc.core.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "emergency", DefaultTTL: 90 * time.Minute, MaxTTL: 6 * time.Hour,
	})
	list, err := svc.ListBreakGlassActivations(bgCtx(), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.NoError(t, err)
	s := list.GetSettings()
	require.NotNil(t, s)
	assert.True(t, s.GetEnabled())
	assert.Equal(t, "emergency", s.GetEmergencyRole())
	assert.Equal(t, int64(90*60), s.GetDefaultTtlSeconds())
	assert.Equal(t, int64(6*3600), s.GetMaxTtlSeconds())

	// Disabled is reported, not hidden: the client can say so before anyone tries.
	svc.core.SetBreakGlassPolicy(core.BreakGlassPolicy{Enabled: false})
	list, err = svc.ListBreakGlassActivations(bgCtx(), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.NoError(t, err)
	assert.False(t, list.GetSettings().GetEnabled())
}

// A non-member gets no settings: the list is refused outright, as before.
func TestBreakGlassGRPC_SettingsNotForNonMembers(t *testing.T) {
	svc := newBreakGlassService(t)
	_, err := svc.ListBreakGlassActivations(authCtx(2, "nobody"), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
}
