package interceptors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestRestrictedPATRefusalStatus_TextIsTheSentinels: the gRPC refusal's fixed
// literals must stay the sentinels' own text, so both transports answer a
// restricted PAT with the same words (PAT-GUARD-3).
func TestRestrictedPATRefusalStatus_TextIsTheSentinels(t *testing.T) {
	for _, sentinel := range []error{
		core.ErrRestrictedPATSelfServiceWrite, core.ErrRestrictedPATCannotMintPAT, core.ErrRestrictedPATCannotBreakGlass,
	} {
		st := status.Convert(restrictedPATRefusalStatus(sentinel))
		assert.Equal(t, codes.PermissionDenied, st.Code(), sentinel)
		assert.Equal(t, sentinel.Error(), st.Message())
	}
	assert.NoError(t, restrictedPATRefusalStatus(nil))
}

// TestRestrictedPATWriteStatus_FollowsTheTable: a refused entry is denied, a
// method the table does not list (a gated RPC) passes.
func TestRestrictedPATWriteStatus_FollowsTheTable(t *testing.T) {
	st := status.Convert(restrictedPATWriteStatus(pb.BreakGlassService_ActivateBreakGlass_FullMethodName))
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Equal(t, core.ErrRestrictedPATCannotBreakGlass.Error(), st.Message())
	assert.NoError(t, restrictedPATWriteStatus(pb.SecretService_CreateSecret_FullMethodName))
}
