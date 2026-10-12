// user_service_role_scopes_fault_test.go — #3093: the GetUserRoleScopes call
// the storage-fault fuzzer faults on gRPC CreateUser (#1) and UpdateUser (#2)
// is the post-commit project-count enrichment for the TARGET user, not an
// authorization read. Authorization for both RPCs fails closed before that
// call is ever reached:
//   - authorizeGlobal -> AuthorizePrincipal -> Authorize denies on any
//     role-resolution error (it never reads GetUserRoleScopes);
//   - UpdateUser's admin-rank ceiling (requireEqualOrGreaterAdminAuthority) is
//     the ONE place either RPC reads GetUserRoleScopes to decide anything, and
//     it is call #1 there: a fault on it refuses the update.
//
// server/faultops' nonLoadBearingAuthzRead rows for these two tuples cite these
// tests as their proof.
package services

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errInjectedAuthzRead = errors.New("fault-fuzz injected failure")

// roleScopesFaultStub records every GetUserRoleScopes call (the user it was
// asked about, and whether that user already existed in storage at the time)
// and fails the call numbered failRoleScopesNth (1-based; 0 = never). With
// failRoleIDsAt it also fails GetUserRoleIDsAt, the role read Authorize uses.
type roleScopesFaultStub struct {
	corestorage.Storage
	failRoleScopesNth int
	failRoleIDsAt     bool

	mu    sync.Mutex
	calls []roleScopesCall
}

type roleScopesCall struct {
	userID        uint
	userCommitted bool
}

func (s *roleScopesFaultStub) GetUserRoleScopes(ctx context.Context, userID uint) ([]corestorage.Scope, error) {
	_, getErr := s.Storage.GetUser(ctx, userID)
	s.mu.Lock()
	s.calls = append(s.calls, roleScopesCall{userID: userID, userCommitted: getErr == nil})
	n := len(s.calls)
	s.mu.Unlock()
	if n == s.failRoleScopesNth {
		return nil, errInjectedAuthzRead
	}
	return s.Storage.GetUserRoleScopes(ctx, userID)
}

func (s *roleScopesFaultStub) GetUserRoleIDsAt(ctx context.Context, userID uint, scope corestorage.Scope) ([]uint, error) {
	if s.failRoleIDsAt {
		return nil, errInjectedAuthzRead
	}
	return s.Storage.GetUserRoleIDsAt(ctx, userID, scope)
}

// ResolveUserPermissionAt (PERF-FIX-6) reads through this stub's own
// GetUserRoleIDsAt, so Authorize still meets failRoleIDsAt.
func (s *roleScopesFaultStub) ResolveUserPermissionAt(ctx context.Context, userID uint, scope corestorage.Scope, permission string) (*corestorage.PrincipalPermission, error) {
	return corestorage.ComposeUserPermissionAt(ctx, s, userID, scope, permission)
}

func (s *roleScopesFaultStub) recorded() []roleScopesCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]roleScopesCall(nil), s.calls...)
}

// newRoleScopesFaultService is newUserService with the stub in front of the
// real storage. The admin (id 1) is a real row holding super_admin globally.
func newRoleScopesFaultService(t *testing.T, stub *roleScopesFaultStub) (*UserGRPCService, *testhelper.RBACTestHelper) {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	stub.Storage = h.Storage
	return NewUserService(core.NewKeyorixCore(stub)), h
}

// TestCreateUser_AuthzReadFaultFailsClosed: a fault on the role read that
// authorizes CreateUser denies the RPC and creates nothing. GetUserRoleScopes
// is never reached.
func TestCreateUser_AuthzReadFaultFailsClosed(t *testing.T) {
	t.Parallel()
	stub := &roleScopesFaultStub{failRoleIDsAt: true}
	svc, h := newRoleScopesFaultService(t, stub)

	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "denieduser", Email: "denieduser@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "an authz read fault must deny, not fail open")
	_, gerr := h.Storage.GetUserByUsername(context.Background(), "denieduser")
	assert.Error(t, gerr, "a denied CreateUser must not have created the user")
	assert.Empty(t, stub.recorded(), "GetUserRoleScopes must not be reached once authorization failed")

	// Control: the same request with the fault off succeeds, so the denial
	// above comes from the injected read failure and not from the fixture.
	stub.failRoleIDsAt = false
	_, err = svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "denieduser", Email: "denieduser@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.NoError(t, err, "control: without the fault the admin may create the user")
}

// TestCreateUser_RoleScopesFaultIsTargetEnrichmentOnly (#3093, CreateUser
// GetUserRoleScopes#1): CreateUser's only GetUserRoleScopes call is for the
// NEW user, after it committed. Faulting it leaves the create successful with
// zero project counts (projectCounts is best-effort), which is what the fuzzer
// observed. Without a fault the call sequence is the same, so no authorization
// decision depends on it.
func TestCreateUser_RoleScopesFaultIsTargetEnrichmentOnly(t *testing.T) {
	t.Parallel()
	for _, failNth := range []int{0, 1} {
		stub := &roleScopesFaultStub{failRoleScopesNth: failNth}
		svc, h := newRoleScopesFaultService(t, stub)

		resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
			Username: "scopesuser", Email: "scopesuser@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		})
		require.NoError(t, err, "failNth=%d", failNth)
		require.NotNil(t, resp.GetUser())
		newID := uint(resp.GetUser().GetId())
		require.NotEqual(t, uint(1), newID)

		calls := stub.recorded()
		require.Len(t, calls, 1, "failNth=%d: CreateUser reads GetUserRoleScopes exactly once", failNth)
		assert.Equal(t, newID, calls[0].userID, "the call is about the created user, not the caller")
		assert.True(t, calls[0].userCommitted, "the call runs after the create committed")

		u, gerr := h.Storage.GetUser(context.Background(), newID)
		require.NoError(t, gerr)
		assert.Equal(t, "scopesuser", u.Username)
		if failNth == 1 {
			assert.Zero(t, resp.GetUser().GetProjectCount(), "a faulted enrichment leaves the counts at zero")
		}
	}
}

// TestUpdateUser_RoleScopesFaultFailsClosedOnCeilingOnly (#3093, UpdateUser
// GetUserRoleScopes#2): call #1 is the admin-rank ceiling read for the target,
// and a fault there refuses the update (fail closed). Call #2 is the
// post-commit enrichment for the same target; a fault there leaves the update
// in place with zero counts, which is what the fuzzer observed.
func TestUpdateUser_RoleScopesFaultFailsClosedOnCeilingOnly(t *testing.T) {
	t.Parallel()
	for _, failNth := range []int{1, 2} {
		stub := &roleScopesFaultStub{}
		svc, h := newRoleScopesFaultService(t, stub)
		target := svc.mustCreate(t, "ceilingtarget", "ceilingtarget@example.com")
		targetID := uint(target.GetId())

		stub.mu.Lock()
		stub.calls = nil
		stub.failRoleScopesNth = failNth
		stub.mu.Unlock()

		resp, err := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: target.GetId(), Email: strPtr("changed@example.com")})
		calls := stub.recorded()
		require.NotEmpty(t, calls)
		assert.Equal(t, targetID, calls[0].userID, "failNth=%d: call #1 is the ceiling read for the target", failNth)

		u, gerr := h.Storage.GetUser(context.Background(), targetID)
		require.NoError(t, gerr)
		switch failNth {
		case 1:
			require.Error(t, err, "a fault on the ceiling read must refuse the update")
			assert.NotEqual(t, codes.OK, status.Code(err))
			assert.Len(t, calls, 1, "nothing after the refused ceiling reads GetUserRoleScopes")
			assert.Equal(t, "ceilingtarget@example.com", u.Email, "a refused update must not have been applied")
			// Control: the same update with the fault off is allowed, so the
			// refusal above comes from the faulted ceiling read.
			stub.mu.Lock()
			stub.failRoleScopesNth = 0
			stub.mu.Unlock()
			_, cerr := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: target.GetId(), Email: strPtr("changed@example.com")})
			require.NoError(t, cerr, "control: without the fault the admin may update the target")
		case 2:
			require.NoError(t, err)
			require.Len(t, calls, 2)
			assert.Equal(t, targetID, calls[1].userID, "call #2 is about the updated target, not the caller")
			assert.Equal(t, "changed@example.com", u.Email, "the update committed before call #2")
			assert.Zero(t, resp.GetProjectCount(), "a faulted enrichment leaves the counts at zero")
		}
	}
}
