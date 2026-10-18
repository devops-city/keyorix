package interceptors

// auth_storage_error_fail_closed_test.go -- the gRPC half of
// INV-MW-cache-hit-recheck-fails-closed (CACHE-FAILCLOSED-1).
//
// gRPC has no auth cache: every RPC re-validates the credential against
// storage, so the HTTP cache-hit "degrade to the cached login" never existed
// here. This pins that it stays that way for both machine tokens and PATs: a
// storage error on the credential lookup is codes.Unavailable with a fixed
// message, the handler is never reached, and a credential revoked before the
// outage is never accepted during it. The fault is injected with
// internal/faultstorage on the exact lookup method over the real storage.
// Green on main by design (a pinning test, not a regression test): it fails
// if someone adds a gRPC auth cache that degrades on error.

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const grpcCFCRawErrorDetail = "pq: connection refused to db-internal-7:5432"

type grpcCFCCase struct {
	name   string
	lookup string
	// mint returns a live credential's bearer and a func that revokes it
	// directly in storage.
	mint func(t *testing.T) (token string, revoke func())
}

func TestAuthInterceptor_CredentialLookupStorageError_FailsClosed(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}))
	ctxBg := context.Background()

	cases := []grpcCFCCase{
		{
			name: "pat", lookup: "GetPersonalAccessTokenByHash",
			mint: func(t *testing.T) (string, func()) {
				h.CreateTestUser(t, "grpc-cfc", 9200)
				proj2 := uint(2)
				h.AssignUserRole(t, 9200, 3, &proj2)
				res, err := h.CoreService.CreateOwnPAT(ctxBg, 9200, "cfc", nil, []string{"secrets.read"}, 2, 0, nil)
				require.NoError(t, err)
				return res.PlainToken, func() {
					require.NoError(t, h.DB.Model(&models.PersonalAccessToken{}).Where("user_id = ?", 9200).Update("revoked", true).Error)
				}
			},
		},
		{
			name: "machine_token", lookup: "GetMachineIdentityCredentialByHash",
			mint: func(t *testing.T) (string, func()) {
				m, err := h.CoreService.CreateMachineIdentity(ctxBg, 2, "ci-bot-cfc", "service", "", "", 1, 0)
				require.NoError(t, err)
				proj2 := uint(2)
				h.AssignUserRole(t, 1, 2, &proj2)
				tok, err := h.CoreService.IssueMachineToken(ctxBg, 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok-cfc"})
				require.NoError(t, err)
				require.NoError(t, h.CoreService.AssignMachineRole(ctxBg, m.ID, 4, core.Scope{ProjectID: 2}, 1, false))
				return tok.PlainToken, func() {
					require.NoError(t, h.DB.Model(&models.MachineIdentityCredential{}).Where("machine_identity_id = ?", m.ID).Update("revoked", true).Error)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, revoke := tc.mint(t)
			fs := faultstorage.NewFaultyStorage(h.Storage, nil)
			interceptor := AuthInterceptor(core.NewKeyorixCore(fs), false)
			reached := 0
			call := func() error {
				_, err := interceptor(bearerCtxFromIP(token, "198.51.100.231"), nil,
					&grpc.UnaryServerInfo{FullMethod: secretMethod},
					func(context.Context, any) (any, error) { reached++; return "ok", nil })
				return err
			}
			armLookupError := func() {
				fs.Arm(&faultstorage.FaultSpec{Method: tc.lookup, NthCall: 1, Kind: faultstorage.KindError, Err: errors.New(grpcCFCRawErrorDetail)})
			}
			requireUnavailable := func(err error, msg string) {
				t.Helper()
				require.True(t, fs.Fired(), "precondition: the fault must fire on %s", tc.lookup)
				require.Equal(t, codes.Unavailable, status.Code(err), msg)
				require.NotContains(t, status.Convert(err).Message(), "connection refused", "the storage error's text must never reach the client")
			}

			require.NoError(t, call(), "healthy storage: the credential authenticates")
			require.Equal(t, 1, reached)

			armLookupError()
			requireUnavailable(call(), "a storage error on the credential lookup must refuse the RPC as Unavailable")
			require.Equal(t, 1, reached, "the refused RPC must never reach the handler")

			revoke()
			for range 3 {
				armLookupError()
				requireUnavailable(call(), "a revoked credential must never be accepted while its lookup fails")
			}
			require.Equal(t, 1, reached)

			fs.Arm(nil)
			require.Equal(t, codes.Unauthenticated, status.Code(call()), "once storage recovers the revocation is seen and denied")
			require.Equal(t, 1, reached)
		})
	}
}
