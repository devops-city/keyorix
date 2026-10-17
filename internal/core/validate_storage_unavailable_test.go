package core

// validate_storage_unavailable_test.go -- a FAILED credential/account lookup in a
// Validate*Token function is a storage fault, not a verdict on the credential.
//
// Found by scripts/drills/disaster.sh (pgdown, PROD-OPS-1): with PostgreSQL
// unreachable, every valid machine token and session answered 401, was
// negative-cached for invalidTokenTTL (so the 401s outlived the outage by that
// long) and was charged to the caller's IP brute-force budget. #1944/#2748 had
// fixed this only for the final roles read. Both directions are pinned: a storage
// fault is ErrAuthStorageUnavailable (retryable, IsAuthTransient), and a positive
// "no such row" stays an ordinary invalid-credential error (not transient), or the
// middleware would stop negative-caching and rate-limiting real bad tokens.

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestValidateToken_CredentialLookupFault_IsAuthStorageUnavailable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineRaw := machineTokenPrefix + "lookupfault"
	patRaw := patPrefix + "lookupfault"

	cases := []struct {
		name string
		run  func(t *testing.T, ms *MockStorage, c *KeyorixCore) error
	}{
		{"session lookup", func(t *testing.T, ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetSession", ctx, "tok").Return(nil, errRolesStorageDown)
			_, _, err := c.ValidateSessionToken(ctx, "tok")
			return err
		}},
		{"session owner lookup", func(t *testing.T, ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 2}, nil)
			ms.On("GetUser", ctx, uint(2)).Return(nil, errRolesStorageDown)
			_, _, err := c.ValidateSessionToken(ctx, "tok")
			return err
		}},
		{"pat lookup", func(t *testing.T, ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetPersonalAccessTokenByHash", ctx, sha256Hex(patRaw)).Return(nil, errRolesStorageDown)
			_, _, _, _, err := c.ValidatePATToken(ctx, patRaw)
			return err
		}},
		{"pat owner lookup", func(t *testing.T, ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetPersonalAccessTokenByHash", ctx, sha256Hex(patRaw)).Return(&models.PersonalAccessToken{ID: 9, UserID: 1}, nil)
			ms.On("GetUser", ctx, uint(1)).Return(nil, errRolesStorageDown)
			_, _, _, _, err := c.ValidatePATToken(ctx, patRaw)
			return err
		}},
		{"machine credential lookup", func(t *testing.T, ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetMachineIdentityCredentialByHash", ctx, sha256Hex(machineRaw)).Return(nil, errRolesStorageDown)
			_, _, _, _, err := c.ValidateMachineToken(ctx, machineRaw)
			return err
		}},
		{"machine identity lookup", func(t *testing.T, ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetMachineIdentityCredentialByHash", ctx, sha256Hex(machineRaw)).
				Return(&models.MachineIdentityCredential{ID: 11, MachineIdentityID: 4}, nil)
			ms.On("GetMachineIdentity", ctx, uint(4)).Return(nil, errRolesStorageDown)
			_, _, _, _, err := c.ValidateMachineToken(ctx, machineRaw)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ms := new(MockStorage)
			err := tc.run(t, ms, NewKeyorixCore(ms))
			require.ErrorIs(t, err, ErrAuthStorageUnavailable)
			assert.True(t, IsAuthTransient(err))
			assert.NotErrorIs(t, err, errRolesStorageDown, "the storage error's detail must not reach the caller")
		})
	}
}

func TestValidateToken_PositiveNotFound_IsNotTransient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineRaw := machineTokenPrefix + "unknown"
	patRaw := patPrefix + "unknown"

	cases := []struct {
		name    string
		run     func(ms *MockStorage, c *KeyorixCore) error
		message string
	}{
		{"session", func(ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetSession", ctx, "tok").Return(nil, storage.ErrSessionNotFound)
			_, _, err := c.ValidateSessionToken(ctx, "tok")
			return err
		}, "session not found"},
		{"pat", func(ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetPersonalAccessTokenByHash", ctx, sha256Hex(patRaw)).Return(nil, gorm.ErrRecordNotFound)
			_, _, _, _, err := c.ValidatePATToken(ctx, patRaw)
			return err
		}, "invalid token"},
		{"machine", func(ms *MockStorage, c *KeyorixCore) error {
			ms.On("GetMachineIdentityCredentialByHash", ctx, sha256Hex(machineRaw)).Return(nil, gorm.ErrRecordNotFound)
			_, _, _, _, err := c.ValidateMachineToken(ctx, machineRaw)
			return err
		}, "invalid token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ms := new(MockStorage)
			err := tc.run(ms, NewKeyorixCore(ms))
			require.Error(t, err)
			assert.False(t, IsAuthTransient(err), "a token that positively does not exist must stay an invalid-credential verdict")
			assert.Equal(t, tc.message, err.Error())
		})
	}
}
