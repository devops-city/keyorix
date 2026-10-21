// machine_token_replace_credential_test.go covers validateReplacementCredential
// and the PAT-006 replace-credential-atomically-with-issuance flow in
// IssueMachineToken (machine_token.go) -- previously exercised by NO test at
// all: every existing IssueMachineToken test leaves ReplaceCredentialID unset,
// so only the replaceID==0 short-circuit branch of validateReplacementCredential
// had ever run.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestValidateReplacementCredential_ZeroID_NoOp(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	hash, err := c.validateReplacementCredential(context.Background(), 1, 0)
	require.NoError(t, err)
	assert.Empty(t, hash)
	ms.AssertNotCalled(t, "GetMachineIdentityCredentialByID", mock.Anything, mock.Anything)
}

func TestValidateReplacementCredential_NotFound(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetMachineIdentityCredentialByID", mock.Anything, uint(50)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.validateReplacementCredential(context.Background(), 1, 50)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found on this machine")
}

// TestValidateReplacementCredential_WrongMachine_Rejected pins the ownership
// check: a credential ID that resolves to a REAL row belonging to a DIFFERENT
// machine must be rejected exactly like a not-found ID -- never revealed as
// "found but not yours".
func TestValidateReplacementCredential_WrongMachine_Rejected(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetMachineIdentityCredentialByID", mock.Anything, uint(50)).
		Return(&models.MachineIdentityCredential{ID: 50, MachineIdentityID: 999, TokenHash: "victim-hash"}, nil)
	c := NewKeyorixCore(ms)
	hash, err := c.validateReplacementCredential(context.Background(), 1, 50)
	require.Error(t, err)
	assert.Empty(t, hash)
}

func TestValidateReplacementCredential_Success(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	ms.On("GetMachineIdentityCredentialByID", mock.Anything, uint(50)).
		Return(&models.MachineIdentityCredential{ID: 50, MachineIdentityID: 1, TokenHash: "old-hash"}, nil)
	c := NewKeyorixCore(ms)
	hash, err := c.validateReplacementCredential(context.Background(), 1, 50)
	require.NoError(t, err)
	assert.Equal(t, "old-hash", hash)
}

// TestIssueMachineToken_ReplaceCredential_EndToEnd exercises PAT-006's whole
// point: rotating a credential revokes the old one and mints the new one in one
// call, and returns the old token's hash for the caller to evict from any auth
// cache -- never tested end-to-end before this. MERGE-FIX-3482G: the revoke commits
// first with its row owed (recorded, then appended), the issue second, fail closed.
func TestIssueMachineToken_ReplaceCredential_EndToEnd(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
	store.On("GetMachineIdentityCredentialByID", mock.Anything, uint(50)).
		Return(&models.MachineIdentityCredential{ID: 50, MachineIdentityID: 1, TokenHash: "old-hash"}, nil)
	store.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{}, nil)
	stubAuthorizedPrincipal(store, 7, Scope{ProjectID: 2}, permRolesAssign)
	store.On("CreateMachineIdentityCredential", mock.Anything, mock.AnythingOfType("*models.MachineIdentityCredential")).
		Return(&models.MachineIdentityCredential{ID: 51}, nil)
	store.On("RevokeMachineIdentityCredential", mock.Anything, uint(2), uint(50)).Return(nil)
	store.On("CreatePendingAuditEvent", mock.Anything, mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return fixed }
	res, err := c.IssueMachineToken(context.Background(), 2, 1, 7, IssueMachineTokenParams{
		Name: "rotated-ci", ReplaceCredentialID: 50,
	})
	require.NoError(t, err)
	assert.Equal(t, "old-hash", res.ReplacedTokenHash, "the old credential's hash must be returned for cache eviction")
	store.AssertCalled(t, "RevokeMachineIdentityCredential", mock.Anything, uint(2), uint(50))
}

// TestIssueMachineToken_ReplaceCredential_BadID_FailsFast pins the ordering
// guarantee the code comment states: an invalid ReplaceCredentialID must be
// caught BEFORE the new credential is created, so a bad rotation request never
// leaves an orphaned extra credential behind.
func TestIssueMachineToken_ReplaceCredential_BadID_FailsFast(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, State: MachineActive}, nil)
	store.On("GetMachineIdentityCredentialByID", mock.Anything, uint(999)).Return(nil, errors.New("not found"))
	store.On("GetMachineRoles", mock.Anything, uint(1)).Return([]*models.Role{}, nil)
	stubAuthorizedPrincipal(store, 7, Scope{ProjectID: 2}, permRolesAssign)

	c := NewKeyorixCore(store)
	_, err := c.IssueMachineToken(context.Background(), 2, 1, 7, IssueMachineTokenParams{
		Name: "rotated-ci", ReplaceCredentialID: 999,
	})
	require.Error(t, err)
	store.AssertNotCalled(t, "CreateMachineIdentityCredential", mock.Anything, mock.Anything)
}
