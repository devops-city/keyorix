package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// #3418 follow-up: a SCIM create must not carry the SSO scheme. Such an account is
// not scimOwned, so SCIM could never deactivate or delete it afterwards, and its
// external_id would pre-bind an SSO identity (resolveSSOUser's fast path).
func TestProvisionSCIMUser_RejectsReservedSSOExternalID(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	_, err := c.ProvisionSCIMUser(ctx, 0, "mallory@example.com", "", "", ssoExternalID("corp", "sub-victim"), true)
	require.ErrorContains(t, err, "reserved")
	_, gerr := st.GetUserByEmail(ctx, "mallory@example.com")
	require.ErrorIs(t, gerr, storage.ErrUserNotFound, "no account may be created")

	u, err := c.ProvisionSCIMUser(ctx, 0, "mallory@example.com", "", "", "okta|mallory", true)
	require.NoError(t, err, "control: a bare externalId still provisions")
	require.True(t, scimOwned(u))
}
