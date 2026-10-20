package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// globalInvitationCountForEmail counts projectID=0 (global) invitations for
// email, so a test can assert "nothing was committed" precisely rather than
// just "the call returned an error".
func globalInvitationCountForEmail(t *testing.T, st *store.LocalStorage, email string) int {
	t.Helper()
	rows, err := st.ListProjectInvitations(context.Background(), 0)
	require.NoError(t, err)
	n := 0
	for _, r := range rows {
		if r.Email == email {
			n++
		}
	}
	return n
}

// TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed is the
// regression test for #2419 (FuzzStorageFaultOperations input decoding, on
// current main, to op="REST POST /api/v1/invitations"
// fault=(method=SupersedeActiveSetupTokens, NthCall=1, kind=error)): a failed
// supersede+create of the setup token must never be reported the same way a
// benign delivery/config failure is (201 "created, link not delivered") --
// the prior active links were NOT actually invalidated, so the caller must
// get a distinguishable, fail-closed signal.
//
// Coordinator follow-up (#2444 review): the invitation insert and the
// setup-token supersede+create now commit or fail together (one outer
// transaction) -- a genuine mint-step fault must leave NEITHER row behind,
// not just the setup token. Before this follow-up, the invitation row was
// still committed on this exact fault, which both misreported oracle (a)
// (reported error, but state changed) and could leave an orphan pending
// invitation blocking a resend.
func TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected storage fault"),
	})

	inv, prov, err := c.InviteGlobalWithLink(ctx, "carol@example.com", "", nil, admin.ID, 0)

	require.Error(t, err, "a failed supersede+create must be reported as an error, not silently swallowed")
	assert.Nil(t, prov)
	assert.Nil(t, inv, "neither the invitation nor the setup token may commit when the mint step fails")
	assert.True(t, errors.Is(err, ErrSetupTokenIssuanceFailed),
		"the error must be distinguishable from a benign config/throttle/delivery failure so the HTTP layer can fail closed")

	// Confirm via fresh, unfaulted reads: NEITHER row exists -- the outer
	// transaction genuinely rolled back the invitation insert together with
	// the mint step, it did not leave an orphan pending invitation with no
	// working link (which could also collide with a resend/duplicate-pending
	// check on an immediate retry -- see the retry-succeeds test below).
	n, err := st.CountSetupTokensSince(ctx, SetupPurposeInvitationAccept, "carol@example.com", c.now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Zero(t, n, "no setup token should exist after a rolled-back issuance")
	assert.Zero(t, globalInvitationCountForEmail(t, st, "carol@example.com"),
		"no invitation row should exist after a rolled-back issuance")
}

// TestInviteGlobalWithLink_SupersedeActiveSetupTokensError_RetrySucceeds proves
// the fix actually unblocks recovery, not just that nothing is left behind:
// an admin retrying the exact same invite immediately after the faulted
// attempt (fault cleared, as a real retry would be) must succeed cleanly --
// no leftover state from the failed attempt collides with it.
func TestInviteGlobalWithLink_SupersedeActiveSetupTokensError_RetrySucceeds(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected storage fault"),
	})
	inv, prov, err := c.InviteGlobalWithLink(ctx, "dave@example.com", "", nil, admin.ID, 0)
	require.Error(t, err)
	assert.Nil(t, inv)
	assert.Nil(t, prov)

	// The fault only fires once (faultstorage's own single-fire semantics);
	// an immediate retry with the exact same request must succeed.
	inv2, prov2, err := c.InviteGlobalWithLink(ctx, "dave@example.com", "", nil, admin.ID, 0)
	require.NoError(t, err, "an immediate retry after a rolled-back attempt must succeed")
	require.NotNil(t, inv2)
	require.NotNil(t, prov2)
	assert.Equal(t, "dave@example.com", inv2.Email)

	assert.Equal(t, 1, globalInvitationCountForEmail(t, st, "dave@example.com"),
		"exactly one invitation should exist after the failed attempt rolled back and the retry succeeded")
	n, err := st.CountSetupTokensSince(ctx, SetupPurposeInvitationAccept, "dave@example.com", c.now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "exactly one setup token should exist after the retry")
}

// TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed_Postgres
// is the real-Postgres sibling: the rollback this fix relies on is a nested
// WithTransaction (SAVEPOINT) inside IssueSetupToken, and SQLite's transaction
// semantics are not always a faithful proxy for Postgres's. Skips when
// KEYORIX_TEST_PG_DSN is unset.
func TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgMigratedDatabaseDSN(t, base))
	st := store.NewLocalStorage(db)
	ctx := context.Background()

	c := NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected storage fault"),
	})

	inv, prov, err := c.InviteGlobalWithLink(ctx, "carol@example.com", "", nil, admin.ID, 0)

	require.Error(t, err)
	assert.Nil(t, prov)
	assert.Nil(t, inv, "neither the invitation nor the setup token may commit when the mint step fails (Postgres)")
	assert.True(t, errors.Is(err, ErrSetupTokenIssuanceFailed))

	n, err := st.CountSetupTokensSince(ctx, SetupPurposeInvitationAccept, "carol@example.com", c.now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Zero(t, n, "no setup token should exist after a rolled-back issuance (Postgres)")
	assert.Zero(t, globalInvitationCountForEmail(t, st, "carol@example.com"),
		"no invitation row should exist after a rolled-back issuance (Postgres)")

	// Immediate retry on the same backend must succeed.
	inv2, prov2, err := c.InviteGlobalWithLink(ctx, "carol@example.com", "", nil, admin.ID, 0)
	require.NoError(t, err, "an immediate retry after a rolled-back attempt must succeed (Postgres)")
	require.NotNil(t, inv2)
	require.NotNil(t, prov2)
	assert.Equal(t, 1, globalInvitationCountForEmail(t, st, "carol@example.com"))
}
