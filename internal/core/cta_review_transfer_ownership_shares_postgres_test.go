// cta_review_transfer_ownership_shares_postgres_test.go — FIX-3102: the ownership
// transfer re-owns the secret's shares in the same transaction as the secret's owner_id
// write. Two independent replicas (two *gorm.DB pools) on real Postgres force the
// interleavings a single-connection test cannot reach. Same technique and fixture as
// concurrency_check_then_act_exempt_review_postgres_test.go (beforeA/afterA hooks).
package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// shareRowsNotOwnedBy counts share_records rows of secretID (live and soft-deleted)
// whose owner_id is not want: the stale previous-owner stamp the bug leaves behind.
func (f *ctaReview) shareRowsNotOwnedBy(secretID, want uint) int64 {
	f.t.Helper()
	return f.countLive(&models.ShareRecord{}, "secret_id = ? AND owner_id <> ?", secretID, want)
}

// TestCTAReview_TransferOwnership_vs_RevokeShare_CrossReplicaPostgres: the previous
// owner's revoke commits on replica B after replica A's transfer has written the
// secret's owner_id but before A's share re-stamp executes. The revoke was legitimate
// (B still saw the previous owner), so it must stick: the share stays revoked, the
// transfer must not resurrect it, and the (now soft-deleted) row is re-stamped too.
//
// Bug origin (#3102):
//
//	Introduced-by: TransferSecretOwnership (secret_ownership.go) moving only the secret's owner_id
//	Detected-by:   review (#3018)
//	Class:         atomicity (two owner keys, one write)
//	Severity:      medium (previous owner lists shares they cannot revoke; new owner the reverse)
//	Guard:         this test, TestTransferSecretOwnership_ReownsShares (both backends)
func TestCTAReview_TransferOwnership_vs_RevokeShare_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	oldOwner := f.user("cta-xfer-old", "project_admin")
	newOwner := f.user("cta-xfer-new", "project_admin")
	recipient := f.user("cta-xfer-rcpt", "project_viewer")
	s := f.secret("cta-xfer-secret", oldOwner.ID)
	share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: oldOwner.ID,
	})
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("update", "share_records", func() { errB = f.coreB.RevokeShare(f.ctx, share.ID, oldOwner.ID) })
	_, errA := f.coreA.TransferSecretOwnership(f.ctx, s.ID, newOwner.ID, oldOwner.ID, ActorTypeUser)
	t.Logf("TransferSecretOwnership (A) err=%v, RevokeShare (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's RevokeShare before A's share re-stamp")
	require.NoError(t, errA)
	require.NoError(t, errB, "the revoke itself reported success")

	assert.Zero(t, f.countLive(&models.ShareRecord{}, "id = ? AND deleted_at IS NULL", share.ID),
		"a share whose revocation reported success is live again")
	assert.Zero(t, f.shareRowsNotOwnedBy(s.ID, newOwner.ID),
		"a share row of the transferred secret kept the previous owner (the revoked row included)")
}

// TestCTAReview_TransferOwnership_RevokeBlockedBehindRestamp_CrossReplicaPostgres: the
// previous owner's revoke starts on replica B while A's transfer transaction holds the
// re-stamped share row, and so waits for it. Whichever way that resolves (the revoke is
// ordered before the transfer and succeeds, or after it and is refused as no longer the
// owner), the outcome must be consistent: success means the share is revoked, refusal
// means it is still live, and in neither case does any row keep the previous owner.
func TestCTAReview_TransferOwnership_RevokeBlockedBehindRestamp_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	oldOwner := f.user("cta-xferb-old", "project_admin")
	newOwner := f.user("cta-xferb-new", "project_admin")
	recipient := f.user("cta-xferb-rcpt", "project_viewer")
	s := f.secret("cta-xferb-secret", oldOwner.ID)
	share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: oldOwner.ID,
	})
	require.NoError(t, err)

	done := make(chan error, 1)
	fired := f.afterA("update", "share_records", func() {
		go func() { done <- f.coreB.RevokeShare(f.ctx, share.ID, oldOwner.ID) }()
	})
	_, errA := f.coreA.TransferSecretOwnership(f.ctx, s.ID, newOwner.ID, oldOwner.ID, ActorTypeUser)
	require.True(t, fired(), "the hook must have started B's RevokeShare after A's share re-stamp")
	require.NoError(t, errA)

	var errB error
	select {
	case errB = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("B's RevokeShare never finished after A's transfer committed")
	}
	t.Logf("RevokeShare (B) err=%v", errB)

	live := f.countLive(&models.ShareRecord{}, "id = ? AND deleted_at IS NULL", share.ID)
	if errB == nil {
		assert.Zero(t, live, "a revoke that reported success left the share live")
	} else {
		assert.EqualValues(t, 1, live, "a refused revoke must leave the share untouched")
	}
	assert.Zero(t, f.shareRowsNotOwnedBy(s.ID, newOwner.ID), "a share row kept the previous owner")
}

// TestCTAReview_ShareSecret_vs_TransferOwnership_CrossReplicaPostgres: the previous
// owner's ShareSecret passed its authority check and read the secret's owner on replica
// A; replica B's transfer then commits (it has nothing to re-stamp yet); A inserts the
// share stamped with the previous owner. Without CreateShareRecord's post-lock owner
// re-check that row commits on a secret the new owner owns: the stale stamp the transfer
// was meant to eliminate, and the previous owner lists a share they can no longer
// revoke. Fail closed: A's share is refused.
//
// Bug origin (#3102): same as TestCTAReview_TransferOwnership_vs_RevokeShare_CrossReplicaPostgres;
// this is the sibling writer found while re-reading the fix as a fault injector.
func TestCTAReview_ShareSecret_vs_TransferOwnership_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	oldOwner := f.user("cta-xfers-old", "project_admin")
	newOwner := f.user("cta-xfers-new", "project_admin")
	recipient := f.user("cta-xfers-rcpt", "project_viewer")
	s := f.secret("cta-xfers-secret", oldOwner.ID)

	var errB error
	fired := f.beforeA("create", "share_records", func() {
		_, errB = f.coreB.TransferSecretOwnership(f.ctx, s.ID, newOwner.ID, oldOwner.ID, ActorTypeUser)
	})
	_, errA := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: oldOwner.ID,
	})
	t.Logf("ShareSecret (A) err=%v, TransferSecretOwnership (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's transfer before A's share INSERT")
	require.NoError(t, errB)

	assert.Error(t, errA, "A must fail closed: it was authorised as an owner who no longer owns the secret")
	assert.Zero(t, f.shareRowsNotOwnedBy(s.ID, newOwner.ID),
		"a share was committed stamped with the previous owner on a secret the new owner owns")
}
