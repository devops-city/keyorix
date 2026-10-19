// cta_review_delete_user_vs_password_postgres_test.go — #2677: DeleteUser must not
// write back a user row it read before a concurrent password change committed.
// Same two-replica fixture as concurrency_check_then_act_exempt_review_postgres_test.go.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_DeleteUser_vs_ChangePassword_CrossReplicaPostgres: replica B's
// ChangePassword runs immediately before replica A's DeleteUser issues its first
// UPDATE of the user row. Before the fix A wrote back its pre-read row with a
// full-row Save, reverting B's committed password change, so RestoreUser later
// let the OLD password in. Now A locks the row and writes only is_active /
// account_state: B either commits first (its new hash survives the delete) or
// waits on A's row lock and then finds the row deleted (it reports failure, and
// the old hash is then legitimately the last one). The invariant asserted holds
// for both: a password change that reported success is never reverted.
//
// Bug origin (#2677):
//
//	Introduced-by: DeleteUser's deprovisioning write (user.IsActive/AccountState set on
//	               the GetUser result, persisted through the full-row UpdateUser/Save)
//	Detected-by:   review (C-GUARD3-EXEMPT-REVIEW, #2725), reproduced by ISSUE-TRIAGE-1's probe
//	Class:         race (stale full-row write)
//	Severity:      medium (needs a password change racing an admin delete; the
//	               restored account accepts the superseded password)
//	Guard:         this test, TestDeleteUser_KeepsConcurrentPasswordChange (default-ci),
//	               and TestFullRowWriteGuard_NoUnexemptedCallerOfFullRowWriter, whose
//	               ledger no longer lists any internal/core caller of UpdateUser.
func TestCTAReview_DeleteUser_vs_ChangePassword_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	victim := f.user("cta-delete-vs-password", "")
	var before models.User
	require.NoError(t, f.setupDB.First(&before, victim.ID).Error)

	var errB error
	fired, waitB := f.beforeAMayBlock("update", "users", func() {
		errB = f.coreB.ChangePassword(f.ctx, victim.ID, "UserPass123!xyz-long-enough", "NewUserPass456!abc-long-enough", "")
	})
	errA := f.coreA.DeleteUser(f.ctx, f.adminID, victim.ID)
	waitB()
	t.Logf("DeleteUser (A) err=%v, ChangePassword (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's ChangePassword before A's user UPDATE")
	require.NoError(t, errA)

	var got models.User
	require.NoError(t, f.setupDB.Unscoped().First(&got, victim.ID).Error)
	assert.True(t, got.DeletedAt.Valid, "the user must be soft-deleted")
	assert.False(t, got.IsActive)
	assert.Equal(t, AccountDeprovisioned, got.AccountState)
	if errB == nil {
		assert.NotEqual(t, before.PasswordHash, got.PasswordHash,
			"#2677: the OLD password hash is live again after a successful password change")
	}
}
