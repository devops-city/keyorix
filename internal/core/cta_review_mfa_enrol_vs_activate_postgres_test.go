// cta_review_mfa_enrol_vs_activate_postgres_test.go — #2692: a late
// BeginMFAEnrollment must never replace a TOTP secret a concurrent ActivateMFA
// activated. The reverse interleaving of #2655
// (TestCTAReview_ActivateMFA_vs_BeginMFAEnrollment_CrossReplicaPostgres). Same
// two-replica fixture as concurrency_check_then_act_exempt_review_postgres_test.go.
package core

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCTAReview_BeginMFAEnrollment_vs_ActivateMFA_CrossReplicaPostgres: replica
// A's BeginMFAEnrollment reads MFAEnabled=false; replica B's ActivateMFA (of the
// earlier pending secret s1) commits before A's upsert executes. A must be
// refused with ErrMFAAlreadyEnabled and the activated s1 must survive.
//
// Bug origin (#2692):
//
//	Introduced-by: UpsertMFASecret's OnConflict{UpdateAll} (unconditional replace),
//	               paired with BeginMFAEnrollment's MFAEnabled check on a pre-read row
//	Detected-by:   review (C-GUARD3-EXEMPT-REVIEW), reproduced by ISSUE-TRIAGE-1's probe
//	Class:         race (stale read, unconditional write)
//	Severity:      high (the enroller is handed a seed that satisfies MFA on an
//	               MFA-enabled account; login verification does not read Activated)
//	Guard:         this test, TestBeginMFAEnrollment_DoesNotReplaceActivatedSecret
//	               (default-ci), the conditional upsert in LocalStorage.UpsertMFASecret,
//	               and TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels,
//	               which no longer exempts UpsertMFASecret.
func TestCTAReview_BeginMFAEnrollment_vs_ActivateMFA_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	victim := f.user("cta-mfa-late-enrol", "")
	_, s1, err := f.setup.BeginMFAEnrollment(f.ctx, victim.ID)
	require.NoError(t, err)
	code, err := totp.GenerateCode(s1, time.Now())
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("create", "mfa_secrets", func() {
		_, errB = f.coreB.ActivateMFA(f.ctx, victim.ID, code, "UserPass123!xyz-long-enough", "")
	})
	_, s2, errA := f.coreA.BeginMFAEnrollment(f.ctx, victim.ID)
	t.Logf("BeginMFAEnrollment (A) err=%v, ActivateMFA (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's ActivateMFA before A's upsert")
	require.NoError(t, errB, "the activation itself reported success")

	row, err := f.setup.Storage().GetMFASecret(f.ctx, victim.ID)
	require.NoError(t, err)
	active, err := f.setup.loadTOTPSecret(f.ctx, victim.ID)
	require.NoError(t, err)
	user, err := f.setup.Storage().GetUser(f.ctx, victim.ID)
	require.NoError(t, err)
	assert.True(t, user.MFAEnabled)
	assert.True(t, row.Activated, "#2692: the activated secret was replaced by a pending one")
	assert.Equal(t, s1, active, "#2692: the stored secret is no longer the one the account holder activated")
	require.ErrorIs(t, errA, ErrMFAAlreadyEnabled, "the late enrolment must be refused")
	assert.Empty(t, s2, "no seed may be handed to the late enroller")
}
