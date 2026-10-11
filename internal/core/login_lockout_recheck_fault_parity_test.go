// login_lockout_recheck_fault_parity_test.go — #2894 review (MERGE-MASTER,
// blocking 2): a storage fault inside the TOCTOU lock RECHECK.
//
// recheckLoginLockFailClosed runs after the credential has already matched. Its
// storage-fault branch used to return a bare error that nobody counted, so at
// threshold−1 a wrong credential locked the account while a correct one plus a
// LockUserForUpdate fault did not. Same oracle as the post-mint faults in
// login_lockout_post_verdict_parity_test.go, one step earlier. Every call site
// that counts a wrong credential is covered here, plus the passwordless site,
// which must be wrapped as post-verdict but NOT counted (its wrong-credential
// branch does not count either).
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// armRecheckFault swaps c's storage for one whose FIRST LockUserForUpdate
// fails. On every correct-credential path below that first call is the
// recheck's own (nothing locks the user row before it when the credential
// matched), and the second one -- recordFailedLogin's -- succeeds, so the test
// observes what the code did with the fault rather than a second fault.
func armRecheckFault(c *KeyorixCore) (fs *faultstorage.FaultyStorage, restore func()) {
	base := c.storage
	fs = faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: LockUserForUpdate"),
	})
	c.storage = fs
	return fs, func() { c.storage = base }
}

func TestLogin_RecheckFaultCostsTheSameAsAWrongPassword(t *testing.T) {
	t.Parallel()

	cc, cdb, _ := newLockoutTestCore(t, true)
	cc.loginLockout = postVerdictParityPolicy
	putAtThresholdMinusOne(t, cdb, 1)
	require.Error(t, login(cc, "wrong"))
	control := readLockoutState(t, cdb, 1)

	pc, pdb, _ := newLockoutTestCore(t, true)
	pc.loginLockout = postVerdictParityPolicy
	putAtThresholdMinusOne(t, pdb, 1)
	fs, restore := armRecheckFault(pc)
	_, _, _, perr := pc.LoginPending(context.Background(), &LoginRequest{Username: "alice", Password: lockoutTestPassword})
	restore()
	require.True(t, fs.Fired(), "the recheck's LockUserForUpdate must have been reached")
	require.Error(t, perr)
	require.ErrorIs(t, perr, ErrLoginPostVerdict, "the credential matched: the transport must audit auth.login_error")
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "LoginPending/recheck")
}

func TestVerifyMFALogin_RecheckFaultCostsTheSameAsAWrongCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	cch, err := cc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, _, _, cerr := cc.VerifyMFALoginPending(ctx, cch, "000000", "ua", "203.0.113.5")
	require.Error(t, cerr)
	control := readLockoutState(t, cdb, 1)

	pc, pdb, pfixed := newMFATestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, pc, pfixed)
	putAtThresholdMinusOne(t, pdb, 1)
	pch, err := pc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	good, err := totp.GenerateCode(secret, pfixed)
	require.NoError(t, err)
	fs, restore := armRecheckFault(pc)
	_, _, _, _, perr := pc.VerifyMFALoginPending(ctx, pch, good, "ua", "203.0.113.5")
	restore()
	require.True(t, fs.Fired())
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "VerifyMFALoginPending/recheck")
}

func TestVerifyMFAStepUp_RecheckFaultCostsTheSameAsAWrongCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	require.Error(t, cc.VerifyMFAStepUp(ctx, 1, "000000"))
	control := readLockoutState(t, cdb, 1)

	pc, pdb, pfixed := newMFATestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, pc, pfixed)
	putAtThresholdMinusOne(t, pdb, 1)
	good, err := totp.GenerateCode(secret, pfixed)
	require.NoError(t, err)
	fs, restore := armRecheckFault(pc)
	perr := pc.VerifyMFAStepUp(ctx, 1, good)
	restore()
	require.True(t, fs.Fired())
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "VerifyMFAStepUp/recheck")
}

func TestFinishWebAuthnLogin_RecheckFaultCostsTheSameAsAFailedAssertion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cc, cdb := newWebAuthnSpecTestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, cc, cdb, 1)
	putAtThresholdMinusOne(t, cdb, 1)
	badParsed, challenge := specLoginAssertion(t)
	badParsed.Response.Signature = []byte("not-the-real-signature")
	cch, err := cc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	ctok, err := cc.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	_, _, _, _, cerr := cc.FinishWebAuthnLoginPending(ctx, cch, ctok, "agent", "203.0.113.5", badParsed)
	require.Error(t, cerr)
	control := readLockoutState(t, cdb, 1)

	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	goodParsed, challenge2 := specLoginAssertion(t)
	pch, err := pc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	ptok, err := pc.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge2, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	fs, restore := armRecheckFault(pc)
	_, _, _, _, perr := pc.FinishWebAuthnLoginPending(ctx, pch, ptok, "agent", "203.0.113.5", goodParsed)
	restore()
	require.True(t, fs.Fired())
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "FinishWebAuthnLoginPending/recheck")
}

func TestFinishWebAuthnReauth_RecheckFaultCostsTheSameAsAFailedAssertion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cc, cdb := newWebAuthnSpecTestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, cc, cdb, 1)
	putAtThresholdMinusOne(t, cdb, 1)
	badParsed, challenge := specLoginAssertion(t)
	badParsed.Response.Signature = []byte("not-the-real-signature")
	ctok, err := cc.storeWebAuthnSession(ctx, 1, webauthnReauthSessionPurpose, &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	require.Error(t, cc.FinishWebAuthnReauth(ctx, 1, ctok, badParsed))
	control := readLockoutState(t, cdb, 1)

	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	goodParsed, challenge2 := specLoginAssertion(t)
	ptok, err := pc.storeWebAuthnSession(ctx, 1, webauthnReauthSessionPurpose, &webauthn.SessionData{Challenge: challenge2, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	fs, restore := armRecheckFault(pc)
	perr := pc.FinishWebAuthnReauth(ctx, 1, ptok, goodParsed)
	restore()
	require.True(t, fs.Fired())
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "FinishWebAuthnReauth/recheck")
}

// TestFinishWebAuthnPasswordlessLogin_RecheckFaultIsPostVerdictButNotCounted:
// a failed passwordless assertion never feeds the counter, so neither may a
// valid one whose recheck faulted -- but it must still be marked post-verdict
// (audited auth.login_error, with the account named) rather than a bare error.
func TestFinishWebAuthnPasswordlessLogin_RecheckFaultIsPostVerdictButNotCounted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	before := readLockoutState(t, pdb, 1)
	goodParsed, challenge := specLoginAssertion(t)
	goodParsed.Response.UserHandle = specWebAuthnID(1)
	ptok, err := pc.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)
	fs, restore := armRecheckFault(pc)
	_, user, _, _, perr := pc.FinishWebAuthnPasswordlessLoginPending(ctx, ptok, "agent", "203.0.113.5", goodParsed)
	restore()
	require.True(t, fs.Fired())
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	require.NotNil(t, user, "post-verdict: the transport needs the account to audit auth.login_error")
	assert.Equal(t, before, readLockoutState(t, pdb, 1),
		"passwordless: a recheck fault must leave the counter exactly where the credential check found it")
}

// TestRecheck_ConcurrentLockIsStillARefusalNotAPostVerdictFault pins the other
// half of the split: when the recheck SUCCEEDS and finds the account locked,
// that is a genuine refusal, not a storage fault -- it must not be wrapped as
// ErrLoginPostVerdict, and must not count again.
func TestRecheck_ConcurrentLockIsStillARefusalNotAPostVerdictFault(t *testing.T) {
	t.Parallel()
	c, db, _ := newLockoutTestCore(t, true)
	c.loginLockout = postVerdictParityPolicy
	u := reloadUser(t, db)
	until := time.Now().UTC().Add(time.Hour)
	require.NoError(t, db.Model(u).Update("login_locked_until", until).Error)
	err := c.recheckLockAfterCredentialMatched(context.Background(), u, true)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrLoginPostVerdict)
	assert.Contains(t, err.Error(), "temporarily locked")
}
