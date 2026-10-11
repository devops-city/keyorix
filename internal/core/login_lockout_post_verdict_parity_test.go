// login_lockout_post_verdict_parity_test.go — #2894 for the login paths whose
// post-verdict window lives entirely inside core.
//
// server/http/handlers/login_lockout_no_oracle_test.go proves the property
// end-to-end over HTTP for /auth/login and /auth/mfa/verify, including the
// transport-owned half (completeLogin's identity read), and that half is ONE
// function shared by all five login handlers. What it cannot reach is a
// genuinely verifying WebAuthn assertion — the handlers package has only a
// fake, non-cryptographic credential fixture, while the real spec vectors live
// here. So the WebAuthn second-factor, passwordless, re-auth and step-up paths
// are proved at the core level instead, against the same comparison:
//
//	a WRONG credential and a CORRECT credential faulted after the match must
//	leave the account's lockout columns in the SAME state.
//
// Each case starts at MaxAttempts−1, because that is where the difference is
// loudest: the control locks the account and, before this fix, the probe did
// not — which is the whole oracle.
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
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// postVerdictParityPolicy is shared by every case here so "threshold−1" means
// the same thing throughout.
var postVerdictParityPolicy = LoginLockoutPolicy{
	Enabled: true, MaxAttempts: 3, Window: time.Hour,
	BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour,
}

// lockoutState is the observable half of the comparison: the four columns an
// attacker can probe for afterwards (by watching whether the account locks).
type lockoutState struct {
	FailedAttempts int
	Locked         bool
	LockoutCount   int
}

func readLockoutState(t *testing.T, db *gorm.DB, userID uint) lockoutState {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, userID).Error)
	return lockoutState{
		FailedAttempts: u.FailedLoginAttempts,
		Locked:         u.LoginLockedUntil != nil,
		LockoutCount:   u.LoginLockoutCount,
	}
}

// putAtThresholdMinusOne writes the counter directly to MaxAttempts−1 rather
// than driving real failures: the credential shapes differ per path (a bad
// assertion, a bad code), and what is under test is the final attempt, not how
// the account got there.
func putAtThresholdMinusOne(t *testing.T, db *gorm.DB, userID uint) {
	t.Helper()
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", userID).
		Updates(map[string]any{
			"failed_login_attempts": postVerdictParityPolicy.MaxAttempts - 1,
			"last_failed_login_at":  time.Now().UTC(),
			"login_locked_until":    nil,
			"login_lockout_count":   0,
		}).Error)
}

// requireSameLockoutCost is the assertion. It also requires the control to
// have actually locked: if it did not, the comparison is vacuous and would
// pass for a fix that simply never counted anything.
func requireSameLockoutCost(t *testing.T, control, probe lockoutState, what string) {
	t.Helper()
	require.True(t, control.Locked,
		"%s: the wrong-credential control must lock the account at threshold-1, or this comparison proves nothing", what)
	assert.Equal(t, control.Locked, probe.Locked,
		"%s: a correct credential plus a post-verdict fault left the account UNLOCKED where a wrong one locks it -- whether the account locks answers 'was the credential right?' (#2894)", what)
	assert.Equal(t, control.FailedAttempts, probe.FailedAttempts, "%s: failed_login_attempts differs", what)
	assert.Equal(t, control.LockoutCount, probe.LockoutCount, "%s: login_lockout_count differs", what)
}

// --- WebAuthn second factor (FinishWebAuthnLogin) ----------------------------

// TestFinishWebAuthnLogin_PostVerdictFaultCostsTheSameAsAFailedAssertion:
// the control is an assertion that genuinely fails to verify; the probe is a
// VALID assertion whose session mint then faults.
func TestFinishWebAuthnLogin_PostVerdictFaultCostsTheSameAsAFailedAssertion(t *testing.T) {
	t.Parallel()

	// Control: a bad assertion.
	cc, cdb := newWebAuthnSpecTestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, cc, cdb, 1)
	putAtThresholdMinusOne(t, cdb, 1)
	badParsed, challenge := specLoginAssertion(t)
	badParsed.Response.Signature = []byte("not-the-real-signature")
	cch, err := cc.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	ctok, err := cc.storeWebAuthnSession(context.Background(), 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	_, _, _, cerr := cc.FinishWebAuthnLogin(context.Background(), cch, ctok, "agent", "203.0.113.5", badParsed)
	require.Error(t, cerr, "control: a tampered assertion must be refused")
	control := readLockoutState(t, cdb, 1)

	// Probe: a valid assertion, faulted at the session mint.
	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	goodParsed, challenge2 := specLoginAssertion(t)
	pch, err := pc.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	ptok, err := pc.storeWebAuthnSession(context.Background(), 1, "login", &webauthn.SessionData{Challenge: challenge2, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	base := pc.storage
	pc.storage = &failCreateSessionStorage{Storage: base}
	_, _, _, perr := pc.FinishWebAuthnLogin(context.Background(), pch, ptok, "agent", "203.0.113.5", goodParsed)
	pc.storage = base
	require.Error(t, perr)
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "FinishWebAuthnLogin/CreateSession")
}

// --- WebAuthn passwordless (FinishWebAuthnPasswordlessLogin) -----------------

func TestFinishWebAuthnPasswordlessLogin_PostVerdictFaultCostsTheSameAsAFailedAssertion(t *testing.T) {
	t.Parallel()

	cc, cdb := newWebAuthnSpecTestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, cc, cdb, 1)
	putAtThresholdMinusOne(t, cdb, 1)
	badParsed, challenge := specLoginAssertion(t)
	badParsed.Response.UserHandle = specWebAuthnID(1)
	badParsed.Response.Signature = []byte("not-the-real-signature")
	ctok, err := cc.storeWebAuthnSession(context.Background(), 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)
	_, _, _, cerr := cc.FinishWebAuthnPasswordlessLogin(context.Background(), ctok, "agent", "203.0.113.5", badParsed)
	require.Error(t, cerr)
	control := readLockoutState(t, cdb, 1)

	// A failed PASSWORDLESS assertion deliberately does not feed the per-account
	// counter (the user is only resolved by the assertion itself, so counting a
	// failure would let anyone lock an arbitrary victim) -- see
	// checkPasswordlessAccountState's comment. So the control here does NOT
	// lock, and the property is the mirror image: the probe must not lock either.
	require.False(t, control.Locked, "setup: a failed passwordless assertion must not feed the lockout")

	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	goodParsed, challenge2 := specLoginAssertion(t)
	goodParsed.Response.UserHandle = specWebAuthnID(1)
	ptok, err := pc.storeWebAuthnSession(context.Background(), 0, "passwordless", &webauthn.SessionData{Challenge: challenge2})
	require.NoError(t, err)
	base := pc.storage
	pc.storage = &failCreateSessionStorage{Storage: base}
	_, _, _, perr := pc.FinishWebAuthnPasswordlessLogin(context.Background(), ptok, "agent", "203.0.113.5", goodParsed)
	pc.storage = base
	require.Error(t, perr)
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	// The CLEAR is what must not have happened: before #2894 the probe came back
	// at 0 failures (cleared on the way to the mint) while the control sat at
	// threshold-1, so an attacker who could fault the mint could also wipe the
	// victim's accumulated lockout progress with a stolen passkey assertion.
	assert.Equal(t, control.FailedAttempts, probe.FailedAttempts,
		"passwordless: a post-verdict fault must leave the counter where the credential check found it, not at 0 (#2894)")
	assert.Equal(t, control.Locked, probe.Locked)
	assert.Equal(t, control.LockoutCount, probe.LockoutCount)
}

// --- WebAuthn re-auth (FinishWebAuthnReauth) ---------------------------------

// TestFinishWebAuthnReauth_PostVerdictFaultCostsTheSameAsAFailedAssertion is
// the clearest red-pre-fix case of the family: FinishWebAuthnReauth cleared the
// counter and THEN wrote the step-up grant, so a fault on that single write
// both denied the re-auth and reset the victim's lockout progress to zero.
func TestFinishWebAuthnReauth_PostVerdictFaultCostsTheSameAsAFailedAssertion(t *testing.T) {
	t.Parallel()

	cc, cdb := newWebAuthnSpecTestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, cc, cdb, 1)
	putAtThresholdMinusOne(t, cdb, 1)
	badParsed, challenge := specLoginAssertion(t)
	badParsed.Response.Signature = []byte("not-the-real-signature")
	ctok, err := cc.storeWebAuthnSession(context.Background(), 1, webauthnReauthSessionPurpose, &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	require.Error(t, cc.FinishWebAuthnReauth(context.Background(), 1, ctok, badParsed))
	control := readLockoutState(t, cdb, 1)

	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	goodParsed, challenge2 := specLoginAssertion(t)
	ptok, err := pc.storeWebAuthnSession(context.Background(), 1, webauthnReauthSessionPurpose, &webauthn.SessionData{Challenge: challenge2, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	base := pc.storage
	pc.storage = &failCreateMFAStepUpGrantStorage{Storage: base}
	perr := pc.FinishWebAuthnReauth(context.Background(), 1, ptok, goodParsed)
	pc.storage = base
	require.Error(t, perr)
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "FinishWebAuthnReauth/CreateMFAStepUpGrant")
}

// --- TOTP step-up (VerifyMFAStepUp) ------------------------------------------

// TestVerifyMFAStepUp_PostVerdictFaultCostsTheSameAsAWrongCode is the TOTP
// sibling of the re-auth case above: same clear-then-write-the-grant ordering,
// same fault, same oracle.
func TestVerifyMFAStepUp_PostVerdictFaultCostsTheSameAsAWrongCode(t *testing.T) {
	t.Parallel()

	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	require.Error(t, cc.VerifyMFAStepUp(context.Background(), 1, "000000"), "control: a wrong code must be refused")
	control := readLockoutState(t, cdb, 1)

	pc, pdb, pfixed := newMFATestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, pc, pfixed)
	putAtThresholdMinusOne(t, pdb, 1)
	// One step past activation's own code, so the anti-replay mark has not seen it.
	step := pfixed.Add(30 * time.Second)
	pc.SetClockForTesting(func() time.Time { return step })
	good, err := totp.GenerateCode(secret, step)
	require.NoError(t, err)
	base := pc.storage
	pc.storage = &failCreateMFAStepUpGrantStorage{Storage: base}
	perr := pc.VerifyMFAStepUp(context.Background(), 1, good)
	pc.storage = base
	require.Error(t, perr)
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "VerifyMFAStepUp/CreateMFAStepUpGrant")
}

// --- TOTP re-auth (requireReauth, via DisableMFA) ----------------------------

// TestRequireReauth_PostVerdictFaultCostsTheSameAsAWrongCode replaces the
// weaker shape of this claim in require_reauth_storage_error_test.go
// (TestRequireReauth_MarkTOTPStepUsedErrorAfterMatch_StillCountsTowardLockout),
// which asserts only "the account ends up locked".
//
// Being straight about what is and is not red pre-fix here, since the
// coordinator asked: for requireReauth the LOCKOUT half was already correct on
// main, and no assertion over this function can be red against main. The
// reason is mechanical — main DISCARDED MarkTOTPStepUsed's error entirely
// (`if fresh, ferr := ...; ferr == nil && fresh`), so the attempt fell through
// to the generic wrong-credential arm, which calls recordFailedLogin. #2888
// introduced postVerdictErr to give that case its own distinct AUDIT event
// (mfa.error rather than mfa.failed) — that is the only half of the sibling
// test that is red against main, and the test's own comment says so.
//
// What this test adds is precision, not a second red proof: it pins the
// lockout columns against a WRONG-CODE control instead of just asserting
// "locked", so the realistic future regression — somebody moving the
// postVerdictErr arm to stop counting, now that it has its own arm to move —
// is caught. Verified red under exactly that mutation (removing
// recordFailedLogin from requireReauth's postVerdictErr branch).
func TestRequireReauth_PostVerdictFaultCostsTheSameAsAWrongCode(t *testing.T) {
	t.Parallel()

	// Control: a wrong code.
	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	require.Error(t, cc.DisableMFA(context.Background(), 1, "000000", ""), "control: a wrong code must be refused")
	control := readLockoutState(t, cdb, 1)

	// Probe: the correct code, with the anti-replay mark faulted after the match.
	pc, pdb, pfixed := newMFATestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, pc, pfixed)
	putAtThresholdMinusOne(t, pdb, 1)
	good, err := totp.GenerateCode(secret, pfixed)
	require.NoError(t, err)
	base := pc.storage
	pc.storage = &markTOTPStepErrStub{Storage: base, err: errors.New("injected: MarkTOTPStepUsed")}
	require.Error(t, pc.DisableMFA(context.Background(), 1, good, ""))
	pc.storage = base
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "requireReauth/MarkTOTPStepUsed")

	var u models.User
	require.NoError(t, pdb.First(&u, 1).Error)
	assert.True(t, u.MFAEnabled, "the disable never actually succeeded, so MFA must still be enabled")
}

// --- the success direction ---------------------------------------------------

// TestLogin_SuccessStillClearsTheCounter is the half that keeps the fix honest:
// deferring the clear must not have removed it. A delivered login still resets
// everything to zero.
func TestLogin_SuccessStillClearsTheCounter(t *testing.T) {
	t.Parallel()
	c, db, _ := newLockoutTestCore(t, true)
	_ = login(c, "wrong")
	_ = login(c, "wrong")
	require.Equal(t, 2, reloadUser(t, db).FailedLoginAttempts, "setup")

	require.NoError(t, login(c, lockoutTestPassword))
	after := reloadUser(t, db)
	assert.Zero(t, after.FailedLoginAttempts, "a delivered login still clears the counter")
	assert.Nil(t, after.LoginLockedUntil)
	assert.Zero(t, after.LoginLockoutCount)
}

// TestLoginCompletion_IsSingleUse pins the two small rules the type carries, so
// a double-Succeeded (or a Failed after a Succeeded) cannot silently undo the
// other.
func TestLoginCompletion_IsSingleUse(t *testing.T) {
	t.Parallel()
	c, db, _ := newLockoutTestCore(t, true)
	ctx := context.Background()
	_ = login(c, "wrong")
	_ = login(c, "wrong")
	u := reloadUser(t, db)
	require.Equal(t, 2, u.FailedLoginAttempts, "setup")

	lc := c.newLoginCompletion(u)
	lc.Succeeded(ctx)
	assert.Zero(t, reloadUser(t, db).FailedLoginAttempts, "Succeeded clears")

	lc.Failed(ctx) // must be a no-op: the completion is already settled
	assert.Zero(t, reloadUser(t, db).FailedLoginAttempts,
		"a Failed after a Succeeded must not re-count the attempt -- a delivered login is delivered")

	// And the nil receiver is safe, for the setup-token path that passes nil.
	var none *LoginCompletion
	none.Succeeded(ctx)
	none.Failed(ctx)
}

// failCreateSessionStorage and failCreateMFAStepUpGrantStorage are defined in
// consume_first_fails_closed_test.go; markTOTPStepErrStub in
// mfa_login_storage_error_test.go.
