// mfa_totp_recovery_lookup_parity_test.go — #2894 review (MERGE-MASTER,
// blocking 2 of the 8bb479fa review): the TOTP vs recovery-code lookup
// asymmetry.
//
// VerifyMFACredentials and verifyMFAStepUpCode used to try the recovery-code
// lookup after ANY TOTP miss. With ConsumeMFARecoveryCode faulting:
//
//	wrong TOTP code:                     TOTP says no, recovery errs -> "unavailable" (503, uncounted, slot released)
//	correct TOTP code, mark write fails: codeMatched                  -> "invalid code" (401, counted, slot kept)
//
// so the status code answered "was the TOTP code right?". A recovery code can
// never be six digits (normalized length 10, see generateRecoveryCodes), so a
// TOTP-shaped input now gets its verdict from the TOTP path alone, and the two
// cases above cost exactly the same.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
)

// totpRecoveryFaultStub fails ConsumeMFARecoveryCode always, and
// MarkTOTPStepUsed when failMark is set.
type totpRecoveryFaultStub struct {
	corestorage.Storage
	failMark bool
}

func (s *totpRecoveryFaultStub) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if s.failMark {
		return false, errors.New("injected: MarkTOTPStepUsed")
	}
	return s.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

func (s *totpRecoveryFaultStub) ConsumeMFARecoveryCode(context.Context, uint, string, time.Time) (bool, error) {
	return false, errors.New("injected: ConsumeMFARecoveryCode")
}

func TestVerifyMFALogin_TOTPCodeVerdictDoesNotDependOnTheRecoveryLookup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Control: a wrong six-digit code, recovery lookup down.
	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	cch, err := cc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	cc.storage = &totpRecoveryFaultStub{Storage: cc.storage}
	_, _, _, _, cerr := cc.VerifyMFALoginPending(ctx, cch, "000000", "ua", "203.0.113.5")
	require.Error(t, cerr)
	control := readLockoutState(t, cdb, 1)

	// Probe: the correct code, its anti-replay mark AND the recovery lookup down.
	pc, pdb, pfixed := newMFATestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, pc, pfixed)
	putAtThresholdMinusOne(t, pdb, 1)
	pch, err := pc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	good, err := totp.GenerateCode(secret, pfixed)
	require.NoError(t, err)
	pc.storage = &totpRecoveryFaultStub{Storage: pc.storage, failMark: true}
	_, _, _, _, perr := pc.VerifyMFALoginPending(ctx, pch, good, "ua", "203.0.113.5")
	require.Error(t, perr)
	probe := readLockoutState(t, pdb, 1)

	assert.Equal(t, errors.Is(cerr, ErrMFAVerificationUnavailable), errors.Is(perr, ErrMFAVerificationUnavailable),
		"a wrong TOTP code answered %q and a correct one answered %q: 503-vs-401 tells the caller which code was right", cerr, perr)
	assert.NotErrorIs(t, cerr, ErrMFAVerificationUnavailable,
		"the TOTP path reached a conclusive verdict; a recovery-code outage must not turn it into 'unavailable'")
	requireSameLockoutCost(t, control, probe, "VerifyMFALogin/TOTP+recovery lookup")
}

func TestVerifyMFAStepUp_TOTPCodeVerdictDoesNotDependOnTheRecoveryLookup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	cc.storage = &totpRecoveryFaultStub{Storage: cc.storage}
	cerr := cc.VerifyMFAStepUp(ctx, 1, "000000")
	require.Error(t, cerr)
	control := readLockoutState(t, cdb, 1)

	pc, pdb, pfixed := newMFATestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, pc, pfixed)
	putAtThresholdMinusOne(t, pdb, 1)
	good, err := totp.GenerateCode(secret, pfixed)
	require.NoError(t, err)
	pc.storage = &totpRecoveryFaultStub{Storage: pc.storage, failMark: true}
	perr := pc.VerifyMFAStepUp(ctx, 1, good)
	require.Error(t, perr)
	probe := readLockoutState(t, pdb, 1)

	assert.Equal(t, errors.Is(cerr, ErrMFAVerificationUnavailable), errors.Is(perr, ErrMFAVerificationUnavailable),
		"step-up: wrong code answered %q, correct code answered %q", cerr, perr)
	assert.NotErrorIs(t, cerr, ErrMFAVerificationUnavailable)
	requireSameLockoutCost(t, control, probe, "VerifyMFAStepUp/TOTP+recovery lookup")
}

// TestVerifyMFALogin_RecoveryShapedCodeStillUsesTheRecoveryPath keeps the
// shape split honest in the other direction: a recovery code is still
// accepted, and a recovery-shaped code is not sent to the TOTP path (so a TOTP
// secret outage cannot affect it).
func TestVerifyMFALogin_RecoveryShapedCodeStillUsesTheRecoveryPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, fixed := newMFATestCore(t)
	_, codes := activateMFAForTest(t, c, fixed)
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	c.storage = &mfaSecretReadErrStub{Storage: c.storage, err: errors.New("injected: GetMFASecret")}
	sess, _, _, err := c.VerifyMFALogin(ctx, ch, codes[0], "ua", "203.0.113.5")
	require.NoError(t, err, "a recovery code must not depend on the TOTP secret being readable")
	require.NotNil(t, sess)
}
