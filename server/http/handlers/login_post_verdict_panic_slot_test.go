package handlers

import (
	"context"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3048: the panic-release wrappers (verifyMFALoginReleasingOnPanic,
// finishWebAuthnLoginReleasingOnPanic) exist so a panic BEFORE any verdict on
// the credential does not spend the IP's login-attempt slot (#2565, CR3). They
// used to release on ANY panic. A panic AFTER the code or assertion had been
// evaluated therefore handed the slot back, while the same fault as a returned
// error keeps it counted (#2880, #2894). For a correct credential that makes a
// faulted request cheaper than a wrong guess.
//
// Each test drives one storage panic on each side of the verdict and asserts
// the slot as a real LoginAttempt row count:
//   - post-verdict (the code matched / the assertion verified, then a storage
//     call panicked): the slot stays counted;
//   - pre-verdict (the calibration: the panic landed before the credential was
//     evaluated): the slot is released, as before.
// The panic must still reach the caller unchanged either way.

// recoverPanic runs f and returns what it panicked with, or nil.
func recoverPanic(f func()) (rec interface{}) {
	defer func() { rec = recover() }()
	f()
	return nil
}

func loginAttemptRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&n).Error)
	return n
}

func TestVerifyMFA_PanicKeepsTheSlotOnlyAfterTheVerdict(t *testing.T) {
	for _, c := range []struct {
		method      string
		postVerdict bool
	}{
		// Pre-verdict: the challenge, the user and the TOTP secret are read
		// before the submitted code is compared.
		{"ConsumeMFAChallenge", false},
		{"GetUser", false},
		{"GetMFASecret", false},
		// Post-verdict: the code has matched. MarkTOTPStepUsed is the
		// anti-replay write right after the match; the identity reads and the
		// session mint follow it.
		{"MarkTOTPStepUsed", true},
		{"GetUserRoles", true},
		{"GetUserPermissions", true},
		{"CreateSession", true},
	} {
		c := c
		t.Run(c.method, func(t *testing.T) {
			h, fs, secret, fixed, db := newIdentityFailClosedTestHandler(t)
			ch, err := h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			code, err := totp.GenerateCode(secret, fixed)
			require.NoError(t, err)
			fs.Arm(&faultstorage.FaultSpec{Method: c.method, NthCall: 1, Kind: faultstorage.KindPanic, Err: errArmedPanicValue})

			rec := recoverPanic(func() { postVerifyMFA(t, h, ch, code) })

			require.True(t, fs.Fired(), "the armed %s panic must have fired", c.method)
			assert.Equal(t, errArmedPanicValue, rec, "the panic must reach the caller with its ORIGINAL value")
			if c.postVerdict {
				assert.EqualValues(t, 1, loginAttemptRows(t, db),
					"%s panicked AFTER the code matched: the slot must stay counted, exactly as the same fault "+
						"returned as an error does (#3048, #2880)", c.method)
			} else {
				assert.Zero(t, loginAttemptRows(t, db),
					"%s panicked BEFORE the code was evaluated: the slot must be released (#2565, CR3)", c.method)
			}
		})
	}
}

func TestFinishWebAuthnLogin_PanicKeepsTheSlotOnlyAfterTheVerdict(t *testing.T) {
	for _, c := range []struct {
		method      string
		postVerdict bool
	}{
		// Pre-verdict: the challenge and ceremony are consumed and the user and
		// credentials loaded before ValidateLogin evaluates the assertion.
		{"ConsumeMFAChallenge", false},
		{"ConsumeWebAuthnSession", false},
		{"ListWebAuthnCredentials", false},
		// Post-verdict: the assertion verified.
		{"GetUserRoles", true},
		{"GetUserPermissions", true},
		{"CreateSession", true},
	} {
		c := c
		t.Run(c.method, func(t *testing.T) {
			h, fs, db := newWebAuthnCompletionEnv(t)
			ch, err := h.coreService.CreateMFAChallenge(context.Background(), 1)
			require.NoError(t, err)
			cred, challenge := wcAssertionJSON(t, false)
			token := wcSeedCeremony(t, db, challenge, 1, "login")
			fs.Arm(&faultstorage.FaultSpec{Method: c.method, NthCall: 1, Kind: faultstorage.KindPanic, Err: errArmedPanicValue})

			rec := recoverPanic(func() { postFinishWebAuthnLogin(t, h, ch, token, cred) })

			require.True(t, fs.Fired(), "the armed %s panic must have fired", c.method)
			assert.Equal(t, errArmedPanicValue, rec, "the panic must reach the caller with its ORIGINAL value")
			if c.postVerdict {
				assert.EqualValues(t, 1, loginAttemptRows(t, db),
					"%s panicked AFTER the assertion verified: the slot must stay counted, exactly as the same "+
						"fault returned as an error does (#3048, #2880)", c.method)
			} else {
				assert.Zero(t, loginAttemptRows(t, db),
					"%s panicked BEFORE the assertion was evaluated: the slot must be released (#2565)", c.method)
			}
		})
	}
}

// TestFinishWebAuthnLogin_PanicFixtureVerifiesWithoutAFault is the premise
// for the post-verdict cases above: with nothing armed, this fixture's
// assertion really verifies and the login is delivered. Without that, a
// "post-verdict" fault could be landing on a request that never passed
// ValidateLogin at all.
func TestFinishWebAuthnLogin_PanicFixtureVerifiesWithoutAFault(t *testing.T) {
	h, _, db := newWebAuthnCompletionEnv(t)
	ch, err := h.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	cred, challenge := wcAssertionJSON(t, false)
	token := wcSeedCeremony(t, db, challenge, 1, "login")
	w := postFinishWebAuthnLogin(t, h, ch, token, cred)
	require.Equal(t, 200, w.Code, "premise: the spec-vector assertion must verify: %s", w.Body.String())
	assert.Zero(t, loginAttemptRows(t, db), "a delivered login keeps no slot (#2936)")
}

// TestLoginPanic_AfterAWrongCredentialKeepsTheSlot covers the other kind of
// verdict: the credential was evaluated and found WRONG, then the storage call
// that records the failure panicked (recordFailedLogin's LockUserForUpdate).
// That request is a failed attempt and keeps its slot. The calibration is the
// same call panicking with nothing evaluated (no fault until the wrong
// credential is processed), so it covers both of core's markers:
// VerifyMFACredentials' after-evaluation mark and FinishWebAuthnLoginPending's
// post-ValidateLogin mark.
func TestLoginPanic_AfterAWrongCredentialKeepsTheSlot(t *testing.T) {
	t.Run("mfa/verify wrong code", func(t *testing.T) {
		env := newLockoutOracleEnvWithMFA(t)
		ch, err := env.h.coreService.CreateMFAChallenge(context.Background(), 1)
		require.NoError(t, err)
		env.fs.Arm(&faultstorage.FaultSpec{Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindPanic, Err: errArmedPanicValue})
		rec := recoverPanic(func() { env.postVerify(t, ch, "000000") })
		require.True(t, env.fs.Fired(), "the wrong code must reach recordFailedLogin")
		assert.Equal(t, errArmedPanicValue, rec)
		assert.EqualValues(t, 1, budgetSlots(t, env.db),
			"a wrong code was evaluated before the panic: the failed attempt keeps its slot (#3048)")
	})
	t.Run("webauthn/login/finish failed assertion", func(t *testing.T) {
		h, fs, db := newWebAuthnCompletionEnv(t)
		ch, err := h.coreService.CreateMFAChallenge(context.Background(), 1)
		require.NoError(t, err)
		cred, challenge := wcAssertionJSON(t, true)
		token := wcSeedCeremony(t, db, challenge, 1, "login")
		fs.Arm(&faultstorage.FaultSpec{Method: "LockUserForUpdate", NthCall: 1, Kind: faultstorage.KindPanic, Err: errArmedPanicValue})
		rec := recoverPanic(func() { postFinishWebAuthnLogin(t, h, ch, token, cred) })
		require.True(t, fs.Fired(), "the failed assertion must reach recordFailedLogin")
		assert.Equal(t, errArmedPanicValue, rec)
		assert.EqualValues(t, 1, loginAttemptRows(t, db),
			"a failed assertion was evaluated before the panic: the failed attempt keeps its slot (#3048)")
	})
}
