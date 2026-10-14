// mfa_verify_challenge_storage_error_test.go — the end-to-end half of the
// ConsumeMFAChallenge pre-verdict fix: driving the REAL /auth/mfa/verify
// handler, a genuine storage failure on the challenge consume must leave the
// IP's login-attempt budget untouched (the reservation the handler takes before
// calling core is released) and answer 503, while a stale/guessed challenge
// token must still spend one slot and answer 401.
//
// Deliberately its own file rather than an addition to
// login_identity_fail_closed_test.go (whose helpers it reuses): that file is
// being edited concurrently by PR #2894.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestVerifyMFA_ChallengeConsumeStorageError_DoesNotSpendTheIPAttemptBudget:
// ConsumeMFAChallenge is the first storage call VerifyMFALogin makes, before
// the submitted code is looked at at all. A storage error there must not
// consume one of the IP's login-attempt slots, must not look like a wrong
// credential, and must leave nothing behind in storage.
func TestVerifyMFA_ChallengeConsumeStorageError_DoesNotSpendTheIPAttemptBudget(t *testing.T) {
	h, fs, secret, fixed, db := newIdentityFailClosedTestHandler(t)
	ctx := context.Background()

	ch, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	fs.Arm(&faultstorage.FaultSpec{
		Method: "ConsumeMFAChallenge", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("simulated: challenge store unavailable"),
	})

	w := postVerifyMFA(t, h, ch, code)
	require.True(t, fs.Fired(), "the armed fault must actually have fired on ConsumeMFAChallenge")

	assert.Equal(t, http.StatusServiceUnavailable, w.Code,
		"a storage error before the code was ever checked must be a retryable 503, not a 401 claiming the credential was wrong")

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, errMFAVerificationUnavailable, body["message"],
		"the client must get the fixed retry message, never the underlying storage error")

	// The symptom the fix is for: the handler reserves an attempt slot before
	// calling core, and must release it when core reports that no verdict was
	// reached. A leftover row means a storage blip silently spent one of this
	// IP's slots for a request whose code was never evaluated.
	var attempts int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&attempts).Error)
	assert.Zero(t, attempts,
		"a pre-verdict storage error must leave the IP's login-attempt budget untouched")

	// Nothing else may be left behind either: no session, and the challenge is
	// still unconsumed (the fault fired in front of the real call).
	var sessions int64
	require.NoError(t, db.Model(&models.Session{}).Count(&sessions).Error)
	assert.Zero(t, sessions, "no session may be minted when verification never ran")
}

// TestVerifyMFA_InvalidChallenge_StillSpendsTheIPAttemptBudget is the
// regression guard for the half that must NOT change: a stale or guessed
// challenge token is a confirmed negative result, and it keeps costing the IP
// one slot. Without this, the obvious over-broad fix (treat every
// ConsumeMFAChallenge error as "not evaluated") would hand an attacker
// unlimited free challenge guesses against the per-IP budget.
func TestVerifyMFA_InvalidChallenge_StillSpendsTheIPAttemptBudget(t *testing.T) {
	h, _, secret, fixed, db := newIdentityFailClosedTestHandler(t)

	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	w := postVerifyMFA(t, h, "no-such-challenge-token", code)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"a stale/guessed challenge token must stay a plain 401, indistinguishable from a wrong code")

	var attempts int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&attempts).Error)
	assert.EqualValues(t, 1, attempts,
		"a confirmed negative result must still spend exactly one of the IP's login-attempt slots")
}
