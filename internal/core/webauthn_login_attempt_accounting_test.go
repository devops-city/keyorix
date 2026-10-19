package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// failConsumeWebAuthnSessionStorage fails ConsumeWebAuthnSession with a plain
// storage error — deliberately NOT storage.ErrWebAuthnSessionInvalid, which is
// that call's expected negative result and takes a different branch.
func failConsumeWebAuthnSessionStorage(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		ConsumeWebAuthnSession: func(storage.Storage, context.Context, string, time.Time) (*models.WebAuthnSession, error) {
			return nil, errors.New("injected fault: ConsumeWebAuthnSession")
		},
	})
}

// TestFinishWebAuthnLogin_MintFailureAfterAssertion_StillCountsTheLoginAttempt
// is the proving test issue #2880 asks for, for the CreateSession half of its
// pair.
//
// #2880 is an attempt-ACCOUNTING question, not an atomicity one: when a storage
// fault lands AFTER the WebAuthn assertion has been evaluated and passed, does
// the request still consume one of the IP's login-attempt slots? The oracle (a)
// finding that raised it is `op="REST POST /auth/webauthn/login/finish"`,
// `nth=1`, `kind=error`, diff `[LoginAttempt]`, on two methods:
//
//	GetUserRoles  -> 500, diff [LoginAttempt]
//	CreateSession -> 401, diff [LoginAttempt]
//
// The answer is YES, it stays counted, and that is INTENDED (#2880, auth
// owner's decision): a request whose credential was genuinely evaluated is a
// login attempt whatever happened afterwards. Releasing the slot for it would
// let an attacker drive unlimited post-verification failures against an IP
// without ever spending budget — the handler states exactly that rule
// ("An invalid/expired challenge or session, or a failed assertion, stays
// counted", server/http/handlers/webauthn.go).
//
// #2880's own text is explicit that the GetUserRoles row already had a proving
// test and the CreateSession row did NOT — and that citing
// TestFinishWebAuthnLogin_MintFailureAfterConsume_FailsClosed for it would be
// citing a test that does not prove the claim: that test proves fail-closed
// (no session issued, both single-use values stay consumed) and asserts
// nothing whatsoever about attempt accounting. This is the missing half.
//
// WHAT IS ASSERTED, and why that is the whole claim: the handler releases the
// reservation on exactly one condition — errors.Is(err,
// ErrWebAuthnLoginNotEvaluated) — and on no other. So "the slot stays counted"
// is, precisely, "the returned error does not wrap that sentinel". A mutation
// that made mintSession's failure wrap ErrWebAuthnLoginNotEvaluated (the
// plausible wrong fix: treating any storage error on this op as
// not-evaluated) turns this red, and is the exact change that would hand an
// attacker the free-retry budget.
//
// This is deliberately the core-level assertion rather than an end-to-end row
// count: the effect itself is already driven end-to-end by
// FuzzStorageFaultOperations on this very op (that is how the finding was
// found), and only internal/core has a fixture that can produce an assertion
// which actually VERIFIES — the handler package's WebAuthn fixtures use a
// cryptographically meaningless credential that never reaches a passed
// assertion, so a handler-level test could not get past the verdict at all.
func TestFinishWebAuthnLogin_MintFailureAfterAssertion_StillCountsTheLoginAttempt(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	c.storage = failCreateSessionStorage(c.storage)

	session, _, _, err := c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err, "a CreateSession failure must still refuse this login")
	require.Nil(t, session)

	// The single load-bearing assertion. See this test's doc comment: the
	// handler's release branch keys on this sentinel and nothing else, so its
	// ABSENCE is what keeps the attempt counted.
	require.NotErrorIs(t, err, ErrWebAuthnLoginNotEvaluated,
		"the assertion WAS evaluated and passed before mintSession ran, so this error must NOT wrap "+
			"ErrWebAuthnLoginNotEvaluated — that sentinel is the handler's only release condition, and "+
			"releasing here would let an attacker drive unlimited post-verification failures against an "+
			"IP for free (#2880)")
}

// TestFinishWebAuthnLogin_PreVerdictFailureDoesNotCountTheLoginAttempt is this
// file's calibration companion, and the reason the test above is not
// vacuous: the same sentinel assertion must come out the OTHER way when the
// fault lands BEFORE any verdict on the assertion. Without it, a mutation that
// simply stopped wrapping ErrWebAuthnLoginNotEvaluated anywhere at all would
// leave the test above green while silently making every pre-verdict storage
// hiccup count against the IP — the #2565 bug, back again.
//
// ConsumeWebAuthnSession is faulted here (not ConsumeMFAChallenge, whose own
// invalid-challenge branch is a deliberate exception documented at that call
// site): a storage error there has evaluated nothing, so the sentinel must be
// present and the handler must release.
func TestFinishWebAuthnLogin_PreVerdictFailureDoesNotCountTheLoginAttempt(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	c.storage = failConsumeWebAuthnSessionStorage(c.storage)

	_, _, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrWebAuthnLoginNotEvaluated,
		"a storage error consuming the ceremony session reached no verdict on the assertion, so it MUST "+
			"wrap ErrWebAuthnLoginNotEvaluated and the handler MUST release the reservation (#2565)")
}
