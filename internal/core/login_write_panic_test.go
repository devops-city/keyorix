package core

// #3277: a PANIC in a login's post-verdict storage WRITE (the TOTP anti-replay
// mark, the session insert) is denied exactly like the same write's error: no
// panic escapes (so the transport answers like a wrong credential and audits
// it), the lockout costs what a wrong credential costs, and no usable session
// exists. A write may have committed before it panicked, so each case runs
// twice: the panic in place of the call (what FaultyStorage injects) and the
// panic after the real call committed. A committed mark stays burned; a
// committed session row is deleted and its token never returned.
//
// The HTTP-level proof for /auth/login and /auth/mfa/verify is
// server/http/handlers' login_lockout_no_oracle_test.go, through
// middleware.Recovery; this file adds the WebAuthn paths (only this package has
// a verifying assertion fixture) and the after-commit panics.

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// panicLoginWriteStorage panics once in method: in place of the call, or after
// the real call committed (afterCommit).
type panicLoginWriteStorage struct {
	corestorage.Storage
	method      string
	afterCommit bool
	fired       bool
}

func (s *panicLoginWriteStorage) arm(method string) bool {
	if s.method != method || s.fired {
		return false
	}
	s.fired = true
	return true
}

func (s *panicLoginWriteStorage) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if s.arm("MarkTOTPStepUsed") {
		if s.afterCommit {
			_, _ = s.Storage.MarkTOTPStepUsed(ctx, userID, step)
		}
		panic("injected panic: MarkTOTPStepUsed")
	}
	return s.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

func (s *panicLoginWriteStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if s.arm("CreateSession") {
		if s.afterCommit {
			_, _ = s.Storage.CreateSession(ctx, session)
		}
		panic("injected panic: CreateSession")
	}
	return s.Storage.CreateSession(ctx, session)
}

func commitLabel(afterCommit bool) string {
	if afterCommit {
		return "after-commit"
	}
	return "before-commit"
}

// newActivatedMFACore is newMFATestCore with TOTP active for user 1, activated
// on the previous step so the current step's code is fresh for the login.
func newActivatedMFACore(t *testing.T) (*KeyorixCore, *gorm.DB, string, string) {
	t.Helper()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)
	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	return c, db, secret, good
}

func TestLoginWritePanic_DeniedLikeItsError(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		for _, method := range []string{"MarkTOTPStepUsed", "CreateSession"} {
			t.Run("VerifyMFALogin/"+method+"/"+commitLabel(afterCommit), func(t *testing.T) {
				t.Parallel()
				testVerifyMFALoginWritePanic(t, method, afterCommit)
			})
		}
		t.Run("FinishWebAuthnLogin/CreateSession/"+commitLabel(afterCommit), func(t *testing.T) {
			t.Parallel()
			testFinishWebAuthnLoginWritePanic(t, afterCommit)
		})
		t.Run("FinishWebAuthnPasswordlessLogin/CreateSession/"+commitLabel(afterCommit), func(t *testing.T) {
			t.Parallel()
			testFinishWebAuthnPasswordlessLoginWritePanic(t, afterCommit)
		})
	}
}

func testVerifyMFALoginWritePanic(t *testing.T, method string, afterCommit bool) {
	ctx := context.Background()

	// Control: a wrong code at threshold-1.
	cc, cdb, _, _ := newActivatedMFACore(t)
	cc.loginLockout = postVerdictParityPolicy
	putAtThresholdMinusOne(t, cdb, 1)
	cch, err := cc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, _, cerr := cc.VerifyMFALogin(ctx, cch, "000000", "ua", "9.9.9.9")
	require.Error(t, cerr, "control: a wrong code must be refused")
	control := readLockoutState(t, cdb, 1)

	// Probe: the right code at threshold-1, the write panics.
	pc, pdb, _, good := newActivatedMFACore(t)
	pc.loginLockout = postVerdictParityPolicy
	putAtThresholdMinusOne(t, pdb, 1)
	pch, err := pc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	base := pc.storage
	st := &panicLoginWriteStorage{Storage: base, method: method, afterCommit: afterCommit}
	pc.storage = st
	var perr error
	var sess *models.Session
	require.NotPanics(t, func() {
		sess, _, _, perr = pc.VerifyMFALogin(ctx, pch, good, "ua", "9.9.9.9")
	}, "a post-verdict %s panic must come back as its error, not reach the Recovery middleware (#3277)", method)
	pc.storage = base
	require.True(t, st.fired, "the %s panic must have fired", method)
	require.Error(t, perr)
	require.Nil(t, sess, "no session token may be returned")
	require.ErrorIs(t, perr, ErrLoginWritePanicked)
	require.NotErrorIs(t, perr, ErrMFAVerificationUnavailable,
		"the code matched: the transport must keep the slot and answer like a wrong code, not 503")
	if method == "CreateSession" {
		require.ErrorIs(t, perr, ErrLoginPostVerdict, "audited auth.login_error, as the error kind")
	} else {
		require.ErrorIs(t, perr, ErrMFAVerificationStorageFailure, "audited mfa.error, as the error kind")
	}
	requireSameLockoutCost(t, control, readLockoutState(t, pdb, 1), "VerifyMFALogin/"+method+"/panic")
	sessions, grants, tokens := countLoginArtifacts(t, pdb)
	assert.Zero(t, sessions+grants+tokens, "a denied login leaves no session, grant or step-up token")
	if method == "CreateSession" && afterCommit {
		assert.EqualValues(t, 1, auditCount(t, pdb, EventUndeliveredSessionRevoked),
			"the row that committed before the panic must be deleted and audited")
	}

	// Replay, on a core with room under the lockout: the same code on a fresh
	// challenge. Refused whenever the step was marked used (it is never given
	// back after a panic); accepted only when the mark never landed, because
	// then the code was never accepted at all.
	rc, rdb, _, rgood := newActivatedMFACore(t)
	rch, err := rc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	rbase := rc.storage
	rc.storage = &panicLoginWriteStorage{Storage: rbase, method: method, afterCommit: afterCommit}
	require.NotPanics(t, func() { _, _, _, _ = rc.VerifyMFALogin(ctx, rch, rgood, "ua", "9.9.9.9") })
	rc.storage = rbase
	replay, err := rc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	rsess, _, _, rerr := rc.VerifyMFALogin(ctx, replay, rgood, "ua", "9.9.9.9")
	markLanded := method == "CreateSession" || afterCommit
	if markLanded {
		require.Error(t, rerr, "the TOTP step was marked used before the panic: the same code must stay burned")
		assert.Nil(t, rsess)
		sessions, _, _ := countLoginArtifacts(t, rdb)
		assert.Zero(t, sessions, "neither the panicked attempt nor the replay may leave a session")
	} else {
		require.NoError(t, rerr, "calibration: the mark never landed, so the code was never accepted")
		assert.NotNil(t, rsess)
	}
}

func testFinishWebAuthnLoginWritePanic(t *testing.T, afterCommit bool) {
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
	_, _, _, cerr := cc.FinishWebAuthnLogin(ctx, cch, ctok, "agent", "203.0.113.5", badParsed)
	require.Error(t, cerr, "control: a tampered assertion must be refused")
	control := readLockoutState(t, cdb, 1)

	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	pc.classificationRestrictedRequiresMFAStepUp = true
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	goodParsed, challenge2 := specLoginAssertion(t)
	pch, err := pc.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	ptok, err := pc.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge2, UserID: specWebAuthnID(1)})
	require.NoError(t, err)
	base := pc.storage
	st := &panicLoginWriteStorage{Storage: base, method: "CreateSession", afterCommit: afterCommit}
	pc.storage = st
	var perr error
	var sess *models.Session
	require.NotPanics(t, func() {
		sess, _, _, perr = pc.FinishWebAuthnLogin(ctx, pch, ptok, "agent", "203.0.113.5", goodParsed)
	}, "a post-verdict CreateSession panic must come back as its error (#3277)")
	pc.storage = base
	require.True(t, st.fired)
	require.Nil(t, sess)
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	require.ErrorIs(t, perr, ErrLoginWritePanicked)
	require.NotErrorIs(t, perr, ErrWebAuthnLoginNotEvaluated, "the assertion verified: the slot stays counted")

	requireSameLockoutCost(t, control, readLockoutState(t, pdb, 1), "FinishWebAuthnLogin/CreateSession/panic")
	sessions, grants, tokens := countLoginArtifacts(t, pdb)
	assert.Zero(t, sessions+grants+tokens, "a denied login leaves no session, grant or step-up token")
	if afterCommit {
		assert.EqualValues(t, 1, auditCount(t, pdb, EventUndeliveredSessionRevoked))
	}
}

func testFinishWebAuthnPasswordlessLoginWritePanic(t *testing.T, afterCommit bool) {
	ctx := context.Background()
	pc, pdb := newWebAuthnSpecTestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	pc.classificationRestrictedRequiresMFAStepUp = true
	seedSpecCredential(t, pc, pdb, 1)
	putAtThresholdMinusOne(t, pdb, 1)
	before := readLockoutState(t, pdb, 1)
	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(1)
	tok, err := pc.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)
	base := pc.storage
	st := &panicLoginWriteStorage{Storage: base, method: "CreateSession", afterCommit: afterCommit}
	pc.storage = st
	var perr error
	var sess *models.Session
	require.NotPanics(t, func() {
		sess, _, _, perr = pc.FinishWebAuthnPasswordlessLogin(ctx, tok, "agent", "203.0.113.5", parsed)
	}, "a post-verdict CreateSession panic must come back as its error (#3277)")
	pc.storage = base
	require.True(t, st.fired)
	require.Nil(t, sess)
	require.ErrorIs(t, perr, ErrLoginPostVerdict)
	require.ErrorIs(t, perr, ErrLoginWritePanicked)

	// A failed passwordless assertion charges nothing, so neither may this, and
	// it must not clear the counter either.
	assert.Equal(t, before, readLockoutState(t, pdb, 1))
	sessions, grants, tokens := countLoginArtifacts(t, pdb)
	assert.Zero(t, sessions+grants+tokens, "a denied login leaves no session, grant or step-up token")
	if afterCommit {
		assert.EqualValues(t, 1, auditCount(t, pdb, EventUndeliveredSessionRevoked))
	}
}
