package core

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// panicIdentityReadStorage panics in one half of GetUserIdentity's read.
func panicIdentityReadStorage(inner storage.Storage, method string) storage.Storage {
	return hooked(inner, &storeHooks{
		GetUserRoles: func(next storage.Storage, ctx context.Context, userID uint) ([]*models.Role, error) {
			if method == "GetUserRoles" {
				panic("injected panic: GetUserRoles")
			}
			return next.GetUserRoles(ctx, userID)
		},
		GetUserPermissions: func(next storage.Storage, ctx context.Context, userID uint) ([]*storage.Permission, error) {
			if method == "GetUserPermissions" {
				panic("injected panic: GetUserPermissions")
			}
			return next.GetUserPermissions(ctx, userID)
		},
	})
}

// TestLoginIdentityReadPanic_DeniedLikeItsError is #3267 for the two WebAuthn
// login paths, which only internal/core can drive with a verifying assertion
// (the HTTP-level proof for /auth/login and /auth/mfa/verify is
// server/http/handlers' login_lockout_no_oracle_test.go, through
// middleware.Recovery). A panic in the post-verdict identity read must come
// back as the same post-verdict error as the read's error kind (no panic
// escapes, so the transport answers like a failed assertion and audits
// auth.login_error), cost the same lockout as a failed assertion, and leave
// nothing written.
func TestLoginIdentityReadPanic_DeniedLikeItsError(t *testing.T) {
	for _, method := range []string{"GetUserRoles", "GetUserPermissions"} {
		t.Run("FinishWebAuthnLogin/"+method, func(t *testing.T) {
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
			pc.storage = panicIdentityReadStorage(base, method)
			var perr error
			require.NotPanics(t, func() {
				_, _, _, perr = pc.FinishWebAuthnLogin(ctx, pch, ptok, "agent", "203.0.113.5", goodParsed)
			}, "a post-verdict identity-read panic must come back as its error, not reach the Recovery middleware (#3267)")
			pc.storage = base
			require.ErrorIs(t, perr, ErrLoginPostVerdict)
			require.ErrorIs(t, perr, ErrLoginIdentityUnavailable)
			require.NotErrorIs(t, perr, ErrWebAuthnLoginNotEvaluated, "the assertion verified: the slot stays counted")

			requireSameLockoutCost(t, control, readLockoutState(t, pdb, 1), "FinishWebAuthnLogin/"+method+"/panic")
			sessions, grants, tokens := countLoginArtifacts(t, pdb)
			assert.Zero(t, sessions+grants+tokens, "a denied login leaves no session, grant or step-up token")
		})

		t.Run("FinishWebAuthnPasswordlessLogin/"+method, func(t *testing.T) {
			t.Parallel()
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
			pc.storage = panicIdentityReadStorage(base, method)
			var perr error
			require.NotPanics(t, func() {
				_, _, _, perr = pc.FinishWebAuthnPasswordlessLogin(ctx, tok, "agent", "203.0.113.5", parsed)
			}, "a post-verdict identity-read panic must come back as its error (#3267)")
			pc.storage = base
			require.ErrorIs(t, perr, ErrLoginPostVerdict)
			require.ErrorIs(t, perr, ErrLoginIdentityUnavailable)

			// A failed passwordless assertion charges nothing (see
			// TestFinishWebAuthnPasswordlessLogin_PostVerdictFaultCostsTheSameAsAFailedAssertion),
			// so neither may this; and it must not clear the counter either.
			assert.Equal(t, before, readLockoutState(t, pdb, 1))
			sessions, grants, tokens := countLoginArtifacts(t, pdb)
			assert.Zero(t, sessions+grants+tokens, "a denied login leaves no session, grant or step-up token")
		})
	}
}
