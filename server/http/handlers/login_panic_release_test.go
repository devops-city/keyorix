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

// This file guards the two panic-release wrappers that sit between the login
// handlers and core: verifyMFALoginReleasingOnPanic (mfa.go) and
// finishWebAuthnLoginReleasingOnPanic (webauthn.go).
//
// #2841 made both core functions return FOUR values — (session, user,
// identity, err) — because the response identity is now resolved inside core,
// BEFORE the session/grant/step-up-token writes, and handed back rather than
// re-read by the handler. Both wrappers therefore had to grow a fourth result
// and forward it. Two things can silently go wrong in a wrapper like that, and
// neither is visible in a compile:
//
//  1. the identity can be dropped on the floor (returning the zero
//     core.UserIdentity instead of forwarding core's), which strips every
//     user's roles and permissions out of the login response while every
//     status code stays 200; and
//  2. the deferred recover() can swallow the panic instead of re-raising it,
//     turning a harness/storage crash into a (nil, nil, zero, nil) "success"
//     — the handler would then dereference a nil session, or worse, treat a
//     crashed login as a completed one.
//
// Each test below fails if its property is broken, and the doc comment on each
// names the mutation that reproduces the red.
//
// Both wrappers exist (#2619 for WebAuthn, CR3 for MFA) to release the per-IP
// login-attempt reservation when core PANICS rather than returns, so a crash
// does not leave a budget slot orphaned-consumed. The reservation is a real
// LoginAttempt row, so "released" is asserted as a row count, not a mock call.

// errArmedPanicValue is what the fault wrapper panics with. The identity of the
// recovered value is the point: a wrapper that recovered and re-panicked with
// something of its own (or with a wrapped//reformatted value) would change what
// the Recovery middleware logs for a real crash.
var errArmedPanicValue = errors.New("simulated: storage layer panicked mid-login")

// TestVerifyMFA_PanicInsideCore_ReleasesTheSlotAndRePanicsUnchanged is the
// red/green for verifyMFALoginReleasingOnPanic's recover arm.
//
// RED on two independent mutations of that recover:
//   - dropping `panic(rec)` (so the wrapper returns its zero values instead):
//     no panic reaches this test at all, and VerifyMFA goes on to hand a
//     nil-session "success" to completeLoginWithIdentity — the failure-as-
//     success conversion this asserts cannot happen.
//   - dropping the ReleaseLoginAttempt call: the LoginAttempt row survives, so
//     the crash permanently consumed one of the per-IP budget slots.
func TestVerifyMFA_PanicInsideCore_ReleasesTheSlotAndRePanicsUnchanged(t *testing.T) {
	h, fs, secret, fixed, db := newIdentityFailClosedTestHandler(t)
	ctx := context.Background()

	ch, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	// ConsumeMFAChallenge is VerifyMFALogin's first storage call, so the panic
	// lands strictly inside the wrapped call — after the reservation was taken
	// and before any verdict on the code.
	fs.Arm(&faultstorage.FaultSpec{
		Method: "ConsumeMFAChallenge", NthCall: 1, Kind: faultstorage.KindPanic,
		Err: errArmedPanicValue,
	})

	recovered := func() (rec any) {
		defer func() { rec = recover() }()
		postVerifyMFA(t, h, ch, code)
		return nil
	}()

	require.NotNil(t, recovered, "the wrapper must RE-PANIC: swallowing the panic would turn a crashed login into a nil-session success")
	assert.Equal(t, errArmedPanicValue, recovered, "the panic must propagate with its ORIGINAL value, unwrapped and unreplaced")
	assert.True(t, fs.Fired(), "the armed panic must actually have fired on ConsumeMFAChallenge")

	var attempts int64
	require.NoError(t, db.Model(&models.LoginAttempt{}).Count(&attempts).Error)
	assert.Zero(t, attempts, "a panic before any verdict must RELEASE the reserved login-attempt slot, not leave it counted")
}

// TestFinishWebAuthnLogin_PanicInsideCore_ReleasesTheSlotAndRePanicsUnchanged
// is the identical red/green for finishWebAuthnLoginReleasingOnPanic. Same two
// mutations, same two reds — kept as its own test rather than a subtest of the
// MFA one because the two wrappers are separate functions that have already
// drifted apart once (#2619 landed the WebAuthn one; CR3 had to add the MFA
// sibling afterwards).
func TestFinishWebAuthnLogin_PanicInsideCore_ReleasesTheSlotAndRePanicsUnchanged(t *testing.T) {
	// Reuses #2565's fixture (webauthn_finish_storage_error_test.go): it is the
	// one in this package with a real relying party wired, which
	// FinishWebAuthnLogin needs to get past its ErrWebAuthnDisabled guard and
	// reach any storage call at all.
	h, fs, db := setupWebAuthnFinishStorageErrorTest(t)
	challenge, token := seedWebAuthnLoginCeremony(t, h, db)

	// ConsumeMFAChallenge is FinishWebAuthnLogin's first storage call, so the
	// credential only has to PARSE — it never reaches verification.
	fs.Arm(&faultstorage.FaultSpec{
		Method: "ConsumeMFAChallenge", NthCall: 1, Kind: faultstorage.KindPanic,
		Err: errArmedPanicValue,
	})

	recovered := func() (rec any) {
		defer func() { rec = recover() }()
		finishWebAuthnLoginHTTP(t, h, challenge, token)
		return nil
	}()

	require.NotNil(t, recovered, "the wrapper must RE-PANIC: swallowing the panic would turn a crashed login into a nil-session success")
	assert.Equal(t, errArmedPanicValue, recovered, "the panic must propagate with its ORIGINAL value, unwrapped and unreplaced")
	assert.True(t, fs.Fired(), "the armed panic must actually have fired on ConsumeMFAChallenge")
	assert.Zero(t, webauthnFinishLoginAttempts(t, db),
		"a panic before any verdict must RELEASE the reserved login-attempt slot, not leave it counted")
}

// TestVerifyMFA_WrapperForwardsTheIdentityCoreResolved is the red/green for the
// wrapper's fourth RESULT, as opposed to its recover arm. #2841 moved the
// identity read inside core so nothing fallible runs after the session and the
// user-scoped step-up token are written; the handler must then USE what core
// returned rather than re-read it (a re-read would reopen the exact window the
// fix closed) — which makes the wrapper the single place the value can be lost.
//
// RED on either mutation:
//   - the wrapper returning `core.UserIdentity{}` instead of forwarding core's
//     identity (the shape a mechanical "just add a fourth return" would
//     produce), or
//   - the handler calling core.VerifyMFALogin a SECOND time next to the
//     wrapper and using that call's identity — the two concatenated call sites
//     the rebase left behind. The second call consumes an already-consumed
//     challenge, so it cannot resolve an identity at all and the roles land
//     empty.
//
// Both reds show up here as a 200 with no roles and no permissions, which is
// why this asserts the CONTENT of the login response rather than its status.
func TestVerifyMFA_WrapperForwardsTheIdentityCoreResolved(t *testing.T) {
	h, _, secret, fixed, db := newIdentityFailClosedTestHandler(t)
	ctx := context.Background()

	// Give alice a real role with a real permission, so a dropped identity is
	// distinguishable from a genuinely role-less user.
	require.NoError(t, db.Create(&models.Role{ID: 7, Name: "auditor", NameFolded: "auditor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 11, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 7, PermissionID: 11}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 7}).Error)

	ch, err := h.coreService.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	w := postVerifyMFA(t, h, ch, code)
	require.Equal(t, http.StatusOK, w.Code, "a correct code with no fault armed must verify")

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	data, _ := body["data"].(map[string]any)
	require.NotNil(t, data, "expected a data envelope in the success response")

	assert.Equal(t, "auditor", data["role"], "the primary role core resolved must reach the response")
	assert.Equal(t, []any{"auditor"}, data["roles"], "the roles core resolved must reach the response, not an empty slice")
	assert.Equal(t, []any{"secrets.read"}, data["permissions"], "the permissions core resolved must reach the response, not an empty slice")
}
