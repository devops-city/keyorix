// login_identity_before_mint_test.go — #2841.
//
// Every login path that writes something USER-SCOPED after minting its session
// used to hand back to the HTTP handler, which then resolved the response
// identity (GetUserIdentity → GetUserRoles + GetUserPermissions) for its body. A
// failure in THAT read was reported to the caller as a failed login while those
// writes stayed: completeLogin revoked the session and nothing else, so
//
//   - the two WebAuthn paths left an ambient MFAStepUpPurposeRestrictedSecretRead
//     MFAStepUpGrant behind, and
//   - the TOTP path left a user-scoped MFAStepupToken behind.
//
// Both satisfy the restricted-secret MFA gate for the rest of the step-up
// window, and both are keyed on the USER, not the session — so they ride into
// some later session the user never completed a second factor for. (The
// remaining two completeLogin callers, Login and ConsumeSetup, write only the
// session, which the existing revoke already covered.)
//
// The fix is ordering, not a second compensation: the read runs before the
// first write. These tests assert the ORDER's observable consequence — that a
// login which reports failure persisted nothing — rather than the order itself,
// because a partial-state bug reports the same error at every layer either way
// and only the persisted rows distinguish the two. The faultops sibling
// (server/faultops/webauthn_login_no_partial_grant_test.go) drives the same
// property through the real REST handler; this file pins it at the core
// boundary, where the ordering actually lives, so a future refactor that moves
// the read back after the mint goes red here even if the HTTP layer is
// restructured.
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// failGetUserRolesStorage fails exactly the read the identity resolution starts
// with. GetUserRoles is chosen (over GetUserPermissions) because it is the one
// the #2841 faultops repro found: op="REST POST /auth/webauthn/login/finish",
// fault=(GetUserRoles, NthCall=1, kind=error).
type failGetUserRolesStorage struct {
	storage.Storage
}

var errInjectedGetUserRoles = errors.New("injected fault: GetUserRoles")

func (s *failGetUserRolesStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	return nil, errInjectedGetUserRoles
}

// countLoginArtifacts returns how many sessions and step-up grants exist.
func countLoginArtifacts(t *testing.T, db *gorm.DB) (sessions, grants, tokens int64) {
	t.Helper()
	require.NoError(t, db.Model(&models.Session{}).Count(&sessions).Error)
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Count(&grants).Error)
	require.NoError(t, db.Model(&models.MFAStepupToken{}).Count(&tokens).Error)
	return sessions, grants, tokens
}

// TestFinishWebAuthnLogin_IdentityReadFailureLeavesNoSessionOrGrant is the
// #2841 regression guard for the second-factor path.
func TestFinishWebAuthnLogin_IdentityReadFailureLeavesNoSessionOrGrant(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)
	// The step-up token is the OTHER post-mint write, and it is only reached
	// when this gate is on — turn it on so the test covers it too.
	c.classificationRestrictedRequiresMFAStepUp = true

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	c.storage = &failGetUserRolesStorage{Storage: c.storage}

	session, user, identity, err := c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLoginIdentityUnavailable,
		"the sentinel stays in the chain; it is distinguished from ErrWebAuthnLoginNotEvaluated by "+
			"that sentinel's absence (the attempt reservation stays counted because the assertion WAS "+
			"evaluated and passed)")
	require.NotErrorIs(t, err, ErrWebAuthnLoginNotEvaluated,
		"the assertion was evaluated and passed, so this must NOT release the per-IP login-attempt slot")
	require.Nil(t, session)
	// #2894: an identity-read failure is post-verdict -- it is answered exactly
	// like a failed credential (not with a 500, #2888), counted toward the
	// lockout, and returns the resolved user so the transport can audit
	// auth.login_error. The property this test is about is unchanged and
	// asserted below: nothing is written.
	require.ErrorIs(t, err, ErrLoginPostVerdict)
	require.NotNil(t, user)
	assert.Equal(t, UserIdentity{}, identity)

	sessions, grants, tokens := countLoginArtifacts(t, db)
	assert.Zero(t, grants, "a login reported as FAILED must leave no MFAStepUpGrant — that grant satisfies "+
		"the restricted-secret MFA gate for the rest of the step-up window, on a later session the user "+
		"never proved a second factor for (#2841)")
	assert.Zero(t, sessions, "a login reported as FAILED must leave no session")
	assert.Zero(t, tokens, "a login reported as FAILED must leave no MFA step-up token")
}

// failGetUserPermissionsStorage fails the OTHER half of the identity read.
// GetUserIdentity reads roles, then permissions; a fault on either one must
// leave the same nothing-written state, and each is pinned separately in
// server/faultops' oracleAByDesignErrors.
type failGetUserPermissionsStorage struct {
	storage.Storage
}

func (s *failGetUserPermissionsStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	return nil, errors.New("injected fault: GetUserPermissions")
}

// TestFinishWebAuthnLogin_PermissionsReadFailureLeavesNoSessionOrGrant is the
// GetUserPermissions sibling of the test above: same sentinels, same
// attempt-stays-counted rule, same nothing-written effect. It is the proving
// test for the GetUserPermissions row in oracleAByDesignErrors (QUEUE-FIX-1;
// the fuzzer found that tuple on #2764's CI, pre-existing on main before #2841).
func TestFinishWebAuthnLogin_PermissionsReadFailureLeavesNoSessionOrGrant(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)
	c.classificationRestrictedRequiresMFAStepUp = true

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	c.storage = &failGetUserPermissionsStorage{Storage: c.storage}

	session, user, identity, err := c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLoginIdentityUnavailable)
	require.ErrorIs(t, err, ErrLoginPostVerdict)
	require.NotErrorIs(t, err, ErrWebAuthnLoginNotEvaluated,
		"the assertion was evaluated and passed, so this must NOT release the per-IP login-attempt slot")
	require.Nil(t, session)
	require.NotNil(t, user, "post-verdict: the user comes back so the transport can audit auth.login_error (#2894)")
	assert.Equal(t, UserIdentity{}, identity)

	sessions, grants, tokens := countLoginArtifacts(t, db)
	assert.Zero(t, grants, "a login reported as FAILED must leave no MFAStepUpGrant (#2841)")
	assert.Zero(t, sessions, "a login reported as FAILED must leave no session")
	assert.Zero(t, tokens, "a login reported as FAILED must leave no MFA step-up token")
}

// TestFinishWebAuthnPasswordlessLogin_IdentityReadFailureLeavesNoSessionOrGrant
// mirrors the above for the passwordless path, which has the identical
// mint-session-then-mint-grant tail.
func TestFinishWebAuthnPasswordlessLogin_IdentityReadFailureLeavesNoSessionOrGrant(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)
	c.classificationRestrictedRequiresMFAStepUp = true

	parsed, challenge := specLoginAssertion(t)
	parsed.Response.UserHandle = specWebAuthnID(1)
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", &webauthn.SessionData{Challenge: challenge})
	require.NoError(t, err)

	c.storage = &failGetUserRolesStorage{Storage: c.storage}

	session, user, identity, err := c.FinishWebAuthnPasswordlessLogin(ctx, token, "test-agent", "203.0.113.5", parsed)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLoginIdentityUnavailable)
	require.Nil(t, session)
	// #2894: an identity-read failure is post-verdict -- it is answered exactly
	// like a failed credential (not with a 500, #2888), counted toward the
	// lockout, and returns the resolved user so the transport can audit
	// auth.login_error. The property this test is about is unchanged and
	// asserted below: nothing is written.
	require.ErrorIs(t, err, ErrLoginPostVerdict)
	require.NotNil(t, user)
	assert.Equal(t, UserIdentity{}, identity)

	sessions, grants, tokens := countLoginArtifacts(t, db)
	assert.Zero(t, grants, "a passwordless login reported as FAILED must leave no MFAStepUpGrant (#2841)")
	assert.Zero(t, sessions, "a passwordless login reported as FAILED must leave no session")
	assert.Zero(t, tokens, "a passwordless login reported as FAILED must leave no MFA step-up token")
}

// TestVerifyMFALogin_IdentityReadFailureLeavesNoSessionOrStepUpToken is the
// TOTP sibling (#2841).
//
// This path mints no MFAStepUpGrant — it writes the user-scoped
// MFAStepupToken instead, which HasActiveMFAStepup reads per-USER, not per
// session. So the same window existed in the same shape: completeLogin revoked
// the session its identity read had failed after, and left the step-up token,
// keeping the restricted-secret MFA gate satisfied for the rest of the window
// on a later session the user never completed a second factor for.
//
// Checked here rather than assumed: the sibling was found by asking what ELSE
// each completeLogin caller writes after minting (the remaining two — Login and
// ConsumeSetup — write only the session, which completeLogin's revoke already
// covered, so they need no change).
func TestVerifyMFALogin_IdentityReadFailureLeavesNoSessionOrStepUpToken(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	// The step-up token is only written when this gate is on.
	c.classificationRestrictedRequiresMFAStepUp = true

	_, secret, err := c.BeginMFAEnrollment(ctx, 1)
	require.NoError(t, err)
	// Activate on the PREVIOUS time step so step T (fixed) stays unburned for
	// the login below — TOTP codes are single-use.
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = c.ActivateMFA(ctx, 1, actCode, mfaTestPassword, "")
	require.NoError(t, err)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	// Swapped in only now, so enrolment/activation (which also read roles) are
	// unaffected and the fault lands on the login's own identity read.
	base := c.storage
	c.storage = &failGetUserRolesStorage{Storage: base}

	session, user, identity, err := c.VerifyMFALogin(ctx, ch, code, "ua", "1.2.3.4")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLoginIdentityUnavailable)
	require.NotErrorIs(t, err, ErrMFAVerificationStorageFailure,
		"the code was verified and passed, so this must NOT release the per-IP login-attempt slot")
	require.Nil(t, session)
	// #2894: an identity-read failure is post-verdict -- it is answered exactly
	// like a failed credential (not with a 500, #2888), counted toward the
	// lockout, and returns the resolved user so the transport can audit
	// auth.login_error. The property this test is about is unchanged and
	// asserted below: nothing is written.
	require.ErrorIs(t, err, ErrLoginPostVerdict)
	require.NotNil(t, user)
	assert.Equal(t, UserIdentity{}, identity)

	c.storage = base
	// Asserted on the ROW, not on HasActiveMFAStepup's verdict: that verdict
	// compares expires_at against time.Now(), while this harness's c.now() is a
	// fixed date in the past, so it would answer false whether or not the token
	// was written — a guard that can never fire. The row's presence is the thing
	// the fix actually changes, and it is what satisfies the gate on any clock
	// where the window is still open.
	sessions, grants, tokens := countLoginArtifacts(t, db)
	assert.Zero(t, tokens, "a login reported as FAILED must leave no MFA step-up token — "+
		"HasActiveMFAStepup is keyed on the USER, so that token satisfies the restricted-secret gate "+
		"from any later session, including one the user never completed a second factor for (#2841)")
	assert.Zero(t, sessions, "a login reported as FAILED must leave no session")
	assert.Zero(t, grants, "the TOTP path mints no step-up GRANT; if one appears here, this test's "+
		"premise about which artefacts this path writes has gone stale")
}

// TestFinishWebAuthnLogin_ReturnsAPopulatedIdentityForARoleHolder is the
// calibration companion: it proves the pre-mint read returns the REAL identity,
// not an empty struct the handler would then have to re-read anyway.
//
// Without this, the #2841 fix could be satisfied by returning UserIdentity{}
// unconditionally — which compiles, passes the guards above (nothing is
// written on failure because nothing fails), and silently strips every logged-in
// user's roles and permissions from the login response, breaking the UI's
// nav/route gating. It is the counterpart to the faultops sibling's
// "successful login still mints its step-up grant" check: each stops the fix
// from being made in the wrong direction at a different layer.
func TestFinishWebAuthnLogin_ReturnsAPopulatedIdentityForARoleHolder(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnSpecTestCore(t)
	ctx := context.Background()
	seedSpecCredential(t, c, db, 1)
	seedWebAuthnLoginRole(t, db, 1, "admin", "secrets.read")

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	parsed, challenge := specLoginAssertion(t)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: challenge, UserID: specWebAuthnID(1)})
	require.NoError(t, err)

	_, _, identity, err := c.FinishWebAuthnLogin(ctx, ch, token, "test-agent", "203.0.113.5", parsed)
	require.NoError(t, err)
	assert.Equal(t, "admin", identity.Role)
	assert.Equal(t, []string{"admin"}, identity.Roles)
	assert.Contains(t, identity.Permissions, "secrets.read")
}

// seedWebAuthnLoginRole gives userID a role carrying one permission. The tables
// are already migrated by newWebAuthnSpecTestCore (see its #2841 note).
func seedWebAuthnLoginRole(t *testing.T, db *gorm.DB, userID uint, roleName, permName string) {
	t.Helper()
	role := &models.Role{Name: roleName, Description: "test"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: permName, Description: "test"}
	require.NoError(t, db.Create(perm).Error)
	// Written through role_permissions directly, which is the table
	// GetUserPermissions' join actually reads (the models carry no GORM
	// many2many association for it).
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID}).Error)
}
