package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const webauthnTestPassword = "Secret#Passw0rd!"

// newWebAuthnTestCore builds a core over real SQLite with a configured WebAuthn
// relying party and a fixed clock. Seeds user id 1 = "alice".
func newWebAuthnTestCore(t *testing.T, withRP bool) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{},
		&models.MFAChallenge{}, &models.WebAuthnCredential{}, &models.WebAuthnSession{}, &models.Notification{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{}))
	hash, _ := bcrypt.GenerateFromPassword([]byte(webauthnTestPassword), int(bcryptCost.Load()))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", Email: "a@b.com", EmailFolded: "a@b.com",
		PasswordHash: string(hash), AccountState: "active"}).Error)

	fixed := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
	if withRP {
		rp, err := webauthn.New(&webauthn.Config{
			RPID: "localhost", RPDisplayName: "Keyorix", RPOrigins: []string{"https://localhost"},
		})
		require.NoError(t, err)
		c.SetWebAuthn(rp)
	}
	return c, db
}

// seedCredential inserts a minimal stored passkey for a user and flips the flag.
func seedCredential(t *testing.T, c *KeyorixCore, db *gorm.DB, userID uint, credID string) {
	t.Helper()
	blob, _ := json.Marshal(webauthn.Credential{ID: []byte(credID)})
	require.NoError(t, db.Create(&models.WebAuthnCredential{
		UserID: userID, CredentialID: []byte(credID), Name: "test key", CredentialBlob: blob,
	}).Error)
	require.NoError(t, c.storage.SetUserWebAuthnEnabled(context.Background(), userID, true))
}

// seedStepUpGrant inserts an active MFAStepUpGrant with Purpose ==
// MFAStepUpPurposeReauth for userID, mirroring what FinishWebAuthnReauth's live
// passkey re-assertion (or a fresh TOTP code, for MFA-enabled accounts) would
// produce. Since a WebAuthn-only account has no typable "code" to hand
// requireReauth directly, this is the only way such an account can satisfy
// requireReauth's password-plus-second-factor-proof requirement in a unit test
// that doesn't drive a full FinishWebAuthnReauth ceremony. Deliberately
// distinct from seedAmbientLoginGrant below, which mints the OTHER purpose
// (MFAStepUpPurposeRestrictedSecretRead) that an ordinary login produces —
// this purpose separation is the fix; see TestWebAuthn_DeleteRequiresReauth's
// and TestWebAuthn_FinishRegistrationRequiresReauth's "ambient login grant is
// rejected" cases.
func seedStepUpGrant(t *testing.T, db *gorm.DB, userID uint, now time.Time) {
	t.Helper()
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: userID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: now.Add(15 * time.Minute)}).Error)
}

// seedAmbientLoginGrant inserts an active MFAStepUpGrant with Purpose ==
// MFAStepUpPurposeRestrictedSecretRead for userID — exactly what
// FinishWebAuthnLogin/FinishWebAuthnPasswordlessLogin mint on every ordinary,
// successful login (ambiently, with no explicit re-authentication intent).
// Used to prove this purpose does NOT satisfy requireReauth's
// account-security-factor-change gate (the confused-deputy bug this purpose
// separation closes).
func seedAmbientLoginGrant(t *testing.T, db *gorm.DB, userID uint, now time.Time) {
	t.Helper()
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: userID, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: now.Add(15 * time.Minute)}).Error)
}

func TestWebAuthn_LoginGateRequiresSecondFactor(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	session, u, err := c.Login(ctx, &LoginRequest{Username: "alice", Password: webauthnTestPassword})
	require.ErrorIs(t, err, ErrMFARequired, "a passkey-enabled account must not get a session from the password step")
	assert.Nil(t, session)
	require.NotNil(t, u)
}

func TestWebAuthn_DisabledServerRejects(t *testing.T) {
	t.Parallel()
	c, _ := newWebAuthnTestCore(t, false) // no RP configured
	ctx := context.Background()
	_, _, err := c.BeginWebAuthnRegistration(ctx, 1)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
}

// FinishWebAuthnRegistration and FinishWebAuthnLogin must refuse just as
// early as their Begin counterparts when no relying party is configured --
// neither should reach the requireReauth/challenge-consumption steps below.
func TestWebAuthn_FinishDisabledServerRejects(t *testing.T) {
	t.Parallel()
	c, _ := newWebAuthnTestCore(t, false)
	ctx := context.Background()
	_, err := c.FinishWebAuthnRegistration(ctx, 1, "tok", "laptop", webauthnTestPassword, nil)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
	_, _, _, err = c.FinishWebAuthnLogin(ctx, "ch", "tok", "ua", "1.2.3.4", nil)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
}

// A malformed/unknown webauthn ceremony session token must be rejected before
// any assertion is parsed -- distinct from TestWebAuthn_FinishLoginRejectsMismatchedSession,
// which covers a session that consumes fine but belongs to the wrong purpose/user.
func TestWebAuthn_FinishLoginRejectsInvalidSessionToken(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, _, err = c.FinishWebAuthnLogin(ctx, ch, "not-a-real-session-token", "ua", "1.2.3.4", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webauthn session")
}

func TestWebAuthn_RegistrationBeginIssuesSingleUseSession(t *testing.T) {
	t.Parallel()
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	creation, token, err := c.BeginWebAuthnRegistration(ctx, 1)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, creation.Response.Challenge)

	// The ceremony session is stored hashed and is single-use.
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(token), c.now())
	require.NoError(t, err)
	assert.Equal(t, "register", sess.Purpose)
	_, err = c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(token), c.now())
	require.Error(t, err, "ceremony session is single-use")
}

func TestWebAuthn_BeginLoginResolvesUserFromChallenge(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	// A challenge for a user with no passkeys is rejected.
	chNoKeys, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, err = c.BeginWebAuthnLogin(ctx, chNoKeys)
	require.Error(t, err, "no passkeys registered")

	// With a passkey, begin returns assertion options + a login session token.
	seedCredential(t, c, db, 1, "cred-1")
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	assertion, token, err := c.BeginWebAuthnLogin(ctx, ch)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, assertion.Response.Challenge)
	require.Len(t, assertion.Response.AllowedCredentials, 1, "the user's passkey is in allowCredentials")

	// Begin does NOT consume the challenge (finish does).
	_, err = c.storage.GetActiveMFAChallenge(ctx, sha256Hex(ch), c.now())
	require.NoError(t, err, "the login challenge stays valid until finish")
}

func TestWebAuthn_BeginLoginRejectsBadChallenge(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")
	_, _, err := c.BeginWebAuthnLogin(ctx, "not-a-real-challenge")
	require.Error(t, err)
}

func TestWebAuthn_DeleteClearsFlagOnLastAndIsUserScoped(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	// A different user cannot delete user 1's passkey by id (also fails re-auth:
	// bob has no password set).
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", AccountState: "active"}).Error)
	require.Error(t, c.DeleteWebAuthnCredential(ctx, 2, cred.ID, webauthnTestPassword))

	// The owner deletes their last passkey → WebAuthn disabled. WebAuthn is now
	// enrolled (seedCredential above), so password alone is no longer sufficient
	// re-auth (#372-follow-up) — a WebAuthn-only account proves it still holds the
	// second factor via an active step-up grant (see seedStepUpGrant's doc comment).
	seedStepUpGrant(t, db, 1, c.now())
	require.NoError(t, c.DeleteWebAuthnCredential(ctx, 1, cred.ID, webauthnTestPassword))
	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.False(t, user.WebAuthnEnabled, "removing the last passkey disables WebAuthn")
}

// #372 / #372-follow-up: DeleteWebAuthnCredential must reject the deletion
// without valid re-authentication — otherwise a stolen session/PAT alone can
// wipe every passkey (and, once the last one is gone, silently disable WebAuthn
// account-wide). Since WebAuthn enrollment is active, the account password
// ALONE is no longer sufficient (requireReauth's second-factor requirement): the
// caller must also hold an active MFA step-up grant, proving they recently
// re-verified the second factor (a WebAuthn login mints one automatically, since
// a passkey assertion has no typable "code" to hand this check directly).
// Mirrors TestMFA_RegenerateRequiresReauth's structure.
func TestWebAuthn_DeleteRequiresReauth(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	// Wrong password → rejected, credential untouched.
	err := c.DeleteWebAuthnCredential(ctx, 1, cred.ID, "wrong-password")
	require.Error(t, err, "delete must reject a bad code/password")

	var stillThere models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ? AND id = ?", 1, cred.ID).First(&stillThere).Error,
		"a failed re-auth must not remove the credential")

	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.True(t, user.WebAuthnEnabled, "a failed re-auth must not touch the WebAuthnEnabled flag")

	// The CORRECT password alone is still refused — WebAuthn is enrolled, so
	// password-only re-auth must not satisfy the second-factor requirement.
	err = c.DeleteWebAuthnCredential(ctx, 1, cred.ID, webauthnTestPassword)
	require.Error(t, err, "correct password alone must not satisfy re-auth once a second factor (WebAuthn) is enrolled")

	var stillThere2 models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ? AND id = ?", 1, cred.ID).First(&stillThere2).Error,
		"password-only re-auth must not remove the credential once a second factor is enrolled")

	// Correct password PLUS an active step-up grant (the caller separately proved
	// they still hold the second factor) → succeeds.
	seedStepUpGrant(t, db, 1, c.now())
	require.NoError(t, c.DeleteWebAuthnCredential(ctx, 1, cred.ID, webauthnTestPassword))
}

// Confused-deputy regression (this fix): TestWebAuthn_DeleteRequiresReauth's
// final positive case used to be satisfied by ANY live MFAStepUpGrant,
// including one minted ambiently by an ordinary WebAuthn login
// (FinishWebAuthnLogin/FinishWebAuthnPasswordlessLogin), not one that proves
// the caller actively re-authenticated at the time of THIS sensitive action.
// That let anyone holding a merely-leaked bearer token (plus the password)
// ride the account owner's own earlier login to delete every passkey (and,
// once the last one is gone, silently disable WebAuthn account-wide) with no
// fresh proof of second-factor possession. Must fail RED against the
// pre-purpose-tagging code (where any grant satisfied HasActiveMFAStepUp) and
// GREEN after it (only a MFAStepUpPurposeReauth grant satisfies it).
func TestWebAuthn_DeleteRequiresReauth_AmbientLoginGrantRejected(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	var cred models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&cred).Error)

	// Exactly what a recent, successful WebAuthn login mints — NOT an explicit
	// re-authentication performed at the time of this delete.
	seedAmbientLoginGrant(t, db, 1, c.now())
	err := c.DeleteWebAuthnCredential(ctx, 1, cred.ID, webauthnTestPassword)
	require.Error(t, err, "a restricted-secret-read-purpose grant (from an ordinary login) must NOT satisfy DeleteWebAuthnCredential's re-auth gate")
	assert.Contains(t, err.Error(), "invalid code or password")

	var stillThere models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ? AND id = ?", 1, cred.ID).First(&stillThere).Error,
		"a refused re-auth must not remove the credential")
	var user models.User
	require.NoError(t, db.First(&user, 1).Error)
	assert.True(t, user.WebAuthnEnabled, "a refused re-auth must not touch the WebAuthnEnabled flag")
}

// #372: FinishWebAuthnRegistration must reject completion of the ceremony without
// a valid current TOTP code or the account password — otherwise a stolen session/
// PAT alone can register an attacker-controlled passkey. The re-auth gate fires
// before the (single-use) registration session is consumed or any attestation is
// parsed, so this is provable without constructing a real WebAuthn attestation:
// a bad password is rejected with the re-auth error, and a correct password
// advances past the gate to the ceremony-session check (a different error).
func TestWebAuthn_FinishRegistrationRequiresReauth(t *testing.T) {
	t.Parallel()
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	_, sessionToken, err := c.BeginWebAuthnRegistration(ctx, 1)
	require.NoError(t, err)

	// Wrong password is rejected by the re-auth gate itself, before the session is
	// consumed (confirmed below: the session is still single-use-valid afterwards).
	_, err = c.FinishWebAuthnRegistration(ctx, 1, sessionToken, "laptop", "wrong-password", nil)
	require.Error(t, err, "finish must reject a bad code/password")
	assert.Contains(t, err.Error(), "invalid code or password")

	// The registration session was NOT consumed by the failed re-auth attempt: it
	// is still there, single-use, to be consumed by a subsequent attempt. Directly
	// consuming it here (bypassing FinishWebAuthnRegistration) proves it — a prior
	// consume would make this fail.
	_, err = c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	require.NoError(t, err, "a failed re-auth must not consume the single-use ceremony session")

	// Start a fresh ceremony (the previous session was just consumed above) and
	// confirm a correct password advances PAST the re-auth gate: the next failure
	// is the ceremony/attestation step, not re-auth (proving the gate opened for a
	// valid password; completing the ceremony itself needs a real attestation
	// blob, out of scope for this regression test).
	_, sessionToken2, err := c.BeginWebAuthnRegistration(ctx, 1)
	require.NoError(t, err)
	_, err = c.FinishWebAuthnRegistration(ctx, 1, sessionToken2, "laptop", webauthnTestPassword, &protocol.ParsedCredentialCreationData{})
	require.Error(t, err, "an empty attestation still fails, just not on re-auth")
	assert.NotContains(t, err.Error(), "invalid code or password")
}

func TestWebAuthn_PasswordlessBeginIssuesSession(t *testing.T) {
	t.Parallel()
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()

	assertion, token, err := c.BeginWebAuthnPasswordlessLogin(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, assertion.Response.Challenge)
	// Usernameless: no specific credential is pre-listed (the authenticator picks).
	assert.Empty(t, assertion.Response.AllowedCredentials)
	// User verification is required so the single gesture is MFA-grade.
	assert.Equal(t, protocol.VerificationRequired, assertion.Response.UserVerification)

	// The ceremony session is stored single-use with the passwordless purpose.
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(token), c.now())
	require.NoError(t, err)
	assert.Equal(t, "passwordless", sess.Purpose)
}

func TestWebAuthn_PasswordlessDisabledServerRejects(t *testing.T) {
	t.Parallel()
	c, _ := newWebAuthnTestCore(t, false)
	ctx := context.Background()
	_, _, err := c.BeginWebAuthnPasswordlessLogin(ctx)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
	_, _, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, "tok", "ua", "1.2.3.4", nil)
	require.ErrorIs(t, err, ErrWebAuthnDisabled)
}

func TestWebAuthn_PasswordlessFinishRejectsWrongPurposeSession(t *testing.T) {
	t.Parallel()
	c, _ := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	// A session minted for the second-factor flow must not complete a passwordless
	// login (purpose check runs before any assertion validation).
	sd := &webauthn.SessionData{Challenge: "x"}
	tok, err := c.storeWebAuthnSession(ctx, 1, "login", sd)
	require.NoError(t, err)
	_, _, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, tok, "ua", "1.2.3.4", nil)
	require.Error(t, err)

	// An unknown/expired session token is rejected too.
	_, _, _, err = c.FinishWebAuthnPasswordlessLogin(ctx, "nope", "ua", "1.2.3.4", nil)
	require.Error(t, err)
}

// A suspended account must not complete WebAuthn second-factor login. The gate fires
// after the user is loaded but before the assertion is validated, so a suspended
// account is refused even with an otherwise-valid ceremony (nil assertion is never
// reached). Mirrors the passwordless path's existing AccountLoginBlocked gate.
func TestWebAuthn_FinishLoginRejectsSuspendedAccount(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: "x"})
	require.NoError(t, err)

	// Admin suspends the account after the ceremony began (challenge + session exist).
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("account_state", AccountSuspended).Error)

	_, _, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "ua", "1.2.3.4", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

// A per-account lockout (e.g. from password brute force) also bars the WebAuthn second
// factor: the gate fires before the assertion is validated, so a locked account is
// refused even with an otherwise-valid ceremony. Parity with the TOTP path.
func TestWebAuthn_FinishLoginHonorsAccountLockout(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	// The account is locked (e.g. via the password path).
	until := c.now().Add(30 * time.Minute)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("login_locked_until", until).Error)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	token, err := c.storeWebAuthnSession(ctx, 1, "login", &webauthn.SessionData{Challenge: "x"})
	require.NoError(t, err)

	_, _, _, err = c.FinishWebAuthnLogin(ctx, ch, token, "ua", "1.2.3.4", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
}

// Platform authenticators (Touch ID, Windows Hello, and most passkeys) never
// implement a signature counter and always report SignCount 0. persistUpdatedCredential's
// #306 stale-write guard must not treat a (0, 0) comparison as "stale" — that would
// silently stop LastUsedAt/blob from ever persisting again after the very first login
// for the common case, mirroring go-webauthn's own Authenticator.UpdateCounter gate
// (which also special-cases 0/0 as never a clone signal).
func TestWebAuthn_PersistUpdatedCredential_ZeroCounterAuthenticatorAlwaysPersists(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	var before models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&before).Error)
	assert.Nil(t, before.LastUsedAt, "no login yet")

	// Simulate two logins in a row from a zero-counter authenticator.
	for i := range 2 {
		c.now = func() time.Time { return time.Date(2026, 6, 12, 10, i, 0, 0, time.UTC) }
		c.persistUpdatedCredential(ctx, 1, &webauthn.Credential{ID: []byte("cred-1"), Authenticator: webauthn.Authenticator{SignCount: 0}})
	}

	var after models.WebAuthnCredential
	require.NoError(t, db.Where("user_id = ?", 1).First(&after).Error)
	require.NotNil(t, after.LastUsedAt, "LastUsedAt must still update on every login even when SignCount stays 0")
	assert.Equal(t, time.Date(2026, 6, 12, 10, 1, 0, 0, time.UTC), after.LastUsedAt.UTC(),
		"the SECOND login's timestamp must persist too — a (0,0) comparison must not be treated as a stale write")
}

func TestWebAuthn_FinishLoginRejectsMismatchedSession(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	// A webauthn session belonging to a different challenge/user must not pair with
	// this challenge. Create a login challenge for user 1, but a ceremony session
	// for a different user (2) — finish must reject the mismatch before any crypto.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", AccountState: "active"}).Error)
	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sd := &webauthn.SessionData{Challenge: "x"}
	otherToken, err := c.storeWebAuthnSession(ctx, 2, "login", sd)
	require.NoError(t, err)

	_, _, _, err = c.FinishWebAuthnLogin(ctx, ch, otherToken, "ua", "1.2.3.4", nil)
	require.Error(t, err, "a webauthn session for another user must not complete this challenge")
}

// #212: a signature-counter regression (go-webauthn's Authenticator.CloneWarning —
// the standard FIDO2 clone-detection signal) must refuse the authentication and
// disable the credential, not just write a passive audit line while login proceeds.
// This is the actual authentication-time enforcement path both FinishWebAuthnLogin
// and FinishWebAuthnPasswordlessLogin call once the library's cryptographic
// assertion check has already succeeded.
func TestWebAuthn_RejectIfCloned_DisablesCredentialAndRejects(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	cred := &webauthn.Credential{ID: []byte("cred-1"), Authenticator: webauthn.Authenticator{CloneWarning: true}}
	err := c.rejectIfCloned(ctx, 1, cred, "203.0.113.9")
	require.Error(t, err, "a regressed signature counter must refuse the authentication")

	var row models.WebAuthnCredential
	require.NoError(t, db.Where("credential_id = ?", []byte("cred-1")).First(&row).Error)
	assert.True(t, row.Disabled, "the flagged credential must be disabled pending re-registration")

	var events int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventWebAuthnCloneDetected).Count(&events).Error)
	assert.Equal(t, int64(1), events, "the clone must be audited distinctly, not just silently logged")

	// The disabled credential must be excluded from every future ceremony — it can
	// never authenticate again until the owner re-registers a fresh passkey.
	wu, err := c.loadWebAuthnUser(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, wu.creds, "a disabled credential must not be offered for future login ceremonies")
}

// A normal, strictly-incrementing counter must NOT be treated as a clone signal and
// must leave the credential fully usable.
func TestWebAuthn_RejectIfCloned_NormalCounterPasses(t *testing.T) {
	t.Parallel()
	c, db := newWebAuthnTestCore(t, true)
	ctx := context.Background()
	seedCredential(t, c, db, 1, "cred-1")

	cred := &webauthn.Credential{ID: []byte("cred-1"), Authenticator: webauthn.Authenticator{CloneWarning: false, SignCount: 42}}
	err := c.rejectIfCloned(ctx, 1, cred, "203.0.113.9")
	require.NoError(t, err, "a normal incrementing counter must not be rejected")

	var row models.WebAuthnCredential
	require.NoError(t, db.Where("credential_id = ?", []byte("cred-1")).First(&row).Error)
	assert.False(t, row.Disabled, "an un-flagged credential must not be disabled")

	wu, err := c.loadWebAuthnUser(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, wu.creds, 1, "an un-flagged credential remains usable")
}
