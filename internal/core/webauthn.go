// webauthn.go — WebAuthn / passkeys (ADR-036): a phishing-resistant second
// factor. Self-service registration of FIDO2 authenticators, and a two-step login
// where a WebAuthn assertion (instead of, or in addition to, TOTP) completes the
// pre-auth challenge minted by the password step. The in-flight ceremony state
// (challenge etc.) is persisted single-use and hashed at rest, like MFAChallenge.
package core

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrWebAuthnDisabled is returned when a WebAuthn operation is attempted but the
// server has no relying party configured (no webauthn block in the config).
var ErrWebAuthnDisabled = errors.New("webauthn is not enabled on this server")

// ErrWebAuthnLoginNotEvaluated is wrapped by FinishWebAuthnLogin when a storage
// lookup the assertion check depends on fails before any verdict is reached:
// consuming the login challenge or the ceremony session (other than the
// expected storage.ErrMFAChallengeInvalid / storage.ErrWebAuthnSessionInvalid
// negatives), or loading the user and their passkeys. The login is still
// denied, but no credential was evaluated, so the HTTP handler releases the
// per-IP login-attempt slot it reserved instead of counting the request as a
// failed attempt, and the per-account lockout counter is never touched (#2565,
// same class as ErrMFAVerificationStorageFailure on /auth/mfa/verify).
var ErrWebAuthnLoginNotEvaluated = errors.New("webauthn login not evaluated: storage lookup failed")

// ErrLoginIdentityUnavailable means the login's assertion VERIFIED, but the
// response identity (roles + permissions, GetUserIdentity) could not be
// resolved — so the login is refused with nothing written (#2841).
//
// It is deliberately NOT ErrWebAuthnLoginNotEvaluated: the assertion WAS
// evaluated and passed, so the per-IP login-attempt reservation must stay
// counted exactly as it did before this sentinel existed, and the per-account
// lockout counters have already been cleared by the successful verification.
// The handler maps it to the same 500 "Login could not be completed. Please try
// again." a post-mint identity failure produced before, so the caller-visible
// behaviour is unchanged — only the ORDER changed, and with it what survives.
var ErrLoginIdentityUnavailable = errors.New("login identity unavailable: could not resolve roles/permissions")

// resolveLoginIdentityBeforeMint reads the response identity BEFORE a login
// writes anything (#2841).
//
// Both WebAuthn login paths used to mint the session, then an ambient
// MFAStepUpGrant, and only afterwards hand back to the HTTP handler, which
// resolved the identity for its response body. A failure in THAT read was
// reported to the caller as a failed login while both writes stayed:
// completeLogin (server/http/handlers/auth.go) revoked the session, but nothing
// revoked the grant. An MFAStepUpPurposeRestrictedSecretRead grant therefore
// outlived a login the caller was told had failed, satisfying the
// restricted-secret MFA gate for the rest of the step-up window on some later
// session the user never proved a second factor for.
//
// Found by FuzzStorageFaultOperations (op="REST POST /auth/webauthn/login/finish",
// fault=(GetUserRoles, NthCall=1, kind=error)); filed as #2841.
//
// Doing the read here, before the writes, closes the window by CONSTRUCTION
// rather than by compensating after the fact — nothing fallible-and-reported
// runs after the session and grant are written, so there is no partial state to
// undo. (The remaining post-mint writes — UpsertMFAStepupToken, the grant
// itself, the audit event — are all explicitly best-effort, errors discarded,
// and cannot make the login report failure.) The caller is expected to return
// this identity so the handler does not re-read it; re-reading would reopen the
// same window one layer up.
func (c *KeyorixCore) resolveLoginIdentityBeforeMint(ctx context.Context, userID uint) (UserIdentity, error) {
	identity, err := c.GetUserIdentity(ctx, userID)
	if err != nil {
		return UserIdentity{}, fmt.Errorf("%w: user %d: %w", ErrLoginIdentityUnavailable, userID, err)
	}
	return identity, nil
}

const webauthnSessionTTL = 5 * time.Minute

// EventWebAuthnCloneDetected is the loud, authentication-rejecting audit event
// fired when go-webauthn's signature-counter clone-detection signal
// (Authenticator.CloneWarning) fires (#212). The library itself already excludes
// the one legitimate always-zero-counter case (see its UpdateCounter: both the
// stored and asserted counts must be zero for the warning to be waived), so any
// warning reaching here is a genuine regression, not a benign authenticator that
// never implemented a counter.
const EventWebAuthnCloneDetected = "webauthn.clone_detected" // #nosec G101 -- audit event type, not a credential

// NotificationWebAuthnCloneDetected is the in-app/email notification type sent to
// the affected account owner alongside EventWebAuthnCloneDetected.
const NotificationWebAuthnCloneDetected = EventWebAuthnCloneDetected

// webauthnUser adapts a Keyorix user + its stored credentials to the
// webauthn.User interface the library expects.
type webauthnUser struct {
	user  *models.User
	creds []webauthn.Credential
}

// WebAuthnID is the stable user handle (8-byte big-endian user ID). It must not
// contain PII (it is stored on the authenticator), so we use the opaque ID.
func (u *webauthnUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.user.ID))
	return b
}
func (u *webauthnUser) WebAuthnName() string                       { return u.user.Username }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (c *KeyorixCore) loadWebAuthnUser(ctx context.Context, userID uint) (*webauthnUser, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	rows, err := c.storage.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, r := range rows {
		if r.Disabled {
			// Flagged by clone-detection (#212, signature-counter regression) —
			// excluded from every ceremony (login candidate set AND registration
			// exclusion list) until the owner deletes it and registers a fresh
			// passkey using the genuine physical authenticator.
			continue
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(r.CredentialBlob, &cred); err != nil {
			continue // skip an unreadable row rather than fail the whole ceremony
		}
		creds = append(creds, cred)
	}
	return &webauthnUser{user: user, creds: creds}, nil
}

// storeWebAuthnSession persists the ceremony SessionData under the hash of an
// opaque token (returned to the caller), single-use and short-lived.
func (c *KeyorixCore) storeWebAuthnSession(ctx context.Context, userID uint, purpose string, sd *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	token, err := generateSecureToken()
	if err != nil {
		return "", err
	}
	if err := c.storage.CreateWebAuthnSession(ctx, &models.WebAuthnSession{
		UserID:    userID,
		TokenHash: sha256Hex(token),
		Purpose:   purpose,
		Data:      data,
		ExpiresAt: c.now().Add(webauthnSessionTTL),
		CreatedAt: c.now(),
	}); err != nil {
		return "", err
	}
	return token, nil
}

// BeginWebAuthnRegistration starts enrolment of a new passkey for the caller. It
// returns the CredentialCreation options (for navigator.credentials.create) and
// an opaque session token to echo back at FinishWebAuthnRegistration.
func (c *KeyorixCore) BeginWebAuthnRegistration(ctx context.Context, userID uint) (*protocol.CredentialCreation, string, error) {
	if c.webauthnRP == nil {
		return nil, "", ErrWebAuthnDisabled
	}
	wu, err := c.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	// Exclude already-registered authenticators so the user can't double-register one.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for i := range wu.creds {
		exclusions = append(exclusions, wu.creds[i].Descriptor())
	}
	// Request a discoverable (resident) credential so the passkey can also be used
	// for passwordless login (ADR-036 addendum). "preferred" is backward-compatible:
	// authenticators that can't store a resident key still register for the
	// second-factor flow.
	creation, sd, err := c.webauthnRP.BeginRegistration(wu,
		webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin registration: %w", err)
	}
	token, err := c.storeWebAuthnSession(ctx, userID, "register", sd)
	if err != nil {
		return nil, "", err
	}
	return creation, token, nil
}

// FinishWebAuthnRegistration verifies the attestation, stores the credential, and
// enables WebAuthn for the user. name is a user-supplied label for the passkey.
// codeOrPassword re-authenticates the caller (#372): a current TOTP code (if MFA
// is already enabled) or the account password, same re-auth as DisableMFA. This
// is the step that actually adds a new, attacker-controllable trust factor to the
// account, so — unlike BeginWebAuthnRegistration, which only opens a ceremony with
// no effect on stored credentials — it must not be reachable by a bearer token
// alone (a stolen session or a scoped, MFA-policy-exempt PAT per ADR-042).
func (c *KeyorixCore) FinishWebAuthnRegistration(ctx context.Context, userID uint, sessionToken, name, codeOrPassword string, parsed *protocol.ParsedCredentialCreationData) (*models.WebAuthnCredential, error) {
	if c.webauthnRP == nil {
		return nil, ErrWebAuthnDisabled
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if err := c.requireReauth(ctx, user, codeOrPassword, "webauthn_register"); err != nil {
		return nil, err
	}
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	if err != nil {
		return nil, fmt.Errorf("invalid or expired registration session")
	}
	if sess.Purpose != "register" || sess.UserID != userID {
		return nil, fmt.Errorf("registration session mismatch")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &sd); err != nil {
		return nil, err
	}
	wu, err := c.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	cred, err := c.webauthnRP.CreateCredential(wu, sd, parsed)
	if err != nil {
		c.auditWebAuthnFailed(ctx, userID, "register")
		return nil, fmt.Errorf("failed to verify attestation: %w", err)
	}
	blob, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	row := &models.WebAuthnCredential{
		UserID:         userID,
		CredentialID:   cred.ID,
		Name:           name,
		CredentialBlob: blob,
		CreatedAt:      c.now(),
	}
	// The credential row and the WebAuthnEnabled flag run in one transaction: a
	// credential surviving a failed flag-set is a phantom row Login's
	// user.WebAuthnEnabled gate never enforces (fails safe, but the user believes
	// they registered a passkey that in fact does nothing, and a retry would only
	// accumulate more orphaned rows).
	firstEnrol := !wu.user.WebAuthnEnabled
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.CreateWebAuthnCredential(ctx, row); err != nil {
			return fmt.Errorf("failed to store credential: %w", err)
		}
		return tx.SetUserWebAuthnEnabled(ctx, userID, true)
	}); err != nil {
		return nil, err
	}
	if firstEnrol {
		// Purge pre-enrolment sessions AND evict them from the auth cache, so a session
		// minted before the security upgrade cannot outlive it even for the cache TTL.
		_ = c.deleteSessionsForUserAndEvict(ctx, userID, 0, "")
	}
	uid := userID
	c.writeAuditEventFull(ctx, "webauthn.registered", &uid, nil, nil, "",
		fmt.Sprintf("user %s registered passkey %q", wu.user.Username, name))
	return row, nil
}

// ListWebAuthnCredentials returns the caller's registered passkeys.
func (c *KeyorixCore) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	return c.storage.ListWebAuthnCredentials(ctx, userID)
}

// DeleteWebAuthnCredential removes one of the caller's passkeys; if it was the
// last one, WebAuthn is disabled for the account. codeOrPassword re-authenticates
// the caller (#372, same re-auth as DisableMFA): deleting every passkey silently
// disables WebAuthn account-wide, a full second-factor downgrade that must not be
// reachable by a bearer token alone (a stolen session or a scoped, MFA-policy-
// exempt PAT per ADR-042).
func (c *KeyorixCore) DeleteWebAuthnCredential(ctx context.Context, userID, id uint, codeOrPassword string) error {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if err := c.requireReauth(ctx, user, codeOrPassword, "webauthn_delete"); err != nil {
		return err
	}
	// The credential delete and the (conditional) WebAuthnEnabled clear run in one
	// transaction: a delete surviving a failed flag-clear leaves WebAuthnEnabled=true
	// with ZERO credentials — Login's user.WebAuthnEnabled gate then requires a
	// WebAuthn assertion the account has no way to produce, a permanent lockout
	// (fails closed, not a bypass, but still a real availability bug). The count
	// read runs on the SAME tx handle so it sees the delete that just happened,
	// not a stale pre-delete count.
	var n int64
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.DeleteWebAuthnCredential(ctx, userID, id); err != nil {
			return err
		}
		var cerr error
		n, cerr = tx.CountWebAuthnCredentials(ctx, userID)
		if cerr != nil {
			return cerr
		}
		if n == 0 {
			return tx.SetUserWebAuthnEnabled(ctx, userID, false)
		}
		return nil
	}); err != nil {
		return err
	}
	if n == 0 {
		// Last passkey removed — security downgrade. Purge all sessions so a session
		// minted under WebAuthn enforcement cannot outlive the second-factor removal,
		// symmetric with FinishWebAuthnRegistration's session purge on first enrolment.
		// Best-effort, same as that call: the credential removal has already committed.
		_ = c.deleteSessionsForUserAndEvict(ctx, userID, 0, "")
	}
	uid := userID
	c.writeAuditEventFull(ctx, "webauthn.credential_removed", &uid, nil, nil, "",
		fmt.Sprintf("user %d removed a passkey (%d remaining)", userID, n))
	return nil
}

// webauthnReauthSessionPurpose is the WebAuthnSession.Purpose value for the
// step-up re-authentication ceremony below — distinct from "register",
// "login", and "passwordless".
const webauthnReauthSessionPurpose = "reauth"

// BeginWebAuthnReauth starts a live passkey re-assertion for an already
// authenticated caller who holds no TOTP factor (WebAuthn-only account) and
// needs to satisfy requireReauth for an account-security-factor change
// (DisableMFA/RegenerateMFARecoveryCodes/ActivateMFA/FinishWebAuthnRegistration/
// DeleteWebAuthnCredential/account email change). Unlike BeginWebAuthnLogin,
// this operates directly on an authenticated userID — there is no pre-login
// MFA challenge to resolve the user from, since the caller is already logged
// in and merely proving they still hold the second factor right now.
func (c *KeyorixCore) BeginWebAuthnReauth(ctx context.Context, userID uint) (*protocol.CredentialAssertion, string, error) {
	if c.webauthnRP == nil {
		return nil, "", ErrWebAuthnDisabled
	}
	wu, err := c.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if len(wu.creds) == 0 {
		return nil, "", fmt.Errorf("no passkeys registered")
	}
	if err := c.checkWebAuthnAccountGates(wu); err != nil {
		return nil, "", err
	}
	// WAUN-001: require user-verification, matching BeginWebAuthnLogin — a
	// stolen/found hardware key must not satisfy re-authentication without the
	// user's own PIN/biometric.
	assertion, sd, err := c.webauthnRP.BeginLogin(wu,
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin reauth: %w", err)
	}
	token, err := c.storeWebAuthnSession(ctx, userID, webauthnReauthSessionPurpose, sd)
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
}

// atomicity: consume-first by design (Session O, O4) — the WebAuthn reauth
// session is consumed BEFORE the MFAStepUpGrant is created. A later
// grant-creation failure must not un-consume it: verified by
// TestFinishWebAuthnReauth_GrantFailureAfterConsume_FailsClosed
// (consume_first_fails_closed_test.go), which injects a CreateMFAStepUpGrant
// failure after a successful consume and confirms no grant is issued and the
// session stays consumed.
//
// FinishWebAuthnReauth verifies the assertion begun by BeginWebAuthnReauth and,
// on success, mints an MFAStepUpGrant with Purpose == MFAStepUpPurposeReauth —
// the ONLY way a WebAuthn-only account can satisfy requireReauth's
// second-factor branch (HasActiveMFAStepUp), since an ambient login-time grant
// is deliberately scoped to MFAStepUpPurposeRestrictedSecretRead and does not
// match. The caller must separately call e.g. DisableMFA/DeleteWebAuthnCredential
// afterward (with the account password) to actually perform the
// account-security-factor change; this function only proves the second factor,
// mirroring how VerifyMFAStepUp+checkRestrictedMFAGate are two separate calls
// for the restricted-secret-read flow.
func (c *KeyorixCore) FinishWebAuthnReauth(ctx context.Context, userID uint, sessionToken string, parsed *protocol.ParsedCredentialAssertionData) error {
	if c.webauthnRP == nil {
		return ErrWebAuthnDisabled
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	if err != nil {
		return fmt.Errorf("invalid or expired webauthn session")
	}
	if sess.Purpose != webauthnReauthSessionPurpose || sess.UserID != userID {
		return fmt.Errorf("webauthn session mismatch")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &sd); err != nil {
		return err
	}
	wu, err := c.loadWebAuthnUser(ctx, userID)
	if err != nil {
		return err
	}
	cred, err := c.webauthnRP.ValidateLogin(wu, sd, parsed)
	if err != nil {
		c.auditWebAuthnFailed(ctx, userID, "reauth")
		c.recordFailedLogin(ctx, user) // count the failed re-auth attempt toward the lockout, mirroring requireReauth
		return fmt.Errorf("assertion verification failed: %w", err)
	}
	// Clone-detection (#212), same as FinishWebAuthnLogin: refuse before treating
	// this as a successful re-auth in any way.
	if err := c.rejectIfCloned(ctx, userID, cred, ""); err != nil {
		return err
	}
	// TOCTOU re-check only — the failure state is NOT cleared here (#2894): the
	// step-up grant below is still to be written, and a fault there denies the
	// re-auth with the same error a failed assertion gets, so it must cost the
	// same lockout progress. See LoginCompletion.
	if err := c.recheckLockAfterCredentialMatched(ctx, user, true); err != nil {
		return err
	}
	c.persistUpdatedCredential(ctx, userID, cred)
	grant := &models.MFAStepUpGrant{
		UserID:    userID,
		Purpose:   models.MFAStepUpPurposeReauth,
		ExpiresAt: c.now().Add(c.mfaStepUpWindow()),
	}
	if err := c.storage.CreateMFAStepUpGrant(ctx, grant); err != nil {
		// #2894: the assertion already verified, so this is a post-verdict storage
		// fault. Count it exactly as a failed assertion would be counted (the
		// recordFailedLogin two branches up), or a correct assertion plus an
		// injected fault here is the cheaper probe.
		return c.denyAfterCredentialMatched(ctx, user, fmt.Errorf("failed to record MFA reauth step-up: %w", err))
	}
	c.clearLoginFailures(ctx, user)
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.reauth_verified", &uid, nil, nil, "",
		fmt.Sprintf("user %s completed WebAuthn re-authentication", user.Username))
	return nil
}

// BeginWebAuthnLogin starts the assertion ceremony for the second login step. It
// resolves the user from the (still-unconsumed) MFA challenge minted by the
// password step, and returns the CredentialAssertion options plus an opaque
// webauthn session token to echo back at FinishWebAuthnLogin (alongside the
// challenge, which is consumed there).
func (c *KeyorixCore) BeginWebAuthnLogin(ctx context.Context, challenge string) (*protocol.CredentialAssertion, string, error) {
	if c.webauthnRP == nil {
		return nil, "", ErrWebAuthnDisabled
	}
	ch, err := c.storage.GetActiveMFAChallenge(ctx, sha256Hex(challenge), c.now())
	if err != nil {
		return nil, "", fmt.Errorf("invalid or expired challenge")
	}
	wu, err := c.loadWebAuthnUser(ctx, ch.UserID)
	if err != nil {
		return nil, "", err
	}
	if len(wu.creds) == 0 {
		return nil, "", fmt.Errorf("no passkeys registered")
	}
	// WAUN-001: require user-verification (PIN or biometric) for the MFA assertion,
	// not just key presence — prevents a stolen/found hardware key from satisfying the
	// second factor without the user's knowledge.
	assertion, sd, err := c.webauthnRP.BeginLogin(wu,
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin login: %w", err)
	}
	token, err := c.storeWebAuthnSession(ctx, ch.UserID, "login", sd)
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
}

// checkWebAuthnAccountGates refuses a WebAuthn second-factor login when the account
// is blocked (suspended/deactivated) or locked out, mirroring the TOTP path in
// VerifyMFALogin and the passwordless path below.
func (c *KeyorixCore) checkWebAuthnAccountGates(wu *webauthnUser) error {
	if !wu.user.IsActive || AccountLoginBlocked(wu.user.ID, wu.user.AccountState) {
		return fmt.Errorf("account is not active")
	}
	// Per-IP limiters are spoofable behind a proxy; bind assertion failures to the
	// account instead. ch.UserID is password-gated so this cannot lock an arbitrary victim.
	if c.loginLocked(wu.user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	return nil
}

// atomicity: consume-first by design (Session O, O4) — the MFA challenge and
// the WebAuthn ceremony session are both consumed BEFORE mintSession runs. A
// later mint failure must not un-consume either: verified by
// TestFinishWebAuthnLogin_MintFailureAfterConsume_FailsClosed
// (consume_first_fails_closed_test.go), which injects a CreateSession failure
// after a successful consume and confirms no session is issued and both
// values stay consumed.
//
// FinishWebAuthnLogin consumes the challenge + webauthn session, verifies the
// assertion, updates the credential's signature counter, and mints the session.
// It also returns the response identity, resolved BEFORE the session and the
// ambient step-up grant are written so the caller does not have to re-read it
// afterwards (#2841 — see resolveLoginIdentityBeforeMint).
//
// Convenience wrapper over FinishWebAuthnLoginPending for callers that own
// nothing further after this returns; every TRANSPORT must use the Pending form
// — see Login/LoginPending and LoginCompletion for why (#2894).
func (c *KeyorixCore) FinishWebAuthnLogin(ctx context.Context, challenge, sessionToken, userAgent, ip string, parsed *protocol.ParsedCredentialAssertionData) (*models.Session, *models.User, UserIdentity, error) {
	session, user, identity, lc, err := c.FinishWebAuthnLoginPending(ctx, challenge, sessionToken, userAgent, ip, parsed)
	if err != nil {
		return nil, user, UserIdentity{}, err
	}
	lc.Succeeded(ctx)
	return session, user, identity, nil
}

// FinishWebAuthnLoginPending is FinishWebAuthnLogin with the lockout accounting
// left open — the returned LoginCompletion MUST get Succeeded or Failed exactly
// once (#2894). On an error return the user is non-nil for every post-verdict
// failure, so a transport can name the account in its auth.login_error event.
func (c *KeyorixCore) FinishWebAuthnLoginPending(ctx context.Context, challenge, sessionToken, userAgent, ip string, parsed *protocol.ParsedCredentialAssertionData) (*models.Session, *models.User, UserIdentity, *LoginCompletion, error) {
	if c.webauthnRP == nil {
		return nil, nil, UserIdentity{}, nil, ErrWebAuthnDisabled
	}
	// Consume the challenge first — it is the single-use login gate.
	ch, err := c.storage.ConsumeMFAChallenge(ctx, sha256Hex(challenge), c.now())
	if err != nil {
		if !errors.Is(err, storage.ErrMFAChallengeInvalid) {
			return nil, nil, UserIdentity{}, nil, fmt.Errorf("%w: consuming login challenge: %w", ErrWebAuthnLoginNotEvaluated, err)
		}
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("invalid or expired challenge")
	}
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	if err != nil {
		if !errors.Is(err, storage.ErrWebAuthnSessionInvalid) {
			return nil, nil, UserIdentity{}, nil, fmt.Errorf("%w: consuming webauthn session: %w", ErrWebAuthnLoginNotEvaluated, err)
		}
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("invalid or expired webauthn session")
	}
	if sess.Purpose != "login" || sess.UserID != ch.UserID {
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("webauthn session mismatch")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &sd); err != nil {
		return nil, nil, UserIdentity{}, nil, err
	}
	wu, err := c.loadWebAuthnUser(ctx, ch.UserID)
	if err != nil {
		// GetUser / ListWebAuthnCredentials failed. The user ID came from a
		// challenge that was just validly consumed (the first factor already
		// passed), so this is never a credential guess: either a storage error
		// or the account being deleted mid-ceremony. Neither evaluated the
		// assertion, so neither may count as a failed attempt.
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("%w: loading webauthn user: %w", ErrWebAuthnLoginNotEvaluated, err)
	}
	// A second-factor WebAuthn login still mints a session, so a suspended or
	// deactivated account must be refused — the challenge may have been issued just
	// before suspension, with nothing rechecking state between steps. Mirrors the
	// passwordless path's AccountLoginBlocked gate (and the password/session gates).
	// Per-account lockout also gates the second factor (parity with VerifyMFALogin).
	if err := c.checkWebAuthnAccountGates(wu); err != nil {
		return nil, nil, UserIdentity{}, nil, err
	}
	cred, err := c.webauthnRP.ValidateLogin(wu, sd, parsed)
	if err != nil {
		c.auditWebAuthnFailed(ctx, ch.UserID, "login")
		c.recordFailedLogin(ctx, wu.user) // count the failed second factor toward the lockout
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("assertion verification failed: %w", err)
	}
	// Clone-detection (#212): a signature-counter regression is a stronger, more
	// specific signal than a simple bad assertion, so it is checked and refused
	// FIRST — before the login is otherwise treated as successful in any way,
	// including clearing the lockout counters below — no session is minted, the
	// credential is disabled, and the owner is alerted (see rejectIfCloned).
	if err := c.rejectIfCloned(ctx, ch.UserID, cred, ip); err != nil {
		return nil, nil, UserIdentity{}, nil, err
	}
	// A concurrent burst of failed second-factor attempts against this account may
	// have tripped the lock since the pre-verification snapshot check above
	// (TOCTOU). Re-check under the same serialization recordFailedLogin uses
	// before minting a session. The lockout counters are deliberately NOT cleared
	// here (#2894): the password-expiry gate, the identity read and the session
	// mint all still have to succeed, and a fault in any of them denies the login
	// with the same response a failed assertion gets — see LoginCompletion.
	if err := c.recheckLockAfterCredentialMatched(ctx, wu.user, true); err != nil {
		if errors.Is(err, ErrLoginPostVerdict) {
			return nil, wu.user, UserIdentity{}, nil, err
		}
		return nil, nil, UserIdentity{}, nil, err
	}
	c.persistUpdatedCredential(ctx, ch.UserID, cred)

	if err := c.enforcePasswordExpiryGate(ctx, wu.user); err != nil {
		return nil, wu.user, UserIdentity{}, nil, c.denyAfterCredentialMatched(ctx, wu.user, err)
	}
	// #2841: the LAST fallible-and-reported read, done BEFORE the
	// session/grant/step-up-token writes. Not "before the first write" — the
	// challenge consume, persistUpdatedCredential's sign-counter update and the
	// password-expiry gate all write earlier; what matters is that nothing
	// fallible-and-reported runs AFTER the writes that would outlive a login
	// reported as failed. See resolveLoginIdentityBeforeMint's doc comment for
	// what used to survive a login this read failed on.
	// #2894: the assertion verified, so a failure here is post-verdict: counted
	// like a failed assertion and wrapped with ErrLoginPostVerdict (the transport
	// answers exactly as for a failed assertion and audits auth.login_error);
	// ErrLoginIdentityUnavailable stays in the chain, ErrWebAuthnLoginNotEvaluated
	// never does, so the per-IP attempt stays counted (#2880).
	identity, err := c.resolveLoginIdentityBeforeMint(ctx, ch.UserID)
	if err != nil {
		return nil, wu.user, UserIdentity{}, nil, c.denyAfterCredentialMatched(ctx, wu.user, err)
	}
	lc := c.newLoginCompletion(wu.user)
	session, err := c.mintSession(ctx, ch.UserID, userAgent, ip)
	if err != nil {
		lc.Failed(ctx)
		return nil, wu.user, UserIdentity{}, nil, fmt.Errorf("%w: %w", ErrLoginPostVerdict, err)
	}
	// Record the MFA step-up window when the classification gate requires it,
	// matching the existing TOTP path in VerifyMFALogin.
	if c.classificationRestrictedRequiresMFAStepUp {
		besteffort.Run(ctx, "webauthn.FinishWebAuthnLogin.UpsertMFAStepupToken", func() error {
			return c.storage.UpsertMFAStepupToken(ctx, ch.UserID, c.now().Add(c.mfaStepUpWindow()))
		})
	}
	// Also mint a genuine MFAStepUpGrant, unconditionally (not gated behind
	// classificationRestrictedRequiresMFAStepUp, matching the pre-existing
	// behavior this fix does not change): a WebAuthn login is itself proof of
	// possessing the second factor, sufficient for reading a restricted secret
	// without a separate re-prompt. Best-effort. Scoped to Purpose ==
	// MFAStepUpPurposeRestrictedSecretRead ONLY — this grant must never be read
	// by requireReauth's account-security-factor-change gate, which requires
	// the distinct MFAStepUpPurposeReauth purpose (see FinishWebAuthnReauth
	// below); an ambient login-time grant is not equivalent to actively
	// proving possession of the second factor at the moment of a
	// takeover-grade change. THIS purpose separation — not gating the write —
	// is the fix for the confused-deputy bug this grant used to enable.
	//
	// Panic-safe as well as error-tolerant: this runs after the session is
	// written, and a panic escaping here reported the login as failed while
	// the session stayed live (#2844, CreateMFAStepUpGrant#1/panic).
	besteffort.Run(ctx, "webauthn.FinishWebAuthnLogin.CreateMFAStepUpGrant", func() error {
		return c.storage.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
			UserID:    ch.UserID,
			Purpose:   models.MFAStepUpPurposeRestrictedSecretRead,
			ExpiresAt: c.now().Add(c.mfaStepUpWindow()),
		})
	})
	uid := ch.UserID
	c.writeAuditEventFull(ctx, "webauthn.login_verified", &uid, nil, nil, ip,
		fmt.Sprintf("user %s passed WebAuthn", wu.user.Username))
	return session, wu.user, identity, lc, nil
}

// BeginWebAuthnPasswordlessLogin starts a discoverable (usernameless) login. No
// user is identified yet — the authenticator reveals which resident passkey (and
// thus which user) to use. User verification is REQUIRED, so the single passkey
// gesture proves both possession and the user (MFA-grade), making this a complete
// passwordless login. Returns the assertion options + an opaque session token.
func (c *KeyorixCore) BeginWebAuthnPasswordlessLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	if c.webauthnRP == nil {
		return nil, "", ErrWebAuthnDisabled
	}
	assertion, sd, err := c.webauthnRP.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin passwordless login: %w", err)
	}
	// userID is unknown until finish resolves it from the credential's user handle.
	token, err := c.storeWebAuthnSession(ctx, 0, "passwordless", sd)
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
}

// atomicity: consume-first by design (Session O, O4) — the WebAuthn ceremony
// session is consumed BEFORE mintSession runs. A later mint failure must not
// un-consume it: verified by
// TestFinishWebAuthnPasswordlessLogin_MintFailureAfterConsume_FailsClosed
// (consume_first_fails_closed_test.go), which injects a CreateSession failure
// after a successful consume and confirms no session is issued.
//
// FinishWebAuthnPasswordlessLogin verifies a discoverable assertion, resolves the
// user from the credential's user handle, enforces account state, and mints a
// session — a full login from a single passkey, no password. Like
// FinishWebAuthnLogin it also returns the response identity, resolved before the
// session/grant writes (#2841).
//
// Convenience wrapper over FinishWebAuthnPasswordlessLoginPending for callers
// that own nothing further after this returns; every TRANSPORT must use the
// Pending form — see Login/LoginPending and LoginCompletion for why (#2894).
func (c *KeyorixCore) FinishWebAuthnPasswordlessLogin(ctx context.Context, sessionToken, userAgent, ip string, parsed *protocol.ParsedCredentialAssertionData) (*models.Session, *models.User, UserIdentity, error) {
	session, user, identity, lc, err := c.FinishWebAuthnPasswordlessLoginPending(ctx, sessionToken, userAgent, ip, parsed)
	if err != nil {
		return nil, user, UserIdentity{}, err
	}
	lc.Succeeded(ctx)
	return session, user, identity, nil
}

// FinishWebAuthnPasswordlessLoginPending is FinishWebAuthnPasswordlessLogin
// with the lockout accounting left open — the returned LoginCompletion MUST get
// Succeeded or Failed exactly once (#2894). On an error return the user is
// non-nil for every post-verdict failure, so a transport can name the account
// in its auth.login_error event.
func (c *KeyorixCore) FinishWebAuthnPasswordlessLoginPending(ctx context.Context, sessionToken, userAgent, ip string, parsed *protocol.ParsedCredentialAssertionData) (*models.Session, *models.User, UserIdentity, *LoginCompletion, error) {
	if c.webauthnRP == nil {
		return nil, nil, UserIdentity{}, nil, ErrWebAuthnDisabled
	}
	sess, err := c.storage.ConsumeWebAuthnSession(ctx, sha256Hex(sessionToken), c.now())
	if err != nil {
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("invalid or expired webauthn session")
	}
	if sess.Purpose != "passwordless" {
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("webauthn session mismatch")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sess.Data, &sd); err != nil {
		return nil, nil, UserIdentity{}, nil, err
	}

	// The discoverable handler resolves the user from the 8-byte user handle that
	// the authenticator returns (our WebAuthnID encoding). ValidatePasskeyLogin then
	// verifies the assertion against that user's stored credentials.
	var resolved *models.User
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) != 8 {
			return nil, fmt.Errorf("unexpected user handle")
		}
		uid := uint(binary.BigEndian.Uint64(userHandle))
		wu, err := c.loadWebAuthnUser(ctx, uid)
		if err != nil {
			return nil, err
		}
		resolved = wu.user
		return wu, nil
	}
	_, cred, err := c.webauthnRP.ValidatePasskeyLogin(handler, sd, parsed)
	if err != nil || resolved == nil {
		c.writeAuditEventFull(ctx, "webauthn.failed", nil, nil, nil, ip, "failed passwordless WebAuthn login")
		return nil, nil, UserIdentity{}, nil, fmt.Errorf("assertion verification failed: %w", err)
	}
	// Clone-detection (#212): refuse before any other gate — a signature-counter
	// regression means this assertion may come from a cloned authenticator, so it
	// must never mint a session regardless of account state. See rejectIfCloned.
	if err := c.rejectIfCloned(ctx, resolved.ID, cred, ip); err != nil {
		return nil, nil, UserIdentity{}, nil, err
	}
	if err := c.checkPasswordlessAccountState(ctx, resolved); err != nil {
		if errors.Is(err, ErrLoginPostVerdict) {
			return nil, resolved, UserIdentity{}, nil, err
		}
		return nil, nil, UserIdentity{}, nil, err
	}
	c.persistUpdatedCredential(ctx, resolved.ID, cred)

	// #2894: this path uses the NOT-COUNTED completion -- a failed discoverable
	// assertion never identifies a user, so it does not feed the per-account
	// counter either, and charging a post-verdict fault would make the CORRECT
	// credential the more expensive one. The fix here is purely that the counter
	// is no longer CLEARED on the way to a denial. See
	// newLoginCompletionNotCounted.
	lc := c.newLoginCompletionNotCounted(resolved)
	if err := c.enforcePasswordExpiryGate(ctx, resolved); err != nil {
		lc.Failed(ctx)
		return nil, resolved, UserIdentity{}, nil, fmt.Errorf("%w: %w", ErrLoginPostVerdict, err)
	}
	// #2841: the LAST fallible-and-reported read, done BEFORE the
	// session/grant/step-up-token writes — see resolveLoginIdentityBeforeMint's
	// doc comment. Post-verdict (#2894), so it is denied exactly like the gate
	// above: not counted on this path, ErrLoginIdentityUnavailable kept in chain.
	identity, err := c.resolveLoginIdentityBeforeMint(ctx, resolved.ID)
	if err != nil {
		lc.Failed(ctx)
		return nil, resolved, UserIdentity{}, nil, fmt.Errorf("%w: %w", ErrLoginPostVerdict, err)
	}
	session, err := c.mintSession(ctx, resolved.ID, userAgent, ip)
	if err != nil {
		lc.Failed(ctx)
		return nil, resolved, UserIdentity{}, nil, fmt.Errorf("%w: %w", ErrLoginPostVerdict, err)
	}
	// Record the MFA step-up window when the classification gate requires it,
	// matching both VerifyMFALogin and FinishWebAuthnLogin.
	if c.classificationRestrictedRequiresMFAStepUp {
		besteffort.Run(ctx, "webauthn.FinishWebAuthnPasswordlessLogin.UpsertMFAStepupToken", func() error {
			return c.storage.UpsertMFAStepupToken(ctx, resolved.ID, c.now().Add(c.mfaStepUpWindow()))
		})
	}
	// Also mint a genuine MFAStepUpGrant, unconditionally (matching the
	// pre-existing behavior this fix does not change) — see the identical
	// comment in FinishWebAuthnLogin for why this purpose does NOT satisfy
	// requireReauth (that requires MFAStepUpPurposeReauth, minted only by
	// FinishWebAuthnReauth's live re-assertion). Best-effort.
	//
	// Panic-safe as well as error-tolerant: this runs after the session is
	// written, and a panic escaping here reported the login as failed while
	// the session stayed live (#2844, CreateMFAStepUpGrant#1/panic).
	besteffort.Run(ctx, "webauthn.FinishWebAuthnPasswordlessLogin.CreateMFAStepUpGrant", func() error {
		return c.storage.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
			UserID:    resolved.ID,
			Purpose:   models.MFAStepUpPurposeRestrictedSecretRead,
			ExpiresAt: c.now().Add(c.mfaStepUpWindow()),
		})
	})
	uid := resolved.ID
	c.writeAuditEventFull(ctx, "webauthn.passwordless_login", &uid, nil, nil, ip,
		fmt.Sprintf("user %s logged in passwordlessly via WebAuthn", resolved.Username))
	return session, resolved, identity, lc, nil
}

// checkPasswordlessAccountState enforces account-state and lockout gates for a
// passwordless WebAuthn login. Extracted from FinishWebAuthnPasswordlessLogin to
// reduce its cognitive complexity.
func (c *KeyorixCore) checkPasswordlessAccountState(ctx context.Context, user *models.User) error {
	// IsActive is an independent gate from AccountState — an admin deactivation
	// (is_active=false) leaves AccountState="active", so both must be checked.
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return fmt.Errorf("account is not active")
	}
	// Honor an active per-account lockout even for a valid passkey (defense in depth).
	// We deliberately do NOT feed failures into the lockout here — see the calling
	// comment in FinishWebAuthnPasswordlessLogin for the reasoning.
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	// Re-check under serialization before minting a session (TOCTOU guard). The
	// clear is NOT done here (#2894) — FinishWebAuthnPasswordlessLogin's own
	// LoginCompletion owns it, after the mint and the transport's identity read.
	// A storage fault in the recheck is post-verdict but NOT counted: this path's
	// failed assertions do not count either (see newLoginCompletionNotCounted).
	return c.recheckLockAfterCredentialMatched(ctx, user, false)
}

// rejectIfCloned inspects a just-verified assertion's credential for a signature-
// counter regression — go-webauthn's standard FIDO2 clone-detection signal
// (Authenticator.CloneWarning), meaning this credential's private key material
// likely exists on more than one device (#212). Previously this was only ever
// written to a passive audit line while the login proceeded normally; now the
// CURRENT authentication is refused (never mints a session on a clone signal), the
// credential is disabled so it cannot authenticate again until the owner deletes it
// and registers a fresh passkey (auto re-enabling isn't safe — the stored counter
// can never again exceed a value a possibly-compromised clone already asserted),
// and the account owner is alerted loudly: a distinct audit event (superseding the
// old passive "clone_warning" line) plus an in-app/email notification, rather than
// only a silent log entry. Returns a rejection error when CloneWarning fired, nil
// otherwise (the normal, incrementing-counter case).
func (c *KeyorixCore) rejectIfCloned(ctx context.Context, userID uint, cred *webauthn.Credential, ip string) error {
	if !cred.Authenticator.CloneWarning {
		return nil
	}
	// Scoped to userID (#307) — the lookup itself enforces ownership, so no separate
	// row.UserID check is needed here.
	if row, err := c.storage.GetWebAuthnCredentialByCredID(ctx, cred.ID, userID); err == nil {
		// Mutation + audit as one unit (#1714) — see markWebAuthnCredentialClonedDisabled.
		//
		// #2836: the discard is safe BY CONSTRUCTION now, not by luck — that
		// function audits the clone signal before any branch can return, so
		// dropping this error cannot lose the incident; it only drops the
		// "what happened to the row" detail, which the audit already carries.
		// Logged anyway so an operator sees a disable that did not take effect
		// without having to read the audit trail.
		if derr := c.markWebAuthnCredentialClonedDisabled(ctx, row, ip); derr != nil {
			log.Printf("webauthn: clone-disable for user %d credential %d did not take effect: %v", userID, row.ID, derr)
		}
	} else {
		// Row lookup failed (rare — e.g. a race with the credential being deleted
		// between assertion verification and this call). Nothing to disable, but
		// the clone signal for THIS login attempt is still real and must still be
		// recorded — this is the one case where the audit write is not paired with
		// a mutation, since there is no row to mutate.
		uid := userID
		c.writeAuditEventFull(ctx, EventWebAuthnCloneDetected, &uid, nil, nil, ip,
			fmt.Sprintf("authentication refused for user %d: signature-counter regression (possible cloned authenticator) — credential lookup failed, nothing disabled", userID))
	}
	c.notify(ctx, userID, NotificationWebAuthnCloneDetected, "Passkey clone suspected",
		"A sign-in attempt was blocked because one of your passkeys reported a signature-counter regression — a sign that its private key may exist on more than one device. The passkey has been disabled; please remove it and register a new one.",
		nil, "/account/security")
	return fmt.Errorf("assertion verification failed: signature counter did not advance (possible cloned authenticator)")
}

// markWebAuthnCredentialClonedDisabled performs a WebAuthn credential's
// disable-on-clone-signal mutation (Disabled: false -> true) and its
// EventWebAuthnCloneDetected audit write as a single unit (#1714), so no
// exported path can do one without the other. row must already be the
// caller's own fetched, owned row (rejectIfCloned's GetWebAuthnCredentialByCredID
// call scopes ownership by construction; MarkWebAuthnCredentialClonedByLookup
// below does the same for a caller that only has (credentialID, userID)).
func (c *KeyorixCore) markWebAuthnCredentialClonedDisabled(ctx context.Context, row *models.WebAuthnCredential, ip string) error {
	// #2700: write `disabled` alone. The previous full-row Save re-INSERTED a
	// passkey the user had concurrently deleted (WebAuthnCredential is hard-
	// deleted, so Save's 0-rows fallback upserts it back).
	matched, err := c.storage.DisableWebAuthnCredential(ctx, row.ID)

	// #2836: the clone-detected audit is written UNCONDITIONALLY, before any
	// branch can return. The signature-counter regression is a fact about this
	// LOGIN ATTEMPT, established before this function was called; whether the
	// row could then be disabled is a separate fact, and belongs in the detail
	// rather than deciding whether the incident is recorded at all.
	//
	// #2700's first version returned early on both !matched and err != nil,
	// skipping the audit — so a passkey deleted (or a database briefly
	// unavailable) in the window between the assertion check and this write
	// turned a clone signal into silence. That was a REGRESSION this branch
	// introduced: the full-row Save it replaced upserted the row back and
	// therefore always reached the audit. Worse, the comment that replaced it
	// claimed "the caller's rejectIfCloned path already audits the clone signal
	// separately for the credential-missing case" — rejectIfCloned's else branch
	// covers only a failed LOOKUP, not a lookup that succeeded and an UPDATE
	// that then matched nothing. The cover was asserted, not checked, and did
	// not exist.
	//
	// Not split into a second webauthn.error event: a storage failure here does
	// not leave the clone verdict unreached (CloneWarning was already true), so
	// there is exactly one incident to record — emitting two events would let an
	// incident count double. The mfa.error/mfa.failed split exists for the
	// opposite case, where no verdict was reached at all.
	outcome := "credential disabled pending re-registration"
	switch {
	case err != nil:
		outcome = fmt.Sprintf("credential could NOT be disabled (storage error: %v) — it may still be usable, treat as unmitigated", err)
	case !matched:
		outcome = "credential was already deleted — nothing left to disable"
	}
	uid := row.UserID
	c.writeAuditEventFull(ctx, EventWebAuthnCloneDetected, &uid, nil, nil, ip,
		fmt.Sprintf("authentication refused for user %d: signature-counter regression (possible cloned authenticator) — %s", row.UserID, outcome))

	if err != nil {
		return err
	}
	if !matched {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	row.Disabled = true
	return nil
}

// ErrWebAuthnCredentialIDMismatch is returned by MarkWebAuthnCredentialClonedByLookup
// when (credentialID, userID) resolves to a real, owned row, but that row's ID
// does not match the caller's expectedID. This is deliberately distinct from
// "not found": the pair is real and does belong to userID, it just isn't the
// SAME credential the caller is claiming to act on — a mismatch a caller must
// never have silently coerced into acting on whichever row the lookup actually
// named instead.
var ErrWebAuthnCredentialIDMismatch = errors.New("webauthn credential id does not match (credential_id, user_id)")

// MarkWebAuthnCredentialClonedByLookup explicitly disables a WebAuthn
// credential on a clone-detection signal, identified by (credentialID,
// userID) rather than an already-resolved row — the ONE thing
// UpdateWebAuthnCredentialProxy (#1714) is allowed to do. The
// GetWebAuthnCredentialByCredID lookup scopes ownership: a caller cannot
// reach a credential it doesn't legitimately identify by both its own
// credentialID and userID together, so there is no separate ownership check
// needed here, matching rejectIfCloned's own "#307" reasoning.
//
// expectedID is checked BEFORE any mutation happens — never after. An
// earlier draft of this fix fetched, mutated, and only THEN compared IDs,
// which would disable the WRONG credential (the one (credentialID, userID)
// actually named) before rejecting the request; that ordering is exactly the
// "stored row is unchanged" property callers of this function get in
// exchange for passing expectedID at all. Returns
// ErrWebAuthnCredentialIDMismatch, unmutated, if the row's real ID doesn't
// match.
func (c *KeyorixCore) MarkWebAuthnCredentialClonedByLookup(ctx context.Context, credentialID []byte, userID, expectedID uint, ip string) (*models.WebAuthnCredential, error) {
	row, err := c.storage.GetWebAuthnCredentialByCredID(ctx, credentialID, userID)
	if err != nil {
		return nil, err
	}
	if row.ID != expectedID {
		return nil, ErrWebAuthnCredentialIDMismatch
	}
	if err := c.markWebAuthnCredentialClonedDisabled(ctx, row, ip); err != nil {
		return nil, err
	}
	return row, nil
}

// persistUpdatedCredential writes back the credential's advanced signature counter
// (and clone-warning flag) plus a last-used timestamp. Best-effort: a write error
// must not fail an otherwise-valid login.
//
// Both FinishWebAuthnLogin and FinishWebAuthnPasswordlessLogin call this
// independently and unsynchronized, so a concurrent cloned-authenticator race can
// have two requests both load the stored row before either writes back: without a
// predicate, a blind Save would let the loser's stale (lower) counter overwrite the
// winner's already-persisted higher one — last UPDATE wins — silently regressing the
// on-disk counter and suppressing the clone-detection audit signal on subsequent
// logins (#306). The actual read-validate-write now happens in ONE atomic
// storage-layer call, storage.Storage.AdvanceWebAuthnCredentialCounter (#517) — see
// its doc (internal/core/storage/interface.go) for why this had to move down a
// layer: composing LockWebAuthnCredentialForUpdate + UpdateWebAuthnCredential as two
// separate calls (as this function used to) left a TOCTOU race window open between
// them. webauthnCredentialMu still serializes same-process callers (belt-and-
// suspenders for the single-process SQLite case, where AdvanceWebAuthnCredentialCounter's
// own row lock is a no-op); combined with LocalStorage's row lock on Postgres, the
// counter stays monotonic across replicas too.
func (c *KeyorixCore) persistUpdatedCredential(ctx context.Context, userID uint, cred *webauthn.Credential) {
	blob, err := json.Marshal(cred)
	if err != nil {
		return
	}
	now := c.now()

	// Best-effort: called from inside FinishWebAuthnLogin/FinishWebAuthnPasswordlessLogin/
	// VerifyMFAStepUp BEFORE mintSession, after recheckLoginLockFailClosed may
	// already have written to this user's lockout row -- an unrecovered panic
	// here would propagate past that write and report the whole login/reauth as
	// failed even though lockout state already changed. (Since #2894 the CLEAR
	// itself happens later, at delivery, so the window this guards is narrower
	// than it was -- but the lock recheck above can still have written.) besteffort.Run closes
	// that gap; found by besteffort_guard_test.go (GUARD-1), no returned-error
	// protection existed here at all before this fix, let alone a panic recover.
	besteffort.Run(ctx, "webauthn.persistUpdatedCredential", func() error {
		c.webauthnCredentialMu.Lock()
		defer c.webauthnCredentialMu.Unlock()
		_, err := c.storage.AdvanceWebAuthnCredentialCounter(ctx, cred.ID, userID, blob, cred.Authenticator.SignCount, now)
		return err
	})
}

func (c *KeyorixCore) auditWebAuthnFailed(ctx context.Context, userID uint, phase string) {
	uid := userID
	c.writeAuditEventFull(ctx, "webauthn.failed", &uid, nil, nil, "",
		fmt.Sprintf("failed WebAuthn %s for user %d", phase, userID))
}
