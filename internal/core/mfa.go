// mfa.go — TOTP multi-factor authentication (RFC 6238): per-user opt-in
// enrolment, two-step login via a short-lived challenge, and single-use recovery
// codes. The TOTP shared secret is stored reversibly encrypted (it cannot be
// hashed); recovery and challenge tokens are SHA-256 hashed at rest.
package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// ErrMFARequired is returned by Login when the password is correct but the
// account has MFA enabled: the caller must issue a challenge (CreateMFAChallenge)
// and complete VerifyMFALogin with a one-time code.
var ErrMFARequired = errors.New("mfa required")

// ErrMFAVerificationStorageFailure marks a VerifyMFALogin/VerifyMFACredentials
// error that comes from a storage read failing BEFORE a verdict on the code
// was reached — as distinct from a confirmed negative result (a genuinely
// wrong/expired/unknown credential, an already-locked or inactive account).
// VerifyMFACredentials itself already keeps this class of error from touching
// the per-account lockout counter (see the storageErr handling below); this
// sentinel lets a caller outside this package apply the same distinction to
// its OWN bookkeeping. Its one caller today is the /auth/mfa/verify HTTP
// handler (server/http/handlers/mfa.go), which reserves an IP-level
// rate-limit slot before calling VerifyMFALogin at all (closing a
// concurrent-burst race, F2 2026-09-20) and needs to release that
// reservation when this sentinel is present — second call site of
// docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md,
// found by the fuzzer (CI on PR #2392, seed 877139548d2805a6) via the
// handler's reservation landing before the GetUser call below even runs.
//
// Applied to ConsumeMFAChallenge's error only when that error is NOT the
// storage.ErrMFAChallengeInvalid sentinel (see that call site): an
// unknown/expired/already-consumed challenge is that call's expected, common
// negative result, not a storage ambiguity, and must stay counted toward the
// IP throttle — confirmed by FuzzLoginThrottleConcurrency
// (server/http/handlers/login_throttle_fuzz_test.go), whose oracle (a) failed
// when the whole branch was tagged. A genuine storage failure on that same
// call IS tagged: it is the earliest pre-verdict position on this path, so
// spending an IP slot on it would charge the caller for a request whose code
// was never looked at.
var ErrMFAVerificationStorageFailure = errors.New("mfa verification storage failure")

// ErrMFAEnrollmentChanged is returned (wrapped) by ActivateMFA when the pending
// TOTP secret was replaced, e.g. by a concurrent BeginMFAEnrollment, after the
// submitted code was validated against it (#2655). Nothing was activated; the
// user must begin enrolment again.
var ErrMFAEnrollmentChanged = errors.New("MFA enrolment changed during activation; begin enrolment again")

// ErrMFAVerificationUnavailable is wrapped IN ADDITION to
// ErrMFAVerificationStorageFailure only when the storage failure happened
// before any submitted code was evaluated (loading the user or the TOTP
// secret, or the recovery-code lookup itself). Only this case may be
// reported to clients as a retryable 503. A storage failure AFTER a code was
// found correct (marking the TOTP step used) must stay indistinguishable
// from a wrong code (401): a distinct response there would confirm a correct
// guess (#2740 review, option C).
var ErrMFAVerificationUnavailable = errors.New("mfa verification unavailable: no code was evaluated")

const (
	mfaIssuer            = "Keyorix"
	mfaRecoveryCodeCount = 10
	mfaChallengeTTL      = 5 * time.Minute
)

// BeginMFAEnrollment generates a fresh TOTP secret, stores it encrypted in a
// pending (not-activated) state, and returns the otpauth:// URI (QR) plus the
// base32 secret (manual entry). Supersedes any prior pending enrolment. Refused
// if MFA is already enabled (disable first), or if at-rest encryption is
// unavailable (see the authEncryptor check below).
func (c *KeyorixCore) BeginMFAEnrollment(ctx context.Context, userID uint) (otpauthURI, base32Secret string, err error) {
	// The TOTP secret is a distinct, always-sensitive credential — unlike a general
	// secret VALUE (whose at-rest encryption is an explicit, informed operator
	// trade-off when disabled), a user enrolling MFA has no visibility into or
	// control over the server's encryption setting. Silently falling back to
	// encryptAuthSecret's plaintext passthrough would store the TOTP seed in the
	// clear with no signal to anyone. Fail closed instead, mirroring how this
	// codebase treats other capabilities that need encryption (audit-checkpoint
	// signing, evidence signing): "unavailable" when encryption is off, not
	// silently weaker.
	if c.authEncryptor == nil || !c.authEncryptor.IsEnabled() {
		return "", "", fmt.Errorf("MFA enrolment requires at-rest encryption to be enabled (the TOTP secret must not be stored in plaintext); ask an administrator to enable encryption")
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("user not found")
	}
	if user.MFAEnabled {
		return "", "", fmt.Errorf("MFA is already enabled; disable it first to re-enrol")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: mfaIssuer, AccountName: user.Username})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	ct, meta, err := c.encryptAuthSecret(key.Secret(), ports.MFASecretAAD(userID))
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}
	if err := c.storage.UpsertMFASecret(ctx, &models.MFASecret{
		UserID: userID, SecretEnc: ct, SecretMeta: meta, Activated: false, CreatedAt: c.now(),
	}); err != nil {
		return "", "", fmt.Errorf("failed to store TOTP secret: %w", err)
	}
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.enrolled", &uid, nil, nil, "", fmt.Sprintf("user %s began MFA enrolment", user.Username))
	return key.URL(), key.Secret(), nil
}

// ActivateMFA verifies a TOTP code against the pending secret, enables MFA, and
// returns N single-use recovery codes (shown once). password re-authenticates the
// caller (#372): code alone is NOT sufficient proof of the account holder here,
// because it is checked against the PENDING secret that BeginMFAEnrollment just
// generated — an attacker with a stolen session or PAT can call BeginMFAEnrollment
// themselves and so always knows a "valid" code for it. Unlike DisableMFA/
// RegenerateMFARecoveryCodes (which re-authenticate against an already-ACTIVE
// factor and so accept a current TOTP code OR the password), activation happens
// before MFA is enabled, so there is no pre-existing TOTP factor to check against —
// the password is the only trustworthy re-proof available at this step.
//
// atomicity: consume-first by design (ORACLE-A-1, 2026-10-05) — this function's
// OWN MarkTOTPStepUsed below burns the matched enrolment-code time-step BEFORE
// the activation transaction runs, and a failure inside that transaction must
// NOT un-burn it: the submitted code has been seen and accepted once, so
// accepting it a second time inside its ±1-step window would make a stolen
// enrolment code replayable. Verified by
// TestActivateMFA_ActivationFailureAfterConsume_FailsClosed
// (consume_first_fails_closed_test.go), whose red proof folds the consume into
// the transaction and shows the replay then succeeds.
//
// Note that requireReauth, called just below, performs NO consumption on this
// path, despite being a class-B row in its own right: activation happens with
// user.MFAEnabled still false, so secondFactorEnrolled is false, requireReauth
// takes its bare-password branch, and neither MarkTOTPStepUsed nor
// ConsumeMFAStepUpGrant runs. This function's own MarkTOTPStepUsed is the only
// consume on the ActivateMFA path — spelled out because PR #2840 originally
// attributed it to requireReauth and was wrong (coordinator review).
func (c *KeyorixCore) ActivateMFA(ctx context.Context, userID uint, code, password, keepSessionToken string) ([]string, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if err := c.requireReauth(ctx, user, password, "activate_reauth"); err != nil {
		return nil, err
	}
	// #2655: keep the validated row's ciphertext so the activation below can
	// require that exact secret is still the stored one.
	pending, err := c.storage.GetMFASecret(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("no pending MFA enrolment; begin enrolment first")
	}
	secret, err := c.decryptAuthSecret(pending.SecretEnc, pending.SecretMeta, ports.MFASecretAAD(userID))
	if err != nil {
		return nil, fmt.Errorf("no pending MFA enrolment; begin enrolment first")
	}
	step, ok := c.validateTOTPStep(secret, code)
	if !ok {
		c.auditMFAFailed(ctx, userID, "activate")
		return nil, fmt.Errorf("invalid code")
	}
	fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, userID, step)
	if ferr != nil {
		// AUTH-AUDIT-1 item 3 (#2744): a storage error is not a wrong code, so it
		// is audited mfa.error. The caller still gets exactly the wrong-code
		// error (the code had matched; any other answer would confirm it), and
		// the step was not marked, so the same code works once storage recovers.
		c.auditMFAError(ctx, userID, "activate", ferr)
		return nil, fmt.Errorf("invalid code")
	}
	if !fresh {
		// A confirmed replay: this one IS a failed attempt.
		c.auditMFAFailed(ctx, userID, "activate")
		return nil, fmt.Errorf("invalid code")
	}
	codes, hashes, err := generateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	// #G08: activating the secret, flipping MFAEnabled, and creating recovery codes must
	// move together — a storage failure between any two of these previously left the
	// account in an inconsistent state (e.g. MFAEnabled=true with no recovery codes ever
	// issued, locking the user out with no fallback the moment their device is lost).
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		// #2655: a conditional write pinned to the secret the code was just
		// validated against. A BeginMFAEnrollment on another replica that
		// replaced it in between (e.g. from a stolen session) matches zero rows;
		// fail closed so the whole transaction rolls back and MFA stays off.
		matched, err := tx.ActivateMFASecret(ctx, userID, pending.SecretEnc)
		if err != nil {
			return fmt.Errorf("failed to activate MFA: %w", err)
		}
		if !matched {
			return fmt.Errorf("failed to activate MFA: %w", ErrMFAEnrollmentChanged)
		}
		if err := tx.SetUserMFAEnabled(ctx, userID, true); err != nil {
			return fmt.Errorf("failed to enable MFA: %w", err)
		}
		if err := tx.CreateMFARecoveryCodes(ctx, userID, hashes); err != nil {
			return fmt.Errorf("failed to store recovery codes: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// Invalidate any OTHER sessions minted before MFA was enabled (and evict them from
	// the auth cache), so a pre-enrolment session cannot outlive the security upgrade —
	// even for the cache TTL (same hygiene as ChangePassword). The CALLING session is
	// kept (resolved the same way ChangePassword does, via keepSessionToken): it just
	// proved both the pending TOTP secret AND the account password, which is strictly
	// more proof of the account holder than an ordinary session carries — revoking it
	// too served no security purpose and instead immediately 401'd the very session
	// that needs to render the just-returned recovery codes (the UI's own
	// recovery-codes-status query refetch, triggered by this call's own success,
	// would otherwise race this purge and force a global logout before the user ever
	// sees them). Best-effort: enrolment must not fail on a session-cleanup error.
	keepID, keepHash := c.resolveKeepSession(ctx, userID, keepSessionToken, "activate_mfa")
	_ = c.deleteSessionsForUserAndEvict(ctx, userID, keepID, keepHash)
	// #2978: the kept session's auth-cache entry still says MFAEnabled=false; clear
	// it (delete-only, never a tombstone) so the next request re-reads the user
	// instead of 403ing MFAEnrollmentRequired until the cache TTL lapses.
	c.clearCachedTokens(keepHash)
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.activated", &uid, nil, nil, "", fmt.Sprintf("user %s activated MFA", user.Username))
	return codes, nil
}

// DisableMFA turns MFA off after verifying a current TOTP code OR the account
// password, then clears the secret and all recovery codes.
func (c *KeyorixCore) DisableMFA(ctx context.Context, userID uint, codeOrPassword, keepSessionToken string) error {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled")
	}
	if err := c.requireReauth(ctx, user, codeOrPassword, "disable"); err != nil {
		return err
	}
	// #G08: flipping MFAEnabled and clearing the secret/recovery codes must move
	// together — a storage failure between the two previously could leave MFAEnabled
	// false while stale credential material survived (or vice versa), an inconsistent
	// state the API nonetheless reported as a clean failure.
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.SetUserMFAEnabled(ctx, userID, false); err != nil {
			return err
		}
		return tx.DeleteMFAForUser(ctx, userID)
	}); err != nil {
		return err
	}
	// Purge all OTHER sessions now that MFA is disabled — the security downgrade must
	// not leave sessions that were minted under MFA enforcement still valid (symmetric
	// with ActivateMFA's session purge on upgrade). The CALLING session is kept (same
	// keepSessionToken resolution as ActivateMFA/ChangePassword): it just proved a
	// current code or the account password via requireReauth above, and revoking it
	// too only forces an immediate, surprising logout of the very request that just
	// disabled MFA, with no security benefit over letting it continue normally.
	// Best-effort: disable must not fail on a cleanup error.
	keepID, keepHash := c.resolveKeepSession(ctx, userID, keepSessionToken, "disable_mfa")
	_ = c.deleteSessionsForUserAndEvict(ctx, userID, keepID, keepHash)
	c.clearCachedTokens(keepHash) // #2978: same stale-MFAEnabled cache entry as ActivateMFA
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.disabled", &uid, nil, nil, "", fmt.Sprintf("user %s disabled MFA", user.Username))
	return nil
}

// RegenerateMFARecoveryCodes issues a fresh set of recovery codes after verifying a
// current TOTP code OR the account password (same re-auth as DisableMFA), replacing
// any existing codes (used and unused). The plaintext codes are returned once and
// never stored. Invalidating the old set means a regenerate also revokes leaked or
// previously-recorded codes.
func (c *KeyorixCore) RegenerateMFARecoveryCodes(ctx context.Context, userID uint, codeOrPassword string) ([]string, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.MFAEnabled {
		return nil, fmt.Errorf("MFA is not enabled")
	}
	if err := c.requireReauth(ctx, user, codeOrPassword, "regenerate_recovery_codes"); err != nil {
		return nil, err
	}
	codes, hashes, err := generateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	// #G08: deleting the old codes and inserting the new set must move together — a
	// storage failure between the two previously could leave the account with ZERO
	// recovery codes (old set gone, new set never landed), an unsafe state the API
	// nonetheless reported as a clean failure.
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.DeleteMFARecoveryCodes(ctx, userID); err != nil {
			return fmt.Errorf("failed to clear old recovery codes: %w", err)
		}
		return tx.CreateMFARecoveryCodes(ctx, userID, hashes)
	}); err != nil {
		return nil, fmt.Errorf("failed to store recovery codes: %w", err)
	}
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.recovery_codes_regenerated", &uid, nil, nil, "",
		fmt.Sprintf("user %s regenerated MFA recovery codes", user.Username))
	return codes, nil
}

// MFARecoveryCodesRemaining reports how many unused recovery codes the user has
// (and the original total), so the account UI can surface a "running low" warning.
// Returns (0, 0) when MFA is not enabled.
func (c *KeyorixCore) MFARecoveryCodesRemaining(ctx context.Context, userID uint) (remaining, total int, err error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return 0, 0, fmt.Errorf("user not found")
	}
	if !user.MFAEnabled {
		return 0, 0, nil
	}
	remaining, err = c.storage.CountUnusedMFARecoveryCodes(ctx, userID)
	if err != nil {
		return 0, 0, err
	}
	return remaining, mfaRecoveryCodeCount, nil
}

// CreateMFAChallenge issues a short-lived single-use challenge for an MFA-enabled
// user that has passed the password step. Only the token hash is stored.
func (c *KeyorixCore) CreateMFAChallenge(ctx context.Context, userID uint) (string, error) {
	return c.CreateMFAChallengeHoldingLoginSlot(ctx, userID, nil)
}

// CreateMFAChallengeHoldingLoginSlot is CreateMFAChallenge for a password step
// that reserved a per-IP login-budget slot and keeps it: the slot id is stored
// on the challenge, and the second factor that consumes the challenge and
// delivers a session hands it back (LoginCompletion.Succeeded). A failed,
// expired or abandoned second factor never does, so the slot stays counted
// (#2936 item 4: N ordinary MFA logins from one office IP no longer use N
// slots). slotID nil means nothing was reserved.
func (c *KeyorixCore) CreateMFAChallengeHoldingLoginSlot(ctx context.Context, userID uint, slotID *uint) (string, error) {
	token, err := generateSecureToken()
	if err != nil {
		return "", err
	}
	if err := c.storage.CreateMFAChallenge(ctx, &models.MFAChallenge{
		UserID: userID, TokenHash: sha256Hex(token), ExpiresAt: c.now().Add(mfaChallengeTTL), CreatedAt: c.now(),
		LoginAttemptID: sharedLoginSlot(slotID),
	}); err != nil {
		return "", err
	}
	return token, nil
}

// atomicity: consume-first by design (Session O, O4) — the challenge, and the
// TOTP step or recovery code, are consumed BEFORE the caller (VerifyMFALogin)
// mints a session. A later mint failure must not un-consume them: verified by
// TestVerifyMFALogin_MintFailureAfterConsume_FailsClosed (mfa_test.go / this
// file's sibling), which injects a CreateSession failure after a successful
// consume and confirms no session is issued and the consumed values stay
// consumed (a same-code retry is still refused).
//
// VerifyMFACredentials consumes a challenge and verifies a TOTP code or a
// recovery code against LocalStorage — everything VerifyMFALogin does EXCEPT
// minting the session and the two post-mint audit writes, extracted (#509) as
// the single source of truth for the second-factor check, mirroring the split
// #506 already established between VerifyPasswordCredentials (the shared
// check) and Login (which additionally mints the session). Returns the
// verified user (ID and Username only are guaranteed populated — see
// verifyMFAWireResponse in internal/storage/store for why nothing else is
// needed past this point) and whether a recovery code (rather than a TOTP
// code) was used.
// VerifyMFACredentials consumes the login challenge and verifies a TOTP or
// recovery code. The 3rd return value, consumedTOTPStep, is non-nil only when
// verification succeeded via a freshly-marked TOTP step (nil for a recovery
// code, or on any failure) — VerifyMFALogin uses it to release the step back
// (#2567) if a later, independent storage call (mintSession) fails after this
// one already succeeded, since the caller's code was never actually at
// fault.
//
// The fourth result is the login-budget slot the consumed challenge holds
// (CreateMFAChallengeHoldingLoginSlot), for VerifyMFALoginPending to hand to
// its LoginCompletion (#2936 item 4); nil whenever the error is non-nil.
func (c *KeyorixCore) VerifyMFACredentials(ctx context.Context, challenge, code string) (*models.User, bool, *int64, *uint, error) { // NOSONAR -- cognitive complexity 18, suppress go:S3776
	ch, err := c.storage.ConsumeMFAChallenge(ctx, sha256Hex(challenge), c.now())
	if err != nil {
		// A missing/expired/already-consumed challenge is ConsumeMFAChallenge's
		// expected, common negative result (a stale or guessed challenge token),
		// reported with the storage.ErrMFAChallengeInvalid sentinel. It is NOT a
		// storage-layer ambiguity and legitimately belongs in the per-IP
		// throttle's count — confirmed by FuzzLoginThrottleConcurrency's oracle
		// (a) (login_throttle_fuzz_test.go), which failed when this whole branch
		// was tagged with ErrMFAVerificationStorageFailure.
		//
		// Anything ELSE this call returns is a genuine storage failure, and it
		// lands BEFORE the submitted code has been looked at at all — the
		// earliest pre-verdict position on this path. It must therefore be
		// treated exactly like the GetUser branch directly below rather than
		// like a guessed challenge: the IP's login-attempt budget slot the
		// handler reserved before calling us (server/http/handlers/mfa.go's
		// VerifyMFA) is released on ErrMFAVerificationStorageFailure, and
		// ErrMFAVerificationUnavailable turns the response into a 503 "retry"
		// rather than a 401 that would claim a credential we never checked was
		// wrong. Without the split, a storage blip here silently spent one of
		// the IP's slots for a request that reached no verdict.
		//
		// This is the same sentinel-driven split FinishWebAuthnLogin
		// (internal/core/webauthn.go) already applies to its own
		// ConsumeMFAChallenge call via ErrWebAuthnLoginNotEvaluated — the MFA
		// path was the one login flow still missing it.
		if !errors.Is(err, storage.ErrMFAChallengeInvalid) {
			return nil, false, nil, nil, fmt.Errorf("%w: %w: consuming login challenge: %w",
				ErrMFAVerificationStorageFailure, ErrMFAVerificationUnavailable, err)
		}
		return nil, false, nil, nil, fmt.Errorf("invalid or expired challenge")
	}
	user, err := c.storage.GetUser(ctx, ch.UserID)
	if err != nil {
		// Same ambiguity as above: GetUser failing on a storage hiccup must not read
		// the same as "this challenge really does belong to no user."
		return nil, false, nil, nil, fmt.Errorf("%w: %w: user not found", ErrMFAVerificationStorageFailure, ErrMFAVerificationUnavailable)
	}
	// Completing a second factor still mints a login session, so a suspended or
	// deactivated account must be refused here too — the challenge may have been
	// issued (password step passed) just before an admin suspended the account, and
	// nothing rechecks the state between the two steps. Mirrors the password,
	// session, PAT, and passwordless-WebAuthn gates.
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, false, nil, nil, fmt.Errorf("account is not active")
	}
	// Per-account lockout also gates the second factor. The per-IP rate limiter is
	// spoofable behind a misconfigured proxy, and it is otherwise the ONLY online
	// throttle on TOTP/recovery-code guessing — binding failures to the account (keyed
	// by ch.UserID, which the attacker does not control) makes second-factor brute force
	// cost the same lockout as password brute force.
	if c.loginLocked(user) {
		return nil, false, nil, nil, fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	// storageErr tracks a genuine storage-read/write failure on either path below,
	// as distinct from a CONFIRMED negative result (wrong code / non-matching
	// recovery code). Fails closed the other direction from the rest of this
	// function's checks: a resolution error here must not be indistinguishable
	// from a legitimate negative result, mirroring roleSetContainsAdmin's own
	// documented precedent (internal/core/authz.go) — except that a false
	// ALLOW is never possible on this path (verified only ever becomes true from
	// a real, successfully-checked code), so the risk this guards against is a
	// false DENY that also falsely counts toward the account lockout and the
	// audit trail (docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md).
	verified, usedRecovery := false, false
	var storageErr error
	// codeMatched records that the submitted code was found CORRECT before a
	// later storage step failed: such a failure must not be reported as
	// "unavailable" (see ErrMFAVerificationUnavailable).
	codeMatched := false
	var consumedTOTPStep *int64 // non-nil iff verified via a freshly-marked TOTP step (#2567, see VerifyMFALogin)
	// Exactly one path evaluates a given input (#2894 review): see isTOTPShaped.
	totpShaped := isTOTPShaped(code)
	if totpShaped {
		if secret, err := c.loadTOTPSecret(ctx, ch.UserID); err != nil {
			storageErr = err
		} else if step, ok := c.validateTOTPStep(secret, code); ok {
			codeMatched = true
			// Single-use within the validity window: atomically advance the last-used
			// step. A code already accepted at this (or a later) step is a replay and
			// MarkTOTPStepUsed returns false, so it is rejected — closing the ~90s
			// replay window the bare totp validation left open.
			if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, ch.UserID, step); ferr != nil {
				storageErr = ferr
			} else if fresh {
				verified = true
				consumedTOTPStep = &step
			}
		}
	}
	if !verified && !totpShaped {
		// Only for input that cannot be a TOTP code. A six-digit input never
		// reaches here: a recovery code can never match it, and looking one up
		// anyway let a recovery-lookup fault turn a WRONG TOTP code into
		// "unavailable" (503, uncounted) while a CORRECT one whose anti-replay
		// mark failed stayed "invalid code" (401, counted) — the status code
		// answered "was the TOTP code right?" (#2894 review).
		if consumed, err := c.storage.ConsumeMFARecoveryCode(ctx, ch.UserID, sha256Hex(normalizeRecoveryCode(code)), c.now()); err != nil {
			storageErr = err
		} else if consumed {
			verified, usedRecovery, storageErr = true, true, nil
		}
	}
	if !verified {
		if storageErr != nil {
			// Always audited distinctly from a confirmed wrong code -- an
			// operator must be able to tell a storage hiccup apart from a
			// genuine bad guess.
			c.auditMFAError(ctx, ch.UserID, "login", storageErr)
			if !codeMatched {
				// Neither path could be conclusively evaluated: do NOT count it
				// toward the lockout -- this request never actually got a
				// verdict on whether its code was right, and its caller (the
				// HTTP handler) releases the login-attempt-rate-limit slot for
				// exactly this wrapped sentinel, for the same reason.
				return nil, false, nil, nil, fmt.Errorf("%w: %w: %s: %w", ErrMFAVerificationStorageFailure, ErrMFAVerificationUnavailable, i18n.T("ErrorRetrievalFailed", nil), storageErr)
			}
			// #2888 (#2740 option C extended to lockout/rate-limit bookkeeping,
			// not just the HTTP response): the code WAS confirmed correct here
			// -- only the anti-replay consumption write (MarkTOTPStepUsed)
			// failed. This must still count toward the lockout exactly like a
			// wrong code would, or the lockout/rate-limit timing becomes a side
			// channel confirming correctness even though the returned error and
			// the HTTP response are already identical either way.
			c.recordFailedLogin(ctx, user)
			return nil, false, nil, nil, fmt.Errorf("%w: %s: %w", ErrMFAVerificationStorageFailure, i18n.T("ErrorRetrievalFailed", nil), storageErr)
		}
		c.auditMFAFailed(ctx, ch.UserID, "login")
		c.recordFailedLogin(ctx, user) // count the failed second factor toward the lockout
		return nil, false, nil, nil, fmt.Errorf("invalid code")
	}
	// Cleared the second factor — but a concurrent burst of failed second-factor
	// attempts against this account may have tripped the lock since the
	// pre-verification snapshot check above (TOCTOU). Re-check under the same
	// serialization recordFailedLogin uses before minting a session. The
	// accumulated failure state is deliberately NOT cleared here (#2894): the
	// login still has a session to mint, a password-expiry gate to pass and an
	// identity payload to resolve, and a fault in any of those must cost the
	// attacker the same lockout progress a wrong code does — see LoginCompletion.
	if err := c.recheckLockAfterCredentialMatched(ctx, user, true); err != nil {
		return user, false, nil, nil, err
	}
	return user, usedRecovery, consumedTOTPStep, ch.LoginAttemptID, nil
}

// VerifyMFALogin consumes a challenge, verifies a TOTP code or a recovery code,
// and on success mints and returns the session (the second login step) together
// with the response identity.
//
// The identity is resolved BEFORE the session/step-up-token writes, and returned
// so the handler does not re-read it — see resolveLoginIdentityBeforeMint
// (#2841). This path is the TOTP sibling of the two WebAuthn login paths: it
// mints no MFAStepUpGrant, but it DOES write a user-scoped MFAStepupToken, which
// HasActiveMFAStepup reads per-user rather than per-session. A login reported as
// failed because the handler's identity read failed used to leave that token
// behind (completeLogin revoked only the session), so the restricted-secret MFA
// gate stayed satisfied for the rest of the window on a later session the user
// never completed a second factor for.
//
// Convenience wrapper over VerifyMFALoginPending for callers that own nothing
// further after this returns; every TRANSPORT must use the Pending form — see
// Login/LoginPending and LoginCompletion for why (#2894).
func (c *KeyorixCore) VerifyMFALogin(ctx context.Context, challenge, code, userAgent, ip string) (*models.Session, *models.User, UserIdentity, error) {
	session, user, identity, lc, err := c.VerifyMFALoginPending(ctx, challenge, code, userAgent, ip)
	if err != nil {
		return nil, user, UserIdentity{}, err
	}
	lc.Succeeded(ctx)
	return session, user, identity, nil
}

// VerifyMFALoginPending is VerifyMFALogin with the lockout accounting left open
// — the returned LoginCompletion MUST get Succeeded or Failed exactly once
// (#2894). On an error return the user is non-nil for every post-verdict
// failure, so a transport can name the account in its auth.login_error event.
func (c *KeyorixCore) VerifyMFALoginPending(ctx context.Context, challenge, code, userAgent, ip string) (*models.Session, *models.User, UserIdentity, *LoginCompletion, error) {
	user, usedRecovery, consumedTOTPStep, heldSlot, err := c.VerifyMFACredentials(ctx, challenge, code)
	if err != nil {
		if errors.Is(err, ErrLoginPostVerdict) {
			// The code matched and the lock recheck faulted: name the account so
			// the transport can audit auth.login_error (#2894 review).
			return nil, user, UserIdentity{}, nil, err
		}
		return nil, nil, UserIdentity{}, nil, err
	}
	// Apply the same password-expiry hard gate as the non-MFA login path (ADR-025).
	// Idempotent: the gate is a no-op when the state is already password_reset_required
	// (set during the initial credential check for MFA-enabled accounts).
	if err := c.enforcePasswordExpiryGate(ctx, user); err != nil {
		// The code was already confirmed correct, so this is a post-verdict storage
		// fault (#2894) — counted toward the lockout exactly like a wrong code.
		return nil, user, UserIdentity{}, nil, c.denyAfterCredentialMatched(ctx, user, err)
	}
	// #2841: the LAST fallible-and-reported read, done BEFORE the session and
	// step-up-token writes. Not "before the first write" — the TOTP step mark and
	// the password-expiry gate write earlier; what matters is that nothing
	// fallible runs AFTER the writes that outlive a login reported as failed.
	// #2894: the code matched, so a failure here is post-verdict — counted toward
	// the lockout exactly like a wrong code, and wrapped with ErrLoginPostVerdict
	// so the transport answers byte-identically to a wrong code and audits
	// auth.login_error. It also keeps ErrLoginIdentityUnavailable in the chain.
	identity, err := c.resolveLoginIdentityBeforeMint(ctx, user.ID)
	if err != nil {
		return nil, user, UserIdentity{}, nil, c.denyAfterCredentialMatched(ctx, user, err)
	}
	lc := c.newLoginCompletion(user)
	lc.holdLoginSlots(heldSlot)
	session, err := c.mintSession(ctx, user.ID, userAgent, ip)
	if err != nil {
		// #2567: VerifyMFACredentials already consumed the TOTP step (anti-replay)
		// before this, independent mintSession/CreateSession call. A failure here
		// has nothing to do with whether the code was right, but the caller is
		// left unable to retry with the SAME correct code until the next 30s
		// time-step — give the step back. Best-effort and CAS-guarded (releases
		// only if nothing else has since advanced the step further): a release
		// failure must not mask the real mintSession error, and must never
		// retroactively weaken anti-replay for a step a LATER request already
		// legitimately consumed.
		if consumedTOTPStep != nil {
			if _, rerr := c.storage.ReleaseTOTPStepIfUnchanged(ctx, user.ID, *consumedTOTPStep); rerr != nil {
				log.Printf("VerifyMFALogin: failed to release TOTP step after mintSession failure for user %d: %v", user.ID, rerr)
			}
		}
		// #2894: the code matched, so count this exactly as a wrong code would be
		// counted, and mark it post-verdict so VerifyMFA audits auth.login_error.
		// Note what is deliberately NOT done here: the per-IP login-attempt slot
		// stays CONSUMED (the handler releases only for ErrMFAVerificationUnavailable),
		// because a wrong code keeps its slot too.
		lc.Failed(ctx)
		return nil, user, UserIdentity{}, nil, fmt.Errorf("%w: %w", ErrLoginPostVerdict, err)
	}
	// Record the MFA step-up window when the classification gate requires it.
	// Best-effort: a write failure does not block the login, but the user won't
	// be able to read restricted secrets until they re-verify successfully.
	// Panic-safe too: it runs after the session is written, so an escaping
	// panic would report a failed login with a live session behind it (#2844).
	if c.classificationRestrictedRequiresMFAStepUp {
		besteffort.Run(ctx, "mfa.VerifyMFALogin.UpsertMFAStepupToken", func() error {
			return c.storage.UpsertMFAStepupToken(ctx, user.ID, c.now().Add(c.mfaStepUpWindow()))
		})
	}
	uid := user.ID
	if usedRecovery {
		c.writeAuditEventFull(ctx, "mfa.recovery_used", &uid, nil, nil, ip, fmt.Sprintf("user %s used a recovery code", user.Username))
	}
	c.writeAuditEventFull(ctx, "mfa.login_verified", &uid, nil, nil, ip, fmt.Sprintf("user %s passed MFA", user.Username))
	return session, user, identity, lc, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func (c *KeyorixCore) loadTOTPSecret(ctx context.Context, userID uint) (string, error) {
	row, err := c.storage.GetMFASecret(ctx, userID)
	if err != nil {
		return "", err
	}
	return c.decryptAuthSecret(row.SecretEnc, row.SecretMeta, ports.MFASecretAAD(userID))
}

// isTOTPShaped reports whether code can be a TOTP code at all: exactly six
// ASCII digits after trimming, the only shape validateTOTPStep can match.
// generateRecoveryCodes' codes normalize to ten characters, so the two shapes
// are disjoint and every input has exactly one path that can verify it. The
// MFA verifiers route on this so that a fault on the OTHER path can never
// change the verdict a conclusive check already reached (#2894 review).
func isTOTPShaped(code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// totpPeriod is the TOTP step length in seconds.
const totpPeriod = 30

// validateTOTPStep verifies code against the current step and ±1 skew and, on a match,
// returns the matched time-step (unix/period) so the caller can enforce single-use
// (anti-replay). Unlike validateTOTP it identifies WHICH step matched.
func (c *KeyorixCore) validateTOTPStep(secret, code string) (int64, bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return 0, false
	}
	now := c.now().UTC()
	for _, delta := range []int64{0, -1, 1} {
		t := now.Add(time.Duration(delta*totpPeriod) * time.Second)
		expected, err := totp.GenerateCodeCustom(secret, t, totp.ValidateOpts{
			Period: totpPeriod, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return t.Unix() / totpPeriod, true
		}
	}
	return 0, false
}

func (c *KeyorixCore) auditMFAFailed(ctx context.Context, userID uint, phase string) {
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.failed", &uid, nil, nil, "", fmt.Sprintf("failed MFA %s for user %d", phase, userID))
}

// auditMFAError records that an MFA attempt could not be conclusively evaluated
// due to a storage failure — distinct from auditMFAFailed's "a code was checked
// and found wrong": this attempt never actually got a verdict, so it must not
// read, on review, as the same thing a genuine wrong-code attempt would
// (docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md).
func (c *KeyorixCore) auditMFAError(ctx context.Context, userID uint, phase string, err error) {
	uid := userID
	c.writeAuditEventFull(ctx, "mfa.error", &uid, nil, nil, "",
		fmt.Sprintf("MFA %s for user %d could not be evaluated (storage error): %v", phase, userID, err))
}

// requireReauth is the shared self-service re-authentication gate (#372) for
// account-security-factor changes. Every caller (DisableMFA,
// RegenerateMFARecoveryCodes, ActivateMFA, FinishWebAuthnRegistration,
// DeleteWebAuthnCredential, UpdateOwnProfile's email-change path) is reachable
// with nothing but a bearer token — a stolen session OR a narrowly-scoped PAT,
// which ADR-042 exempts from MFA policy entirely — so this check is the only thing
// standing between a leaked bearer and a full account-security-factor takeover.
//
// Once a second factor is enrolled (user.MFAEnabled or user.WebAuthnEnabled), the
// account password ALONE is no longer sufficient proof — accepting it would let a
// bearer-token thief satisfy "step-up" re-auth with nothing but a password,
// defeating the entire point of requiring a SECOND factor. In that case the
// caller must additionally prove they still hold the second factor, via one of:
//
//  1. codeOrPassword is itself a CURRENT, currently-valid TOTP code, checked
//     directly against the already-active secret (only possible when
//     user.MFAEnabled — never against an in-flight, not-yet-activated
//     enrolment secret, which an attacker who just called
//     BeginMFAEnrollment/BeginWebAuthnRegistration themselves would already
//     know). Anti-replay via MarkTOTPStepUsed, same as VerifyMFACredentials —
//     this branch never persists a grant at all, so it is inherently
//     single-use per call: MarkTOTPStepUsed marks the matched time-step used
//     immediately, and a second requireReauth call presenting the identical
//     code fails this branch outright (falls through toward the password
//     branch below, empty-handed). A TOTP-enrolled account therefore already
//     needs a FRESH code for every subsequent sensitive action — there is no
//     separate TOTP "step-up grant" mechanism that mints a reusable
//     MFAStepUpPurposeReauth token; VerifyMFAStepUp exists but mints the
//     distinct MFAStepUpPurposeRestrictedSecretRead purpose for the
//     classification gate only, and is never consulted here.
//  2. codeOrPassword is the correct account password AND the user separately
//     holds an active MFA step-up grant with Purpose ==
//     MFAStepUpPurposeReauth (ConsumeMFAStepUpGrant) — an independent,
//     time-limited proof that they recently re-verified their second factor
//     FOR THIS SPECIFIC PURPOSE. A passkey assertion has no typable "code" to
//     hand this function directly, so a WebAuthn-only account proves this via
//     FinishWebAuthnReauth (a fresh, live passkey assertion performed at the
//     time of the sensitive action — see webauthn.go), not merely by having
//     logged in recently. An ordinary login (VerifyMFALogin/FinishWebAuthnLogin/
//     FinishWebAuthnPasswordlessLogin) mints only a
//     MFAStepUpPurposeRestrictedSecretRead grant, which does NOT satisfy this
//     branch — a purpose-agnostic grant would let anyone holding a merely
//     leaked bearer token (plus the password) ride the account owner's own
//     earlier login to authorize an account-security-factor takeover, which is
//     exactly the confused-deputy bug this purpose separation closes.
//     ConsumeMFAStepUpGrant atomically consumes the grant it accepts (unlike
//     the read-only HasActiveMFAStepUp used by the restricted-secret-read
//     gate), so this is also single-use: the SAME live grant satisfies at
//     most ONE sensitive action, never a second, different one within its
//     window — closing the blast radius a purely-additive Purpose field left
//     open (one passkey touch must not open a 15-minute window good for
//     disabling MFA, deleting every WebAuthn credential, regenerating
//     recovery codes, AND changing the account email, all chained together).
//
// With no second factor enrolled at all, the account password alone remains
// sufficient re-auth — unchanged from before this check existed.
//
// Feeds the same per-account lockout the second login factor (VerifyMFALogin)
// uses, keyed by user (not IP, since this is an authenticated-session endpoint):
// without it, this check would be the only throttle on guessing. phase labels the
// mfa.failed audit event on a failed attempt.
//
// atomicity: consume-first by design (Session O, O4) — the TOTP step, or the
// MFAStepUpGrant, is consumed as PART OF verification itself (there is no
// separate later "issue" step to fail after): a return of nil here already
// means the consume succeeded AND the caller may proceed; an error already
// means nothing was consumed successfully. Existing single-use coverage:
// TestRequireReauth_GrantConsumedOnFirstAction_SecondDifferentActionRejected
// and its siblings (mfa_stepup_grant_single_use_test.go).
func (c *KeyorixCore) requireReauth(ctx context.Context, user *models.User, codeOrPassword, phase string) error {
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	secondFactorEnrolled := user.MFAEnabled || user.WebAuthnEnabled
	ok := false
	// storageErr tracks a genuine storage-read failure that happened BEFORE any
	// code or password was evaluated (only loading the TOTP secret), as distinct
	// from a CONFIRMED negative result (wrong code/password), mirroring
	// VerifyMFACredentials' own storageErr handling (#2548 sibling, found during
	// the FIX-1 sweep): a resolution error here must not be indistinguishable
	// from a legitimate negative result, or it both wrongly reports "invalid
	// code or password" and wrongly counts toward the account lockout for a
	// code/password that was never actually checked. Once set, storageErr takes
	// precedence in the final verdict below even if the OTHER path (TOTP vs.
	// password+step-up-grant) independently produced a clean negative result --
	// same precedence VerifyMFACredentials already uses between its TOTP and
	// recovery-code paths.
	//
	// postVerdictErr (#2888 round 2) is the DIFFERENT case: the code or password
	// WAS confirmed correct, and a SUBSEQUENT write (the anti-replay mark, or
	// consuming the step-up grant) failed. The response must still stay
	// identical to a wrong code/password (#2740 option C) -- but unlike
	// storageErr, this must still count toward the lockout, exactly like a
	// genuine wrong guess, and is audited as mfa.error (not mfa.failed) rather
	// than silently discarded, so an operator can still tell the two apart. An
	// earlier version of this function discarded MarkTOTPStepUsed/
	// ConsumeMFAStepUpGrant's own error entirely to achieve the identical
	// response -- which also meant a correct guess whose consumption write
	// happened to fail went completely unaudited as anything OTHER than a
	// confirmed wrong answer, the exact ambiguity storageErr exists to avoid in
	// the other direction.
	var storageErr, postVerdictErr error
	if user.MFAEnabled {
		if secret, err := c.loadTOTPSecret(ctx, user.ID); err != nil {
			storageErr = err
		} else if step, matched := c.validateTOTPStep(secret, codeOrPassword); matched {
			// Use the same anti-replay path as VerifyMFACredentials: identify the
			// matched time-step and atomically mark it used so a stolen code cannot
			// be replayed within the ±1 step (~90 s) window.
			if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, user.ID, step); ferr != nil {
				postVerdictErr = ferr
			} else if fresh {
				ok = true
			}
		}
	}
	if !ok && codeOrPassword != "" && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(codeOrPassword)) == nil {
		if !secondFactorEnrolled {
			ok = true
		} else if consumed, gerr := c.storage.ConsumeMFAStepUpGrant(ctx, user.ID, models.MFAStepUpPurposeReauth, c.authEffectiveNow()); gerr != nil {
			postVerdictErr = gerr
		} else if consumed {
			// The password is correct AND the caller independently proved they
			// still hold the enrolled second factor recently, FOR THIS PURPOSE —
			// password alone would not be enough on its own, but password + a
			// fresh, genuine reauth-purpose step-up grant is equivalent proof to
			// supplying the code directly. A restricted-secret-read-purpose grant
			// (minted ambiently by login) does not match and is rejected here.
			//
			// ConsumeMFAStepUpGrant (not the non-consuming HasActiveMFAStepUp) is
			// deliberate: accepting the grant here also atomically marks it
			// consumed (a conditional UPDATE ... WHERE consumed_at IS NULL,
			// mirroring ConsumeMFARecoveryCode/ConsumeWebAuthnSession), so the
			// SAME live grant from one passkey touch or TOTP-adjacent reauth
			// cannot go on to satisfy a SECOND, different sensitive action within
			// its ~15-minute window. Without this, one proof would open a single
			// window good for disabling MFA, deleting every WebAuthn credential,
			// regenerating recovery codes, AND changing the account email, all
			// chained off the same grant.
			ok = true
		}
	}
	if !ok {
		if storageErr != nil {
			// Neither path could be conclusively evaluated — do NOT audit as a
			// failed attempt and do NOT count it toward the lockout: this request
			// never actually got a verdict on whether its code/password was right.
			c.auditMFAError(ctx, user.ID, phase, storageErr)
			return fmt.Errorf("%w: %s: %w", ErrMFAVerificationStorageFailure, i18n.T("ErrorRetrievalFailed", nil), storageErr)
		}
		if postVerdictErr != nil {
			// The code/password WAS confirmed correct; only a subsequent
			// consumption write failed. Audited distinctly for an operator, but
			// still counts toward the lockout and returns the SAME generic error
			// as a genuine wrong code/password (#2888, #2740 option C extended to
			// lockout bookkeeping): a correct guess must never be cheaper,
			// lockout-wise, than a wrong one.
			c.auditMFAError(ctx, user.ID, phase, postVerdictErr)
			c.recordFailedLogin(ctx, user)
			return fmt.Errorf("invalid code or password")
		}
		c.auditMFAFailed(ctx, user.ID, phase)
		c.recordFailedLogin(ctx, user) // count the failed re-auth attempt toward the lockout
		return fmt.Errorf("invalid code or password")
	}
	c.clearLoginFailures(ctx, user)
	uid := user.ID
	c.writeAuditEventFull(ctx, "mfa.reauth_verified", &uid, nil, nil, "",
		fmt.Sprintf("user %s completed MFA re-authentication (phase: %s)", user.Username, phase))
	return nil
}

// generateRecoveryCodes returns n human-friendly codes and their SHA-256 hashes.
func generateRecoveryCodes(n int) (codes, hashes []string, err error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous 0/O/1/I
	for i := 0; i < n; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		var sb strings.Builder
		for j, x := range b {
			if j == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, sha256Hex(normalizeRecoveryCode(code)))
	}
	return codes, hashes, nil
}

// normalizeRecoveryCode makes entry forgiving: upper-cased, dash/space-stripped.
func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}
