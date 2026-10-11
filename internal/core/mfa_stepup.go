// mfa_stepup.go — explicit MFA step-up verification for an already-authenticated
// user. Allows re-verifying a TOTP code (or recovery code) without going through
// re-login, creating an MFAStepUpGrant that satisfies the
// checkRestrictedMFAGate for reading "restricted" classified secrets.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// VerifyMFAStepUp verifies a TOTP code (or recovery code) for an authenticated
// user and, on success, creates an MFAStepUpGrant that enables reading
// restricted secrets for the configured window (default 15 min).
// Mirrors the TOTP-path of VerifyMFACredentials: loadTOTPSecret +
// validateTOTPStep + MarkTOTPStepUsed for anti-replay, recovery-code fallback,
// and the same per-account lockout the login second factor feeds.
func (c *KeyorixCore) VerifyMFAStepUp(ctx context.Context, userID uint, code string) error {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !user.IsActive || AccountLoginBlocked(user.ID, user.AccountState) {
		return fmt.Errorf("account is not active")
	}
	if c.loginLocked(user) {
		return fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
	}
	if !user.MFAEnabled {
		return fmt.Errorf("MFA is not enabled on this account; enrol with 'keyorix mfa enroll' first")
	}

	// storageErr distinguishes a genuine storage-read/write failure from a
	// CONFIRMED negative result (wrong code / non-matching recovery code),
	// mirroring VerifyMFACredentials' own storageErr handling (#2548): a
	// resolution error here must not be indistinguishable from a legitimate
	// negative result, or it both wrongly reports "invalid code" and wrongly
	// counts toward the account lockout for a code that was never actually
	// checked. verifyMFAStepUpCode used to collapse both cases into a single
	// bool, which is exactly the bug #2548 fixed for the login path but never
	// reached here — this is that same sibling, found during the FIX-1 sweep.
	verified, storageErr := c.verifyMFAStepUpCode(ctx, userID, code)
	if !verified {
		if storageErr != nil {
			c.auditMFAError(ctx, userID, "stepup", storageErr)
			// #2888 (#2740 option C extended to lockout bookkeeping): when the
			// code WAS confirmed correct and only a subsequent write (the
			// anti-replay mark) failed, verifyMFAStepUpCode does NOT wrap this
			// error with ErrMFAVerificationUnavailable (unlike the genuinely
			// pre-verdict case) -- that is exactly the signal used here to still
			// count it toward the lockout, same as a wrong code would be. A
			// correct guess must never be cheaper, lockout-wise, than a wrong one.
			if !errors.Is(storageErr, ErrMFAVerificationUnavailable) {
				c.recordFailedLogin(ctx, user)
			}
			return fmt.Errorf("%w: %s: %w", ErrMFAVerificationStorageFailure, i18n.T("ErrorRetrievalFailed", nil), storageErr)
		}
		c.auditMFAFailed(ctx, userID, "stepup")
		c.recordFailedLogin(ctx, user)
		return fmt.Errorf("invalid code")
	}

	// From here on the submitted code has been found CORRECT (and consumed). Every
	// failure now is post-verdict (ErrLoginPostVerdict), which the handler answers
	// byte-for-byte like a wrong code and never echoes (#2947): a different
	// message (the raw storage error, "unable to verify account lock state",
	// "failed to record MFA step-up") would confirm a correct guess and expose
	// storage detail. The real cause goes to the server log; the denial is
	// counted like a wrong code and audited mfa.error (#2894 review; the
	// stepup/CreateMFAStepUpGrant row of oracleAByDesignErrors lists that
	// AuditEvent).
	//
	// TOCTOU re-check only — the failure state is NOT cleared here (#2894): the
	// step-up grant below is still to be written, and a fault there denies the
	// step-up while leaving the counter at 0, making a CORRECT code the cheaper
	// probe than a wrong one. See LoginCompletion.
	if err := c.recheckLockAfterCredentialMatched(ctx, user, true); err != nil {
		if errors.Is(err, ErrLoginPostVerdict) {
			log.Printf("SECURITY: MFA step-up for user %d: code verified but the lockout re-check failed (reported to the caller as an invalid code): %v", userID, err)
			// Counted already; audited here, synchronously like the wrong-code
			// branch's mfa.failed, so an operator sees the fault (#2894 review).
			c.auditMFAError(ctx, userID, "stepup", err)
			return err
		}
		// The recheck found the account locked by a concurrent burst. Answer
		// exactly like a wrong code (#2894 review): a wrong code at this moment
		// gets "invalid code" too, and its recordFailedLogin is a no-op on a
		// locked account, so both cost the same and read the same.
		c.auditMFAFailed(ctx, userID, "stepup")
		return fmt.Errorf("invalid code")
	}

	grant := &models.MFAStepUpGrant{
		UserID:    userID,
		Purpose:   models.MFAStepUpPurposeRestrictedSecretRead,
		ExpiresAt: c.now().Add(c.mfaStepUpWindow()),
	}
	if err := c.storage.CreateMFAStepUpGrant(ctx, grant); err != nil {
		log.Printf("SECURITY: MFA step-up for user %d: code verified but the grant could not be recorded (reported to the caller as an invalid code): %v", userID, err)
		// #2894: the code already verified, so count this post-verdict storage
		// fault exactly as a wrong code would be counted (recordFailedLogin above).
		perr := c.denyAfterCredentialMatched(ctx, user, fmt.Errorf("failed to record MFA step-up: %w", err))
		c.auditMFAError(ctx, userID, "stepup", perr)
		return perr
	}
	c.clearLoginFailures(ctx, user)
	uid := userID
	c.writeAuditEvent(ctx, "mfa.stepup_verified", &uid, nil,
		fmt.Sprintf("user %d completed MFA step-up for restricted secret access", userID))
	return nil
}

// atomicity: consume-first by design (Session O, O4) — the TOTP step (or
// recovery code) is consumed BEFORE VerifyMFAStepUp creates the
// MFAStepUpGrant. A later grant-creation failure must not un-consume it:
// verified by TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed
// (consume_first_fails_closed_test.go), which injects a CreateMFAStepUpGrant
// failure after a successful consume and confirms no grant is issued and the
// code stays consumed.
//
// verifyMFAStepUpCode checks code against the user's TOTP secret, falling
// back to a recovery code, mirroring the login second-factor verification.
// Returns (true, nil) on a confirmed match, (false, nil) on a confirmed
// negative result (the code genuinely doesn't match either path), and
// (false, err) on a storage failure -- err is wrapped with
// ErrMFAVerificationUnavailable only when NEITHER path reached a verdict at
// all (codeMatched stays false); the caller (VerifyMFAStepUp) uses exactly
// that wrap to decide whether to count the attempt toward the lockout (#2888
// round 2: a code confirmed correct, with only its anti-replay MarkTOTPStepUsed
// write failing, still counts, exactly like a wrong code would -- it must
// never be cheaper, lockout-wise, than a genuine bad guess, even though the
// RESPONSE this produces is already identical to a wrong code either way).
// The input's shape picks the one path that can verify it (isTOTPShaped), so
// a failed TOTP secret read never preempts a valid recovery code, and a
// recovery-lookup fault never overrides a conclusive TOTP verdict.
func (c *KeyorixCore) verifyMFAStepUpCode(ctx context.Context, userID uint, code string) (bool, error) {
	var storageErr error
	codeMatched := false // see VerifyMFACredentials / ErrMFAVerificationUnavailable
	// Exactly one path evaluates a given input, as in VerifyMFACredentials: a
	// six-digit code gets its verdict from the TOTP path alone, so a recovery-
	// lookup fault cannot make a wrong TOTP code read differently from a correct
	// one (#2894 review). See isTOTPShaped.
	if isTOTPShaped(code) {
		if secret, serr := c.loadTOTPSecret(ctx, userID); serr != nil {
			storageErr = serr
		} else if step, ok := c.validateTOTPStep(secret, code); ok {
			codeMatched = true
			if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, userID, step); ferr != nil {
				storageErr = ferr
			} else if fresh {
				return true, nil
			}
		}
	} else {
		consumed, cerr := c.storage.ConsumeMFARecoveryCode(ctx, userID, sha256Hex(normalizeRecoveryCode(code)), c.now())
		if cerr != nil {
			storageErr = cerr
		} else if consumed {
			return true, nil
		}
	}
	if storageErr != nil && !codeMatched {
		storageErr = fmt.Errorf("%w: %w", ErrMFAVerificationUnavailable, storageErr)
	}
	return false, storageErr
}

// HasActiveMFAStepUp reports whether userID holds a current, unexpired step-up
// grant for the exact purpose given. Returns (false, nil) — not an error —
// when no matching grant exists. purpose is not optional: a grant minted for
// one purpose (e.g. restricted-secret reads) must never be read as
// authorizing a different one (e.g. an account-security-factor change).
func (c *KeyorixCore) HasActiveMFAStepUp(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose) (bool, error) {
	grant, err := c.storage.GetActiveMFAStepUpGrant(ctx, userID, purpose, c.authEffectiveNow())
	if err != nil {
		return false, err
	}
	return grant != nil, nil
}

// DefaultMFAStepUpGrantRetention is the fallback MFAStepUpGrant retention
// window (config.ClassificationConfig.MFAStepUpGrantRetentionDays, 0 = this
// default) used when PruneMFAStepUpGrants is called with a non-positive
// retention.
const DefaultMFAStepUpGrantRetention = 30 * 24 * time.Hour

// PruneMFAStepUpGrants removes MFAStepUpGrant rows that expired more than
// `retention` ago (retention <= 0 falls back to
// DefaultMFAStepUpGrantRetention). `before`, when non-zero and EARLIER than
// the retention-derived cutoff, narrows the deletion window further —
// mirroring PruneLoginAttempts's clamp (CORE-RATE-003): the effective cutoff
// can never be LATER than now-retention, so a caller (originally including
// server/http/handlers/mfa_stepup_proxy.go's PruneMFAStepUpGrantsProxy,
// deleted along with the rest of the /system tier, ADR-108; server/main.go's
// store-mfa-002 scheduler is the live caller today) can only narrow the
// window, never widen it into an unbounded wipe. Returns
// the number of rows removed.
//
// Unlike PruneLoginAttempts, this does NOT emit an audit event. LoginAttempt
// rows are themselves the sole record that a login/rate-limit event ever
// happened, so PruneLoginAttempts audits every deletion (mirroring
// PurgeExpiredSoftDeletes/PurgeExpiredComplianceRecords). An MFAStepUpGrant
// row is different: its CREATION is already permanently, independently
// audited (VerifyMFAStepUp emits mfa.stepup_verified, and audit events are
// append-only / never purged — ADR-029), so the grant row itself is a
// short-lived operational copy, not the sole evidentiary record. Losing N of
// these to routine maintenance is unremarkable; a log line is proportionate
// to the lower stakes.
func (c *KeyorixCore) PruneMFAStepUpGrants(ctx context.Context, retention time.Duration, before time.Time) (int64, error) {
	if retention <= 0 {
		retention = DefaultMFAStepUpGrantRetention
	}
	cutoff := c.now().Add(-retention)
	if !before.IsZero() && before.Before(cutoff) {
		cutoff = before
	}

	n, err := c.storage.PruneMFAStepUpGrants(ctx, cutoff)
	if err != nil {
		return n, err
	}
	if n > 0 {
		log.Printf("MFA step-up grant prune removed %d row(s) expired before %s", n, cutoff.UTC().Format(time.RFC3339))
	}
	return n, nil
}
