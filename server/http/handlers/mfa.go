// mfa.go — HTTP handlers for TOTP MFA: self-service enrol/activate/disable
// (authenticated) and the public two-step login verify.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// EnrollMFA begins TOTP enrolment for the authenticated caller and returns the
// otpauth:// provisioning URI (for a QR code) plus the base32 secret.
func (h *AuthHandler) EnrollMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	uri, secret, err := h.coreService.BeginMFAEnrollment(r.Context(), userCtx.UserID)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"otpauth_uri": uri,
		"secret":      secret,
	}, "Scan the QR code in your authenticator app, then activate with a code.")
}

// ActivateMFA confirms enrolment with a TOTP code and returns the one-time-shown
// recovery codes. Requires the account password to re-authenticate the caller
// (#372): code alone proves control of the just-generated pending secret, which an
// attacker with a stolen session or PAT could have generated themselves via
// EnrollMFA, so it is not proof this is really the account holder.
func (h *AuthHandler) ActivateMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	token := extractBearerToken(r)
	codes, err := h.coreService.ActivateMFA(r.Context(), userCtx.UserID, body.Code, body.Password, token)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	message := "MFA enabled. Save these recovery codes now — they will not be shown again."
	ended := h.endSetupSessionIfComplete(w, r, userCtx.UserID, token)
	if ended {
		message += " Account setup is complete: sign in again with your password and a code."
	}
	sendSuccess(w, map[string]interface{}{
		"recovery_codes":            codes,
		"reauthentication_required": ended,
	}, message)
}

// DisableMFA turns off MFA after verifying a current code or the password.
func (h *AuthHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	proof := body.Code
	if proof == "" {
		proof = body.Password
	}
	if err := h.coreService.DisableMFA(r.Context(), userCtx.UserID, proof, extractBearerToken(r)); err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{"mfa_enabled": false}, "MFA disabled")
}

// RegenerateRecoveryCodes issues a fresh set of recovery codes (replacing the old
// ones) after verifying a current TOTP code or the password. The codes are returned
// once and never shown again.
func (h *AuthHandler) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	proof := body.Code
	if proof == "" {
		proof = body.Password
	}
	codes, err := h.coreService.RegenerateMFARecoveryCodes(r.Context(), userCtx.UserID, proof)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"recovery_codes": codes,
	}, "New recovery codes generated. Save them now — they replace your old codes and will not be shown again.")
}

// RecoveryCodesStatus reports how many unused recovery codes remain (and the total),
// so the account UI can prompt a regenerate when the user is running low.
func (h *AuthHandler) RecoveryCodesStatus(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	remaining, total, err := h.coreService.MFARecoveryCodesRemaining(r.Context(), userCtx.UserID)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"remaining": remaining,
		"total":     total,
	}, "")
}

// VerifyMFA completes the two-step login: it consumes the challenge from
// /auth/login, verifies the TOTP (or recovery) code, and returns a session.
func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		Challenge string `json:"mfa_challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	// F2 (2026-09-20): reserve before the (slow) TOTP/recovery-code check —
	// see reserveLoginAttempt's doc (reserved after decode, matching Login).
	//
	// CR3 (2026-10-02): unlike every sibling reserveLoginAttempt call site, this
	// one releases the reservation below when VerifyMFALogin fails with
	// core.ErrMFAVerificationStorageFailure — a storage/internal error never
	// reaches a verdict on the code at all, so it must not consume the same
	// budget slot a genuine wrong guess (or a success) does. Found by the
	// fuzzer reserving before ANY of VerifyMFACredentials' storage calls run,
	// so a fault on the FIRST one (e.g. GetUser, CI seed 877139548d2805a6)
	// already shows the same orphaned-LoginAttempt-row symptom GetMFASecret's
	// finding did — see docs/findings/2026-10-02-FINDING-mfa-login-getmfasecret-storage-error-counted-as-wrong-code.md.
	attemptID, reserved := h.coreService.ReserveLoginAttempt(r.Context(), ip)
	// CR3's release-on-error only covers a RETURNED storage error; a PANIC inside
	// VerifyMFALogin (e.g. ConsumeMFAChallenge#1/panic, FuzzStorageFaultOperations)
	// skips the err!=nil branch below entirely, bypassing ReleaseLoginAttempt the exact
	// same way the CR3 finding did — see FinishWebAuthnLogin's identical sibling fix
	// (webauthn.go) for the full reasoning; this is the same release-only-pre-verdict
	// rule applied to VerifyMFA's own reservation.
	//
	// #2841: the wrapper forwards the response identity core now resolves BEFORE
	// the session/step-up-token writes, so there is exactly ONE call to
	// VerifyMFALogin on this path — re-reading the identity in the handler would
	// reopen the very window this fix closed.
	session, user, identity, lc, err := h.verifyMFALoginReleasingOnPanic(r.Context(), body.Challenge, body.Code, r.Header.Get("User-Agent"), ip, reserved, attemptID)
	if err != nil {
		// FIX-1 (#2548) + #2740 review (option C), #2888 round 2: 503 "retry" and
		// the reservation release are BOTH ONLY for ErrMFAVerificationUnavailable
		// -- the genuinely pre-verdict case (the code was never evaluated at
		// all). ErrMFAVerificationStorageFailure WITHOUT that wrap means the
		// code WAS found correct and only a later write (the anti-replay mark)
		// failed; releasing the slot for THAT case was the actual bug: a wrong
		// code always keeps its slot consumed, so a correct-code-but-write-
		// failed attempt releasing its slot was a side channel confirming
		// correctness, observable by watching when 429s start -- regardless of
		// this response's own status/body already matching the wrong-code case.
		if errors.Is(err, core.ErrMFAVerificationUnavailable) {
			if reserved {
				h.coreService.ReleaseLoginAttempt(r.Context(), attemptID)
			}
			sendError(w, "ServiceUnavailable", errMFAVerificationUnavailable, http.StatusServiceUnavailable, nil)
			return
		}
		// #2894: a storage fault AFTER the code matched (the password-expiry gate,
		// or the session mint) reaches here with the SAME 401 body a wrong code
		// gets, and core has already counted it toward the lockout exactly as a
		// wrong code would be -- but it must not be invisible in the audit trail.
		// Previously this branch wrote NO audit event at all for a mintSession
		// failure; now it writes auth.login_error, the operator-only half of the
		// #2888 split. user is non-nil for every post-verdict failure.
		if errors.Is(err, core.ErrLoginPostVerdict) && user != nil {
			username := user.Username
			goSafe(func() { h.coreService.LogAuthError(context.Background(), username, ip, err) }) // #nosec G118
		}
		// #2841 + #2894: the identity read now happens inside core, before the
		// session and the user-scoped step-up token are written, and a failure
		// there is post-verdict (ErrLoginPostVerdict wrapping
		// ErrLoginIdentityUnavailable): counted like a wrong code, audited above,
		// and answered with the SAME 401 a wrong code gets — not the 500
		// completeLogin used to send, which would confirm the code was right
		// (#2888). The attempt reservation stays counted (#2880).
		sendError(w, "Unauthorized", "Invalid or expired code", http.StatusUnauthorized, nil)
		return
	}
	resp := h.completeLoginWithIdentity(w, r, session, user, identity, lc)
	// #2936: the session is delivered, so this step's slot goes back. The
	// password step's slot, bound to the challenge, went back inside core
	// (LoginCompletion.Succeeded), so a delivered MFA login costs no slot. The
	// one exception is a password-step slot the in-memory fallback took: it is
	// never bound to the shared challenge row (sharedLoginSlot), so it stays
	// counted until it ages out.
	h.returnLoginSlot(r.Context(), loginSlot{id: attemptID, ok: reserved})
	goSafe(func() {
		h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, r.Header.Get("User-Agent"))
	}) // #nosec G118
	goSafe(func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }) // #nosec G118
	sendSuccess(w, resp, "Login successful")
}

// verifyMFALoginReleasingOnPanic calls core.VerifyMFALogin, releasing the reserved
// login-attempt slot and re-panicking unchanged if the call panics instead of
// returning — see VerifyMFA's call-site comment, and FinishWebAuthnLogin's identical
// sibling (webauthn.go), for why this exists.
//
// #2841: it forwards all of VerifyMFALoginPending's results, including the
// response identity core resolves before its session/step-up-token writes. The
// wrapper is deliberately transparent: it adds the release-on-panic side effect
// and changes nothing else. The recover() re-panics with the ORIGINAL value, so a
// panic is never converted into a "success" and never swallowed — the slot is
// released and the panic continues to the recovery middleware.
//
// #3048: it releases ONLY while the code had not been evaluated yet
// (core.LoginVerdict). A panic after the code matched is a post-verdict fault
// like any other: the slot stays counted, as it does when the same fault comes
// back as an error (#2880), or a correct code would cost less than a wrong one.
func (h *AuthHandler) verifyMFALoginReleasingOnPanic(ctx context.Context, challenge, code, userAgent, ip string, reserved bool, attemptID uint) (session *models.Session, user *models.User, identity core.UserIdentity, lc *core.LoginCompletion, err error) {
	ctx, verdict := core.WithLoginVerdict(ctx)
	defer func() {
		if rec := recover(); rec != nil {
			if reserved && !verdict.Reached() {
				h.coreService.ReleaseLoginAttempt(ctx, attemptID)
			}
			panic(rec)
		}
	}()
	// Pending form: VerifyMFA's own completeLoginWithIdentity call commits the
	// accounting (#2894). A panic here leaves the counter exactly as the code check found
	// it, which is the conservative end of the two.
	return h.coreService.VerifyMFALoginPending(ctx, challenge, code, userAgent, ip)
}

// errMFAVerificationUnavailable is returned (with http.StatusServiceUnavailable)
// when a storage error kept an MFA verification from reaching a verdict on the
// code at all (core.ErrMFAVerificationStorageFailure) — deliberately distinct
// from "Invalid or expired code" (#2548, FIX-1): the caller's credential was
// never actually checked, so telling them it was wrong would be misleading, and
// retrying immediately is the correct client behavior for a transient failure.
const errMFAVerificationUnavailable = "A temporary error occurred while verifying your code. Please try again."

// mfaSafeMessages are the fixed, deliberately client-safe error strings core's
// MFA functions return for expected failure modes (missing user, already/not
// enrolled, bad code, lockout, etc.) — never wrapped around a lower-layer
// error, so passing them through as-is cannot leak driver/schema detail
// (backlog #116). The reauth-related entries mirror webauthnSafeMessages:
// both files' self-service flows call the same core.requireReauth function.
var mfaSafeMessages = map[string]bool{
	"user not found": true,
	"MFA enrolment requires at-rest encryption to be enabled (the TOTP secret must not be stored in plaintext); ask an administrator to enable encryption": true,
	"MFA is already enabled; disable it first to re-enrol": true,
	"no pending MFA enrolment; begin enrolment first":      true,
	"invalid code":             true,
	"MFA is not enabled":       true,
	"invalid code or password": true,
	"account temporarily locked due to repeated failed logins; try again later": true,
}

// writeMFAErr maps a core MFA error to a 400 response: a recognized safe
// message (mfaSafeMessages) is passed through as-is; anything else — including
// every error wrapping a lower-layer failure (e.g. "failed to store TOTP
// secret: %w") or a bare storage-layer error — is logged server-side and
// replaced with clientSafe()'s generic message before it reaches the client.
func (h *AuthHandler) writeMFAErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	if !mfaSafeMessages[msg] {
		log.Printf("MFA error: %v", err)
		msg = clientSafe(err)
	}
	sendError(w, "Error", msg, http.StatusBadRequest, nil)
}
