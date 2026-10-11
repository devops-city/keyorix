// webauthn.go — HTTP handlers for WebAuthn / passkeys (ADR-036): self-service
// registration (authenticated) of FIDO2 authenticators, listing/removing them,
// and the public two-step login assertion ceremony. The ceremony state is carried
// between begin and finish by an opaque webauthn_session token (hashed at rest).
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// maxWebAuthnBody caps the ceremony request body (attestation/assertion blobs are
// small; this bounds parsing of untrusted input).
const maxWebAuthnBody = 64 * 1024

// BeginWebAuthnRegistration starts passkey enrolment for the authenticated caller.
func (h *AuthHandler) BeginWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	creation, sessionToken, err := h.coreService.BeginWebAuthnRegistration(r.Context(), userCtx.UserID)
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"publicKey":        creation.Response,
		"webauthn_session": sessionToken,
	}, "Create a passkey, then finish registration.")
}

// FinishWebAuthnRegistration verifies the attestation and stores the passkey.
// Requires a current TOTP code or the account password to re-authenticate the
// caller (#372): this is the step that actually adds a new trust factor to the
// account, so it must not be reachable by a bearer token alone.
// Body: { webauthn_session, name, code, password, credential: <PublicKeyCredential> }.
func (h *AuthHandler) FinishWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		WebAuthnSession string          `json:"webauthn_session"`
		Name            string          `json:"name"`
		Code            string          `json:"code"`
		Password        string          `json:"password"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Credential) == 0 {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		sendError(w, "BadRequest", "Invalid attestation", http.StatusBadRequest, nil)
		return
	}
	proof := body.Code
	if proof == "" {
		proof = body.Password
	}
	cred, err := h.coreService.FinishWebAuthnRegistration(r.Context(), userCtx.UserID, body.WebAuthnSession, strings.TrimSpace(body.Name), proof, parsed)
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	message := "Passkey registered."
	ended := h.endSetupSessionIfComplete(w, r, userCtx.UserID, extractBearerToken(r))
	if ended {
		message += " Account setup is complete: sign in again with your password and passkey."
	}
	sendSuccess(w, map[string]interface{}{
		"id":                        cred.ID,
		"name":                      cred.Name,
		"created_at":                cred.CreatedAt,
		"reauthentication_required": ended,
	}, message)
}

// ListWebAuthnCredentials returns the caller's registered passkeys.
func (h *AuthHandler) ListWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	creds, err := h.coreService.ListWebAuthnCredentials(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "InternalError", "Failed to list passkeys", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]interface{}{
			"id":           c.ID,
			"name":         c.Name,
			"created_at":   c.CreatedAt,
			"last_used_at": c.LastUsedAt,
		})
	}
	sendSuccess(w, out, "")
}

// DeleteWebAuthnCredential removes one of the caller's passkeys. Requires a
// current TOTP code or the account password to re-authenticate the caller (#372):
// deleting the last passkey silently disables WebAuthn account-wide, a full
// second-factor downgrade that must not be reachable by a bearer token alone.
// Body: { code, password } (either satisfies the re-auth check).
func (h *AuthHandler) DeleteWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid credential id", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	// An empty body simply fails the re-auth check below; only malformed JSON is a
	// bad request.
	if err := decodeJSON(r, &body); err != nil && !errors.Is(err, io.EOF) {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	proof := body.Code
	if proof == "" {
		proof = body.Password
	}
	if err := h.coreService.DeleteWebAuthnCredential(r.Context(), userCtx.UserID, uint(id), proof); err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{"id": id, "deleted": true}, "Passkey removed.")
}

// BeginWebAuthnReauth starts a live passkey re-assertion for the authenticated
// caller, used to satisfy requireReauth's second-factor requirement
// (DisableMFA/RegenerateMFARecoveryCodes/ActivateMFA/FinishWebAuthnRegistration/
// DeleteWebAuthnCredential/account email change) when the account has no TOTP
// factor to type a code from. Unlike BeginWebAuthnLogin, this operates on the
// already-authenticated caller directly, not a pre-login MFA challenge.
func (h *AuthHandler) BeginWebAuthnReauth(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	assertion, sessionToken, err := h.coreService.BeginWebAuthnReauth(r.Context(), userCtx.UserID)
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"publicKey":        assertion.Response,
		"webauthn_session": sessionToken,
	}, "Complete the passkey assertion to re-authenticate.")
}

// FinishWebAuthnReauth verifies the assertion begun by BeginWebAuthnReauth and,
// on success, records a step-up grant scoped ONLY to re-authentication
// (MFAStepUpPurposeReauth) — it does not by itself perform any account change.
// The caller must separately call the actual mutating endpoint (e.g.
// /auth/mfa/disable, DELETE /auth/webauthn/credentials/{id}) with the account
// password afterward, mirroring how /auth/mfa/stepup and a restricted-secret
// read are two separate calls.
// Body: { webauthn_session, credential: <PublicKeyCredential> }.
func (h *AuthHandler) FinishWebAuthnReauth(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		WebAuthnSession string          `json:"webauthn_session"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Credential) == 0 {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		sendError(w, "BadRequest", "Invalid assertion", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.FinishWebAuthnReauth(r.Context(), userCtx.UserID, body.WebAuthnSession, parsed); err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, nil, "Re-authentication verified.")
}

// BeginWebAuthnLogin starts the assertion ceremony for the second login step.
// Body: { mfa_challenge }. Public (the challenge from /auth/login is the bearer).
func (h *AuthHandler) BeginWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", errTooManyAttempts, http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		Challenge string `json:"mfa_challenge"`
	}
	if err := decodeJSON(r, &body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	// F2 (2026-09-20): reserve before resolving the challenge — see
	// reserveLoginAttempt's doc (reserved after decode, matching Login).
	h.reserveLoginAttempt(r.Context(), ip)
	assertion, sessionToken, err := h.coreService.BeginWebAuthnLogin(r.Context(), body.Challenge)
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"publicKey":        assertion.Response,
		"webauthn_session": sessionToken,
	}, "Complete the passkey assertion.")
}

// FinishWebAuthnLogin verifies the assertion and returns a session.
// Body: { mfa_challenge, webauthn_session, credential: <PublicKeyCredential> }.
func (h *AuthHandler) FinishWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", errTooManyAttempts, http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		Challenge       string          `json:"mfa_challenge"`
		WebAuthnSession string          `json:"webauthn_session"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Credential) == 0 {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		sendError(w, "BadRequest", "Invalid assertion", http.StatusBadRequest, nil)
		return
	}
	// F2 (2026-09-20): reserve before the (slow) assertion verification — see
	// reserveLoginAttempt's doc (reserved after decode+parse, matching Login).
	//
	// #2565: releasable, like VerifyMFA's. When FinishWebAuthnLogin fails with
	// core.ErrWebAuthnLoginNotEvaluated (a storage error before any verdict on
	// the assertion), the login is still denied but the reservation is
	// released: a request that was never evaluated must not consume the
	// budget slot a genuine failed assertion does. An invalid/expired
	// challenge or session, or a failed assertion, stays counted.
	attemptID, reserved := h.coreService.ReserveLoginAttempt(r.Context(), ip)
	// #2619 release-on-error only covers a RETURNED storage error; a PANIC inside
	// FinishWebAuthnLogin (e.g. ConsumeMFAChallenge#1/panic, FuzzStorageFaultOperations)
	// skips the err!=nil branch below entirely, bypassing ReleaseLoginAttempt the exact
	// same way the #2619 finding did — the outer Recovery middleware still turns the
	// panic into a 500, but the reserved slot stays orphaned-consumed. Recover here,
	// release, then re-panic unchanged so Recovery's own logging/response behavior is
	// untouched; a panic AFTER this call (e.g. during completeLogin, post-verdict) is
	// deliberately NOT covered by this recover — the assertion was already evaluated by
	// then, so the slot must stay counted exactly like a successful or failed evaluation
	// would (same release-only-pre-verdict rule #2619 established for the error path).
	//
	// #2841: the wrapper forwards the response identity core now resolves BEFORE
	// the session/grant/step-up-token writes, so there is exactly ONE call to
	// FinishWebAuthnLogin on this path — re-reading the identity in the handler
	// would reopen the very window this fix closed.
	session, user, identity, err := h.finishWebAuthnLoginReleasingOnPanic(r.Context(), body.Challenge, body.WebAuthnSession, r.Header.Get(hdrUserAgent), ip, parsed, reserved, attemptID)
	if err != nil {
		if errors.Is(err, core.ErrWebAuthnLoginNotEvaluated) {
			log.Printf("FinishWebAuthnLogin: %v", err)
			if reserved {
				h.coreService.ReleaseLoginAttempt(r.Context(), attemptID)
			}
			// FIX-1 (#2548 sibling, consistency with VerifyMFA/MFAStepUp): a storage
			// error never reached a verdict on the assertion — see
			// errMFAVerificationUnavailable's doc (mfa.go). Reused here rather than
			// a separate constant: the message is about retrying a second-factor
			// check generically, not specific to TOTP.
			sendError(w, "ServiceUnavailable", errMFAVerificationUnavailable, http.StatusServiceUnavailable, nil)
			return
		}
		// #2841: the identity read now happens inside core, before the
		// session/grant/step-up-token writes (not before the FIRST write — the
		// challenge consume, the credential sign-counter update and the
		// lockout-counter clear all land earlier; what matters is that nothing
		// fallible-and-reported runs after the writes that would outlive a login
		// reported as failed).
		// Keep its caller-visible shape identical to the 500 completeLogin used
		// to produce for the same failure — a transient authz-resolution error
		// is not an assertion failure and must not be reported as one (and
		// unlike ErrWebAuthnLoginNotEvaluated, the assertion WAS evaluated and
		// passed, so the attempt reservation stays counted exactly as before).
		if errors.Is(err, core.ErrLoginIdentityUnavailable) {
			log.Printf("FinishWebAuthnLogin: %v", err)
			sendError(w, "Internal", errLoginIncomplete, http.StatusInternalServerError, nil)
			return
		}
		sendError(w, "Unauthorized", "Assertion failed or challenge expired", http.StatusUnauthorized, nil)
		return
	}
	resp, ok := h.completeLoginWithIdentity(w, session, user, identity)
	if !ok {
		return
	}
	goSafe(func() {
		h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, r.Header.Get(hdrUserAgent))
	}) // #nosec G118
	goSafe(func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }) // #nosec G118
	sendSuccess(w, resp, "Login successful")
}

// finishWebAuthnLoginReleasingOnPanic calls core.FinishWebAuthnLogin, releasing the
// reserved login-attempt slot and re-panicking unchanged if the call panics instead of
// returning — see FinishWebAuthnLogin's call-site comment for why this exists.
//
// #2841: it forwards all FOUR of FinishWebAuthnLogin's results, including the
// response identity core resolves before its session/grant/step-up-token writes.
// The wrapper is deliberately transparent: it adds the release-on-panic side
// effect and changes nothing else. The recover() re-panics with the ORIGINAL
// value, so a panic is never converted into a (nil, nil, zero, nil) "success"
// and never swallowed — the slot is released and the panic continues to the
// Recovery middleware.
func (h *AuthHandler) finishWebAuthnLoginReleasingOnPanic(ctx context.Context, challenge, webAuthnSession, userAgent, ip string, parsed *protocol.ParsedCredentialAssertionData, reserved bool, attemptID uint) (session *models.Session, user *models.User, identity core.UserIdentity, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			if reserved {
				h.coreService.ReleaseLoginAttempt(ctx, attemptID)
			}
			panic(rec)
		}
	}()
	return h.coreService.FinishWebAuthnLogin(ctx, challenge, webAuthnSession, userAgent, ip, parsed)
}

// BeginWebAuthnPasswordlessLogin starts a usernameless passkey login. Public, no
// body — the authenticator reveals which resident passkey/user to use.
func (h *AuthHandler) BeginWebAuthnPasswordlessLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", errTooManyAttempts, http.StatusTooManyRequests, nil)
		return
	}
	// G1 (2026-09-27): reserve before starting the ceremony (a storage write —
	// creates a WebAuthnSession row and, unlike BeginWebAuthnLogin's sibling
	// two lines up the call chain, this endpoint has no bearer challenge from a
	// prior /auth/login call, so it's callable from a cold start by anyone) —
	// see reserveLoginAttempt's doc. This endpoint shared checkLoginRateLimit's
	// gate but never reserved a slot at all (F2/#1981 left it out of scope), so
	// unlike BeginWebAuthnLogin it never contributed to the shared per-IP
	// budget and could be called without limit.
	h.reserveLoginAttempt(r.Context(), ip)
	assertion, sessionToken, err := h.coreService.BeginWebAuthnPasswordlessLogin(r.Context())
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"publicKey":        assertion.Response,
		"webauthn_session": sessionToken,
	}, "Complete the passkey assertion to sign in.")
}

// FinishWebAuthnPasswordlessLogin verifies a discoverable assertion and returns a
// session. Body: { webauthn_session, credential: <PublicKeyCredential> }.
func (h *AuthHandler) FinishWebAuthnPasswordlessLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", errTooManyAttempts, http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		WebAuthnSession string          `json:"webauthn_session"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Credential) == 0 {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		sendError(w, "BadRequest", "Invalid assertion", http.StatusBadRequest, nil)
		return
	}
	// F2 (2026-09-20): reserve before the (slow) assertion verification — see
	// reserveLoginAttempt's doc (reserved after decode+parse, matching Login).
	h.reserveLoginAttempt(r.Context(), ip)
	session, user, identity, err := h.coreService.FinishWebAuthnPasswordlessLogin(r.Context(), body.WebAuthnSession, r.Header.Get(hdrUserAgent), ip, parsed)
	if err != nil {
		// #2841, same reasoning as the second-factor path above.
		if errors.Is(err, core.ErrLoginIdentityUnavailable) {
			log.Printf("FinishWebAuthnPasswordlessLogin: %v", err)
			sendError(w, "Internal", errLoginIncomplete, http.StatusInternalServerError, nil)
			return
		}
		sendError(w, "Unauthorized", "Passwordless login failed", http.StatusUnauthorized, nil)
		return
	}
	resp, ok := h.completeLoginWithIdentity(w, session, user, identity)
	if !ok {
		return
	}
	goSafe(func() {
		h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, r.Header.Get(hdrUserAgent))
	}) // #nosec G118
	goSafe(func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }) // #nosec G118
	sendSuccess(w, resp, "Login successful")
}

// webauthnSafeMessages are the fixed, deliberately client-safe error strings
// core's WebAuthn/MFA functions return for expected failure modes (missing
// user, expired/mismatched session or challenge, locked-out or bad re-auth,
// etc.) — never wrapped around a lower-layer error, so passing them through
// as-is cannot leak driver/schema details (backlog #116).
var webauthnSafeMessages = map[string]bool{
	"user not found": true,
	"invalid or expired registration session": true,
	"registration session mismatch":           true,
	"invalid or expired challenge":            true,
	"no passkeys registered":                  true,
	"account is not active":                   true,
	"account temporarily locked due to repeated failed logins; try again later": true,
	"invalid or expired webauthn session":                                       true,
	"webauthn session mismatch":                                                 true,
	"unexpected user handle":                                                    true,
	"invalid code or password":                                                  true,
}

// writeWebAuthnErr maps a core error to an HTTP status: disabled → 501, else 400.
// A recognized safe message (webauthnSafeMessages) is passed through as-is;
// anything else — including every error wrapping a lower-layer failure (e.g.
// "failed to store credential: %w") — is logged server-side and replaced with
// clientSafe()'s generic message before it reaches the client.
func (h *AuthHandler) writeWebAuthnErr(w http.ResponseWriter, err error) {
	if errors.Is(err, core.ErrWebAuthnDisabled) {
		sendError(w, "NotImplemented", err.Error(), http.StatusNotImplemented, nil) // nosemgrep: keyorix-raw-error-to-client -- ErrWebAuthnDisabled is a fixed sentinel with a known-safe message, not a raw backend/driver error
		return
	}
	msg := err.Error()
	if !webauthnSafeMessages[msg] {
		log.Printf("WebAuthn error: %v", err)
		msg = clientSafe(err)
	}
	sendError(w, "Error", msg, http.StatusBadRequest, nil)
}

// decodeJSON decodes a size-capped JSON request body.
func decodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(io.LimitReader(r.Body, maxWebAuthnBody)).Decode(v)
}
