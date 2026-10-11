// pat_restriction_writes.go — what a RESTRICTED personal access token may do on
// the writes that no permission gate covers (ADR-042, PAT-GUARD-3; Andrei's
// decision of 2026-10-11).
//
// A PAT restriction is enforced by Authorize. A write behind a permission gate
// (HTTP RequirePermission/RequireScoped*, or a gRPC handler's authorize* call)
// inherits it. An ungated write never reaches Authorize, so the restriction meant
// nothing there: a token confined to one project's secrets.read could change its
// owner's password, enrol or remove a second factor, or request access to other
// projects. The decision: a restricted PAT is REFUSED on every ungated write,
// deny-by-default, except an explicit allowlist with a written reason each.
//
// restrictedPATUngatedWrites is that single table, for both transports. The HTTP
// middleware (server/middleware RefuseRestrictedPATUngatedWrites) and the gRPC auth
// interceptors refuse from it; the family-wide guards derive every ungated write
// from the code (server/http TestEveryUngatedWriteDeclaresRestrictedPATPolicy, from
// router.go's AST; server/grpc TestEveryUngatedGRPCWriteDeclaresRestrictedPATPolicy,
// from the services' AST) and fail on one missing here, then check every entry
// behaviourally with #3062's restricted personas.
//
// A route that is not in the table is permission-gated, so Authorize applies the
// restriction to it. Unrestricted PATs, sessions and machine tokens never consult
// the table.
package core

import "errors"

// ErrRestrictedPATSelfServiceWrite refuses an ungated self-service write
// (profile, password, MFA, passkeys, access requests, notifications, ...)
// authenticated by a restricted PAT. Those writes act on the owner's account or
// ask for access the token does not hold, outside anything its restriction can
// express, so a token confined below its owner may not make them.
var ErrRestrictedPATSelfServiceWrite = errors.New("a restricted personal access token cannot perform this self-service action")

// RestrictedPATWritePolicy is the decision for one ungated write. The zero value
// is "refused": allowing a write takes an explicit Allowed and a Reason.
type RestrictedPATWritePolicy struct {
	// Allowed lets a restricted PAT through to the handler.
	Allowed bool
	// Reason says why an allowed write is safe for a restricted token. Required
	// when Allowed; optional context otherwise.
	Reason string
	// Refusal is the error a refused write returns; nil means
	// ErrRestrictedPATSelfServiceWrite. Writes refused before this table existed
	// keep their own sentinel.
	Refusal error
}

// RefusalError returns the error a refused write answers with.
func (p RestrictedPATWritePolicy) RefusalError() error {
	if p.Refusal != nil {
		return p.Refusal
	}
	return ErrRestrictedPATSelfServiceWrite
}

const (
	reasonOwnRevoke = "Revokes only the caller's OWN token or session (another user's id is a 404) and only " +
		"ever reduces access: whoever holds a restricted token must be able to kill a leaked sibling " +
		"credential, and DELETE /auth/tokens/{id} on its own id is how a PAT logs out (PAT-GUARD-2, #3071)."
	reasonInHandlerAuthorize = "Permission-gated in substance: the handler authorizes through Authorize at the " +
		"scope named in the body, which applies the restriction (a token confined elsewhere gets 403). " +
		"Refusing it would stop a restricted token creating anything even inside its own restriction."
	reasonSecretAccessRequestResolve = "Permission-gated in substance, like its sibling PUT /projects/{id}/access-requests/" +
		"{requestId} (gated on roles.assign): Approve/RejectSecretAccessRequest call requireAccessRequestAuthorityAt, " +
		"which applies the PAT restriction for roles.assign at the request's own project and then requires admin " +
		"authority there, so a token without roles.assign at that project gets 403 from core."
	reasonNotPATAuthenticated = "Not PAT-authenticated: outside /api/v1's Authentication middleware, so no " +
		"request here carries a PAT restriction; its credential is "
)

// refusedSelfService is the default entry: refused with
// ErrRestrictedPATSelfServiceWrite.
var refusedSelfService = RestrictedPATWritePolicy{}

// restrictedPATUngatedWrites maps every ungated write to its restricted-PAT
// policy. HTTP keys are noPermissionGateAllowlist's ("<METHOD> <mounted path>");
// gRPC keys are full method names.
var restrictedPATUngatedWrites = map[string]RestrictedPATWritePolicy{
	// My Account, MFA, passkeys: the owner's account, not the token's restriction.
	"PUT /api/v1/auth/profile":                        refusedSelfService,
	"POST /api/v1/auth/change-password":               refusedSelfService,
	"POST /api/v1/auth/mfa/enroll":                    refusedSelfService,
	"POST /api/v1/auth/mfa/activate":                  refusedSelfService,
	"POST /api/v1/auth/mfa/disable":                   refusedSelfService,
	"POST /api/v1/auth/mfa/recovery-codes/regenerate": refusedSelfService,
	// A step-up grant is the user's, not the token's: the owner opens it from a
	// session and every credential of theirs, a restricted PAT included, reads under it.
	"POST /api/v1/auth/mfa/stepup":                  refusedSelfService,
	"POST /api/v1/auth/webauthn/register/begin":     refusedSelfService,
	"POST /api/v1/auth/webauthn/register/finish":    refusedSelfService,
	"DELETE /api/v1/auth/webauthn/credentials/{id}": refusedSelfService,
	"POST /api/v1/auth/webauthn/reauth/begin":       refusedSelfService,
	"POST /api/v1/auth/webauthn/reauth/finish":      refusedSelfService,
	"POST /api/v1/auth/tokens":                      {Refusal: ErrRestrictedPATCannotMintPAT},
	"POST /api/v1/auth/end-impersonation":           refusedSelfService,
	"POST /api/v1/notifications/read-all":           refusedSelfService,
	"POST /api/v1/notifications/{id}/read":          refusedSelfService,
	"DELETE /api/v1/secrets/{id}/self-share":        refusedSelfService,

	// Access the token does not hold: requesting, withdrawing, escalating (deciding a secret access request is allowed below).
	"POST /api/v1/projects/{id}/access-requests":                      refusedSelfService,
	"POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw": refusedSelfService,
	"POST /api/v1/projects/{id}/break-glass":                          {Refusal: ErrRestrictedPATCannotBreakGlass},
	"POST /api/v1/secret-access-requests":                             refusedSelfService,
	"POST /api/v1/secret-access-requests/{requestId}/withdraw":        refusedSelfService,
	"/keyorix.v1.BreakGlassService/ActivateBreakGlass":                {Refusal: ErrRestrictedPATCannotBreakGlass},

	// Allowed: own-credential revocation.
	"DELETE /api/v1/auth/tokens/{id}":    {Allowed: true, Reason: reasonOwnRevoke},
	"DELETE /api/v1/auth/tokens/expired": {Allowed: true, Reason: reasonOwnRevoke + " Bulk form: the caller's own EXPIRED tokens only."},
	"DELETE /api/v1/auth/sessions/{id}":  {Allowed: true, Reason: reasonOwnRevoke},

	// Allowed: deciding a secret access request (Andrei's decision of 2026-10-11,
	// parity with the permission-gated PUT /projects/{id}/access-requests/{requestId}).
	"PUT /api/v1/secret-access-requests/{requestId}": {Allowed: true, Reason: reasonSecretAccessRequestResolve},

	// Allowed: authorized inside the handler through Authorize.
	"POST /api/v1/secrets":                 {Allowed: true, Reason: reasonInHandlerAuthorize},
	"POST /api/v1/folders":                 {Allowed: true, Reason: reasonInHandlerAuthorize},
	"POST /api/v1/rotation-policies":       {Allowed: true, Reason: reasonInHandlerAuthorize},
	"POST /api/v1/dynamic-secrets/configs": {Allowed: true, Reason: reasonInHandlerAuthorize},

	// Allowed: pre-authentication and infrastructure routes, which a PAT never
	// authenticates. A token that wants to end itself revokes itself (above).
	"POST /auth/login":                        {Allowed: true, Reason: reasonNotPATAuthenticated + "the password."},
	"POST /auth/logout":                       {Allowed: true, Reason: reasonNotPATAuthenticated + "the session token it ends; a PAT bearer is not a session and is not touched."},
	"POST /auth/refresh":                      {Allowed: true, Reason: reasonNotPATAuthenticated + "the refresh token."},
	"POST /auth/password-reset":               {Allowed: true, Reason: reasonNotPATAuthenticated + "none (a reset link is emailed)."},
	"POST /auth/mfa/verify":                   {Allowed: true, Reason: reasonNotPATAuthenticated + "the login challenge."},
	"POST /auth/webauthn/login/begin":         {Allowed: true, Reason: reasonNotPATAuthenticated + "the login challenge."},
	"POST /auth/webauthn/login/finish":        {Allowed: true, Reason: reasonNotPATAuthenticated + "the login challenge and the passkey assertion."},
	"POST /auth/webauthn/passwordless/begin":  {Allowed: true, Reason: reasonNotPATAuthenticated + "the passkey ceremony."},
	"POST /auth/webauthn/passwordless/finish": {Allowed: true, Reason: reasonNotPATAuthenticated + "the passkey assertion."},
	"POST /system/init":                       {Allowed: true, Reason: reasonNotPATAuthenticated + "the bootstrap token on an empty deployment."},
	"POST /auth/setup/consume":                {Allowed: true, Reason: reasonNotPATAuthenticated + "the single-use setup token."},
	"POST /auth/saml/{provider}/acs":          {Allowed: true, Reason: reasonNotPATAuthenticated + "the IdP's signed assertion."},
	"HANDLE /metrics":                         {Allowed: true, Reason: reasonNotPATAuthenticated + "the optional static metrics token."},
	"MOUNT /swagger/":                         {Allowed: true, Reason: reasonNotPATAuthenticated + "none (static docs behind a config flag)."},
}

// RestrictedPATUngatedWritePolicy returns the restricted-PAT policy of the
// ungated write key, and false when key is not an ungated write (a gated route,
// whose restriction Authorize enforces).
func RestrictedPATUngatedWritePolicy(key string) (RestrictedPATWritePolicy, bool) {
	p, ok := restrictedPATUngatedWrites[key]
	return p, ok
}

// RestrictedPATUngatedWrites returns a copy of the whole table, for the guards.
func RestrictedPATUngatedWrites() map[string]RestrictedPATWritePolicy {
	out := make(map[string]RestrictedPATWritePolicy, len(restrictedPATUngatedWrites))
	for k, v := range restrictedPATUngatedWrites {
		out[k] = v
	}
	return out
}

// RestrictedPATWriteRefusal returns the refusal for a restricted PAT calling the
// write key, or nil when the write is allowed or not ungated. Call it only for a
// request that carries a PAT restriction.
func RestrictedPATWriteRefusal(key string) error {
	if p, ok := restrictedPATUngatedWrites[key]; ok && !p.Allowed {
		return p.RefusalError()
	}
	return nil
}
