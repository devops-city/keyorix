// account_setup.go — the setup steps a restricted or factor-less account must
// finish before it may do anything else (#3024), and the setup-only session
// that carries an account needing BOTH of them through to a normal MFA login.
//
// Two gates used to wait for each other: a restricted account (ADR-025
// pending_first_login / password_reset_required — a recovered admin, a
// one-time-password user, an admin-forced reset) was confined to
// change-password, and under security.require_mfa (ADR-112) a session without
// a second factor was confined to enrolment, which refused change-password.
// PendingAccountSetupSteps is now the one definition of what is pending; the
// HTTP gate (server/middleware.EnforceAccountSetup) allows the union of the
// pending steps' endpoints, so the two can be done in either order.
//
// A login that needs both steps gets a setup-only session (models.Session.
// SetupOnly): short-lived (SetupSessionTTL, carried through refresh), confined
// to the setup steps, and revoked by EndSetupSessionIfComplete once nothing is
// pending, so it never turns into a full session. The account's next login is
// a normal two-step MFA login.
package core

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Setup step names, as reported to clients in a setup gate's 403 pending_steps.
const (
	SetupStepChangePassword = "change_password"
	SetupStepEnrollMFA      = "enroll_mfa"
)

// SetupSessionTTL is the hard ceiling on a setup-only session's whole life,
// from login, regardless of the configured session TTLs; refresh never extends
// it. Long enough to change a password and enrol an authenticator, short enough
// that a one-time password's session does not linger.
const SetupSessionTTL = 15 * time.Minute

// EventAccountSetupCompleted audits the end of a setup-only session: both setup
// steps are done, every session of the account is revoked, and the next login
// is a normal MFA login.
const EventAccountSetupCompleted = "auth.account_setup_completed"

// PendingAccountSetupSteps lists the setup steps still owed, in the order a
// client should offer them: change_password while the account is restricted
// (any credential), enroll_mfa while the deployment requires MFA and an
// interactive session's account has no second factor (PATs and machine tokens
// are exempt, ADR-112). Empty means nothing is owed.
func PendingAccountSetupSteps(restricted, hasSecondFactor, interactiveSession, requireMFA bool) []string {
	var steps []string
	if restricted {
		steps = append(steps, SetupStepChangePassword)
	}
	if requireMFA && interactiveSession && !hasSecondFactor {
		steps = append(steps, SetupStepEnrollMFA)
	}
	return steps
}

// SetRequireMFA tells core whether the deployment requires MFA
// (security.require_mfa). The HTTP router calls it with the same value it
// configures the setup gate with, so session issuance and the gate agree.
func (c *KeyorixCore) SetRequireMFA(on bool) {
	c.deploymentRequiresMFA = on
}

func userHasSecondFactor(u *models.User) bool {
	return u.MFAEnabled || u.WebAuthnEnabled
}

// pendingSetupStepsFor is PendingAccountSetupSteps for an interactive session
// of u under this deployment's policy.
func (c *KeyorixCore) pendingSetupStepsFor(u *models.User) []string {
	return PendingAccountSetupSteps(AccountRestricted(u.AccountState), userHasSecondFactor(u), true, c.deploymentRequiresMFA)
}

// needsSetupSession reports whether an interactive login for u must be a
// setup-only session: both setup steps are owed.
func (c *KeyorixCore) needsSetupSession(u *models.User) bool {
	return len(c.pendingSetupStepsFor(u)) == 2
}

// EndSetupSessionIfComplete revokes every session of userID when token names
// a setup-only session of that user and the account owes no setup step any
// more, and reports whether it did. Called by the HTTP handlers of the steps
// that can finish setup (change-password, MFA activation, passkey
// registration) after the step succeeded, so a setup-only session never
// outlives the setup it exists for.
//
// Not a setup-only session (an ordinary session, a PAT, an unknown token):
// nothing happens, false. A step still pending: the session continues, false.
// If the account cannot be re-read, the setup session is revoked anyway: it
// owes nothing a fresh login cannot redo, and continuing it on a state nobody
// checked would be the fail-open side.
func (c *KeyorixCore) EndSetupSessionIfComplete(ctx context.Context, userID uint, token string) bool {
	if token == "" {
		return false
	}
	sess, err := c.storage.GetSession(ctx, token)
	if err != nil || sess == nil || !sess.SetupOnly || sess.UserID != userID {
		return false
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err == nil && len(c.pendingSetupStepsFor(user)) > 0 {
		return false
	}
	reason := "both setup steps are done"
	if err != nil {
		reason = fmt.Sprintf("the account could not be re-read (%v), so the setup session was ended rather than continued", err)
		log.Printf("SECURITY: EndSetupSessionIfComplete: user %d: %s", userID, reason)
	}
	// Every session, the caller's included (keepID 0): the setup session must not
	// survive, and no other session of this account predates the setup.
	outcome := "every session was revoked and the next login requires the second factor"
	if err := c.deleteSessionsForUserAndEvict(ctx, userID, 0, ""); err != nil {
		// deleteSessionsForUserAndEvict has logged and audited the failure
		// (EventSessionRevocationFailed). The surviving session is still
		// setup-only and owes nothing, which both transports refuse with a
		// re-authentication answer (HTTP EnforceAccountSetup, gRPC
		// enforceGRPCAccessPolicy), so it never gains full access; report true
		// so the client is told to sign in again.
		outcome = fmt.Sprintf("its sessions could not be revoked (%v); the setup-only session is refused on every endpoint until it expires", err)
	}
	c.writeAuditEventFull(ctx, EventAccountSetupCompleted, &userID, nil, nil, "",
		fmt.Sprintf("user %d finished account setup in a setup-only session (%s); %s", userID, reason, outcome))
	return true
}
