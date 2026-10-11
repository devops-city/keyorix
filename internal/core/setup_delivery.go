// setup_delivery.go — credential-delivery producers (ADR-028).
//
// These turn the setup-token primitive + delivery channel into the admin-facing
// flows: provisioning a brand-new account's first-credential link, and resending it.
// A producer issues a token, builds the absolute setup link, delivers it via the
// configured channel, and audits the delivery. In out-of-band mode the link is
// returned to the admin to relay; that display is itself audited
// (credential.displayed_out_of_band) because a human briefly sees a credential.
package core

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrSetupBaseURLRequired is returned when a setup link is requested but
// credential_delivery.base_url is unconfigured. It is a misconfiguration (a relative
// link is never a fallback), so the HTTP layer maps it to a 400 with this reason
// rather than a generic 500 — letting an admin fix the config.
var ErrSetupBaseURLRequired = errors.New("credential_delivery.base_url is required to issue a setup link")

// ErrResendThrottleUnverifiable is wrapped by checkResendThrottle when the
// throttle's own count query fails. The throttle fails CLOSED (no link is
// issued), but this is a storage fault, not a throttle verdict: unlike a real
// "limit reached", a caller that had not yet persisted anything must not
// persist anything either (#2599, see provisionInvitationSetupLink).
var ErrResendThrottleUnverifiable = errors.New("could not verify resend limits, please try again")

// auditCredentialDisplayedOutOfBand records that a human saw a credential
// out-of-band (ADR-028's one audited "a human saw this" checkpoint). Deliberately
// takes ONLY the non-sensitive fields the description needs (subject email, actor,
// artifact type label) — never the credential/password value itself — so the
// actual secret is never even in scope in the function that builds the audit
// description, not merely unreferenced by convention.
func (c *KeyorixCore) auditCredentialDisplayedOutOfBand(ctx context.Context, actor *uint, subjectEmail, artifact string) {
	c.writeAuditEventFull(ctx, "credential.displayed_out_of_band", actor, nil, nil, "",
		fmt.Sprintf("credential shown out-of-band to admin (subject=%s, artifact=%s)", subjectEmail, artifact))
}

// Resend throttling (ADR-028 abuse section): a minimum interval between issues for
// the same subject, and a daily cap, both per (purpose, email).
const (
	resendMinInterval = 60 * time.Second
	resendDailyCap    = 10
)

// SetCredentialDelivery wires the credential-delivery channel and the base URL used
// to build absolute setup links (ADR-028). The server/CLI calls this at startup from
// the credential_delivery config. A nil deliverer means out-of-band: the link is
// returned to the caller rather than sent.
func (c *KeyorixCore) SetCredentialDelivery(d ports.CredentialDelivery, baseURL string) {
	c.credentialDelivery = d
	c.setupBaseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
}

// ProvisionSetupResult reports how a setup link was provisioned and delivered.
type ProvisionSetupResult struct {
	Email        string `json:"email"`
	Channel      string `json:"channel"`                  // smtp | out_of_band | log
	Delivered    bool   `json:"delivered"`                // true if actually sent
	LinkForAdmin string `json:"link_for_admin,omitempty"` // set in out-of-band mode
}

// provisionSetupLink issues a setup token for the request's subject and delivers it
// via the configured channel, returning the outcome. Requires a configured base URL
// (a relative link is a misconfiguration, not a fallback).
//
// Always enforces the per-subject resend throttle (ADR-028 abuse section,
// checkResendThrottle) — including on what looks like an "initial" provision, not just
// explicit resends. Without this, a create→soft-delete→recreate loop against the same
// email would bypass the throttle entirely: DeleteUser is an unconditional soft delete
// and GetUserByEmail excludes soft-deleted rows, so the same address becomes immediately
// reusable for another "initial" CreateUserWithSetupLink, each one an unthrottled SMTP
// send against the org's own mail relay (#183). checkResendThrottle is keyed on the raw
// email address in the setup-token store, independent of the (deletable/recreatable) user
// row, so the count survives the delete. The count-then-act window (check, then
// IssueSetupToken) is serialized under setupResendMu so a concurrent burst for the same
// (purpose, email) can't all observe a sub-cap count before any of them writes the token
// that would push the next check over the cap.
func (c *KeyorixCore) provisionSetupLink(ctx context.Context, req IssueSetupTokenRequest, displayName, assignmentSummary string) (*ProvisionSetupResult, error) {
	if c.setupBaseURL == "" {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrSetupBaseURLRequired)
	}
	c.setupResendMu.Lock()
	if err := c.checkResendThrottle(ctx, req.Purpose, req.SubjectEmail); err != nil {
		c.setupResendMu.Unlock()
		return nil, err
	}
	issued, err := c.IssueSetupToken(ctx, req)
	c.setupResendMu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.deliverSetupLink(ctx, issued, req, displayName, assignmentSummary)
}

// provisionSetupLinkThrottled is now a thin alias for provisionSetupLink, kept as an
// explicitly-named entry point at resend/reset call sites where the throttle is the whole
// point — provisionSetupLink itself always enforces checkResendThrottle (see above), so
// there is no longer a distinct unthrottled variant to be paired with.
func (c *KeyorixCore) provisionSetupLinkThrottled(ctx context.Context, req IssueSetupTokenRequest, displayName, assignmentSummary string) (*ProvisionSetupResult, error) {
	return c.provisionSetupLink(ctx, req, displayName, assignmentSummary)
}

// deliverSetupLink builds the absolute setup link from a freshly issued token and
// delivers it via the configured channel (or hands it back out-of-band), auditing
// the delivery. Split from provisionSetupLink so the slow delivery step runs outside
// the resend-throttle lock.
func (c *KeyorixCore) deliverSetupLink(ctx context.Context, issued *IssueSetupTokenResult, req IssueSetupTokenRequest, displayName, assignmentSummary string) (*ProvisionSetupResult, error) {
	link := c.setupBaseURL + "/auth/setup/" + issued.PlainToken

	var result ports.DeliveryResult
	if c.credentialDelivery != nil {
		var err error
		result, err = c.credentialDelivery.DeliverSetupLink(ctx, ports.SetupLinkRequest{
			RecipientEmail:    req.SubjectEmail,
			DisplayName:       displayName,
			Link:              link,
			Purpose:           req.Purpose,
			AssignmentSummary: assignmentSummary,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	} else {
		// No channel configured → out-of-band: hand the link back to the caller.
		result = ports.DeliveryResult{Channel: ports.ChannelOutOfBand, Delivered: false, LinkForAdmin: link}
	}

	// Audit the delivery (no token on the row).
	actor := actorOrSubject(req.CreatedBy, req.SubjectUserID)
	c.writeAuditEventFull(ctx, "setup_link.delivered", actor, nil, nil, "",
		fmt.Sprintf("setup link delivered (purpose=%s, subject=%s, channel=%s, delivered=%t)",
			req.Purpose, req.SubjectEmail, result.Channel, result.Delivered))
	// When the link is shown to the admin out of band, record that a human saw a
	// credential — the one path the ADR singles out for compliance.
	if result.LinkForAdmin != "" {
		c.auditCredentialDisplayedOutOfBand(ctx, actor, req.SubjectEmail, "link")
	}

	return &ProvisionSetupResult{
		Email:        req.SubjectEmail,
		Channel:      result.Channel,
		Delivered:    result.Delivered,
		LinkForAdmin: result.LinkForAdmin,
	}, nil
}

// CreateUserWithSetupLink creates a user in pending_first_login state with NO usable
// password and provisions an account_setup link, so the user sets their own password
// via the link instead of the admin choosing one (ADR-025 / ADR-028). Returns the
// created user and the delivery outcome (the link to relay in out-of-band mode).
func (c *KeyorixCore) CreateUserWithSetupLink(ctx context.Context, req *CreateUserRequest, createdBy uint) (*models.User, *ProvisionSetupResult, error) {
	if c.setupBaseURL == "" {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrSetupBaseURLRequired)
	}

	// Create the account with a random, unusable password and confined directly to
	// pending_first_login in the SAME write — no second UpdateUser that, on failure,
	// could strand an active account with a password nobody knows. The real password
	// is set when the user consumes the setup link.
	reqCopy := *req
	unusable, err := randomUnusablePassword()
	if err != nil {
		return nil, nil, err
	}
	reqCopy.Password = unusable
	reqCopy.AccountState = AccountPendingFirstLogin
	user, err := c.CreateUser(ctx, &reqCopy)
	if err != nil {
		return nil, nil, err
	}
	c.LogUserCreated(ctx, createdBy, user.ID, user.Username)

	res, err := c.provisionSetupLink(ctx, IssueSetupTokenRequest{
		Purpose:       SetupPurposeAccountSetup,
		SubjectEmail:  user.Email,
		SubjectUserID: &user.ID,
		CreatedBy:     createdBy,
	}, user.DisplayName, "")
	if err != nil {
		// The account exists but the link could not be provisioned; surface the user
		// so the caller can resend rather than orphaning a half-created account.
		return user, nil, err
	}
	return user, res, nil
}

// OneTimePasswordResult carries the out-of-band one-time password for the admin to
// relay (ADR-028 Part E). It is returned once, at creation, and never stored in clear:
// only the bcrypt hash is persisted, and the account is forced into
// password_reset_required so the user must replace it on first login.
type OneTimePasswordResult struct {
	Email    string `json:"email"`
	OTPValue string `json:"one_time_password"`
	// ExpiresAt is when the one-time password stops working (UTC); after it, login is
	// refused like a wrong password and an administrator has to issue another.
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateUserWithOneTimePassword creates a user with a server-generated initial password
// and forces it into password_reset_required (ADR-025), returning the password once for
// the admin to relay out-of-band (ADR-028 Part E). It is the alternative to the
// setup-link path for when an admin wants to set an initial credential rather than have
// the end user choose one: the admin holds the first credential, so the account must
// change it on first login. The password is never emailed and never persisted in clear
// (only its bcrypt hash). No base URL is required — there is no link.
func (c *KeyorixCore) CreateUserWithOneTimePassword(ctx context.Context, req *CreateUserRequest, createdBy uint) (*models.User, *OneTimePasswordResult, error) {
	otp, err := GenerateInitialCredential()
	if err != nil {
		return nil, nil, err
	}

	// Create the account directly in password_reset_required with the generated
	// password, in the SAME write — no second UpdateUser that, on failure, could
	// strand an active account whose credential the admin already saw.
	reqCopy := *req
	reqCopy.Password = otp
	reqCopy.AccountState = AccountPasswordResetRequired
	// The expiry is written by the same insert as the password (OTP-EXPIRY-1).
	expiresAt := c.now().Add(c.effectiveOneTimePasswordTTL()).UTC()
	reqCopy.OneTimePasswordExpiresAt = &expiresAt
	user, err := c.CreateUser(ctx, &reqCopy)
	if err != nil {
		return nil, nil, err
	}
	c.LogUserCreated(ctx, createdBy, user.ID, user.Username)

	// Record that a human saw a credential — the one path the ADR singles out for
	// compliance (artifact=one_time_password, vs the setup-link artifact). Uses
	// req.Email (the original request parameter, never touched by the
	// otp-carrying reqCopy/CreateUser call above) rather than user.Email, so the
	// audit description's only input never shares a struct/call with the actual
	// generated password.
	actor := actorOrSubject(createdBy, &user.ID)
	c.auditCredentialDisplayedOutOfBand(ctx, actor, req.Email, "one_time_password")

	return user, &OneTimePasswordResult{Email: user.Email, OTPValue: otp, ExpiresAt: expiresAt}, nil
}

// ResendAccountSetupLink reissues an account_setup link for an existing user,
// superseding the prior active token, and re-delivers it. Throttled per ADR-028.
//
// A non-zero, non-self createdBy must also hold the admin-rank ceiling
// requireAdminRankCeilingForTarget enforces (S1 sweep, CLI-split inventory
// #2012) -- the sharpest instance of the S1 pivot in this whole family: in
// out-of-band delivery mode (no credentialDelivery channel configured,
// deliverSetupLink's default), the result's LinkForAdmin field hands the raw
// setup token straight back to the API CALLER, not to the target's email. A
// users.write holder with no other elevated authority could, before this,
// mint and receive a fresh setup token for a HIGHER-privileged account and
// complete setup with an attacker-chosen password -- full account takeover,
// with no need to also compromise UpdateUser or the target's real email.
func (c *KeyorixCore) ResendAccountSetupLink(ctx context.Context, userID, createdBy uint) (*ProvisionSetupResult, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if createdBy != userID {
		if err := c.requireAdminRankCeilingForTarget(ctx, createdBy, userID, "resend the setup link of"); err != nil {
			return nil, err
		}
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, fmt.Errorf("account suspended")
	}
	return c.provisionSetupLinkThrottled(ctx, IssueSetupTokenRequest{
		Purpose:       SetupPurposeAccountSetup,
		SubjectEmail:  user.Email,
		SubjectUserID: &user.ID,
		CreatedBy:     createdBy,
	}, user.DisplayName, "")
}

// checkResendThrottle enforces the per-subject resend limits: a minimum interval
// between issues and a daily cap (ADR-028 abuse section). Counting failures fail
// open — a throttle-store error must not block a legitimate resend.
func (c *KeyorixCore) checkResendThrottle(ctx context.Context, purpose, email string) error {
	key := strings.TrimSpace(strings.ToLower(email))

	// Fail CLOSED on a count error: an abuse control that silently no-ops whenever
	// the store hiccups isn't a control. A transient error briefly delays a
	// legitimate resend (acceptable); it must never open the door to unthrottled
	// setup-link mail to a victim address.
	n, err := c.storage.CountSetupTokensSince(ctx, purpose, key, c.now().Add(-24*time.Hour))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrResendThrottleUnverifiable)
	}
	if n >= resendDailyCap {
		return fmt.Errorf("%s: resend limit reached (max %d per day)", i18n.T("ErrorValidation", nil), resendDailyCap)
	}
	m, err := c.storage.CountSetupTokensSince(ctx, purpose, key, c.now().Add(-resendMinInterval))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), ErrResendThrottleUnverifiable)
	}
	if m >= 1 {
		return fmt.Errorf("%s: please wait before requesting another setup link", i18n.T("ErrorValidation", nil))
	}
	return nil
}

// randomUnusablePassword returns a high-entropy random string used as the initial
// password of a setup-link account. It is never disclosed, so no one can log in
// until the user sets a real password via the link.
func randomUnusablePassword() (string, error) {
	// This password is a throwaway placeholder — it is never returned, and the account is
	// confined to pending_first_login until the real password is set on setup-link consume.
	// But it still flows through CreateUser's password-policy check, so it must satisfy the
	// policy (a raw base64 draw can randomly lack a required character class). Reuse the
	// policy-compliant one-time-password generator (all four classes guaranteed).
	return GenerateInitialCredential()
}

// One-time-password character classes (ADR-028 Part E). Visually ambiguous characters
// (0/O, 1/l/I) are excluded so the password survives being read aloud or copied by hand
// when the admin relays it out of band.
const (
	otpLower   = "abcdefghijkmnpqrstuvwxyz" // no l, o
	otpUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I, O
	otpDigits  = "23456789"                 // no 0, 1
	otpSpecial = "!@#$%^&*-_=+"
	otpLength  = 20
)

// GenerateInitialCredential returns a high-entropy credential that satisfies the default
// ADR-025 password policy (length + all four character classes). It seeds one character
// from each required class so the policy always holds regardless of the random draw,
// fills the rest from the union, then shuffles so the seeded characters aren't in fixed
// positions. All randomness is from crypto/rand.
func GenerateInitialCredential() (string, error) {
	classes := []string{otpLower, otpUpper, otpDigits, otpSpecial}
	all := otpLower + otpUpper + otpDigits + otpSpecial

	out := make([]byte, otpLength)
	for i, class := range classes {
		ch, err := randChar(class)
		if err != nil {
			return "", err
		}
		out[i] = ch
	}
	for i := len(classes); i < otpLength; i++ {
		ch, err := randChar(all)
		if err != nil {
			return "", err
		}
		out[i] = ch
	}
	if err := shuffleBytes(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// randChar returns a uniformly random byte from set using crypto/rand.
func randChar(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return set[n.Int64()], nil
}

// shuffleBytes performs an in-place Fisher–Yates shuffle using crypto/rand, so the
// class-seeded characters do not stay in their initial positions.
func shuffleBytes(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		jj := int(j.Int64())
		b[i], b[jj] = b[jj], b[i]
	}
	return nil
}
