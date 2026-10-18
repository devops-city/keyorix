// pat.go — Personal Access Tokens (ADR-027, ADR-042).
//
// A PAT is a long-lived bearer credential a user creates from the My Account page.
// It authenticates API requests AS that user. By default it inherits the owner's
// full permission set; optionally (ADR-042) it carries a least-privilege
// restriction — a permission allowlist and/or a single-project or single-
// environment scope — that narrows it below the owner (never above). The raw
// token is returned once on
// creation; only its SHA-256 hash is stored. Raw tokens carry the patPrefix so the
// auth middleware can route them to ValidatePATToken and secret scanners can detect
// leaks.
package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	// patPrefix marks a raw PAT. Load-bearing: middleware routing + secret scanning.
	patPrefix = "kx_pat_"
	// patTouchInterval throttles last_used_at writes on the auth hot path.
	patTouchInterval = 30 * time.Second
)

// EventPATCreated/EventPATRevoked are audited on every self-service PAT
// create/revoke (F3, audit-completeness campaign). Descriptions carry only
// the token id/name, never the raw token or its hash.
const (
	EventPATCreated = "pat.created"
	EventPATRevoked = "pat.revoked"
)

// CreatePATResult carries the freshly created token plus its one-time plaintext.
// The plaintext is never persisted and never returned again.
type CreatePATResult struct {
	Token      *models.PersonalAccessToken
	PlainToken string
}

// CreateOwnPAT generates a new personal access token for the caller. expiresAt may
// be nil for a non-expiring token. scopes, when non-empty, is a least-privilege
// permission allowlist (ADR-042); projectScope/environmentScope, when non-zero,
// confine the token to a single project / environment. All only ever NARROW the
// token below its owner — they are enforced at request time as a filter
// intersected with the owner's live permissions, so a token can never grant more
// than its owner currently holds.
func (c *KeyorixCore) CreateOwnPAT(ctx context.Context, userID uint, name string, expiresAt *time.Time, scopes []string, projectScope, environmentScope uint, allowedCIDRs []string) (*CreatePATResult, error) { // NOSONAR -- domain-driven parameter count
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	// PAT-GUARD-1: a restricted PAT must not mint a token. The child is
	// unrestricted unless asked otherwise, so this was a one-call escape from every
	// dimension of the restriction (project, environment, permissions and the CIDR
	// allowlist). Creation never runs Authorize, so the chokepoint could not catch it.
	if patRestrictionFromContext(ctx) != nil {
		return nil, ErrRestrictedPATCannotMintPAT
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%s: token name is required", i18n.T("ErrorValidation", nil))
	}

	scopesJSON, err := encodePATScopes(scopes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	cidrsJSON, err := encodePATCIDRs(allowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	raw := patPrefix + base64.RawURLEncoding.EncodeToString(b)

	pat := &models.PersonalAccessToken{
		UserID:           userID,
		Name:             strings.TrimSpace(name),
		TokenHash:        sha256Hex(raw),
		TokenPrefix:      raw[:len(patPrefix)+6], // e.g. "kx_pat_ab12cd" for display
		Scopes:           scopesJSON,
		ProjectScope:     projectScope,
		EnvironmentScope: environmentScope,
		AllowedCIDRs:     cidrsJSON,
		ExpiresAt:        expiresAt,
		CreatedAt:        c.now(),
	}
	// AUDIT-TX-2: the token and its pat.created row commit in ONE transaction,
	// so a credential is never minted unaudited.
	var created *models.PersonalAccessToken
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var err error
		if created, err = tx.CreatePersonalAccessToken(ctx, pat); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		// Description never carries the raw token or its hash — only the id/name,
		// same discipline as every other credential-creation audit event.
		c.writeAuditEventFullOn(ctx, tgt, EventPATCreated, actorPtr(userID), nil, nil, "",
			fmt.Sprintf("user %d created PAT %d (%q)", userID, created.ID, created.Name))
		return nil
	}); err != nil {
		return nil, err
	}
	return &CreatePATResult{Token: created, PlainToken: raw}, nil
}

// ListOwnPATs returns the caller's tokens (hashes are never exposed by the HTTP DTO).
func (c *KeyorixCore) ListOwnPATs(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListPersonalAccessTokensByUser(ctx, userID)
}

// RevokeOwnPAT revokes one of the caller's tokens after verifying ownership. A token
// owned by another user is reported as not found to prevent ID enumeration. On success
// it returns the token's hash so the caller can evict the auth cache immediately: the
// HTTP token cache is keyed by SHA-256(raw token), which equals the stored TokenHash,
// so without eviction a revoked PAT would keep authenticating until the cache TTL.
func (c *KeyorixCore) RevokeOwnPAT(ctx context.Context, userID, tokenID uint) (tokenHash string, err error) {
	if userID == 0 || tokenID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user and token IDs are required")
	}
	pat, err := c.storage.GetPersonalAccessTokenByID(ctx, tokenID)
	if err != nil || pat.UserID != userID {
		return "", fmt.Errorf("%s: token not found", i18n.T("ErrorNotFound", nil))
	}
	if err := c.storage.RevokePersonalAccessToken(ctx, tokenID); err != nil {
		return "", err
	}
	c.writeAuditEvent(ctx, EventPATRevoked, actorPtr(userID), nil,
		fmt.Sprintf("user %d revoked PAT %d (%q)", userID, pat.ID, pat.Name))
	return pat.TokenHash, nil
}

// ValidatePATToken resolves a raw PAT to its owning user, role names, any
// least-privilege restriction (ADR-042; nil when the token is unrestricted),
// and the PAT's row id, mirroring the shape of ValidateSessionToken so the
// auth middleware can use either. It rejects revoked/expired tokens and
// inactive users. The caller (middleware) is expected to gate on the
// patPrefix.
//
// #G60: this deliberately does NOT touch last_used_at itself. A PAT's network
// allowlist (the restriction's AllowedCIDRs) is evaluated by the CALLER
// (server/middleware, server/grpc/interceptors), strictly after this function
// returns — stamping last_used_at in here would record the token as "used"
// even for a request the caller is about to reject outright for arriving
// from a disallowed network, making the timestamp lie about whether the
// token actually succeeded from that request's source. The returned PAT id
// lets the caller invoke TouchPATLastUsed itself, once its own restriction
// check has actually passed.
//
// A storage failure while reading the owner's roles returns
// ErrRoleResolutionUnavailable (#1944) — never an empty role list.
func (c *KeyorixCore) ValidatePATToken(ctx context.Context, raw string) (*models.User, []string, *PATRestriction, uint, error) {
	if !strings.HasPrefix(raw, patPrefix) {
		return nil, nil, nil, 0, fmt.Errorf("not a personal access token")
	}
	pat, err := c.storage.GetPersonalAccessTokenByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, nil, nil, 0, credentialLookupError(err, "invalid token")
	}
	if pat.Revoked {
		return nil, nil, nil, 0, ErrPATRevoked
	}
	if IsPATExpired(pat, c.authEffectiveNow()) {
		c.emitPATExpiredNotification(ctx, pat)
		return nil, nil, nil, 0, ErrPATExpired
	}
	user, err := c.storage.GetUser(ctx, pat.UserID)
	if err != nil {
		return nil, nil, nil, 0, credentialLookupError(err, "user not found")
	}
	if !user.IsActive {
		return nil, nil, nil, 0, fmt.Errorf("user inactive")
	}
	// A suspended/blocked account must not authenticate via a PAT either. SuspendUser sets
	// account_state but deliberately leaves is_active untouched (and kills sessions), so
	// without this an admin's suspend would cut off session access yet leave the user's
	// personal access tokens fully working. Mirror ValidateSessionToken's account-state
	// gate so suspension is immediately effective on every credential type.
	if AccountLoginBlocked(user.ID, user.AccountState) {
		return nil, nil, nil, 0, fmt.Errorf("account is not active")
	}

	restriction := patRestrictionFrom(pat)

	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		// #1944: fail the validation with a distinguishable, retryable error
		// instead of returning a valid-looking identity with an empty role
		// list (see ErrRoleResolutionUnavailable).
		return nil, nil, nil, 0, ErrRoleResolutionUnavailable
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, restriction, pat.ID, nil
}

// TouchPATLastUsed records that PAT patID was just used, subject to the same
// patTouchInterval throttle the inline stamp always used. Split out of
// ValidatePATToken (#G60) so the caller only stamps last_used_at AFTER its
// own network-restriction (CIDR allowlist) check has passed — see
// ValidatePATToken's doc comment for why touching unconditionally during
// validation was misleading. Best-effort: never fails the caller's request.
func (c *KeyorixCore) TouchPATLastUsed(ctx context.Context, patID uint) {
	if patID == 0 {
		return
	}
	_ = c.storage.TouchPersonalAccessToken(ctx, patID, c.now(), patTouchInterval)
}

// CurrentPATRestriction re-fetches a PAT's restriction fresh from storage by its
// raw token, bypassing any cached UserContext snapshot the auth middleware may be
// holding (#146). The middleware's short-circuit cache holds a validated token's
// full UserContext — including PATRestriction.AllowedCIDRs — for up to
// validTokenTTL; on a cache HIT the network-allowlist check would otherwise be
// enforced against that stale snapshot, not the token's current restriction. This
// lets the network check re-verify fresh on every request regardless of cache
// state, at the cost of one extra lightweight lookup per PAT-authenticated
// request (session/machine tokens carry no such per-request-narrowable
// restriction and are unaffected). Returns an error on any lookup failure — the
// caller must NOT treat that as "unrestricted" (that would fail OPEN on the exact
// check this exists to keep honest). Since CACHE-FAILCLOSED-1 the caller does
// not fall back to the last-known restriction either: a failed re-check
// refuses the request as temporarily unavailable (INV-MW-cache-hit-recheck-
// fails-closed), because the same failed read is the one that would have seen
// a revocation.
//
// #G18: also surfaces ErrPATRevoked/ErrPATExpired — previously this only ever
// read Permissions/ProjectID/EnvironmentID/AllowedCIDRs off the freshly-read
// row and silently discarded Revoked/ExpiresAt, so a cache-hit request kept
// authenticating with a PAT that had been revoked or had expired since the
// cache entry was written, for up to validTokenTTL. The caller must now treat
// these two sentinels as "deny the request", not as a transient lookup
// failure to degrade past (see serveAuthCacheHit).
func (c *KeyorixCore) CurrentPATRestriction(ctx context.Context, raw string) (*PATRestriction, error) {
	pat, err := c.storage.GetPersonalAccessTokenByHash(ctx, sha256Hex(raw))
	if err != nil {
		if credentialRowGone(err) {
			// CRED-CACHE-REVOKE-1: a deleted PAT row (the retention purge, or
			// any out-of-band delete) is a definitive deny, like revoked.
			return nil, fmt.Errorf("%w: token not found", ErrPATRevoked)
		}
		return nil, err
	}
	if pat.Revoked {
		return nil, ErrPATRevoked
	}
	if IsPATExpired(pat, c.authEffectiveNow()) {
		return nil, ErrPATExpired
	}
	return patRestrictionFrom(pat), nil
}

// patRestrictionFrom builds the request-time restriction for a token, or nil when
// the token is unrestricted (no scopes and no project confinement).
func patRestrictionFrom(pat *models.PersonalAccessToken) *PATRestriction {
	scopes := DecodePATScopes(pat.Scopes)
	cidrs := DecodePATCIDRs(pat.AllowedCIDRs)
	if len(scopes) == 0 && pat.ProjectScope == 0 && pat.EnvironmentScope == 0 && len(cidrs) == 0 {
		return nil
	}
	return &PATRestriction{Permissions: scopes, ProjectID: pat.ProjectScope, EnvironmentID: pat.EnvironmentScope, AllowedCIDRs: cidrs}
}
