// machine_token.go — machine-identity authentication + RBAC (ADR-030).
//
// Machine identities (ADR-023) can now hold opaque bearer tokens and be granted
// project-scoped roles, so a CI/automation/Kubernetes workload can authenticate
// to the API as a least-privilege principal. Tokens mirror personal access
// tokens (hashed at rest, kx_machine_ prefix); role grants mirror user_roles.
package core

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

const (
	machineTokenPrefix = "kx_machine_"
	// machineTouchInterval throttles last_used_at writes on the auth hot path.
	machineTouchInterval = 30 * time.Second
)

// ErrMachineTokenRevoked/ErrMachineTokenExpired are returned by
// ValidateMachineToken/CurrentMachineTokenRestriction on the same two
// conditions ErrPATRevoked/ErrPATExpired cover for PATs — the caller (auth
// middleware) surfaces either as a 401.
//
// ErrMachineIdentityNotActive is the THIRD such condition (#2518): the
// credential itself is fine but its owning machine identity is no longer
// active (suspended / revoked / deprovisioned). CurrentMachineTokenRestriction's
// own doc comment already named it one of the signals its caller "must treat as
// deny the request, not a transient lookup failure to degrade past" — but it
// returned a plain fmt.Errorf, which the auth middleware's cache-hit path
// cannot tell apart from a storage blip, so it fell into the
// degrade-to-stale-snapshot branch instead (INV-MW-05). A typed sentinel is
// what makes the claim in that doc comment actually checkable by the caller.
var (
	ErrMachineTokenRevoked      = errors.New("token revoked")
	ErrMachineTokenExpired      = errors.New("token expired")
	ErrMachineIdentityNotActive = errors.New("machine identity is not active")
)

// IssueMachineTokenResult carries the freshly minted token. PlainToken is shown
// once and never persisted (only its hash is stored).
type IssueMachineTokenResult struct {
	Credential        *models.MachineIdentityCredential
	PlainToken        string
	ReplacedTokenHash string // non-empty when ReplaceCredentialID was set; caller should evict auth cache
}

// machineInProject fetches a machine identity and verifies it belongs to the
// given project. Every project-scoped machine operation goes through here so a
// caller authorized at project A cannot act on a machine in project B by passing
// its id in the path (the route gate only proves rights at the path's project).
// A project mismatch is reported as "not found" to avoid cross-project id
// enumeration.
func (c *KeyorixCore) machineInProject(ctx context.Context, projectID, machineID uint) (*models.MachineIdentity, error) {
	m, err := c.storage.GetMachineIdentity(ctx, machineID)
	if err != nil || m.ProjectID != projectID {
		return nil, fmt.Errorf("machine identity not found")
	}
	return m, nil
}

// IssueMachineTokenParams groups the token-specific fields for IssueMachineToken.
type IssueMachineTokenParams struct {
	Name           string
	ExpiresAt      *time.Time
	Classification string
	AllowedCIDRs   []string
	// ReplaceCredentialID, when non-zero, atomically revokes the specified existing
	// credential immediately after the new one is issued (PAT-006: eliminates the
	// overlap window in the manual two-step issue-then-revoke rotation flow).
	// The credential must belong to the same machine; it is rejected if not found.
	ReplaceCredentialID uint
}

// validateReplacementCredential pre-validates the credential-to-replace (PAT-006):
// fetches it and confirms it belongs to the given machine. Returns the old token
// hash (for cache eviction) or empty string when replaceID is 0.
func (c *KeyorixCore) validateReplacementCredential(ctx context.Context, machineID, replaceID uint) (string, error) {
	if replaceID == 0 {
		return "", nil
	}
	oldCred, err := c.storage.GetMachineIdentityCredentialByID(ctx, replaceID)
	if err != nil || oldCred.MachineIdentityID != machineID {
		return "", fmt.Errorf("replace_credential_id: credential not found on this machine")
	}
	return oldCred.TokenHash, nil
}

// IssueMachineToken mints an opaque bearer token for an active machine identity.
// The raw token is returned once for out-of-band delivery; only its SHA-256 hash
// is stored. params.AllowedCIDRs, when non-nil and non-empty, restricts the token
// to requests whose source IP falls within one of the listed CIDR blocks.
func (c *KeyorixCore) IssueMachineToken(ctx context.Context, projectID, machineID, actorID uint, params IssueMachineTokenParams) (*IssueMachineTokenResult, error) {
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return nil, err
	}
	if m.State != MachineActive {
		return nil, fmt.Errorf("cannot issue a token for a %s machine identity (must be active)", m.State)
	}
	// MACH-001: enforce a privilege ceiling — a non-admin cannot issue a token for
	// a machine that holds admin-tier roles, since the token would carry those roles
	// and the actor could use it to escalate their own effective privileges. Every
	// caller of IssueMachineToken (CLI, gRPC, HTTP) passes a real user's ID, never a
	// machine principal's, so ActorTypeUser is exact here, not a default.
	if err := c.requireMachinePrivilegeCeiling(ctx, ActorTypeUser, actorID, projectID, machineID); err != nil {
		return nil, err
	}
	classification := params.Classification
	if !IsValidClassification(classification) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty)")
	}
	// Default a token's classification to its machine identity's tier when unset.
	if classification == "" {
		classification = m.Classification
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	raw := machineTokenPrefix + base64.RawURLEncoding.EncodeToString(b)

	// PAT-006: pre-validate the credential to replace BEFORE creating the new one
	// so we fail fast without leaving an orphaned new credential if the old ID is bad.
	oldCredHash, err := c.validateReplacementCredential(ctx, machineID, params.ReplaceCredentialID)
	if err != nil {
		return nil, err
	}

	var cidrJSON string
	if len(params.AllowedCIDRs) > 0 {
		validated, err := encodePATCIDRs(params.AllowedCIDRs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", "invalid CIDR allowlist", err)
		}
		cidrJSON = validated
	}
	cred := &models.MachineIdentityCredential{
		MachineIdentityID: machineID,
		Name:              strings.TrimSpace(params.Name),
		TokenHash:         sha256Hex(raw),
		TokenPrefix:       raw[:len(machineTokenPrefix)+6], // "kx_machine_ab12cd"
		AllowedCIDRs:      cidrJSON,
		ExpiresAt:         params.ExpiresAt,
		Classification:    classification,
		CreatedAt:         c.now(),
	}
	// PAT-006: create the new credential and (when rotating) revoke the replaced one
	// in the SAME transaction. The two used to be sequential storage calls: on a
	// revoke failure the function returned an error, but the just-created new
	// credential was never rolled back — an orphaned row nobody could use (its plain
	// token was discarded along with the error) while the old credential the caller
	// believed was being replaced stayed live. Wrapping both means a revoke failure
	// now leaves NEITHER change applied, matching the error message's own claim.
	//
	// AUDIT-TX-2: the token_issued / token_rotated row is the last statement of
	// that same transaction, so a credential never commits unaudited.
	var created *models.MachineIdentityCredential
	err = c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		var cerr error
		created, cerr = tx.CreateMachineIdentityCredential(ctx, cred)
		if cerr != nil {
			return fmt.Errorf("failed to store machine token: %w", cerr)
		}
		if params.ReplaceCredentialID != 0 {
			if rerr := tx.RevokeMachineIdentityCredential(ctx, projectID, params.ReplaceCredentialID); rerr != nil {
				return fmt.Errorf("failed to revoke old credential %d: %w", params.ReplaceCredentialID, rerr)
			}
			c.logMachineEventOn(ctx, tgt, "machine_identity.token_rotated", m, actorID)
			return nil
		}
		c.logMachineEventOn(ctx, tgt, "machine_identity.token_issued", m, actorID)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if params.ReplaceCredentialID != 0 {
		return &IssueMachineTokenResult{Credential: created, PlainToken: raw, ReplacedTokenHash: oldCredHash}, nil
	}
	return &IssueMachineTokenResult{Credential: created, PlainToken: raw}, nil
}

// ListMachineTokens returns a machine's credentials (hashes are never exposed by
// the DTO), after verifying the machine belongs to the project.
func (c *KeyorixCore) ListMachineTokens(ctx context.Context, projectID, machineID uint) ([]*models.MachineIdentityCredential, error) {
	if _, err := c.machineInProject(ctx, projectID, machineID); err != nil {
		return nil, err
	}
	return c.storage.ListMachineIdentityCredentials(ctx, machineID)
}

// RevokeMachineToken revokes one credential after verifying the machine belongs
// to the project and the credential belongs to the machine. It returns the revoked
// token's hash so the caller can evict it from the auth cache immediately (the HTTP
// token cache is keyed by SHA-256(raw) == TokenHash); without that a revoked machine
// token keeps authenticating until the positive-cache TTL.
func (c *KeyorixCore) RevokeMachineToken(ctx context.Context, projectID, machineID, credentialID, actorID uint) (tokenHash string, err error) {
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return "", err
	}
	cred, err := c.storage.GetMachineIdentityCredentialByID(ctx, credentialID)
	if err != nil || cred.MachineIdentityID != machineID {
		return "", fmt.Errorf("token not found")
	}
	if err := c.storage.RevokeMachineIdentityCredential(ctx, projectID, credentialID); err != nil {
		return "", err
	}
	c.logMachineEvent(ctx, "machine_identity.token_revoked", m, actorID)
	return cred.TokenHash, nil
}

// MachineTokenHashes returns the hashes of all of a machine identity's credentials,
// so the caller can evict them from the auth cache when the identity is suspended or
// revoked (which must reject its tokens immediately, not after the cache TTL).
func (c *KeyorixCore) MachineTokenHashes(ctx context.Context, machineID uint) ([]string, error) {
	creds, err := c.storage.ListMachineIdentityCredentials(ctx, machineID)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(creds))
	for _, cr := range creds {
		if cr.TokenHash != "" {
			hashes = append(hashes, cr.TokenHash)
		}
	}
	return hashes, nil
}

// ClassifyMachineToken sets (or clears, with "") the data-classification label on a
// machine credential, after verifying the machine belongs to the project and the
// credential to the machine. Audited.
func (c *KeyorixCore) ClassifyMachineToken(ctx context.Context, projectID, machineID, credentialID uint, level string, actorID uint) (*models.MachineIdentityCredential, error) {
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return nil, err
	}
	cred, err := c.storage.GetMachineIdentityCredentialByID(ctx, credentialID)
	if err != nil || cred.MachineIdentityID != machineID {
		return nil, fmt.Errorf("token not found")
	}
	if cred.Classification == level {
		return cred, nil // no-op
	}
	old := cred.Classification
	// #2696: a column-scoped write of `classification` alone, conditional on the
	// value this function actually read. The previous full-row Save carried every
	// other column of the unlocked read back with it — `revoked` included — so a
	// RevokeMachineToken committing on another replica between the read above and
	// this write was silently reverted and the revoked token authenticated again.
	// A no-match means the label moved under us; fail closed rather than clobber
	// the concurrent classifier's value, and write no audit event (nothing of ours
	// was persisted).
	matched, err := c.storage.SetMachineIdentityCredentialClassification(ctx, cred.ID, old, level)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("token classification changed concurrently; re-read and retry")
	}
	cred.Classification = level
	aid, pid := actorID, m.ProjectID
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "machine_identity.token_classified", &aid, nil, &pid, "",
		fmt.Sprintf("machine credential %d (machine %d) classification set to %q", cred.ID, machineID, level), diff)
	return cred, nil
}

// ClassifyMachineTokenByID sets a machine credential's data-classification label by
// credential ID alone, with no project/machine ownership check. This was the ONLY
// route into this mutation for a caller that has just a credential ID -- originally
// server/http/handlers' UpdateMachineIdentityCredentialProxy (#1714), since deleted
// along with the rest of the RemoteStorage-sync proxy tree (ADR-108 Phase 6,
// #2162/#2171), which called storage.UpdateMachineIdentityCredential via this rather
// than directly since that mutates state with no audit write. Unlike
// ClassifyMachineToken (the human-facing, project-scoped API), this performs no
// project/machine authorization -- it relied on its (now-deleted) caller having
// already authorized the actor before deciding to relay the write. No production
// caller currently reaches this method; do not add one without also adding the
// authorization check this function itself does not perform.
func (c *KeyorixCore) ClassifyMachineTokenByID(ctx context.Context, credentialID uint, level string) error {
	if !IsValidClassification(level) {
		return fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	cred, err := c.storage.GetMachineIdentityCredentialByID(ctx, credentialID)
	if err != nil {
		return err
	}
	if cred.Classification == level {
		return nil // no-op
	}
	old := cred.Classification
	// #2696: same column-scoped conditional write as ClassifyMachineToken's —
	// see its comment. This function has no production caller today, which is
	// precisely why it must not be left holding the full-row primitive for
	// whoever adds one.
	matched, err := c.storage.SetMachineIdentityCredentialClassification(ctx, cred.ID, old, level)
	if err != nil {
		return err
	}
	if !matched {
		return fmt.Errorf("token classification changed concurrently; re-read and retry")
	}
	cred.Classification = level
	var pid *uint
	if m, err := c.storage.GetMachineIdentity(ctx, cred.MachineIdentityID); err == nil {
		pid = &m.ProjectID
	}
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "machine_identity.token_classified", nil, nil, pid, "",
		fmt.Sprintf("machine credential %d (machine %d) classification set to %q", cred.ID, cred.MachineIdentityID, level), diff)
	return nil
}

// ValidateMachineToken resolves a raw machine token to its identity, granted
// role names, network restriction, and the credential's row id. It rejects
// revoked/expired credentials and any machine not in the active state. The
// middleware gates on the machineTokenPrefix before calling this.
//
// #G60: this deliberately does NOT touch last_used_at itself (sibling of the
// same fix in ValidatePATToken). The credential's network allowlist is
// evaluated by the CALLER (server/middleware, server/grpc/interceptors),
// strictly after this function returns — stamping last_used_at in here would
// record the credential as "used" even for a request the caller is about to
// reject outright for arriving from a disallowed network. The returned
// credential id lets the caller invoke TouchMachineTokenLastUsed itself, once
// its own restriction check has actually passed.
//
// A storage failure while reading the machine's roles returns
// ErrRoleResolutionUnavailable (#2748) — never an empty role list.
func (c *KeyorixCore) ValidateMachineToken(ctx context.Context, raw string) (*models.MachineIdentity, []string, *MachineTokenRestriction, uint, error) {
	if !strings.HasPrefix(raw, machineTokenPrefix) {
		return nil, nil, nil, 0, fmt.Errorf("not a machine token")
	}
	cred, err := c.storage.GetMachineIdentityCredentialByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, nil, nil, 0, credentialLookupError(err, "invalid token")
	}
	if cred.Revoked {
		return nil, nil, nil, 0, ErrMachineTokenRevoked
	}
	if cred.ExpiresAt != nil && c.authEffectiveNow().After(*cred.ExpiresAt) {
		return nil, nil, nil, 0, ErrMachineTokenExpired
	}
	m, err := c.storage.GetMachineIdentity(ctx, cred.MachineIdentityID)
	if err != nil {
		return nil, nil, nil, 0, credentialLookupError(err, "machine identity not found")
	}
	if m.State != MachineActive {
		// Same sentinel as CurrentMachineTokenRestriction's identical check
		// (#2518). Not load-bearing here — every caller of this function denies
		// on any error — but a sibling condition returning a differently-typed
		// error is exactly how the cache-hit path came to be unable to see it,
		// so the two are kept in step.
		return nil, nil, nil, 0, fmt.Errorf("%w: %s", ErrMachineIdentityNotActive, m.State)
	}

	roles, err := c.storage.GetMachineRoles(ctx, m.ID)
	if err != nil {
		// #2748: fail the validation with the same distinguishable, retryable
		// error ValidatePATToken/ValidateSessionToken use (#1944) instead of
		// returning a valid-looking machine principal with an empty role list.
		// Both user-credential paths were fixed by #1944; these two machine
		// paths were missed by it. See ErrRoleResolutionUnavailable.
		return nil, nil, nil, 0, ErrRoleResolutionUnavailable
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return m, roleNames, machineRestrictionFrom(cred), cred.ID, nil
}

// TouchMachineTokenLastUsed records that machine credential credID was just
// used, subject to the same machineTouchInterval throttle the inline stamp
// always used. Split out of ValidateMachineToken (#G60) so the caller only
// stamps last_used_at AFTER its own network-restriction (CIDR allowlist)
// check has passed. Best-effort: never fails the caller's request.
func (c *KeyorixCore) TouchMachineTokenLastUsed(ctx context.Context, credID uint) {
	if credID == 0 {
		return
	}
	_ = c.storage.TouchMachineIdentityCredential(ctx, credID, c.now(), machineTouchInterval)
}

// CurrentMachineTokenRestriction re-fetches a machine token's network restriction
// fresh from storage by its raw token, mirroring CurrentPATRestriction (#146) —
// generalized to machine tokens as part of #G18. Before this, the auth
// middleware's cache-hit path only ever refreshed a PAT's restriction, so a
// machine token's AllowedCIDRs allowlist (and the credential's
// revoked/expired/machine-inactive state) kept being served from the stale
// cached UserContext snapshot for up to validTokenTTL. Returns
// ErrMachineTokenRevoked/ErrMachineTokenExpired, or a plain error when the
// machine identity itself is no longer active (mirroring ValidateMachineToken's
// own checks) — the caller must treat all three as "deny the request", not a
// transient lookup failure to degrade past.
//
// SESSION-PERF (#2403 follow-up): this runs on EVERY cache hit (#G18's whole
// point — the check must be fresh every time, never cached across requests),
// which made it the single largest measured CPU/query cost on the machine-token
// read path (67% of cumulative CPU time in a profile under load). The fix is
// NOT to cache this result — that would reopen the exact staleness window #G18
// closed (a revoked/expired/deactivated token trusted for up to validTokenTTL).
// Instead, GetMachineIdentityCredentialWithIdentityStateByHash fetches the
// credential AND the owning identity's State in ONE query (a JOIN) instead of
// the two sequential round trips this function used before — same freshness,
// same checks, same fail-closed behavior on every single call, just one DB
// round trip instead of two.
func (c *KeyorixCore) CurrentMachineTokenRestriction(ctx context.Context, raw string) (*MachineTokenRestriction, error) {
	cred, identityState, err := c.storage.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, sha256Hex(raw))
	if err != nil {
		if credentialRowGone(err) {
			// CRED-CACHE-REVOKE-1: the credential (or its owning identity) row
			// no longer exists. That is as definitive as revoked, so the
			// cache-hit caller must deny and evict, not degrade to the cached
			// snapshot until validTokenTTL runs out.
			return nil, fmt.Errorf("%w: credential not found", ErrMachineTokenRevoked)
		}
		return nil, err
	}
	if cred.Revoked {
		return nil, ErrMachineTokenRevoked
	}
	if cred.ExpiresAt != nil && c.authEffectiveNow().After(*cred.ExpiresAt) {
		return nil, ErrMachineTokenExpired
	}
	if identityState != MachineActive {
		// #2518: wrap the typed sentinel so the auth middleware's cache-hit path
		// can distinguish this DEFINITIVE deny from an indeterminate storage
		// error, while keeping the concrete state in the message for logs. A
		// bare fmt.Errorf here meant suspending a machine identity took up to
		// validTokenTTL to take effect on every replica other than the one that
		// ran the suspension (only that one flushes via
		// SetMachineTokenCacheFlusher).
		return nil, fmt.Errorf("%w: %s", ErrMachineIdentityNotActive, identityState)
	}
	return machineRestrictionFrom(cred), nil
}

// CurrentFederatedMachineState re-reads, on an HTTP auth-cache hit, whether the
// machine identity a federated OIDC / Kubernetes-JWT principal (ADR-031)
// authenticated as is still active. That principal has no Keyorix credential
// row to re-check (CurrentMachineTokenRestriction's job for opaque machine
// tokens), so the identity's own state is the one revocation signal.
// A no-longer-active identity, or one whose row is gone, is DEFINITIVE
// (ErrMachineIdentityNotActive): the caller denies and evicts. Any other error
// is a failed lookup: the caller refuses the request as temporarily
// unavailable (CACHE-FAILCLOSED-1), never serves the cached principal.
//
// Before this the cache hit ran the session branch's account re-read for user
// id 0, which never exists, so the re-check always failed and the cached
// principal was served regardless: a suspended federated identity kept
// authenticating for up to validTokenTTL on every replica that did not run
// the suspension. Same single read as that account re-read, so no new round
// trip.
func (c *KeyorixCore) CurrentFederatedMachineState(ctx context.Context, machineIdentityID uint) error {
	m, err := c.storage.GetMachineIdentity(ctx, machineIdentityID)
	if err != nil {
		if credentialRowGone(err) {
			return fmt.Errorf("%w: identity not found", ErrMachineIdentityNotActive)
		}
		return err
	}
	if m.State != MachineActive {
		return fmt.Errorf("%w: %s", ErrMachineIdentityNotActive, m.State)
	}
	return nil
}

// credentialRowGone reports whether a by-hash credential lookup failed because
// no row matched: gorm.ErrRecordNotFound on the GORM path, sql.ErrNoRows on the
// prepared-statement path (credential_lookup_raw.go). Both storage methods wrap
// every failure in the same "not found" text, so only the wrapped cause tells a
// vanished row apart from a transient storage error. The cache-hit caller
// denies and evicts on the first and refuses with 503 on the second
// (INV-MW-05, INV-MW-cache-hit-recheck-fails-closed): both refuse, but only a
// definitive verdict may evict or count as a revocation.
func credentialRowGone(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, sql.ErrNoRows)
}

// machineTokenCIDRCorrupted is returned by machineRestrictionFrom when the stored
// column is non-empty but fails JSON parsing. Returning nil would silently widen
// the token to global network access; the sentinel contains no valid CIDR so
// IPInCIDRs blocks all source IPs until the token is re-issued.
var machineTokenCIDRCorrupted = []string{"<corrupted>"}

// machineRestrictionFrom decodes the JSON AllowedCIDRs on a credential into a
// MachineTokenRestriction. Returns nil when no CIDRs are set.
func machineRestrictionFrom(cred *models.MachineIdentityCredential) *MachineTokenRestriction {
	if cred.AllowedCIDRs == "" {
		return nil
	}
	var cidrs []string
	if err := json.Unmarshal([]byte(cred.AllowedCIDRs), &cidrs); err != nil {
		return &MachineTokenRestriction{AllowedCIDRs: machineTokenCIDRCorrupted}
	}
	if len(cidrs) == 0 {
		return nil
	}
	return &MachineTokenRestriction{AllowedCIDRs: cidrs}
}

// requireEnvironmentInProject fails closed unless scope.EnvironmentID is 0
// (global) or names an environment of scope.ProjectID. environment_id is
// caller-supplied, and a machine-role grant or removal scoped to (project A, an
// environment of project B) must never be stored or acted on (#2595). Same check
// as CreateSecret / dynamic secrets / rotation policies. Shared by
// AssignMachineRole and RemoveMachineRole so the two cannot drift.
func (c *KeyorixCore) requireEnvironmentInProject(ctx context.Context, scope Scope) error {
	if scope.EnvironmentID == 0 {
		return nil
	}
	env, err := c.storage.GetEnvironment(ctx, scope.EnvironmentID)
	if err != nil {
		if !isEnvironmentNotFoundErr(err) {
			return fmt.Errorf("failed to verify target environment %d: %w", scope.EnvironmentID, err)
		}
		return fmt.Errorf("%s: environment %d not found", i18n.T("ErrorValidation", nil), scope.EnvironmentID)
	}
	if env.ProjectID != scope.ProjectID {
		return fmt.Errorf("%s: environment %d does not belong to project %d", i18n.T("ErrorValidation", nil), scope.EnvironmentID, scope.ProjectID)
	}
	return nil
}

// AssignMachineRole grants a role to a machine identity at the given scope and
// audits it. The machine must belong to scope.ProjectID — the caller is only
// proven to hold roles.assign at that project, so a machine in another project
// must not be reachable through this path. The grant is additionally gated by
// requireGranterHoldsRolePermissions (the same escalation-by-proxy ceiling
// AddProjectMember applies, and by the role's real bundled permissions, not only
// its name) — an admin-credentialed machine identity is just as much a
// self-escalation vector as an admin user grant. Also gated by the #419
// separation-of-duties preventive check (requireMachineGrantNoSoDViolation,
// sod.go) — a machine identity holds real permissions too and Authorize
// authorizes it, so the same toxic-permission-pair concern applies.
// actorIsMachine distinguishes a machine-credential-authenticated GRANTING actor
// (also actorID==0) from the true actorID==0 system pseudo-actor — distinct from
// machineID, the role's TARGET.
func (c *KeyorixCore) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope Scope, actorID uint, actorIsMachine bool) error {
	m, err := c.machineInProject(ctx, scope.ProjectID, machineID)
	if err != nil {
		return err
	}
	if err := c.requireEnvironmentInProject(ctx, scope); err != nil {
		return err
	}
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return err
	}
	if err := c.requireGranterHoldsRolePermissions(ctx, actorID, roleID, scope, actorIsMachine); err != nil {
		return err
	}
	// GUARD-2: the check-then-write below must be serialized across every
	// replica of an HA deployment, not just within this process — mirrors
	// AssignUserRole/AssignRoleToGroup's identical WithNamedLock use
	// (#1646/#1780). AssignMachineRole had NO serialization at all (not even
	// an in-process mutex) before this: two concurrent grants of two
	// individually-clean roles to the SAME machine identity could each pass
	// requireMachineGrantNoSoDViolation against a stale pre-grant permission
	// set and both commit, jointly completing a toxic SoD pair on a machine
	// credential.
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("machine", machineID), func(ctx context.Context) error {
		if err := c.requireMachineGrantNoSoDViolation(ctx, machineID, roleID); err != nil {
			return err
		}
		// AUDIT-TX-2: the grant and its role_granted row commit together.
		return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
			if err := tx.AssignMachineRole(ctx, machineID, roleID, scope); err != nil {
				return err
			}
			c.logMachineEventOn(ctx, tgt, "machine_identity.role_granted", m, actorID)
			return nil
		})
	})
}

// RemoveMachineRole revokes a machine identity's role grant at the given scope.
// scope.EnvironmentID, when non-zero, must name an environment of scope.ProjectID
// (fail closed, same as AssignMachineRole); storage matches the scope exactly, so
// a project-wide (EnvironmentID 0) removal never touches an environment-scoped grant.
//
// Uses the SAME lock key as AssignMachineRole (sodGrantLockKey("machine", machineID)),
// not a separate one: a grant and a removal racing on the same machine identity must
// serialize against each other too, not just against other grants/removals of their
// own kind (GUARD-2, check-then-act lock guard).
func (c *KeyorixCore) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope Scope, actorID uint) error {
	m, err := c.machineInProject(ctx, scope.ProjectID, machineID)
	if err != nil {
		return err
	}
	return c.withMachineRoleRemovalGuards(ctx, machineID, scope, func(ctx context.Context) error {
		return c.removeMachineRoleWriteOn(ctx, c.storage, c.auditNow(), m, roleID, scope, actorID)
	})
}

// withMachineRoleRemovalGuards runs write under exactly the named lock and
// scope validation a machine-role removal requires — hoisted out of
// RemoveMachineRole so the access-review revoke transaction (#2676) reuses this
// decision rather than restating it, the same arrangement
// withUserRoleRemovalGuards / withGroupRoleRemovalGuards use for their
// respective principals.
func (c *KeyorixCore) withMachineRoleRemovalGuards(ctx context.Context, machineID uint, scope Scope, write func(ctx context.Context) error) error {
	return c.storage.WithNamedLock(ctx, sodGrantLockKey("machine", machineID), func(ctx context.Context) error {
		if err := c.requireEnvironmentInProject(ctx, scope); err != nil {
			return err
		}
		return write(ctx)
	})
}

// removeMachineRoleWriteOn is the machine-role removal's persistent effect
// through an explicit storage handle and audit target — the machine counterpart
// of removeUserRoleWriteOn.
func (c *KeyorixCore) removeMachineRoleWriteOn(ctx context.Context, st storage.Storage, tgt auditTarget, m *models.MachineIdentity, roleID uint, scope Scope, actorID uint) error {
	if err := st.RemoveMachineRole(ctx, m.ID, roleID, scope); err != nil {
		return err
	}
	c.logMachineEventOn(ctx, tgt, "machine_identity.role_removed", m, actorID)
	return nil
}

// ListMachineRoles returns every role granted to a machine identity in the
// given project (for display), after verifying the machine belongs to it.
func (c *KeyorixCore) ListMachineRoles(ctx context.Context, projectID, machineID uint) ([]*models.Role, error) {
	if _, err := c.machineInProject(ctx, projectID, machineID); err != nil {
		return nil, err
	}
	return c.storage.GetMachineRoles(ctx, machineID)
}
