// secret_render.go — server-side rendering of templates that embed secret
// references (${secret:<environment>/<name>}). Resolution is scoped to one project,
// where an environment name and a secret name are unique, so a reference resolves
// unambiguously. Each referenced value is read through the per-secret permission
// check, so the caller only ever renders secrets they may read.
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/secrettemplate"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// timingCanaryID stands in for a real environment/secret ID when equalizing
// resolution timing (see equalizeReferenceResolutionCost): auto-increment IDs
// start at 1, so this can never collide with a real row, and every lookup
// against it is a guaranteed, harmless miss.
const timingCanaryID = ^uint(0)

// timingCanaryPlaintext/timingCanaryAAD are fixed, non-secret inputs used only
// to exercise the secret-value encryptor's real cost (KMS wrap + AES-256-GCM)
// when a render reference must NOT trigger a real decrypt — see
// equalizeReferenceResolutionCost. Never persisted; the result is discarded.
var (
	timingCanaryPlaintext = []byte("keyorix-render-timing-equalizer")     // NOSONAR -- not a credential; timing-equalization sentinel
	timingCanaryAAD       = []byte("keyorix-render-timing-equalizer-aad") // NOSONAR -- not a credential; timing-equalization sentinel
)

// RenderSecretTemplate expands ${secret:<environment>/<name>} references in template
// against the given project, returning the rendered output. A reference to an unknown
// environment/secret, or one the user cannot read, fails the whole render (no partial
// output). Values are never logged — but each resolved value IS recorded as a secret read
// (audit event + access log), so a bulk render can't be used as a covert exfiltration
// channel invisible to the audit trail and the anomaly detector. username/ip/ua attribute
// the reads (pass-through from the request); empty is tolerated.
func (c *KeyorixCore) RenderSecretTemplate(ctx context.Context, template string, projectID, userID uint, username, ip, ua string) (string, error) {
	if projectID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if userID == 0 {
		return "", fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	// #G10 (partial — see note): the review flags that this enumerates projectID's full
	// environment list with no membership/authorization check. A hard project-role gate
	// here was evaluated and reverted: this codebase's RBAC role grant and its "read a
	// specific secret" grant are the SAME permission (secrets.read) at overlapping scope,
	// so any project-role check strong enough to gate environment enumeration would ALSO
	// always satisfy the per-secret ValidateSecretAccess check below via its own RBAC
	// fallback — making a share-only user (no project role, but a direct/group share or
	// ACL grant on one specific secret) unable to ever pass the gate, even for a template
	// referencing only secrets they ARE independently entitled to read. Regression-tested
	// in secret_render_test.go's "non-reader cannot resolve" / UniformResponseForNotFound
	// VsForbidden cases, which rely on exactly that share-only access pattern.
	// What's ALREADY safe today: envByName is never returned to the caller — a reference
	// to an unknown environment and a reference to an existing-but-forbidden secret both
	// resolve to the identical ErrSecretRefNotFound sentinel (TMPL-002/#181), so an
	// unrelated caller cannot use this to enumerate environment names or secret existence
	// via a distinguishable error. The residual gap is narrower than the finding implies —
	// an authenticated caller with zero relationship to projectID can still cause a real
	// (masked-result) storage query against it — and needs a design that accounts for the
	// share-only access path before it can close without a regression. Left as a documented
	// gap rather than shipped with a silent access-narrowing side effect.

	envs, err := c.storage.ListEnvironmentsByProject(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("list environments: %w", err)
	}
	envByName := make(map[string]uint, len(envs))
	for _, e := range envs {
		envByName[e.Name] = e.ID
	}

	// staged accumulates every reference successfully resolved while checking the
	// template, in first-seen order (secrettemplate.Render resolves distinct
	// references in exactly that order via stageRenderRef below). Its max-reads
	// budget consumption and secret.read audit emission are deferred to the commit
	// loop below and applied ONLY once the ENTIRE template is confirmed to render
	// successfully. Without this, a template naming N references where a LATER one
	// fails would leave the earlier, successfully-decrypted-but-ultimately-discarded
	// ones "half charged": budget consumed and an audit trail generated for values
	// that were never delivered to anyone, and a large template with one
	// deliberately-failing reference could be used to probe/burn another read's
	// budget or flood the audit trail with reads that produced no output. This
	// extends the function's existing "fails the whole render, no partial output"
	// contract to its side effects, not just its return value.
	var staged []*stagedSecretRead

	output, err := secrettemplate.Render(template, func(ref string) (string, error) {
		return c.stageRenderRef(ctx, ref, projectID, userID, envByName, &staged)
	})
	if err != nil {
		return "", err
	}

	for _, s := range staged {
		if err := c.commitStagedSecretRead(ctx, s, projectID, userID, username, ip, ua); err != nil {
			return "", err
		}
	}
	return output, nil
}

// stagedSecretRead holds a reference successfully resolved during
// RenderSecretTemplate's staging pass (stageRenderRef): the permission check
// passed and the value decrypted cleanly, but the max-reads budget consumption
// and secret.read audit emission for it have NOT been committed yet — see
// RenderSecretTemplate's commit loop.
type stagedSecretRead struct {
	secret     *models.SecretNode
	version    *models.SecretVersion
	secretName string
}

// stageRenderRef resolves one secret reference for RenderSecretTemplate: it runs
// the permission check and decrypts the value, but does NOT consume max-reads
// budget or emit a secret.read audit event — those are staged into *staged and
// committed by the caller only once the WHOLE template is confirmed to render
// successfully.
//
// It also performs the SAME SHAPE of DB lookup and decrypt-cost work regardless
// of whether the reference turns out to be unknown, forbidden, or readable — see
// equalizeReferenceResolutionCost — so response timing can't be used to tell the
// three cases apart, defeating this function's own anti-enumeration design (#181).
func (c *KeyorixCore) stageRenderRef(ctx context.Context, ref string, projectID, userID uint, envByName map[string]uint, staged *[]*stagedSecretRead) (string, error) {
	envName, secretName, err := splitRenderRef(ref)
	if err != nil {
		return "", err
	}
	envID, ok := envByName[envName]
	if !ok {
		// TMPL-002: fall through to the SAME GetSecretByName call a known
		// environment would make, against a canary ID that can never match a real
		// row, instead of returning immediately — an unknown environment must not
		// resolve FASTER than a known one, or timing alone reveals which case
		// occurred (also avoids leaking the environment name in the HTTP response
		// via sendRenderTemplateError).
		envID = timingCanaryID
	}
	secret, err := c.storage.GetSecretByName(ctx, secretName, projectID, envID)
	if err != nil || secret == nil {
		// A reference to a name that doesn't exist. Deliberately the SAME sentinel
		// (same error, same eventual HTTP status/message) as "exists but you can't
		// read it" below — see the permission check for why (#181).
		c.equalizeReferenceResolutionCost(ctx, userID, nil)
		return "", ErrSecretRefNotFound
	}
	// Run the permission check BEFORE anything that could distinguish this from the
	// "doesn't exist" branch above. GetSecretByName has no ACL of its own, so if we
	// let a permission failure surface its own distinct error/status here, a
	// `viewer`-role project member with no access to this secret could enumerate
	// candidate names via ${secret:<env>/<guess>} and learn existence per guess from
	// 404-vs-403 alone — info never surfaced by their normal scoped listing. Folding
	// both outcomes into the identical ErrSecretRefNotFound closes that oracle (#181).
	if _, err := c.ValidateSecretAccess(ctx, secret.ID, userID); err != nil {
		c.equalizeReferenceResolutionCost(ctx, userID, secret)
		return "", ErrSecretRefNotFound
	}
	// From here on this mirrors getSecretValueForUser's body exactly, minus the
	// max-reads increment (deferred to commitStagedSecretRead).
	if err := c.enforceSecretReadGuards(ctx, secret, userID); err != nil {
		return "", err
	}
	version, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}
	val, err := c.decryptVersionValue(secret, version)
	if err != nil {
		return "", err
	}
	*staged = append(*staged, &stagedSecretRead{secret: secret, version: version, secretName: secretName})
	return string(val), nil
}

// equalizeReferenceResolutionCost performs the same SHAPE of DB lookup and
// decrypt-cost work that a successful reference resolution performs, so a
// caller cannot use response timing to tell "reference doesn't exist" (secret
// == nil) apart from "reference exists but userID may not read it" (secret !=
// nil) apart from "reference exists and is readable". Mirrors the
// dummy-bcrypt-hash technique VerifyPasswordCredentials uses for unknown-user
// logins (bcrypt_cost.go): run the SAME real, expensive primitive on a fixed
// canary input rather than skipping it.
//
// Scope: this closes the dominant, easily-measurable gap — a not-found
// reference costing zero DB round trips and no decrypt versus a readable one
// costing several DB round trips plus a real decrypt. It does NOT attempt to
// make CheckSecretPermission's OWN internal cost constant across every one of
// its (owner/share/group/ACL/RBAC) branches — that variability is
// architectural and already a documented residual gap (see the #G10 comment
// above), not something a per-reference timing equalizer here can close.
func (c *KeyorixCore) equalizeReferenceResolutionCost(ctx context.Context, userID uint, secret *models.SecretNode) {
	if secret == nil {
		// No real secret to check; ValidateSecretAccess still walks its normal
		// first step (a GetSecret lookup) against a canary ID that can never
		// exist before failing, giving this branch the same representative
		// DB-call shape a genuine permission check pays.
		_, _ = c.ValidateSecretAccess(ctx, timingCanaryID, userID)
		_, _ = c.storage.GetLatestSecretVersion(ctx, timingCanaryID)
	} else {
		// The permission check already ran for real (and denied) by the time this
		// is called; pad with the SAME read-guard + version-lookup shape the
		// readable path pays next, using the real (existing) secret — read-only,
		// so this is harmless even though the caller isn't authorized to read its
		// value.
		_ = c.enforceSecretReadGuards(ctx, secret, userID)
		_, _ = c.storage.GetLatestSecretVersion(ctx, secret.ID)
	}
	if c.secretValueEncryptor != nil {
		// Real crypto cost (KMS wrap + AES-256-GCM) — the same primitive the
		// readable path's decrypt pays — on fixed, non-secret canary input.
		_, _, _ = c.secretValueEncryptor.EncryptSecretWithAAD(timingCanaryPlaintext, timingCanaryAAD)
	}
}

// commitStagedSecretRead applies the max-reads budget consumption and emits the
// secret.read audit event (+ access log) for one staged reference — the
// deferred side effects of a reference RenderSecretTemplate has already
// confirmed is part of a successful render. Mirrors readVersionValue's
// max-reads enforcement (versions.go); the value itself was already decrypted
// during staging, so there's nothing left to decrypt here.
func (c *KeyorixCore) commitStagedSecretRead(ctx context.Context, s *stagedSecretRead, projectID, userID uint, username, ip, ua string) error {
	if s.secret.MaxReads != nil && *s.secret.MaxReads > 0 {
		ok, err := c.storage.TryIncrementSecretNodeReadCount(ctx, s.secret.ID, *s.secret.MaxReads)
		if err != nil {
			return fmt.Errorf("max-reads enforcement failed: %w", err)
		}
		if !ok {
			return errSecretMaxReadsExhausted()
		}
		// Best-effort per-version read_count (CLI/gRPC display only, not the
		// enforcement mechanism above): a failure here must not block an
		// already-authorized read.
		_, _ = c.storage.TryIncrementSecretReadCount(ctx, s.version.ID, *s.secret.MaxReads)
	}
	// Record the read like the single-secret read path does, so a bulk render is
	// auditable and visible to the anomaly detector. SESSION-PERF #2403 follow-up
	// (item 3): now synchronous and checked (DetachedAuditContext still protects it
	// from the request's own cancellation) instead of fire-and-forget — propagates
	// as an error the same way the max-reads check above already does, rather than
	// silently dropping an audit-write failure.
	if err := c.LogSecretReadWithProject(DetachedAuditContext(ctx), userID, s.secret.ID, projectID, username, s.secretName, ip, ua); err != nil {
		return fmt.Errorf("failed to record audit trail for rendered secret: %w", err)
	}
	return nil
}

// splitRenderRef splits "<environment>/<name>"; the name may contain further slashes.
func splitRenderRef(ref string) (env, name string, err error) {
	ref = strings.TrimSpace(ref)
	i := strings.IndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", fmt.Errorf("invalid reference %q: expected \"<environment>/<name>\"", ref)
	}
	return ref[:i], ref[i+1:], nil
}
