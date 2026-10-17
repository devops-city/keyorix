package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// secretExpiryClockRegressionTolerance bounds how far c.now() may read
// EARLIER than secretExpiryWatermark before checkSecretExpiryClockNotRegressed
// refuses the read. Must be small enough to still catch a deliberate/
// NTP-less manual clock reset (the #1632 threat model: an operator, or an
// NTP correction, stepping the clock back by an hour or more) and large
// enough not to false-positive on ordinary small backward NTP slew steps
// (NTP step corrections, as opposed to gradual slewing, are typically
// sub-second to low-single-digit seconds).
const secretExpiryClockRegressionTolerance = 30 * time.Second

// checkSecretExpiryClockNotRegressed refuses to trust now for the secret-value
// disclosure guard if it looks EARLIER than a time this process has already
// legitimately observed for this same check (more than
// secretExpiryClockRegressionTolerance behind secretExpiryWatermark) — see
// secretExpiryWatermark's doc comment (service.go) for what this does and
// does not protect against. On success, advances the watermark to now (never
// backward — the watermark itself must not regress, or a second, slower
// backward step could walk it down unnoticed).
//
// Part 2 regression audit continuation (2026-09-04): .UTC() below is not
// cosmetic — it strips any monotonic clock reading a real time.Now()-derived
// now carries (see time.Time's package doc). Before this fix, comparing two
// monotonic-carrying values (this call's now against the previously-stored
// secretExpiryWatermark, both ultimately from c.now()==time.Now in
// production) used ONLY their monotonic delta, which never regresses even
// when the OS wall clock is stepped backward — so this guard could never
// actually detect the exact regression it exists to catch. The guard's own
// tests never caught this because their now values come from time.Date(...)
// test doubles, which the stdlib guarantees never carry a monotonic
// reading — the tests exercised wall-clock-only comparisons throughout,
// silently different semantics from the real production path. Stripped
// locally (not just relying on the caller) so this function is correct
// regardless of what future callers pass in.
func (c *KeyorixCore) checkSecretExpiryClockNotRegressed(now time.Time) error {
	now = now.UTC()
	c.secretExpiryWatermarkMu.Lock()
	defer c.secretExpiryWatermarkMu.Unlock()
	if !c.secretExpiryWatermark.IsZero() && now.Before(c.secretExpiryWatermark.Add(-secretExpiryClockRegressionTolerance)) {
		// Deliberately the SAME error i18n key and text as an ordinary expired
		// secret, not a distinct "clock anomaly detected" message: telling a
		// caller specifically that clock regression was detected is itself an
		// oracle (it confirms the manipulation had an effect worth reacting
		// to). A uniform refusal reveals nothing beyond "this read did not
		// succeed," matching how every other guard in this bundle refuses.
		// The same sentinel too (ERRMAP-1), so every transport answers it with
		// the identical SecretExpired status and code, never a distinct one.
		return errSecretExpired(false)
	}
	if now.After(c.secretExpiryWatermark) {
		c.secretExpiryWatermark = now
	}
	return nil
}

// GetSecretVersions retrieves all versions of a secret.
func (c *KeyorixCore) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if _, err := c.storage.GetSecret(ctx, secretID); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return versions, nil
}

// GetSecretVersionsWithPermissionCheck retrieves all versions of a secret with permission validation.
func (c *KeyorixCore) GetSecretVersionsWithPermissionCheck(ctx context.Context, secretID, userID uint) ([]*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.GetSecretVersions(ctx, secretID)
}

// GetSecretVersion retrieves a specific version of a secret.
func (c *KeyorixCore) GetSecretVersion(ctx context.Context, secretID uint, versionNumber int) (*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if versionNumber <= 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "version number must be positive")
	}
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	for _, version := range versions {
		if version.VersionNumber == versionNumber {
			return version, nil
		}
	}
	return nil, fmt.Errorf("%s: version %d not found", i18n.T("ErrorVersionNotFound", nil), versionNumber)
}

// GetSecretVersionWithPermissionCheck retrieves a specific version of a secret with permission validation.
func (c *KeyorixCore) GetSecretVersionWithPermissionCheck(ctx context.Context, secretID, userID uint, versionNumber int) (*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.GetSecretVersion(ctx, secretID, versionNumber)
}

// GetLatestSecretVersion retrieves the latest version of a secret.
func (c *KeyorixCore) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNoVersionsFound", nil))
	}
	// Versions are ordered by version DESC, so first is latest.
	return versions[0], nil
}

// GetLatestSecretVersionWithPermissionCheck retrieves the latest version of a secret with permission validation.
func (c *KeyorixCore) GetLatestSecretVersionWithPermissionCheck(ctx context.Context, secretID, userID uint) (*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.ValidateSecretAccess(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.GetLatestSecretVersion(ctx, secretID)
}

// GetSecretValue retrieves the decrypted value of the latest version of a secret.
// It has no user principal of its own — used both directly by machine/embedded
// callers (server/http's isMachine branch, the embedded CLI) and, via
// getSecretValueForUser, as the shared tail of the *WithPermissionCheck variants.
// A direct call here is always treated as userID 0 for the classification gate
// (see checkRestrictedSecretReadApproval) — there is no user to check an approval
// against, matching the machine-read design decision.
func (c *KeyorixCore) GetSecretValue(ctx context.Context, secretID uint) (value []byte, err error) {
	defer func() { noteValueReadErr(ctx, err, secretID) }()
	return c.getSecretValueForUser(ctx, secretID, 0, nil, nil)
}

// GetSecretValueResolved is GetSecretValue for a caller that has already
// authoritatively resolved the secret (e.g. via the route's own scoped-
// permission middleware) — skips the redundant storage.GetSecret fetch
// getSecretValueForUser would otherwise do internally (SESSION-PERF, #2403
// follow-up). Same guards, same classification gate (userID 0, matching
// GetSecretValue's own machine-read semantics), same disclosure path — only
// the fetch is skipped, nothing else changes.
func (c *KeyorixCore) GetSecretValueResolved(ctx context.Context, secret *models.SecretNode) (value []byte, err error) {
	defer func() { noteValueReadErr(ctx, err, secret.ID) }()
	return c.getSecretValueForUser(ctx, secret.ID, 0, secret, nil)
}

// enforceSecretReadGuards runs every read-time guard a secret-value
// disclosure must pass EXCEPT max-reads (which is inherently tied to the
// specific counting read call via readVersionValue, not a reusable "may I
// read" predicate): expiration, suspended status, the classification-
// restricted gate bundle (step-up/approval/permission), and the temporal
// access-schedule window.
//
// #G09: several secret-value-disclosing functions (InspectCertificate,
// RotateSecret's confirmation check) were written as independent
// implementations that only replicated SOME of this bundle — most
// consequentially, checkSecretAccessSchedule (the temporal window) was
// wired into the METADATA read path (GetSecretWithPermissionCheck) but never
// into the actual VALUE read path below, so a caller could read a secret's
// value outside its configured access window even though a metadata read of
// the same secret correctly refused. Route every value-disclosing function
// through this one guard bundle instead of re-implementing a subset of it.
func (c *KeyorixCore) enforceSecretReadGuards(ctx context.Context, secret *models.SecretNode, userID uint) error {
	return c.enforceSecretReadGuardsWith(ctx, secret, userID, c.storage.GetSecretAccessSchedule)
}

// enforceSecretReadGuardsWith is enforceSecretReadGuards with the schedule read
// supplied by the caller (PERF-FIX-4): the same guards in the same order, the
// schedule step last; only where the schedule row comes from differs.
func (c *KeyorixCore) enforceSecretReadGuardsWith(ctx context.Context, secret *models.SecretNode, userID uint, loadSchedule scheduleLoader) error {
	// #1632: c.now(), not a bare time.Now() -- the injected/test-controllable
	// clock every other security-relevant expiry check in this package uses
	// (service.go's `now func() time.Time` field). This is the actual
	// secret-VALUE disclosure guard (see the #G09 comment above), so it must
	// be seam-testable the same way ValidateSessionToken/ValidateMachineToken
	// etc. already are -- a bare time.Now() here could not be moved
	// backward in a test at all, which is itself part of what made this the
	// worst site in the #1632 sweep: there was no way to even exercise the
	// hazard without actually changing the OS clock.
	//
	// The seam alone does not close the hazard -- it only makes it testable.
	// checkSecretExpiryClockNotRegressed is the actual fix: it refuses this
	// read outright if c.now() looks EARLIER than a time this process has
	// already legitimately observed, rather than trusting a wall clock that
	// may have just been stepped backward past this secret's real
	// Expiration. See secretExpiryWatermark's doc comment (service.go) for
	// why this is in-memory only, and named there as a residual limitation.
	now := c.now()
	if err := c.checkSecretExpiryClockNotRegressed(now); err != nil {
		return err
	}
	if secret.Expiration != nil && now.After(*secret.Expiration) {
		// Expiry is judged first, but a secret that is ALSO suspended with the
		// clear-synced-copies marker still has to tell the operator and k8s-sync to
		// clear (not keep) its copies (#3215): carry the marker, only when suspended.
		return errSecretExpired(secret.Status == SecretStatusSuspended && secret.SuspendClearSyncedCopies)
	}
	if secret.Status == SecretStatusSuspended {
		return errSecretSuspended(secret.SuspendClearSyncedCopies)
	}
	if err := c.checkRestrictedSecretReadApproval(ctx, secret, userID); err != nil {
		return err
	}
	return checkSecretAccessScheduleWith(ctx, secret.ID, loadSchedule)
}

// getSecretValueForUser is GetSecretValue's real body, plus the classification
// gate keyed on userID (0 = no identifiable user). Kept unexported and separate
// from GetSecretValue's public, userID-less signature so *WithPermissionCheck
// callers — which already resolved a real userID via ValidateSecretAccess — can
// thread it through instead of losing it at the handoff.
//
// preResolved, when non-nil (GetSecretValueResolved; SESSION-PERF, #2403
// follow-up), is used in place of fetching the secret again — the caller has
// already done so, authoritatively, for the exact same ID. nil (every other
// caller, unchanged) fetches as before. Never re-validates preResolved.ID
// against secretID: GetSecretValueResolved derives secretID FROM
// preResolved.ID, so the two can never disagree by construction.
func (c *KeyorixCore) getSecretValueForUser(ctx context.Context, secretID, userID uint, preResolved *models.SecretNode, preState *storage.SecretScheduleAndLatestVersion) ([]byte, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	secret := preResolved
	if secret == nil {
		var err error
		secret, err = c.storage.GetSecret(ctx, secretID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
		}
	}
	// PERF-FIX-4 (C5): the schedule step and the latest-version lookup share one
	// storage read (one statement on a warm version cache). The guard order and
	// the error that fires first are unchanged: the schedule is still judged
	// last in the guard bundle, a failure of the shared read surfaces as the
	// schedule-read error, and the version result is looked at only after every
	// guard passed, with GetLatestSecretVersion's own error.
	//
	// preState, when non-nil (GetPermittedSecretValue, OPT-READPATH-2), is that same
	// snapshot as the request's read-permission check read it moments earlier: the
	// schedule guard is judged on it (at the current time) and its latest version is
	// served, instead of reading both again.
	var state *storage.SecretScheduleAndLatestVersion
	loadSchedule := c.scheduleAndVersionLoader(&state)
	if preState != nil {
		state = preState
		loadSchedule = func(context.Context, uint) (*models.SecretAccessSchedule, error) { return preState.Schedule, nil }
	}
	if err := c.enforceSecretReadGuardsWith(ctx, secret, userID, loadSchedule); err != nil {
		return nil, err
	}
	if state.LatestVersionErr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), state.LatestVersionErr)
	}
	if state.LatestVersion == nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), storage.ErrSecretVersionNotFound)
	}
	return c.readVersionValue(ctx, secret, state.LatestVersion)
}

// GetSecretValueWithPermissionCheck retrieves the decrypted value with permission validation.
func (c *KeyorixCore) GetSecretValueWithPermissionCheck(ctx context.Context, secretID, userID uint) (value []byte, err error) {
	defer func() { noteValueReadErr(ctx, err, secretID) }()
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.ValidateSecretAccess(ctx, secretID, userID); err != nil {
		return nil, err
	}
	// Delegate to the shared body with the real userID — avoids duplicating
	// max-reads logic while still giving the classification gate a user to check
	// an approved secret-scoped access request against.
	return c.getSecretValueForUser(ctx, secretID, userID, nil, nil)
}

// ReadPermittedSecret is proof that GetSecretForValueRead's read-permission check
// (the same EnforceSecretReadPermission + access-schedule check as
// GetSecretWithPermissionCheck) passed for one user on one secret. Its fields are
// unexported, so outside this package it can only be obtained from that check, and
// GetPermittedSecretValue cannot be handed an unchecked secret.
type ReadPermittedSecret struct {
	secret *models.SecretNode
	userID uint
	// state is the schedule/latest-version snapshot the check's schedule step read
	// (OPT-READPATH-2); the value step judges its schedule guard on it and serves its
	// latest version instead of reading both again. nil: the value step reads them.
	state *storage.SecretScheduleAndLatestVersion
}

// Secret returns the secret as the permission check resolved it.
func (p *ReadPermittedSecret) Secret() *models.SecretNode { return p.secret }

// GetSecretForValueRead is GetSecretWithPermissionCheck for a request that goes on
// to read the value: same checks, same errors, same returned secret, plus the proof
// GetPermittedSecretValue takes (PERF-FIX-3).
//
// Its schedule step reads the schedule together with the latest version
// (GetSecretScheduleAndLatestVersion, one statement) and keeps that snapshot for
// GetPermittedSecretValue, so a value read reads them once (OPT-READPATH-2). A
// failure of that read is the schedule step's error, as before.
func (c *KeyorixCore) GetSecretForValueRead(ctx context.Context, id, userID uint) (*ReadPermittedSecret, error) {
	return c.GetSecretForRead(ctx, id, userID, true)
}

// GetSecretForRead is GetSecretForValueRead for a transport that serves either the
// metadata or the value from one handler. withValue false (a metadata read) reads the
// schedule alone, exactly as GetSecretWithPermissionCheck does, and keeps no snapshot:
// a metadata read never depends on the version read.
func (c *KeyorixCore) GetSecretForRead(ctx context.Context, id, userID uint, withValue bool) (_ *ReadPermittedSecret, err error) {
	defer func() { noteValueReadErr(ctx, err, id) }()
	if !withValue || readPathReuseOff.Load() {
		secret, err := c.GetSecretWithPermissionCheck(ctx, id, userID)
		if err != nil {
			return nil, err
		}
		return &ReadPermittedSecret{secret: secret, userID: userID}, nil
	}
	secret, err := c.checkSecretReadPermission(ctx, id, userID)
	if err != nil {
		return nil, err
	}
	var state *storage.SecretScheduleAndLatestVersion
	if err := checkSecretAccessScheduleWith(ctx, id, c.scheduleAndVersionLoader(&state)); err != nil {
		return nil, err
	}
	if secret, err = unexpiredSecret(secret); err != nil {
		return nil, err
	}
	return &ReadPermittedSecret{secret: secret, userID: userID, state: state}, nil
}

// scheduleAndVersionLoader is a scheduleLoader backed by GetSecretScheduleAndLatestVersion
// that leaves the snapshot it read in *state.
func (c *KeyorixCore) scheduleAndVersionLoader(state **storage.SecretScheduleAndLatestVersion) scheduleLoader {
	return func(ctx context.Context, id uint) (*models.SecretAccessSchedule, error) {
		s, err := c.storage.GetSecretScheduleAndLatestVersion(ctx, id)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorStorageFailed", nil), "no schedule/version snapshot")
		}
		*state = s
		return s.Schedule, nil
	}
}

// GetPermittedSecretValue is GetSecretValueWithPermissionCheck for a request whose
// read permission GetSecretForValueRead has just checked (PERF-FIX-3). The
// permission decision is not evaluated a second time and the secret is not fetched
// again (the second evaluation was the same CheckSecretPermission call with the same
// arguments, ~12 statements); everything else is GetSecretValueWithPermissionCheck's
// own tail: the full read-guard bundle (clock, expiry, suspended, classification
// gate with the real userID, schedule), the latest version and the atomic max-reads
// accounting.
func (c *KeyorixCore) GetPermittedSecretValue(ctx context.Context, p *ReadPermittedSecret) (value []byte, err error) {
	defer func() {
		if p != nil && p.secret != nil {
			noteValueReadErr(ctx, err, p.secret.ID)
		}
	}()
	if p == nil || p.secret == nil || p.userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	return c.getSecretValueForUser(ctx, p.secret.ID, p.userID, p.secret, p.state)
}

// GetSecretValueByVersion retrieves the decrypted value of a specific version of a secret.
// Like GetSecretValue, a direct call has no user principal — see
// getSecretValueByVersionForUser.
func (c *KeyorixCore) GetSecretValueByVersion(ctx context.Context, secretID uint, versionNumber int) (value []byte, err error) {
	defer func() { noteValueReadErr(ctx, err, secretID) }()
	return c.getSecretValueByVersionForUser(ctx, secretID, versionNumber, 0)
}

// getSecretValueByVersionForUser is GetSecretValueByVersion's real body, plus the
// classification gate keyed on userID (0 = no identifiable user).
func (c *KeyorixCore) getSecretValueByVersionForUser(ctx context.Context, secretID uint, versionNumber int, userID uint) ([]byte, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if versionNumber <= 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "version number must be positive")
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if err := c.enforceSecretReadGuards(ctx, secret, userID); err != nil {
		return nil, err
	}
	version, err := c.GetSecretVersion(ctx, secretID, versionNumber)
	if err != nil {
		return nil, err
	}
	// Route through the shared enforcement path so a by-version read is subject to the
	// same atomic max-reads cap as the latest-version read — defense-in-depth against a
	// future caller that uses the by-version path to bypass the read ceiling.
	return c.readVersionValue(ctx, secret, version)
}

// EventSecretRolledBack is audited when a secret is restored to a prior version.
const EventSecretRolledBack = "secret.rolled_back"

// RollbackSecret restores a secret to the value of a prior version by re-instating that
// value as a NEW version — version history stays append-only (the rollback itself is a
// new version, so it too can be undone). The caller (transport) must have enforced
// scoped secrets.write. Unlike a value read, this fetches the historical version
// directly (no max-reads / expiry guard) since a restore is a write, not a use.
func (c *KeyorixCore) RollbackSecret(ctx context.Context, secretID uint, targetVersion int, actorID uint, actorName string) (*models.SecretNode, error) {
	version, err := c.GetSecretVersion(ctx, secretID, targetVersion)
	if err != nil {
		return nil, err
	}
	latest, err := c.storage.GetLatestSecretVersion(ctx, secretID)
	if err == nil && latest != nil && latest.VersionNumber == targetVersion {
		return nil, fmt.Errorf("version %d is already the current version", targetVersion)
	}
	// Decrypt the historical version's value to re-instate it. The parent node is
	// needed to reconstruct the at-rest AAD (secretID:projectID:versionNumber).
	node, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	val, err := c.decryptVersionValue(node, version)
	if err != nil {
		return nil, fmt.Errorf("failed to read version %d: %w", targetVersion, err)
	}
	// AUDIT-MUTATION-TX-1: secret.rolled_back commits with the re-instated version,
	// always (every caller is a user-initiated rollback), so a rollback never lands
	// without its row; a failed audit write stores nothing.
	return c.rotateSecret(ctx, secretID, val, actorID, actorName, true, func(s *models.SecretNode) (mutationAuditRow, bool) {
		uid := actorID
		row := mutationAuditRow{
			eventType:   EventSecretRolledBack,
			userID:      &uid,
			secretID:    s.ID,
			projectID:   s.ProjectID,
			description: fmt.Sprintf("rolled back secret %q to the value of version %d", s.Name, targetVersion),
		}
		if a, ok := secretMutationAuditFromContext(ctx); ok {
			row.ip, row.userAgent, row.clientOrigin = a.IP, a.UserAgent, a.ClientOrigin
		}
		return row, true
	})
}

// GetSecretValueByVersionWithPermissionCheck retrieves the decrypted value of a specific version with permission validation.
func (c *KeyorixCore) GetSecretValueByVersionWithPermissionCheck(ctx context.Context, secretID, userID uint, versionNumber int) (value []byte, err error) {
	defer func() { noteValueReadErr(ctx, err, secretID) }()
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.ValidateSecretAccess(ctx, secretID, userID); err != nil {
		return nil, err
	}
	return c.getSecretValueByVersionForUser(ctx, secretID, versionNumber, userID)
}

// readVersionValue applies max-reads enforcement and decryption for a secret version.
// Shared by GetSecretValue and GetSecretValueWithPermissionCheck.
func (c *KeyorixCore) readVersionValue(ctx context.Context, secret *models.SecretNode, version *models.SecretVersion) ([]byte, error) {
	if secret.MaxReads != nil && *secret.MaxReads > 0 {
		// Atomic check-and-increment against the SECRET (not the version, #133): the
		// conditional UPDATE serializes concurrent reads on the row, so they can never
		// collectively exceed the cap, and the count carries forward across rotate/
		// rollback creating a new version — a per-version counter would reset to zero
		// on every new version, letting a burn-after-N-reads secret become re-readable
		// simply by rolling back. Fail closed — if enforcement can't be confirmed,
		// don't hand back the value.
		ok, err := c.storage.TryIncrementSecretNodeReadCount(ctx, secret.ID, *secret.MaxReads)
		if err != nil {
			return nil, fmt.Errorf("max-reads enforcement failed: %w", err)
		}
		if !ok {
			return nil, errSecretMaxReadsExhausted()
		}
		// Best-effort per-version read_count (CLI/gRPC display only, not the
		// enforcement mechanism above): a failure here must not block an already-
		// authorized read.
		_, _ = c.storage.TryIncrementSecretReadCount(ctx, version.ID, *secret.MaxReads)
	}
	return c.decryptVersionValue(secret, version)
}
