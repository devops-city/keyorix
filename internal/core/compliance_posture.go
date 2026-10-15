// compliance_posture.go — a single, deployment-wide controls-posture snapshot for
// auditors (ISO 27001 / SOC 2 / NIS2 / DORA). GetCompliancePosture rolls up the
// state of the controls Keyorix already enforces — audit-trail integrity, access
// recertification coverage, dormant standing access, secret-rotation hygiene,
// second-factor coverage, and break-glass usage — into one structured object,
// grouped by control area. Read-only; gated by audit.read (not the universal
// system_viewer baseline — see #255/#272 disclosure-family fix in router.go).
package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/pkg/trust"
)

// dormantThreshold is how long without a secret access marks a standing grant
// dormant in the posture roll-up.
const dormantThreshold = 90 * 24 * time.Hour

// AuditIntegrityPosture summarises the tamper-evident audit trail (ADR-029).
type AuditIntegrityPosture struct {
	ChainVerified bool   `json:"chain_verified"`
	ChainedEvents int64  `json:"chained_events"`
	Checkpointed  bool   `json:"checkpointed"`
	Reason        string `json:"reason,omitempty"` // failure/notes when not fully verified
	// VerificationStatus is valid | broken | not_proven
	// (docs/specs/audit-incremental-verification.md §4); ChainVerified is true
	// only for valid. LastFullVerificationAt is when the last full verification
	// (rolling cycle or full job) completed; LastCheckedAt when the scheduler last
	// checked the tail. Both nil when not recorded (or a full walk was run now).
	VerificationStatus     string     `json:"verification_status,omitempty"`
	LastFullVerificationAt *time.Time `json:"last_full_verification_at,omitempty"`
	LastCheckedAt          *time.Time `json:"last_checked_at,omitempty"`
}

// AccessGovernancePosture summarises access recertification + dormant access.
type AccessGovernancePosture struct {
	Projects                 int `json:"projects"`
	ProjectsWithOpenCampaign int `json:"projects_with_open_campaign"`
	ProjectsNeverReviewed    int `json:"projects_never_reviewed"`
	OpenCampaigns            int `json:"open_campaigns"`
	PendingItems             int `json:"pending_items"`       // undecided items across open campaigns
	ProjectsOverdue          int `json:"projects_overdue"`    // overdue for recertification (A.5.18 cadence)
	DormantRoleGrants        int `json:"dormant_role_grants"` // per-grant: no/old activity at the specific capability the grant confers (#258/#487)
	SoDViolations            int `json:"sod_violations"`      // principals holding a forbidden permission pair (A.5.3)
}

// RotationPosture summarises secret-rotation hygiene (ISO A.5.15 / NIS2).
type RotationPosture struct {
	TotalSecrets   int `json:"total_secrets"`   // all static secrets in scope
	CoveredSecrets int `json:"covered_secrets"` // those with a rotation schedule
	Overdue        int `json:"overdue"`
	DueSoon        int `json:"due_soon"`
}

// IdentityPosture summarises second-factor (MFA / passkey) coverage.
type IdentityPosture struct {
	ActiveUsers           int `json:"active_users"`
	UsersWithSecondFactor int `json:"users_with_second_factor"`
	SecondFactorPercent   int `json:"second_factor_percent"`
}

// EmergencyAccessPosture summarises break-glass usage (NIS2/DORA).
type EmergencyAccessPosture struct {
	ActiveActivations int `json:"active_activations"`
	TotalActivations  int `json:"total_activations"`
	// UnreviewedActivations is ADR-112's break-glass posture deviation (§3,
	// item 4): activations with no recorded review that are already older than
	// break_glass.review_window. This is what "every activation must be
	// reviewed afterwards" is ENFORCED by -- the ADR's own words are "an open
	// activation without a recorded review shows as a posture deviation". A
	// pending review never blocks break-glass ACTIVATION itself
	// (INV-CORE-break-glass-unreviewed-reported-never-blocks-activation,
	// narrowed #2461 round 2) -- escalation here is the "emergency-access"
	// control going to Gap (EvaluateControls), a recurring SECURITY: log line,
	// a repeating admin notification, and an audit event (see
	// RunBreakGlassReviewReminder), not a lockout on the activation path.
	//
	// Counted from the activations this snapshot already fetched per project,
	// not from a second global query: ListUnreviewedBreakGlassActivationsBefore
	// exists for the periodic reminder, which has no project list to work from,
	// but re-running it here would read the same rows twice and could disagree
	// with TotalActivations/ActiveActivations above if a row changed in between.
	UnreviewedActivations int `json:"unreviewed_activations"`
	// OldestUnreviewedAgeHours is the age of the longest-outstanding unreviewed
	// activation, 0 when there are none. A bare count cannot distinguish "one
	// review is a day late" from "one has been ignored for a year", and the
	// second is the one an auditor cares about.
	OldestUnreviewedAgeHours int `json:"oldest_unreviewed_age_hours"`
	// ReviewWindowHours is the threshold the two fields above were computed
	// against, so a report is interpretable without also knowing the
	// deployment's config.
	ReviewWindowHours int `json:"review_window_hours"`
	// IndependentReviewImpossible is
	// INV-CORE-break-glass-independent-review-impossible-is-visible (#2461
	// round 2, Andrei's decision item (c)): true when the deployment has at
	// most one active
	// global admin-tier holder, so no human OTHER than a break-glass activator
	// could ever satisfy ReviewBreakGlass's self-review refusal for an
	// activation they performed -- independent review is structurally
	// impossible, not merely currently unperformed. Approximated the same way
	// guardLastGlobalAdmin* approximates "another administrator exists"
	// elsewhere: active global admin-tier holder count, not a precise count of
	// who holds roles.assign at every project (which would need scanning every
	// project's grants and is out of scope here). Self-review stays refused
	// regardless of this flag; it exists to make the structural gap VISIBLE,
	// never to silently read identical to "reviewed" or to an ordinary
	// unreviewed backlog.
	IndependentReviewImpossible bool `json:"independent_review_impossible"`
}

// AccessRequestPosture summarises the dual-control access-request/approval workflow
// (ADR-024, ISO 27001 A.5.3): how many project access requests exist and in what
// state, across the deployment. The dual-control invariants themselves — a
// requester can never approve their own request (maker != checker), and a distinct
// approver can only sign off once, with the role granted only once
// RequiredApprovals distinct approvers have done so — are already enforced by
// ApproveAccessRequestWithExpiry (internal/core/invitations.go); this rollup gives
// an auditor visibility into the counts that workflow produces, not new
// enforcement (#257).
type AccessRequestPosture struct {
	TotalRequests int `json:"total_requests"`
	Pending       int `json:"pending"`
	Approved      int `json:"approved"`
	Rejected      int `json:"rejected"`
	Withdrawn     int `json:"withdrawn"`
	Expired       int `json:"expired"`
	// RequiredApprovals is the currently-configured N-of-M dual-control threshold
	// (SetDualControlPolicy): >1 means at least two distinct approvers — never the
	// requester — must sign off before a request's role grant lands.
	RequiredApprovals int `json:"required_approvals"`
}

// LegalHoldPosture reports whether a litigation/investigation hold is in effect
// (ISO 27001 A.5.34) — while active the purge jobs preserve all records.
type LegalHoldPosture struct {
	Active   bool       `json:"active"`
	PlacedAt *time.Time `json:"placed_at,omitempty"`
	Reason   string     `json:"reason,omitempty"`
}

// AnomaliesPosture summarises detected access anomalies (NIS2 detection).
type AnomaliesPosture struct {
	Unacknowledged   int `json:"unacknowledged"`     // open alerts awaiting review
	HighSeverityOpen int `json:"high_severity_open"` // open alerts of high severity
}

// ClassificationPosture summarises secret data-classification coverage (A.5.12).
// The flat fields count STATIC secrets (unchanged for back-compat); DynamicConfigs
// (and, later, machine entities) extend coverage to the other secret-bearing
// surfaces so the posture reflects classification across all of them.
type ClassificationPosture struct {
	TotalSecrets int `json:"total_secrets"`
	Public       int `json:"public"`
	Internal     int `json:"internal"`
	Confidential int `json:"confidential"`
	Restricted   int `json:"restricted"`
	Unclassified int `json:"unclassified"`
	// DynamicConfigs counts dynamic-secret configs by classification (A.5.12).
	DynamicConfigs ClassificationCounts `json:"dynamic_configs"`
	// MachineIdentities counts machine identities by classification (A.5.12).
	MachineIdentities ClassificationCounts `json:"machine_identities"`
	// MachineCredentials counts machine-token credentials by classification (A.5.12).
	MachineCredentials ClassificationCounts `json:"machine_credentials"`
}

// ClassificationCounts is a per-level tally of a set of classifiable entities.
type ClassificationCounts struct {
	Total        int `json:"total"`
	Public       int `json:"public"`
	Internal     int `json:"internal"`
	Confidential int `json:"confidential"`
	Restricted   int `json:"restricted"`
	Unclassified int `json:"unclassified"`
}

// classificationCountsFromMap builds ClassificationCounts from a label→count map
// (the empty label "" is the unclassified bucket).
func classificationCountsFromMap(m map[string]int) ClassificationCounts {
	cc := ClassificationCounts{
		Public:       m[ClassificationPublic],
		Internal:     m[ClassificationInternal],
		Confidential: m[ClassificationConfidential],
		Restricted:   m[ClassificationRestricted],
		Unclassified: m[""],
	}
	for _, n := range m {
		cc.Total += n
	}
	return cc
}

// RetentionPosture reports the configured data-retention windows (ISO 27001 A.5.33
// / GDPR storage-limitation). Each value is a number of days; 0 means that record
// type is kept indefinitely. Enabled mirrors whether any window is set — evidence
// that storage-limitation is actively enforced rather than left unbounded.
type RetentionPosture struct {
	Enabled                    bool `json:"enabled"`
	AnomalyAlertsDays          int  `json:"anomaly_alerts_days"`
	ClosedAccessReviewsDays    int  `json:"closed_access_reviews_days"`
	BreakGlassDays             int  `json:"break_glass_days"`
	ResolvedAccessRequestsDays int  `json:"resolved_access_requests_days"`
}

// RiskPosture summarises the risk register (ISO 27001 A.5.8 risk treatment): how
// many governed, time-bound exceptions are currently active and how many expire soon
// (so an auditor sees accepted-with-a-deadline risks rather than ungoverned gaps).
type RiskPosture struct {
	ActiveExceptions int `json:"active_exceptions"`
	ExpiringSoon     int `json:"expiring_soon"` // active exceptions expiring within the soon window
	// Expired counts exceptions that have passed their expiry but are still marked
	// non-revoked (#395) — a stale, never-renewed acceptance whose underlying risk is
	// unmitigated again. These already drop out of ActiveExceptions above, so without
	// this field a lapsed exception becomes invisible to compliance posture/evidence
	// the instant it expires, rather than surfacing as a gap needing attention.
	Expired int `json:"expired"`
}

// CertificatePosture reports certificate hygiene from the cached cert expiry (ADR-056).
// NotEvaluated counts certificate-typed secrets whose certificate hasn't been parsed
// yet (no inspection/scan) — full coverage needs the certificate-expiry scan enabled.
type CertificatePosture struct {
	TotalCertificates int `json:"total_certificates"`
	Expired           int `json:"expired"`
	ExpiringSoon      int `json:"expiring_soon"` // within the 30-day window
	NotEvaluated      int `json:"not_evaluated"`
}

// ComplianceTrend reports the week-over-week direction of the deployment's
// compliance posture, derived by comparing the current CompliancePostureSnapshot
// (written just before this field is populated) against the most recent prior
// snapshot that is at least 20 hours old (avoiding same-day self-comparison).
type ComplianceTrend struct {
	PreviousDate *time.Time `json:"previous_date,omitempty"`
	// PassedDelta is the change in passed-controls count since the previous
	// snapshot (positive = more controls passing now).
	PassedDelta *int `json:"passed_delta,omitempty"`
	// FailedDelta is the change in failed-controls count since the previous
	// snapshot (negative = fewer controls failing now — an improvement).
	FailedDelta *int `json:"failed_delta,omitempty"`
	// Direction summarises the overall movement: "improving" | "regressing" |
	// "stable" | "no_data" (no previous snapshot exists yet).
	Direction string `json:"direction"`
}

// CompliancePosture is the deployment's control posture at a point in time.
//
// #136: every sub-rollup is queried best-effort so one failing signal doesn't abort
// the whole snapshot — but a query failure must never read the same as "checked,
// found clean" (e.g. LegalHold.Active=false on a DB error looks identical to no hold
// in effect, and this snapshot gets HMAC-signed into evidence packs an auditor
// trusts). Degraded + DegradedReasons make a partial snapshot detectable instead of
// indistinguishable from a fully-clean one.
type CompliancePosture struct {
	GeneratedAt      time.Time               `json:"generated_at"`
	AuditIntegrity   AuditIntegrityPosture   `json:"audit_integrity"`
	AccessGovernance AccessGovernancePosture `json:"access_governance"`
	Rotation         RotationPosture         `json:"rotation"`
	Identity         IdentityPosture         `json:"identity"`
	EmergencyAccess  EmergencyAccessPosture  `json:"emergency_access"`
	AccessRequests   AccessRequestPosture    `json:"access_requests"`
	Classification   ClassificationPosture   `json:"classification"`
	Anomalies        AnomaliesPosture        `json:"anomalies"`
	LegalHold        LegalHoldPosture        `json:"legal_hold"`
	Retention        RetentionPosture        `json:"retention"`
	Risk             RiskPosture             `json:"risk"`
	Certificates     CertificatePosture      `json:"certificates"`
	SupplyChain      SupplyChainPosture      `json:"supply_chain"`
	// Degraded is true when one or more sub-rollups below could not be queried — the
	// zero/clean values they carry are UNKNOWN, not verified-clean. An evidence pack
	// consumer must treat a degraded snapshot as incomplete, not passing.
	Degraded bool `json:"degraded"`
	// DegradedReasons names each failed sub-rollup with its underlying error.
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
	// Trend holds the week-over-week posture direction. Nil on the very first call
	// (no previous snapshot exists). Best-effort: a snapshot I/O failure leaves
	// Trend as nil rather than aborting the posture response.
	Trend *ComplianceTrend `json:"trend,omitempty"`
}

// degrade records that a posture sub-rollup could not be queried: it flips Degraded
// and appends a human-readable reason, so evidence packs signal "incomplete" instead
// of silently reading the affected fields as a verified-clean zero value.
func (p *CompliancePosture) degrade(area string, err error) {
	p.Degraded = true
	p.DegradedReasons = append(p.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

// DegradedArea reports whether any recorded DegradedReasons entry names an area
// starting with one of the given prefixes — i.e. whether the specific signal a
// consumer (e.g. the control-framework matrix) depends on failed to collect this
// run. Used so a downstream "pass/gap" evaluation derived from a degraded field
// can surface as unknown rather than silently trusting the field's zero value.
func (p *CompliancePosture) DegradedArea(prefixes ...string) bool {
	for _, reason := range p.DegradedReasons {
		for _, prefix := range prefixes {
			if strings.HasPrefix(reason, prefix) {
				return true
			}
		}
	}
	return false
}

// SupplyChainPosture reports software-supply-chain integrity: whether this deployment
// verifies updates against a pinned signing key (ADR-062/064) and the offline-entitlement
// state (ADR-065). A signed-release deployment embeds the update-signing key, so every
// update bundle is verified offline against it before it can be staged.
type SupplyChainPosture struct {
	// UpdateSigningTrusted is true when at least one update-signing key is pinned into this
	// build — i.e. update bundles are verified against a trusted key (a signed release).
	UpdateSigningTrusted bool `json:"update_signing_trusted"`
	// TrustedUpdateKeys is how many update-signing key-ids are pinned (≥1 in a release).
	TrustedUpdateKeys int `json:"trusted_update_keys"`
	// LicenseState is the offline-license state ("active"/"expiring_soon"/.../"none").
	LicenseState string `json:"license_state"`
	// LicenseValid is true when the license currently grants commercial features.
	LicenseValid bool `json:"license_valid"`
}

// riskExpiringSoonWindow is how far ahead an active exception counts as "expiring
// soon" in the posture.
const riskExpiringSoonWindow = 14 * 24 * time.Hour

// complianceSnapshot holds every underlying sub-query that both GetCompliancePosture
// and GenerateComplianceEvidence need, fetched EXACTLY ONCE per generation (#256).
// Before this, GenerateComplianceEvidence independently re-ran the same queries a
// second time after GetCompliancePosture had already run them — with no transaction
// or snapshot isolation between the two passes, a concurrent write (a role granted, a
// secret rotated, an SoD violation created/resolved) landing between the two reads
// could make the resulting evidence pack's sections mutually inconsistent, even
// though it gets HMAC-signed as one atomic point-in-time attestation. Building one
// snapshot and having both the posture rollup and the evidence pack read from it
// removes that gap entirely: there is no second pass left to diverge from the first.
//
// Each field pairs the fetched value with its own error (nil on success) so callers
// keep applying the exact fail-open/degrade semantics they always have — a posture
// sub-rollup and the evidence pack's copy of the same signal each still record their
// own DegradedReasons entry — without re-issuing the query to learn that outcome.
type complianceSnapshot struct {
	projects []*models.Project

	auditChain    *AuditVerifyReport
	auditChainErr error

	rotationStatuses []*RotationStatusEntry
	rotationErr      error

	totalSecrets    int
	totalSecretsErr error

	sodReport *SoDViolationsReport
	sodErr    error

	// riskExceptionsActive and riskExceptionsExpired both come from the SAME single
	// listRiskExceptionRows(ctx, true) read (#256) — active-only exceptions, and a
	// count of non-revoked exceptions whose expiry has already passed (#395), i.e.
	// stale acceptances that dropped out of riskExceptionsActive with no compliance
	// visibility. One storage read, two derived views.
	riskExceptionsActive  []*RiskExceptionView
	riskExceptionsExpired int
	riskExceptionsErr     error

	// Per-project results, keyed by project ID.
	campaignsByProject         map[uint][]*CampaignWithProgress
	campaignsErrByProject      map[uint]error
	breakGlassByProject        map[uint][]*models.BreakGlassActivation
	breakGlassErrByProject     map[uint]error
	accessRequestsByProject    map[uint][]*models.AccessRequest
	accessRequestsErrByProject map[uint]error
}

// buildComplianceSnapshot fetches every shared sub-query once. ListProjects is the
// one query treated as fatal (mirroring the previous accessGovernancePosture/
// GenerateComplianceEvidence behavior) — everything else is best-effort, with its
// error recorded on the snapshot for the caller to degrade on rather than abort.
func (c *KeyorixCore) buildComplianceSnapshot(ctx context.Context) (*complianceSnapshot, error) {
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	snap := &complianceSnapshot{
		projects:                   projects,
		campaignsByProject:         make(map[uint][]*CampaignWithProgress, len(projects)),
		campaignsErrByProject:      make(map[uint]error, len(projects)),
		breakGlassByProject:        make(map[uint][]*models.BreakGlassActivation, len(projects)),
		breakGlassErrByProject:     make(map[uint]error, len(projects)),
		accessRequestsByProject:    make(map[uint][]*models.AccessRequest, len(projects)),
		accessRequestsErrByProject: make(map[uint]error, len(projects)),
	}

	// The persisted verification state, not a walk (spec audit-incremental-verification §5).
	snap.auditChain, snap.auditChainErr = c.AuditVerificationStatus(ctx)
	snap.rotationStatuses, snap.rotationErr = c.GetRotationStatus(ctx, nil, nil)
	if _, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{Page: 1, PageSize: 1}); err == nil {
		snap.totalSecrets = int(total)
	} else {
		snap.totalSecretsErr = err
	}
	snap.sodReport, snap.sodErr = c.DetectSoDViolations(ctx)
	if views, err := c.listRiskExceptionRows(ctx, true); err == nil {
		for _, v := range views {
			switch v.Status {
			case ExceptionStatusActive:
				snap.riskExceptionsActive = append(snap.riskExceptionsActive, v)
			case ExceptionStatusExpired:
				snap.riskExceptionsExpired++
			}
		}
	} else {
		snap.riskExceptionsErr = err
	}

	for _, proj := range projects {
		pid := proj.ID
		camps, cErr := c.ListAccessReviewCampaigns(ctx, pid)
		snap.campaignsByProject[pid] = camps
		snap.campaignsErrByProject[pid] = cErr

		acts, bErr := c.ListBreakGlassActivations(ctx, pid)
		snap.breakGlassByProject[pid] = acts
		snap.breakGlassErrByProject[pid] = bErr

		reqs, rErr := c.storage.ListAccessRequests(ctx, pid)
		if rErr == nil {
			applyAccessRequestEffectiveExpiry(reqs, c.now())
		}
		snap.accessRequestsByProject[pid] = reqs
		snap.accessRequestsErrByProject[pid] = rErr
	}
	return snap, nil
}

// applyAccessRequestEffectiveExpiry corrects the in-memory State of any row that is
// still persisted as pending but whose ExpiresAt has passed — mirroring how
// ListBreakGlassActivations computes an activation's effective expired state without
// writing it back. The posture/evidence snapshot is read-only (unlike the core
// ListAccessRequests method, which lazily persists this same transition on read), so
// a stale "pending" row must not be reported as still-pending here without also
// issuing a write this snapshot is not meant to perform.
func applyAccessRequestEffectiveExpiry(reqs []*models.AccessRequest, now time.Time) {
	for _, r := range reqs {
		if r.State == AccessRequestPending && r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			r.State = AccessRequestExpired
		}
	}
}

// GetCompliancePosture aggregates the deployment's control posture. It is an
// on-demand admin report (it walks every project for the access-governance roll-up),
// not a hot path.
func (c *KeyorixCore) GetCompliancePosture(ctx context.Context) (*CompliancePosture, error) {
	p, postureSnap, err := c.computeCompliancePosture(ctx)
	if err != nil {
		return nil, err
	}

	// Persist today's snapshot for trend tracking (best-effort — a write failure
	// must not abort the posture response an auditor is waiting on). A degraded
	// posture is returned to the caller (it carries Degraded/DegradedReasons) but
	// is NEVER persisted (#2834): a stored snapshot is an audit artefact, and its
	// counts would silently omit the sub-rollups that failed to read.
	if !p.Degraded {
		_ = c.storage.SaveCompliancePostureSnapshot(ctx, postureSnap)
	}

	// Fetch the previous snapshot and compute the trend.
	p.Trend = c.computeComplianceTrend(ctx, postureSnap)

	return p, nil
}

// computeCompliancePosture builds today's posture and the snapshot row derived from
// it, without writing anything.
func (c *KeyorixCore) computeCompliancePosture(ctx context.Context) (*CompliancePosture, *models.CompliancePostureSnapshot, error) {
	snap, err := c.buildComplianceSnapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	p := c.compliancePostureFromSnapshot(ctx, snap)
	return p, buildCompliancePostureSnapshot(p, truncateToUTCDay(c.now())), nil
}

// truncateToUTCDay returns t with the time portion stripped (UTC midnight), so that
// one snapshot per calendar day is stored regardless of what time the call arrives.
func truncateToUTCDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// buildCompliancePostureSnapshot derives a CompliancePostureSnapshot from the given
// posture using EvaluateControls for an accurate pass/fail/degraded count.
func buildCompliancePostureSnapshot(p *CompliancePosture, snapshotDate time.Time) *models.CompliancePostureSnapshot {
	controls := EvaluateControls(p)
	var passed, failed, degraded int
	for _, ctrl := range controls {
		switch ctrl.Status {
		case ControlStatusPass, ControlStatusNotConfigured:
			passed++
		case ControlStatusGap:
			failed++
		case ControlStatusUnknown, ControlStatusPartiallyEvaluated:
			// Partial coverage is genuine uncertainty, not a clean pass -- same
			// bucket as Unknown, not Pass, so it doesn't inflate the passed count.
			degraded++
		}
	}
	return &models.CompliancePostureSnapshot{
		TotalControls:    len(controls),
		PassedControls:   passed,
		FailedControls:   failed,
		DegradedControls: degraded,
		SnapshotDate:     snapshotDate,
	}
}

// computeComplianceTrend fetches the previous snapshot and computes trend direction.
// Best-effort: a storage error returns a "no_data" trend rather than an error.
func (c *KeyorixCore) computeComplianceTrend(ctx context.Context, current *models.CompliancePostureSnapshot) *ComplianceTrend {
	prev, err := c.storage.GetPreviousCompliancePostureSnapshot(ctx, c.now())
	if err != nil || prev == nil {
		return &ComplianceTrend{Direction: "no_data"}
	}

	passedDelta := current.PassedControls - prev.PassedControls
	failedDelta := current.FailedControls - prev.FailedControls

	direction := "stable"
	if passedDelta > 0 || failedDelta < 0 {
		direction = "improving"
	} else if passedDelta < 0 || failedDelta > 0 {
		direction = "regressing"
	}

	return &ComplianceTrend{
		PreviousDate: &prev.SnapshotDate,
		PassedDelta:  &passedDelta,
		FailedDelta:  &failedDelta,
		Direction:    direction,
	}
}

// compliancePostureFromSnapshot builds the posture rollup entirely from an
// already-fetched complianceSnapshot — no query in this function touches storage.
func (c *KeyorixCore) compliancePostureFromSnapshot(ctx context.Context, snap *complianceSnapshot) *CompliancePosture {
	p := &CompliancePosture{GeneratedAt: c.now()}

	// Audit-trail integrity.
	applyAuditIntegrityPosture(p, snap)

	// Second-factor coverage across active users.
	if id, err := c.identityPosture(ctx); err == nil {
		p.Identity = id
	} else {
		p.degrade("identity", err)
	}

	// Rotation hygiene (deployment-wide).
	applyRotationPosture(p, snap)

	// Access governance + emergency access — per project.
	c.accessGovernancePostureFromSnapshot(ctx, p, snap)

	// Separation-of-duties violations (A.5.3), net of governed risk exceptions
	// (#170): an approved, active "sod"-category exception suppresses only the ONE
	// violation it names, not the whole SoD control.
	if sod, err := snap.sodReport, snap.sodErr; err == nil {
		p.AccessGovernance.SoDViolations = len(c.suppressExceptedSoDViolations(sod.Violations, snap.riskExceptionsActive, snap.riskExceptionsErr))
		// #420: a principal whose permissions couldn't be read means the scan may be
		// missing a violation for them — the posture rollup must say so too, not just
		// count what it managed to see.
		for _, reason := range sod.DegradedReasons {
			p.degrade("sod_violations", fmt.Errorf("%s", reason))
		}
	} else {
		p.degrade("sod_violations", err)
	}

	// Data-classification coverage (A.5.12).
	p.Classification = c.classificationPosture(ctx, p)

	// Open access anomalies (NIS2 detection).
	c.applyAnomalyPosture(ctx, p)

	// Legal hold (A.5.34).
	if hold, err := c.storage.GetActiveLegalHold(ctx); err == nil {
		if hold != nil {
			at := hold.PlacedAt
			p.LegalHold = LegalHoldPosture{Active: true, PlacedAt: &at, Reason: hold.Reason}
		}
	} else {
		p.degrade("legal_hold", err)
	}

	// Risk register — governed, time-bound exceptions (A.5.8). Derived from the same
	// listRiskExceptionRows(ctx, true) read as suppressExceptedSoDViolations above and
	// as the evidence pack's RiskExceptions field — one query, several consumers.
	// Expired (#395) comes from that identical read: a stale, never-renewed exception
	// means the risk it accepted is unmitigated again, so it must stay visible to the
	// control matrix rather than silently reading as "no exceptions" the moment
	// expiry passes.
	c.applyRiskExceptionPosture(p, snap)

	// Certificate hygiene from the cached cert expiry (ADR-056).
	p.Certificates = c.certificatePosture(ctx, p)

	// Data-retention windows (A.5.33).
	rp := c.retentionPolicy
	p.Retention = RetentionPosture{
		Enabled:                    rp.Configured(),
		AnomalyAlertsDays:          rp.AnomalyAlertsDays,
		ClosedAccessReviewsDays:    rp.ClosedAccessReviewsDays,
		BreakGlassDays:             rp.BreakGlassDays,
		ResolvedAccessRequestsDays: rp.ResolvedAccessRequestsDays,
	}

	// Supply-chain integrity (ADR-062/064/065): signed, offline-verifiable updates plus
	// offline entitlement. A non-release/source build pins no keys (control not in force).
	sc := SupplyChainPosture{}
	if reg, rerr := c.defaultTrustRegistry(); rerr == nil && reg != nil {
		ids := reg.KeyIDs(trust.PurposeUpdate)
		sc.TrustedUpdateKeys = len(ids)
		sc.UpdateSigningTrusted = len(ids) > 0
	} else if rerr != nil {
		// DefaultRegistry only errors when the embedded key material itself is
		// malformed (a build/release integrity problem) — distinct from an
		// ordinary unsigned/source build, which parses its empty key spec with a
		// nil error. Left un-degraded, this read the same as "no keys embedded"
		// (NotConfigured), masking a genuine "couldn't even check" failure.
		p.degrade("supply_chain", rerr)
	}
	ls := c.LicenseStatus()
	sc.LicenseState = string(ls.State)
	sc.LicenseValid = ls.Grants()
	p.SupplyChain = sc

	return p
}

func applyAuditIntegrityPosture(p *CompliancePosture, snap *complianceSnapshot) {
	v, err := snap.auditChain, snap.auditChainErr
	if err != nil {
		p.AuditIntegrity.Reason = err.Error()
		p.degrade("audit_integrity", err)
		return
	}
	if v == nil {
		return
	}
	p.AuditIntegrity = AuditIntegrityPosture{
		ChainVerified:          v.Valid,
		ChainedEvents:          v.ChainedEvents,
		Checkpointed:           v.Checkpointed,
		VerificationStatus:     v.Status,
		LastFullVerificationAt: v.LastFullVerificationAt,
		LastCheckedAt:          v.LastCheckedAt,
	}
	switch {
	case v.Status == AuditVerifyStatusNotProven:
		p.AuditIntegrity.Reason = v.NotProvenReason
	case !v.Valid:
		p.AuditIntegrity.Reason = v.Reason
	case v.CheckpointReason != "":
		p.AuditIntegrity.Reason = v.CheckpointReason
	}
}

func applyRotationPosture(p *CompliancePosture, snap *complianceSnapshot) {
	statuses, err := snap.rotationStatuses, snap.rotationErr
	if err != nil {
		p.degrade("rotation", err)
		return
	}
	if snap.totalSecretsErr != nil {
		p.degrade("rotation:total_secrets", snap.totalSecretsErr)
	} else {
		p.Rotation.TotalSecrets = snap.totalSecrets
	}
	p.Rotation.CoveredSecrets = len(statuses)
	for _, s := range statuses {
		switch s.Status {
		case RotationStatusOverdue:
			p.Rotation.Overdue++
		case RotationStatusDueSoon:
			p.Rotation.DueSoon++
		}
	}
}

func (c *KeyorixCore) applyAnomalyPosture(ctx context.Context, p *CompliancePosture) {
	unack := false
	alerts, err := c.storage.ListAnomalyAlerts(ctx, &unack)
	if err != nil {
		p.degrade("anomalies", err)
		return
	}
	p.Anomalies.Unacknowledged = len(alerts)
	for _, a := range alerts {
		if a.Severity == "high" {
			p.Anomalies.HighSeverityOpen++
		}
	}
}

func (c *KeyorixCore) applyRiskExceptionPosture(p *CompliancePosture, snap *complianceSnapshot) {
	if snap.riskExceptionsErr != nil {
		p.degrade("risk", snap.riskExceptionsErr)
		return
	}
	active, soon := 0, 0
	cutoff := c.now().Add(riskExpiringSoonWindow)
	for _, e := range snap.riskExceptionsActive {
		active++
		if e.ExpiresAt.Before(cutoff) {
			soon++
		}
	}
	p.Risk = RiskPosture{ActiveExceptions: active, ExpiringSoon: soon, Expired: snap.riskExceptionsExpired}
}

// suppressExceptedSoDViolations drops any violation covered by an active, APPROVED
// "sod"-category risk exception whose Reference matches it exactly (#170). Before
// this, a registered exception was purely decorative — GetCompliancePosture
// reported every raw violation regardless, so the "governed acceptance" mechanism
// didn't actually accept anything. Fails safe: a lookup error reports every
// violation unfiltered rather than risking an under-count from a partial exception
// list. exceptions/exceptionsErr come from the shared complianceSnapshot's single
// ListRiskExceptions(ctx, true) read (#256) rather than a fresh query here.
func (c *KeyorixCore) suppressExceptedSoDViolations(violations []SoDViolation, exceptions []*RiskExceptionView, exceptionsErr error) []SoDViolation {
	if len(violations) == 0 || exceptionsErr != nil {
		return violations
	}
	excepted := make(map[string]bool, len(exceptions))
	for _, e := range exceptions {
		if e.Category != "sod" || !e.Approved {
			continue
		}
		excepted[e.Reference] = true
	}
	if len(excepted) == 0 {
		return violations
	}
	out := make([]SoDViolation, 0, len(violations))
	for _, v := range violations {
		if excepted[v.Reference] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// classificationPosture counts secrets per classification level via cheap count
// queries (PageSize 1 → only the total), rather than walking every secret row.
// Reports into cp.degrade on any failed count so a query error reads as "unknown",
// not as a verified-zero count for that classification/entity kind.
func (c *KeyorixCore) classificationPosture(ctx context.Context, cp *CompliancePosture) ClassificationPosture {
	count := func(level string) int {
		f := &storage.SecretFilter{Page: 1, PageSize: 1}
		if level != "" {
			lvl := level
			f.Classification = &lvl
		}
		_, total, err := c.storage.ListSecrets(ctx, f)
		if err != nil {
			cp.degrade("classification:secrets:"+level, err)
			return 0
		}
		return int(total)
	}
	p := ClassificationPosture{
		TotalSecrets: count(""),
		Public:       count(ClassificationPublic),
		Internal:     count(ClassificationInternal),
		Confidential: count(ClassificationConfidential),
		Restricted:   count(ClassificationRestricted),
		Unclassified: count("unclassified"),
	}
	if m, err := c.storage.CountDynamicSecretConfigsByClassification(ctx); err == nil {
		p.DynamicConfigs = classificationCountsFromMap(m)
	} else {
		cp.degrade("classification:dynamic_configs", err)
	}
	if m, err := c.storage.CountMachineIdentitiesByClassification(ctx); err == nil {
		p.MachineIdentities = classificationCountsFromMap(m)
	} else {
		cp.degrade("classification:machine_identities", err)
	}
	if m, err := c.storage.CountMachineIdentityCredentialsByClassification(ctx); err == nil {
		p.MachineCredentials = classificationCountsFromMap(m)
	} else {
		cp.degrade("classification:machine_credentials", err)
	}
	return p
}

// identityPosture counts active users and how many have a second factor (MFA or
// passkey), paging through all of them (no silent cap).
func (c *KeyorixCore) identityPosture(ctx context.Context) (IdentityPosture, error) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	const pageSize = 500
	var out IdentityPosture
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return out, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, u := range users {
			if !u.IsActive {
				continue
			}
			out.ActiveUsers++
			if u.MFAEnabled || u.WebAuthnEnabled {
				out.UsersWithSecondFactor++
			}
		}
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}
	if out.ActiveUsers > 0 {
		out.SecondFactorPercent = out.UsersWithSecondFactor * 100 / out.ActiveUsers
	}
	return out, nil
}

// accessGovernancePosture walks every project, rolling up campaign coverage,
// dormant role grants, and break-glass usage. campaigns/break-glass per project come
// from the shared complianceSnapshot (#256) rather than a fresh query per call.
func (c *KeyorixCore) accessGovernancePostureFromSnapshot(ctx context.Context, p *CompliancePosture, snap *complianceSnapshot) {
	p.AccessGovernance.Projects = len(snap.projects)
	p.AccessRequests.RequiredApprovals = c.requiredApprovals()
	recertCutoff := c.now().AddDate(0, 0, -c.recertCadence())
	// CP-005: hoist the role-permissions cache across all per-project iterations so
	// GetRolePermissions is called at most once per role, not once per project per role.
	sharedPermsByRole := map[uint][]*models.Permission{}
	sharedDegradedRoles := map[uint]bool{}
	for _, proj := range snap.projects {
		pid := proj.ID
		accumulateCampaignPosture(p, pid, recertCutoff, snap)
		p.AccessGovernance.DormantRoleGrants += c.countDormantRoleGrants(ctx, pid, p, sharedPermsByRole, sharedDegradedRoles)
		c.accumulateBreakGlassPosture(p, pid, snap)
		accumulateAccessRequestPosture(p, pid, snap)
	}
	// Deployment-wide, not per-project -- computed once rather than inside the
	// loop above (#2461 round 2,
	// INV-CORE-break-glass-independent-review-impossible-is-visible).
	if impossible, err := c.independentBreakGlassReviewImpossible(ctx); err == nil {
		p.EmergencyAccess.IndependentReviewImpossible = impossible
	} else {
		p.degrade("emergency_access:independent_reviewer", err)
	}
}

// independentBreakGlassReviewImpossible reports whether this deployment has at
// most one active global admin-tier holder -- i.e. whether a break-glass
// activator could ever find an independent reviewer at all
// (INV-CORE-break-glass-independent-review-impossible-is-visible,
// #2461 round 2, Andrei's decision item (c)). Approximated the same way
// guardLastGlobalAdmin* approximates "another administrator exists" elsewhere
// in this file: active global admin-tier holder count, not a precise count of
// who holds roles.assign at every project scope (scanning every project's
// grants to answer that exactly is out of scope for a posture signal).
//
// No install-admin role seeded at all (adminIDs empty) returns false, not
// true: this proxy has nothing to count in that configuration, and guessing
// "impossible" from an absent signal would be worse than leaving the
// question to the one check that genuinely answers it per-activation
// (ReviewBreakGlass's own self-review refusal).
func (c *KeyorixCore) independentBreakGlassReviewImpossible(ctx context.Context) (bool, error) {
	adminIDs, err := c.adminBypassRoleIDSet(ctx)
	if err != nil {
		return false, err // #2496: fail closed -- "can't tell" must not read as "fine"
	}
	if len(adminIDs) == 0 {
		return false, nil
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return false, fmt.Errorf("failed to resolve global role assignments: %w", err)
	}
	holders, err := c.resolveGlobalAdminHolders(ctx, adminIDs, assignments, nil, nil)
	if err != nil {
		return false, err
	}
	return len(holders) <= 1, nil
}

func accumulateCampaignPosture(p *CompliancePosture, pid uint, recertCutoff time.Time, snap *complianceSnapshot) {
	campaigns, err := snap.campaignsByProject[pid], snap.campaignsErrByProject[pid]
	if err != nil {
		p.degrade(fmt.Sprintf("access_governance:campaigns:project=%d", pid), err)
		return
	}
	if len(campaigns) == 0 {
		p.AccessGovernance.ProjectsNeverReviewed++
	}
	open, lastClosed := splitCampaigns(campaigns)
	if open != nil {
		p.AccessGovernance.ProjectsWithOpenCampaign++
		p.AccessGovernance.OpenCampaigns++
		p.AccessGovernance.PendingItems += open.Progress.Pending
		// CP-002: a campaign that has been open past the recertification cadence cutoff
		// is itself overdue — count it regardless of whether it's still in progress.
		if open.Campaign.CreatedAt.Before(recertCutoff) {
			p.AccessGovernance.ProjectsOverdue++
		}
		return
	}
	overdue := lastClosed == nil
	if lastClosed != nil && lastClosed.Campaign.ClosedAt != nil {
		overdue = lastClosed.Campaign.ClosedAt.Before(recertCutoff)
	}
	if overdue {
		p.AccessGovernance.ProjectsOverdue++
	}
}

func (c *KeyorixCore) accumulateBreakGlassPosture(p *CompliancePosture, pid uint, snap *complianceSnapshot) {
	acts, err := snap.breakGlassByProject[pid], snap.breakGlassErrByProject[pid]
	if err != nil {
		p.degrade(fmt.Sprintf("emergency_access:project=%d", pid), err)
		return
	}
	// ADR-112 §3 item 4 (#2461): an activation with no recorded review, already
	// older than the review window, IS the posture deviation the ADR requires.
	// Reported for a still-active activation too, not only a concluded one --
	// the ADR's wording is "an OPEN activation without a recorded review", and
	// ReviewBreakGlass deliberately refuses to review one that is still active,
	// so excluding those here would hide exactly the activations that cannot be
	// closed out yet.
	window := c.breakGlassReviewWindow()
	p.EmergencyAccess.ReviewWindowHours = int(window.Hours())
	cutoff := c.now().Add(-window)
	p.EmergencyAccess.TotalActivations += len(acts)
	for _, a := range acts {
		if a.State == BreakGlassActive {
			p.EmergencyAccess.ActiveActivations++
		}
		if a.ReviewedAt == nil && !a.CreatedAt.After(cutoff) {
			p.EmergencyAccess.UnreviewedActivations++
			if ageHours := int(c.now().Sub(a.CreatedAt).Hours()); ageHours > p.EmergencyAccess.OldestUnreviewedAgeHours {
				p.EmergencyAccess.OldestUnreviewedAgeHours = ageHours
			}
		}
	}
}

func accumulateAccessRequestPosture(p *CompliancePosture, pid uint, snap *complianceSnapshot) {
	reqs, err := snap.accessRequestsByProject[pid], snap.accessRequestsErrByProject[pid]
	if err != nil {
		p.degrade(fmt.Sprintf("access_requests:project=%d", pid), err)
		return
	}
	p.AccessRequests.TotalRequests += len(reqs)
	for _, r := range reqs {
		switch r.State {
		case AccessRequestPending:
			p.AccessRequests.Pending++
		case AccessRequestApproved:
			p.AccessRequests.Approved++
		case AccessRequestRejected:
			p.AccessRequests.Rejected++
		case AccessRequestWithdrawn:
			p.AccessRequests.Withdrawn++
		case AccessRequestExpired:
			p.AccessRequests.Expired++
		}
	}
}

// countDormantRoleGrants counts individual role grants in the project that are
// stale standing access — a grant whose holder hasn't exercised the CAPABILITY it
// confers recently (or ever). Cheap: the project's role assignments + the two
// last-activity maps, no full secret walk.
//
// Per-grant, not per-user (#258): a user can hold several role grants in the same
// project — e.g. an everyday project_viewer grant they use weekly, plus a
// project_admin grant handed out "just in case" that they've never actually
// exercised. Counting dormancy per USER (as this used to) meant that ordinary
// secret-read activity under the viewer grant masked the separate, genuinely-stale
// admin grant as "non-dormant" — the coarse per-project activity check couldn't
// tell which grant the activity was attributable to. Each (principal, role) grant
// is now assessed independently, so the unused admin-tier grant is correctly
// flagged even though the same user is actively reading secrets elsewhere.
//
// The activity signal used per grant is matched against the SPECIFIC permission(s)
// that grant's own bundle confers, at two tiers (roleIsAdminTier):
//   - A plain read/write-tier role is credited "used" via LastUserSecretReadActivity
//     when its bundle includes secrets.read, and/or via LastUserSecretWriteActivity
//     (create/update/rotate — all three are gated by the single secrets.write
//     permission, #424) when its bundle includes secrets.write (#487 round 112) —
//     not, as before, by ANY combined read-or-write activity regardless of which of
//     the two the grant actually confers. A write-tier grant (e.g. a CI/CD pipeline
//     operator or secret-provisioning admin) may legitimately never read a secret's
//     value back at all, so it must not need a read to count as used; symmetrically,
//     a read-only grant must not be masked non-dormant purely because the SAME user
//     also holds a separate write-only grant they actually exercise.
//   - An admin-tier role (secrets.delete/admin, or a role-management permission
//     like roles.assign) is credited via LastUserRoleManagementActivity /
//     LastUserSecretDeletionActivity — an actually-observed elevated action MATCHING
//     the specific capability this grant's own permission bundle confers (#487) —
//     since ordinary secret reads/writes don't attest to any ADMIN capability being
//     used at all, and an elevated action of a DIFFERENT kind doesn't attest to THIS
//     grant's specific admin capability being used either.
//
// This is an approximation, not a perfect per-grant attribution: the audit trail
// doesn't record which specific grant authorized a given action, only that SOME
// action satisfying a given permission occurred. Two grants in the same project
// (at either tier) are distinguished whenever they confer DIFFERENT specific
// capabilities (#487, extended to the plain tier in round 112) — e.g. one role
// bundles only secrets.read, the other only secrets.write, or one bundles only
// roles.assign, the other only secrets.delete: only the grant whose OWN permission
// bundle covers the observed action's capability is credited, so exercising one no
// longer masks the other.
//
// Two grants that bundle the SAME specific capability (e.g. two roles that both
// carry secrets.delete, or both carry secrets.read) remain genuinely
// indistinguishable, and — after actually investigating the fix this round (#487,
// round 112) — this is now a CONFIRMED structural limitation of the authorization
// model itself, not a gap left by insufficient audit-trail plumbing: Authorize/
// RoleSetHasPermission resolve permission as a boolean OR across the union of a
// principal's applicable role IDs (internal/core/authz.go, RoleSetHasPermission's
// SQL is a plain COUNT(*) over the role-permission join, with no notion of "the one
// role that matched"). When two grants each individually and equally satisfy the
// same permission check, there is no principled way to attribute a resulting action
// to one over the other — recording "which role(s) covered this permission" at the
// moment of the action would recompute the exact same STATIC role-definition
// membership test already available at read time (a role's permission bundle
// doesn't vary per request), so it adds no information the read-time
// hasPermission check above doesn't already have. Manufacturing a tie-break (e.g.
// "credit the first matching role ID") would be an arbitrary, unjustified
// attribution — worse than the current, honestly-ambiguous approximation. Both
// grants are credited (neither shown falsely dormant) — the same "no worse than
// before" behaviour as pre-#487 for this narrower, structurally irreducible case.
// See roleIsAdminTier's doc for the exact tier boundary.
func (c *KeyorixCore) countDormantRoleGrants(ctx context.Context, projectID uint, cp *CompliancePosture, permsByRole map[uint][]*models.Permission, degradedRoles map[uint]bool) int { // NOSONAR -- cognitive complexity 25, suppress go:S3776
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:assignments:project=%d", projectID), err)
		return 0
	}
	readActivity, err := c.storage.LastUserSecretReadActivity(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:read_activity:project=%d", projectID), err)
		return 0
	}
	writeActivity, err := c.storage.LastUserSecretWriteActivity(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:write_activity:project=%d", projectID), err)
		return 0
	}
	roleMgmtActivity, err := c.storage.LastUserRoleManagementActivity(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:role_management_activity:project=%d", projectID), err)
		return 0
	}
	secretsDeletionActivity, err := c.storage.LastUserSecretDeletionActivity(ctx, projectID)
	if err != nil {
		cp.degrade(fmt.Sprintf("dormant_role_grants:secrets_deletion_activity:project=%d", projectID), err)
		return 0
	}
	cutoff := c.now().Add(-dormantThreshold)

	rolePerms := func(roleID uint) []*models.Permission {
		if v, ok := permsByRole[roleID]; ok {
			return v
		}
		perms, err := c.storage.GetRolePermissions(ctx, roleID)
		if err != nil {
			// Can't resolve this role's permission bundle; degrade once per role and
			// fall back to treating it as non-admin-tier (the plain read/write
			// activity check) rather than silently under- or over-counting.
			if !degradedRoles[roleID] {
				degradedRoles[roleID] = true
				cp.degrade(fmt.Sprintf("dormant_role_grants:role_permissions:project=%d:role=%d", projectID, roleID), err)
			}
			permsByRole[roleID] = nil
			return nil
		}
		permsByRole[roleID] = perms
		return perms
	}
	seen := map[[2]uint]bool{} // dedup identical (principal, role) grant rows
	dormant := 0
	for _, a := range assignments {
		if a.PrincipalType != "user" {
			continue
		}
		key := [2]uint{a.PrincipalID, a.RoleID}
		if seen[key] {
			continue
		}
		seen[key] = true
		perms := rolePerms(a.RoleID)
		if roleIsAdminTier(perms) {
			if !grantUsedAdmin(perms, a.PrincipalID, cutoff, roleMgmtActivity, secretsDeletionActivity) {
				dormant++
			}
		} else {
			if !grantUsedPlain(perms, a.PrincipalID, cutoff, readActivity, writeActivity) {
				dormant++
			}
		}
	}
	return dormant
}

// roleHasPermission reports whether any entry in perms has the given name.
func roleHasPermission(perms []*models.Permission, name string) bool {
	for _, p := range perms {
		if p.Name == name {
			return true
		}
	}
	return false
}

// grantUsedPlain reports whether a plain-tier (non-admin) grant has been exercised
// within the dormancy window, checking only the specific permission buckets the role
// actually confers.
func grantUsedPlain(perms []*models.Permission, uid uint, cutoff time.Time, readActivity, writeActivity map[uint]time.Time) bool {
	if roleHasPermission(perms, "secrets.read") {
		if last, ok := readActivity[uid]; ok && !last.Before(cutoff) {
			return true
		}
	}
	if roleHasPermission(perms, "secrets.write") {
		if last, ok := writeActivity[uid]; ok && !last.Before(cutoff) {
			return true
		}
	}
	return false
}

// grantUsedAdmin reports whether an admin-tier grant has been exercised within the
// dormancy window, checking only the specific elevated permission buckets it confers.
func grantUsedAdmin(perms []*models.Permission, uid uint, cutoff time.Time, roleMgmtActivity, secretsDeletionActivity map[uint]time.Time) bool {
	if roleHasPermission(perms, "roles.assign") {
		if last, ok := roleMgmtActivity[uid]; ok && !last.Before(cutoff) {
			return true
		}
	}
	if roleHasPermission(perms, "secrets.delete") || roleHasPermission(perms, "secrets.admin") {
		if last, ok := secretsDeletionActivity[uid]; ok && !last.Before(cutoff) {
			return true
		}
	}
	return false
}
