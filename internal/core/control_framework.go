// control_framework.go — the compliance control matrix (ISO 27001 / SOC 2 / NIS2 /
// DORA / ENS). Where GetCompliancePosture reports raw figures, GetComplianceControls
// maps each control Keyorix enforces to its clause references across the regimes an
// auditor cares about, and evaluates a live status (pass / gap / not-configured)
// from the posture. It turns the scattered A.5.x tiles into one auditor-ready
// framework map. Read-only; gated by audit.read at every real entry point (HTTP
// GET /api/v1/compliance/controls and /compliance/controls.csv, and the gRPC
// ComplianceGRPCService.GetComplianceControls). Do not gate this — or any new
// caller — on system.read: that permission is granted to every user via the
// baseline system_viewer role, so it is equivalent to no gate at all for this
// disclosure-sensitive control matrix. Gating on system.read was a real,
// fixed vulnerability (CP-001/CP-008); see the regression test
// TestComplianceService_SystemViewerDenied in
// server/grpc/services/compliance_service_test.go.
package core

import (
	"context"
	"fmt"
	"time"
)

// ControlStatus is a control's evaluated state.
type ControlStatus string

const (
	ControlStatusPass          ControlStatus = "pass"
	ControlStatusGap           ControlStatus = "gap"
	ControlStatusNotConfigured ControlStatus = "not_configured"
	// ControlStatusUnknown marks a control whose underlying signal could not be
	// collected this run (its posture sub-rollup query failed — see
	// CompliancePosture.Degraded). #136: a failed collection must never silently
	// read as "pass" just because the zero-value field it's evaluated from looks
	// clean — an auditor relying on this matrix needs to see "unknown", not a false
	// "pass".
	ControlStatusUnknown ControlStatus = "unknown"
	// ControlStatusPartiallyEvaluated marks a control whose population is a mix of
	// evaluated and not-yet-evaluated members — distinct from Pass (everything
	// evaluated, nothing failing) and from NotConfigured (nothing evaluated at
	// all). Added 2026-09-07: certificateHygieneStatus previously had no way to
	// express this state, so a certificate-typed secret nobody has scanned yet
	// silently fell through to Pass alongside the ones that genuinely passed —
	// false assurance on a compliance surface an auditor reads at face value.
	ControlStatusPartiallyEvaluated ControlStatus = "partially_evaluated"
)

// FrameworkRefs maps a control to clauses across the regimes Keyorix targets.
type FrameworkRefs struct {
	ISO27001 []string `json:"iso_27001,omitempty"` // Annex A:2022 control ids, e.g. "A.5.18"
	SOC2     []string `json:"soc2,omitempty"`      // Trust Services Criteria, e.g. "CC6.1"
	NIS2     []string `json:"nis2,omitempty"`      // article refs, e.g. "Art.21(2)(i)"
	DORA     []string `json:"dora,omitempty"`      // article refs, e.g. "Art.9"
	// ENS maps to the security measures of Spain's Esquema Nacional de Seguridad
	// (Real Decreto 311/2022, Anexo II), e.g. ctrlOpAcc4. Codes name the measure in
	// the org.* (organisational) / op.* (operational) / mp.* (protection) frameworks.
	ENS []string `json:"ens,omitempty"`
}

// ControlState is one control's evaluated posture for the framework matrix.
type ControlState struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Area       string        `json:"area"`
	Status     ControlStatus `json:"status"`
	Detail     string        `json:"detail"`
	Frameworks FrameworkRefs `json:"frameworks"`
}

// ControlsSummary tallies controls by status.
type ControlsSummary struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Gap           int `json:"gap"`
	NotConfigured int `json:"not_configured"`
	// Unknown counts controls whose signal could not be collected this run (#136) —
	// a non-zero value here means the matrix is incomplete, not fully passing.
	Unknown int `json:"unknown"`
	// PartiallyEvaluated counts controls whose population is a mix of evaluated and
	// not-yet-evaluated members (added 2026-09-07) — distinct from Pass and from
	// NotConfigured; see ControlStatusPartiallyEvaluated.
	PartiallyEvaluated int `json:"partially_evaluated"`
}

// ComplianceControls is the evaluated control matrix at a point in time.
type ComplianceControls struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Controls    []ControlState  `json:"controls"`
	Summary     ControlsSummary `json:"summary"`
}

// GetComplianceControls evaluates the control matrix from the current posture.
func (c *KeyorixCore) GetComplianceControls(ctx context.Context) (*ComplianceControls, error) {
	p, err := c.GetCompliancePosture(ctx)
	if err != nil {
		return nil, err
	}
	controls := EvaluateControls(p)
	out := &ComplianceControls{GeneratedAt: c.now(), Controls: controls}
	out.Summary.Total = len(controls)
	for _, ctrl := range controls {
		switch ctrl.Status {
		case ControlStatusPass:
			out.Summary.Pass++
		case ControlStatusGap:
			out.Summary.Gap++
		case ControlStatusNotConfigured:
			out.Summary.NotConfigured++
		case ControlStatusUnknown:
			out.Summary.Unknown++
		case ControlStatusPartiallyEvaluated:
			out.Summary.PartiallyEvaluated++
		}
	}
	return out, nil
}

// controlStatus evaluates a control's status, but overrides to ControlStatusUnknown
// whenever `degraded` is true — i.e. whenever the posture sub-rollup(s) this control
// depends on failed to collect this run (#136). `bad` (the ordinary gapIf input) is
// only trusted when the underlying signal is known-good.
func controlStatus(degraded, bad bool) ControlStatus {
	if degraded {
		return ControlStatusUnknown
	}
	return gapIf(bad)
}

// gapIf returns Gap when bad is true, else Pass — the common two-state evaluation.
func gapIf(bad bool) ControlStatus {
	if bad {
		return ControlStatusGap
	}
	return ControlStatusPass
}

// EvaluateControls derives the control matrix from a posture snapshot. It is a pure
// function (no storage) so the mapping and status logic are unit-testable in
// isolation. The order is stable (grouped by area) for a deterministic report.
func EvaluateControls(p *CompliancePosture) []ControlState {
	ag := p.AccessGovernance
	return []ControlState{
		{
			ID: "audit-trail-integrity", Name: "Tamper-evident audit trail", Area: "Audit & accountability",
			Status:     controlStatus(p.DegradedArea("audit_integrity"), !p.AuditIntegrity.ChainVerified),
			Detail:     fmt.Sprintf("chain verified=%t, checkpointed=%t, %d events", p.AuditIntegrity.ChainVerified, p.AuditIntegrity.Checkpointed, p.AuditIntegrity.ChainedEvents),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.28", "A.8.15"}, SOC2: []string{"CC7.2", "CC4.1"}, NIS2: []string{"Art.21(2)(i)"}, DORA: []string{"Art.9"}, ENS: []string{"op.exp.8", "op.exp.10"}},
		},
		{
			ID: "access-recertification", Name: "Access recertification at planned intervals", Area: ctrlAccessGovernance,
			Status:     controlStatus(p.DegradedArea("access_governance:campaigns:"), ag.ProjectsOverdue > 0 || ag.ProjectsNeverReviewed > 0),
			Detail:     fmt.Sprintf("%d overdue, %d never reviewed, %d pending items", ag.ProjectsOverdue, ag.ProjectsNeverReviewed, ag.PendingItems),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.18"}, SOC2: []string{"CC6.2", "CC6.3"}, NIS2: []string{"Art.21(2)(i)"}, DORA: []string{"Art.9"}, ENS: []string{ctrlOpAcc4}},
		},
		{
			ID: "dormant-access", Name: "No dormant standing access", Area: ctrlAccessGovernance,
			Status:     controlStatus(p.DegradedArea("dormant_role_grants:"), ag.DormantRoleGrants > 0),
			Detail:     fmt.Sprintf("%d dormant role grant(s) (no use in the last %d days)", ag.DormantRoleGrants, dormantThresholdDays),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.18", "A.8.2"}, SOC2: []string{"CC6.1"}, ENS: []string{"op.acc.2", ctrlOpAcc4}},
		},
		{
			ID: "separation-of-duties", Name: "Separation of duties (no toxic combinations)", Area: ctrlAccessGovernance,
			Status:     controlStatus(p.DegradedArea("sod_violations", "evidence:sod_violations"), ag.SoDViolations > 0),
			Detail:     fmt.Sprintf("%d SoD violation(s)", ag.SoDViolations),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.3"}, SOC2: []string{"CC5.1"}, DORA: []string{"Art.5"}, ENS: []string{"op.acc.3"}},
		},
		{
			ID: "second-factor", Name: "Second-factor coverage", Area: "Identity",
			Status:     controlStatus(p.DegradedArea("identity"), p.Identity.SecondFactorPercent < 100),
			Detail:     fmt.Sprintf("%d%% of active users have a second factor", p.Identity.SecondFactorPercent),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.17", "A.8.5"}, SOC2: []string{"CC6.1"}, NIS2: []string{"Art.21(2)(j)"}, DORA: []string{"Art.9"}, ENS: []string{"op.acc.5", "op.acc.6"}},
		},
		{
			ID: "secret-rotation", Name: "Secret-rotation hygiene", Area: "Cryptography",
			// CP-007: also fail when fewer secrets are covered than exist in the deployment
			// (vacuous-truth pass when CoveredSecrets == 0 and Overdue == 0 but TotalSecrets > 0).
			Status: controlStatus(p.DegradedArea("rotation", "evidence:rotation_overdue"),
				p.Rotation.Overdue > 0 || (p.Rotation.TotalSecrets > 0 && p.Rotation.CoveredSecrets < p.Rotation.TotalSecrets)),
			Detail:     fmt.Sprintf("%d overdue, %d due soon; %d of %d secrets covered", p.Rotation.Overdue, p.Rotation.DueSoon, p.Rotation.CoveredSecrets, p.Rotation.TotalSecrets),
			Frameworks: FrameworkRefs{ISO27001: []string{ctrlA515, "A.8.24"}, SOC2: []string{"CC6.1"}, NIS2: []string{"Art.21(2)(h)"}, ENS: []string{"op.exp.11"}},
		},
		{
			ID: "certificate-hygiene", Name: "Certificate expiry hygiene", Area: "Cryptography",
			Status:     certificateHygieneStatus(p),
			Detail:     certificateHygieneDetail(p),
			Frameworks: FrameworkRefs{ISO27001: []string{ctrlA515, "A.8.24"}, SOC2: []string{"CC6.1"}, NIS2: []string{"Art.21(2)(h)"}, ENS: []string{"op.exp.11"}},
		},
		{
			ID: "data-classification", Name: "Secret data classification", Area: "Asset management",
			Status:     classificationStatus(p),
			Detail:     classificationDetail(p),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.12", "A.5.13"}, SOC2: []string{"CC3.2"}, ENS: []string{"mp.info.2"}},
		},
		{
			ID: "anomaly-detection", Name: "Access-anomaly detection & response", Area: "Detection",
			Status:     controlStatus(p.DegradedArea("anomalies"), p.Anomalies.HighSeverityOpen > 0),
			Detail:     fmt.Sprintf("%d open anomalies (%d high severity)", p.Anomalies.Unacknowledged, p.Anomalies.HighSeverityOpen),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.8.16"}, SOC2: []string{"CC7.2", "CC7.3"}, NIS2: []string{"Art.21(2)(b)"}, DORA: []string{"Art.10"}, ENS: []string{"op.mon.1", "op.exp.7"}},
		},
		{
			ID: "emergency-access", Name: "Governed emergency (break-glass) access", Area: ctrlAccessGovernance,
			// #2461 round 2: an unreviewed activation past the review window used to
			// be purely informational here (Status always Pass-or-Unknown, never
			// Gap) -- "visibility is the control"
			// (INV-CORE-break-glass-unreviewed-reported-never-blocks-activation)
			// does not mean this
			// matrix may silently read a real posture deviation as passing. A
			// failed collection still needs to surface as unknown, not a default
			// Pass or a false Gap.
			Status:     controlStatus(p.DegradedArea("emergency_access:", "evidence:break_glass:"), p.EmergencyAccess.UnreviewedActivations > 0),
			Detail:     fmt.Sprintf("%d active, %d total activations (all audited), %d unreviewed past the window", p.EmergencyAccess.ActiveActivations, p.EmergencyAccess.TotalActivations, p.EmergencyAccess.UnreviewedActivations),
			Frameworks: FrameworkRefs{ISO27001: []string{ctrlA515}, SOC2: []string{"CC6.1"}, DORA: []string{"Art.9"}, ENS: []string{ctrlOpAcc4, "op.exp.7"}},
		},
		{
			ID: "emergency-access-independent-reviewer", Name: "Break-glass has an independent reviewer available", Area: ctrlAccessGovernance,
			// INV-CORE-break-glass-independent-review-impossible-is-visible
			// (#2461 round 2, Andrei's decision item (c)): a deployment
			// where no human other than the activator could ever review an
			// activation must say so as its own distinct finding -- never silently
			// read identical to "reviewed" or to an ordinary unreviewed backlog.
			Status:     controlStatus(p.DegradedArea("emergency_access:", "evidence:break_glass:"), p.EmergencyAccess.IndependentReviewImpossible),
			Detail:     independentReviewerDetail(p.EmergencyAccess),
			Frameworks: FrameworkRefs{ISO27001: []string{ctrlA515}, SOC2: []string{"CC6.1"}, DORA: []string{"Art.9"}, ENS: []string{ctrlOpAcc4}},
		},
		{
			ID: "access-request-hygiene", Name: "Access-request approval hygiene (no stale, unresolved lapses)", Area: ctrlAccessGovernance,
			// A pending access request (ADR-024's dual-control workflow, #257) that
			// lapses with no explicit approve/reject/withdraw decision is the same
			// shape of gap as #395's stale risk exceptions: an access decision that was
			// supposed to be made never was — it just silently expired. RequiredApprovals
			// (the configured N-of-M dual-control threshold; ApproveAccessRequestWithExpiry
			// already enforces maker != checker) is surfaced in Detail for auditor
			// context, but only Expired drives the verdict — a deployment with zero
			// requests, or requests that were all explicitly resolved, must stay Pass
			// rather than gapping on an unconfigured/default posture.
			Status:     controlStatus(p.DegradedArea("access_requests:"), p.AccessRequests.Expired > 0),
			Detail:     fmt.Sprintf("%d expired without resolution, %d pending of %d total request(s); required approvers=%d", p.AccessRequests.Expired, p.AccessRequests.Pending, p.AccessRequests.TotalRequests, p.AccessRequests.RequiredApprovals),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.3"}, SOC2: []string{"CC6.2", "CC5.1"}, ENS: []string{"op.acc.3"}},
		},
		{
			ID: "data-retention", Name: "Data-retention / storage limitation", Area: "Data governance",
			Status:     statusFromBool(p.Retention.Enabled),
			Detail:     retentionDetail(p.Retention),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.33"}, SOC2: []string{"CC3.2"}, DORA: []string{"Art.12"}, ENS: []string{"mp.info.1"}},
		},
		{
			ID: "legal-hold", Name: "Litigation/investigation legal hold", Area: "Data governance",
			// capability present; active state is informational — but #136's worst
			// instance is exactly here: a failed query previously read byte-identical
			// to "no hold", so a degraded collection must surface as unknown instead.
			Status:     controlStatus(p.DegradedArea("legal_hold"), false),
			Detail:     legalHoldDetail(p, p.DegradedArea("legal_hold")),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.34"}, DORA: []string{"Art.12"}, ENS: []string{"mp.info.6"}},
		},
		{
			ID: "risk-exception-hygiene", Name: "Risk-exception register hygiene (no stale, unrenewed acceptances)", Area: "Risk governance",
			// #395: a risk exception is a governed, time-bound acceptance of a control
			// gap — once it expires with no renewal or revocation, the risk it was
			// excepting is unmitigated again. It simply drops out of ActiveExceptions
			// at that point, so without this control an auditor has no visibility into
			// the lapsed acceptance at all.
			Status:     controlStatus(p.DegradedArea("risk"), p.Risk.Expired > 0),
			Detail:     fmt.Sprintf("%d active exception(s), %d expired but not yet revoked/renewed", p.Risk.ActiveExceptions, p.Risk.Expired),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.8"}, SOC2: []string{"CC3.2"}, DORA: []string{"Art.6"}, ENS: []string{"org.3"}},
		},
		{
			ID: "supply-chain-integrity", Name: "Software supply-chain integrity (signed, verifiable updates)", Area: "Supply chain",
			Status:     supplyChainStatus(p),
			Detail:     supplyChainDetail(p),
			Frameworks: FrameworkRefs{ISO27001: []string{"A.5.19", "A.5.20", "A.5.21"}, SOC2: []string{"CC8.1"}, NIS2: []string{"Art.21(2)(d)"}, DORA: []string{"Art.28"}, ENS: []string{"op.pl.2", "op.exp.2"}},
		},
	}
}

// supplyChainStatus is Pass when this deployment verifies updates against a pinned signing
// key (a signed release). A source/dev build pins no key, so the control is "not configured"
// (it does not apply to an unsigned build) rather than a gap. But if the trust-registry
// lookup itself failed this run (#145 — the embedded key material was malformed, a
// build/release integrity problem, not an ordinary unsigned build), that must surface as
// Unknown rather than silently reading identical to "not configured".
func supplyChainStatus(p *CompliancePosture) ControlStatus {
	if p.DegradedArea("supply_chain") {
		return ControlStatusUnknown
	}
	return statusFromBool(p.SupplyChain.UpdateSigningTrusted)
}

func supplyChainDetail(p *CompliancePosture) string {
	s := p.SupplyChain
	if p.DegradedArea("supply_chain") {
		return "UNKNOWN — trust-registry lookup failed this run (embedded key material malformed); do not treat as unsigned/not-configured"
	}
	if !s.UpdateSigningTrusted {
		return "no pinned update-signing key (unsigned/source build) — offline bundle verification not in force"
	}
	return fmt.Sprintf("update bundles verified offline against %d pinned signing key(s); license: %s",
		s.TrustedUpdateKeys, s.LicenseState)
}

// certificateHygieneStatus is Pass/Gap once certificate-expiry scanning (ADR-055) has
// actually evaluated at least one certificate. That scan is opt-in/off by default, and
// CertificatePosture.Expired only ever increments for a certificate the scan has parsed
// — so with the scan disabled, Expired stays permanently 0 and the control would read as
// a false "pass" even though not a single certificate was ever checked (#397). Mirror the
// supply-chain-integrity escape hatch above: "never enabled" is not-configured, distinct
// from "enabled but this run's collection failed", which is Unknown (#136).
//
// Corrected 2026-09-07: a MIX of evaluated and not-yet-evaluated certificates previously
// fell through to Pass whenever none of the evaluated ones were expired — the unevaluated
// ones were silently invisible to the status, only surfacing in the free-text Detail line.
// A partially-scanned population and a fully-clean one are not the same claim; the former
// is now ControlStatusPartiallyEvaluated, never Pass.
func certificateHygieneStatus(p *CompliancePosture) ControlStatus {
	if p.DegradedArea("certificates") {
		return ControlStatusUnknown
	}
	c := p.Certificates
	if c.NotEvaluated == c.TotalCertificates {
		return ControlStatusNotConfigured
	}
	if c.Expired > 0 {
		// A confirmed expired certificate is a Gap regardless of how much of the
		// rest of the population remains unevaluated — this must never be masked
		// by, or downgraded to, the partial-coverage state below.
		return ControlStatusGap
	}
	if c.NotEvaluated > 0 {
		return ControlStatusPartiallyEvaluated
	}
	return ControlStatusPass
}

func certificateHygieneDetail(p *CompliancePosture) string {
	c := p.Certificates
	if p.DegradedArea("certificates") {
		return "UNKNOWN — certificate posture could not be collected this run"
	}
	if c.NotEvaluated == c.TotalCertificates {
		if c.TotalCertificates == 0 {
			return "no certificate-typed secrets to evaluate"
		}
		return fmt.Sprintf("certificate-expiry scanning not enabled — %d certificate(s) never evaluated", c.TotalCertificates)
	}
	return fmt.Sprintf("%d expired, %d expiring soon of %d certificate(s) (%d not yet evaluated)", c.Expired, c.ExpiringSoon, c.TotalCertificates, c.NotEvaluated)
}

// classificationTotals folds all four classifiable surfaces the posture already
// collects — static secrets, dynamic-secret configs, machine identities, and
// machine-token credentials — into one unclassified/total pair (#396). Before this,
// the data-classification control only ever reflected
// p.Classification.Unclassified/TotalSecrets (static secrets), so a deployment with a
// perfectly-classified secret store but thousands of unclassified dynamic-secret
// configs, machine identities, or machine credentials still reported a clean Pass —
// those sub-counts were collected by classificationPosture but never folded into the
// control's pass/fail decision.
func classificationTotals(p *CompliancePosture) (unclassified, total int) {
	c := p.Classification
	unclassified = c.Unclassified + c.DynamicConfigs.Unclassified + c.MachineIdentities.Unclassified + c.MachineCredentials.Unclassified
	total = c.TotalSecrets + c.DynamicConfigs.Total + c.MachineIdentities.Total + c.MachineCredentials.Total
	return unclassified, total
}

// classificationStatus is Gap when any classifiable surface — static secrets,
// dynamic-secret configs, machine identities, or machine-token credentials — has an
// unclassified item (A.5.12). See classificationTotals for why all four surfaces
// must be folded in rather than just static secrets (#396).
func classificationStatus(p *CompliancePosture) ControlStatus {
	unclassified, _ := classificationTotals(p)
	return controlStatus(p.DegradedArea("classification:"), unclassified > 0)
}

func classificationDetail(p *CompliancePosture) string {
	unclassified, total := classificationTotals(p)
	return fmt.Sprintf("%d of %d classifiable items unclassified across secrets/dynamic-configs/machine-identities/machine-credentials", unclassified, total)
}

// independentReviewerDetail reports
// INV-CORE-break-glass-independent-review-impossible-is-visible's distinct
// finding in
// human-readable form -- it must say outright that independent review is
// impossible, not leave an auditor to infer it from a count being 1.
func independentReviewerDetail(e EmergencyAccessPosture) string {
	if e.IndependentReviewImpossible {
		return "no reviewer other than the activator is available in this deployment -- independent post-activation review is not currently possible"
	}
	return "an independent reviewer is available"
}

// statusFromBool maps an enabled flag to pass / not-configured (an unset optional
// control is "not configured" rather than a gap — it may not apply to every install).
func statusFromBool(enabled bool) ControlStatus {
	if enabled {
		return ControlStatusPass
	}
	return ControlStatusNotConfigured
}

func retentionDetail(r RetentionPosture) string {
	if !r.Enabled {
		return "no retention windows configured (records kept indefinitely)"
	}
	return fmt.Sprintf("windows set: anomaly=%dd, reviews=%dd, break-glass=%dd, requests=%dd",
		r.AnomalyAlertsDays, r.ClosedAccessReviewsDays, r.BreakGlassDays, r.ResolvedAccessRequestsDays)
}

// legalHoldDetail describes the legal-hold state. When degraded is true, the
// underlying query failed this run — #136: LegalHold.Active=false is then the
// query's zero-value fallback, NOT a verified "no hold in effect", so the detail
// must say so explicitly rather than implying "none currently active".
func legalHoldDetail(p *CompliancePosture, degraded bool) string {
	if degraded {
		return "UNKNOWN — legal-hold status could not be verified this run (query failed); do not treat as inactive"
	}
	if p.LegalHold.Active {
		return fmt.Sprintf("ACTIVE — purges blocked (%s)", p.LegalHold.Reason)
	}
	return "available; none currently active"
}
