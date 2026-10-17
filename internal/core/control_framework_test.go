package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findControl returns the control with the given id (or fails the test).
func findControl(t *testing.T, controls []ControlState, id string) ControlState {
	t.Helper()
	for _, c := range controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %q not found", id)
	return ControlState{}
}

// A fully-healthy posture yields all controls pass/not-configured, never a gap, and
// every control carries an ISO 27001 reference.
func TestEvaluateControls_HealthyPosture(t *testing.T) {
	t.Parallel()
	p := &CompliancePosture{
		AuditIntegrity:   AuditIntegrityPosture{ChainVerified: true, Checkpointed: true, ChainedEvents: 100},
		AccessGovernance: AccessGovernancePosture{Projects: 3},
		Rotation:         RotationPosture{CoveredSecrets: 10},
		Identity:         IdentityPosture{ActiveUsers: 5, UsersWithSecondFactor: 5, SecondFactorPercent: 100},
		Classification:   ClassificationPosture{TotalSecrets: 10},
		Anomalies:        AnomaliesPosture{},
		Retention:        RetentionPosture{Enabled: true, AnomalyAlertsDays: 90},
	}
	controls := EvaluateControls(p)
	require.NotEmpty(t, controls)
	for _, c := range controls {
		assert.NotEqual(t, ControlStatusGap, c.Status, "healthy posture has no gaps: %s", c.ID)
		assert.NotEmpty(t, c.Frameworks.ISO27001, "control %s maps to an ISO 27001 clause", c.ID)
		assert.NotEmpty(t, c.Frameworks.ENS, "control %s maps to an ENS measure", c.ID)
		assert.NotEmpty(t, c.Name)
	}
	// Retention enabled → pass.
	assert.Equal(t, ControlStatusPass, findControl(t, controls, "data-retention").Status)
}

// Each unhealthy posture figure flips the matching control to a gap.
func TestEvaluateControls_GapsFromPosture(t *testing.T) {
	t.Parallel()
	p := &CompliancePosture{
		AuditIntegrity: AuditIntegrityPosture{ChainVerified: false},
		AccessGovernance: AccessGovernancePosture{
			Projects: 4, ProjectsOverdue: 2, ProjectsNeverReviewed: 1, DormantRoleGrants: 3, SoDViolations: 1,
		},
		Rotation:       RotationPosture{Overdue: 2},
		Identity:       IdentityPosture{ActiveUsers: 5, UsersWithSecondFactor: 3, SecondFactorPercent: 60},
		Classification: ClassificationPosture{TotalSecrets: 10, Unclassified: 4},
		Anomalies:      AnomaliesPosture{Unacknowledged: 3, HighSeverityOpen: 1},
		Retention:      RetentionPosture{Enabled: false},
	}
	controls := EvaluateControls(p)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "audit-trail-integrity").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "access-recertification").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "dormant-access").Status)
	// RECERT-BOUND-1: the evidence says which period "dormant" means.
	assert.Equal(t, "3 dormant role grant(s) (no use in the last 90 days)", findControl(t, controls, "dormant-access").Detail)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "separation-of-duties").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "second-factor").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "secret-rotation").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "data-classification").Status)
	assert.Equal(t, ControlStatusGap, findControl(t, controls, "anomaly-detection").Status)
	// Retention unconfigured is "not configured", not a hard gap.
	assert.Equal(t, ControlStatusNotConfigured, findControl(t, controls, "data-retention").Status)
}

// TestEvaluateControls_EmergencyAccessGapsOnUnreviewedActivation is #2461
// round 2's proving test: an unreviewed break-glass activation past the
// review window used to be purely informational on this control (Status
// hard-coded to never gap) --
// INV-CORE-break-glass-unreviewed-reported-never-blocks-activation requires
// it to surface as a real Gap, not just a number in Detail nobody is forced
// to notice.
func TestEvaluateControls_EmergencyAccessGapsOnUnreviewedActivation(t *testing.T) {
	t.Parallel()
	clean := &CompliancePosture{EmergencyAccess: EmergencyAccessPosture{ActiveActivations: 1, TotalActivations: 3}}
	assert.Equal(t, ControlStatusPass, findControl(t, EvaluateControls(clean), "emergency-access").Status)

	unreviewed := &CompliancePosture{EmergencyAccess: EmergencyAccessPosture{TotalActivations: 3, UnreviewedActivations: 1}}
	gapped := findControl(t, EvaluateControls(unreviewed), "emergency-access")
	assert.Equal(t, ControlStatusGap, gapped.Status)
	assert.Contains(t, gapped.Detail, "1 unreviewed")
}

// TestEvaluateControls_EmergencyAccessIndependentReviewerGapsWithOneAdmin is
// INV-CORE-break-glass-independent-review-impossible-is-visible's proving
// test: a deployment where independent review is
// structurally impossible must gap on its OWN distinct control, regardless
// of whether any activation is currently unreviewed.
func TestEvaluateControls_EmergencyAccessIndependentReviewerGapsWithOneAdmin(t *testing.T) {
	t.Parallel()
	possible := &CompliancePosture{EmergencyAccess: EmergencyAccessPosture{IndependentReviewImpossible: false}}
	passC := findControl(t, EvaluateControls(possible), "emergency-access-independent-reviewer")
	assert.Equal(t, ControlStatusPass, passC.Status)

	impossible := &CompliancePosture{EmergencyAccess: EmergencyAccessPosture{IndependentReviewImpossible: true}}
	gapC := findControl(t, EvaluateControls(impossible), "emergency-access-independent-reviewer")
	assert.Equal(t, ControlStatusGap, gapC.Status)
	assert.Contains(t, gapC.Detail, "independent post-activation review is not currently possible")
}

// #396: the data-classification control must fold ALL FOUR classifiable surfaces —
// static secrets, dynamic-secret configs, machine identities, and machine-token
// credentials — into its pass/fail decision, not just static secrets. A deployment
// with a perfectly-classified secret store but a pile of unclassified dynamic
// configs / machine identities / machine credentials must report a Gap, never a
// false Pass.
func TestEvaluateControls_DataClassification_NonSecretSurfaces(t *testing.T) {
	t.Parallel()
	// Zero unclassified STATIC secrets, but each of the other three surfaces has an
	// unclassified item.
	p := &CompliancePosture{
		Classification: ClassificationPosture{
			TotalSecrets: 10, Unclassified: 0,
			DynamicConfigs:     ClassificationCounts{Total: 5, Unclassified: 2},
			MachineIdentities:  ClassificationCounts{Total: 3, Unclassified: 1},
			MachineCredentials: ClassificationCounts{Total: 4, Unclassified: 1},
		},
	}
	controls := EvaluateControls(p)
	dc := findControl(t, controls, "data-classification")
	assert.Equal(t, ControlStatusGap, dc.Status, "unclassified dynamic-configs/machine-identities/machine-credentials must gap the control even with 0 unclassified static secrets")
	assert.Contains(t, dc.Detail, "4 of 22 classifiable items unclassified")
	assert.Contains(t, dc.Detail, "secrets/dynamic-configs/machine-identities/machine-credentials")

	// Fully clean across every surface stays Pass.
	clean := EvaluateControls(&CompliancePosture{
		Classification: ClassificationPosture{
			TotalSecrets:       10,
			DynamicConfigs:     ClassificationCounts{Total: 5},
			MachineIdentities:  ClassificationCounts{Total: 3},
			MachineCredentials: ClassificationCounts{Total: 4},
		},
	})
	dcClean := findControl(t, clean, "data-classification")
	assert.Equal(t, ControlStatusPass, dcClean.Status)
}

// Every ENS reference is a well-formed RD 311/2022 measure code: it names one of the
// three measure frameworks (org. / op. / mp.) so the matrix can't carry a typo'd or
// stray code that an auditor would reject.
func TestEvaluateControls_ENSMeasureCodesWellFormed(t *testing.T) {
	t.Parallel()
	controls := EvaluateControls(&CompliancePosture{})
	validPrefix := func(code string) bool {
		for _, p := range []string{"org.", "op.", "mp."} {
			if strings.HasPrefix(code, p) {
				return true
			}
		}
		return false
	}
	for _, c := range controls {
		for _, code := range c.Frameworks.ENS {
			assert.True(t, validPrefix(code),
				"control %s has ENS code %q outside the org./op./mp. frameworks", c.ID, code)
		}
	}
}

func TestGetComplianceControls_SummaryTallies(t *testing.T) {
	t.Parallel()
	c, _, _ := newEvidenceExportCore(t) // real in-memory store, empty deployment
	got, err := c.GetComplianceControls(context.Background())
	require.NoError(t, err)
	assert.Equal(t, len(got.Controls), got.Summary.Total)
	assert.Equal(t, got.Summary.Total, got.Summary.Pass+got.Summary.Gap+got.Summary.NotConfigured+got.Summary.Unknown+got.Summary.PartiallyEvaluated)
	assert.False(t, got.GeneratedAt.IsZero())
}

// The supply-chain-integrity control reflects whether updates are verified against a
// pinned signing key: a signed release passes; an unsigned/source build is "not
// configured" (the control doesn't apply), never a gap.
func TestEvaluateControls_SupplyChainIntegrity(t *testing.T) {
	t.Parallel()
	signed := EvaluateControls(&CompliancePosture{
		SupplyChain: SupplyChainPosture{UpdateSigningTrusted: true, TrustedUpdateKeys: 1, LicenseState: "active", LicenseValid: true},
	})
	sc := findControl(t, signed, "supply-chain-integrity")
	assert.Equal(t, ControlStatusPass, sc.Status)
	assert.Contains(t, sc.Detail, "1 pinned signing key")
	assert.Contains(t, sc.Frameworks.NIS2, "Art.21(2)(d)")

	unsigned := EvaluateControls(&CompliancePosture{SupplyChain: SupplyChainPosture{}})
	scu := findControl(t, unsigned, "supply-chain-integrity")
	assert.Equal(t, ControlStatusNotConfigured, scu.Status)
	assert.NotEqual(t, ControlStatusGap, scu.Status)
}

// #397: certificate-expiry scanning (ADR-055) is opt-in/off by default. With it
// disabled, not a single certificate has ever been evaluated, so the control must read
// as not-configured — never a permanent, unearned "pass" just because Expired stayed 0.
func TestEvaluateControls_CertificateHygiene_ScanningNeverEnabled(t *testing.T) {
	t.Parallel()
	// No certificate secrets at all: trivially nothing to evaluate.
	none := EvaluateControls(&CompliancePosture{})
	cn := findControl(t, none, "certificate-hygiene")
	assert.Equal(t, ControlStatusNotConfigured, cn.Status)
	assert.NotEqual(t, ControlStatusPass, cn.Status)

	// Certificate-typed secrets exist, but the scan has never parsed one of them
	// (CertNotAfter cache is empty for every one) — still not-configured, not pass.
	unscanned := EvaluateControls(&CompliancePosture{
		Certificates: CertificatePosture{TotalCertificates: 3, NotEvaluated: 3},
	})
	cu := findControl(t, unscanned, "certificate-hygiene")
	assert.Equal(t, ControlStatusNotConfigured, cu.Status)
	assert.NotEqual(t, ControlStatusPass, cu.Status)
	assert.Contains(t, cu.Detail, "not enabled")
}

// #395: a risk exception is a governed, time-bound acceptance of a control gap — once
// it expires without renewal or revocation, the risk it was excepting is unmitigated
// again. Zero exceptions, or exceptions that are all current, must pass; any
// expired-but-not-yet-revoked exception must surface as a gap naming the count.
func TestEvaluateControls_RiskExceptionHygiene(t *testing.T) {
	t.Parallel()
	none := EvaluateControls(&CompliancePosture{})
	rn := findControl(t, none, "risk-exception-hygiene")
	assert.Equal(t, ControlStatusPass, rn.Status)

	current := EvaluateControls(&CompliancePosture{
		Risk: RiskPosture{ActiveExceptions: 2, ExpiringSoon: 1, Expired: 0},
	})
	rc := findControl(t, current, "risk-exception-hygiene")
	assert.Equal(t, ControlStatusPass, rc.Status, "all-current exceptions must not gap the control")

	stale := EvaluateControls(&CompliancePosture{
		Risk: RiskPosture{ActiveExceptions: 1, Expired: 3},
	})
	rs := findControl(t, stale, "risk-exception-hygiene")
	assert.Equal(t, ControlStatusGap, rs.Status)
	assert.Contains(t, rs.Detail, "3 expired but not yet revoked/renewed")

	// A degraded expired-exception collection must surface as unknown, never a false
	// pass just because Expired's zero value looks clean (#136).
	degraded := EvaluateControls(&CompliancePosture{
		DegradedReasons: []string{"risk: simulated db failure"},
	})
	rd := findControl(t, degraded, "risk-exception-hygiene")
	assert.Equal(t, ControlStatusUnknown, rd.Status)
}

// #767 added AccessRequestPosture (dual-control access-request/approval workflow,
// ADR-024/#257) to the posture, but nothing evaluated it as a control. A request
// that lapses (expires) with no explicit approve/reject/withdraw decision is the
// same shape of gap as #395's stale risk exceptions: zero requests, or requests that
// were all explicitly resolved, must pass; any expired-but-unresolved request must
// surface as a gap naming the count.
func TestEvaluateControls_AccessRequestHygiene(t *testing.T) {
	t.Parallel()
	none := EvaluateControls(&CompliancePosture{})
	an := findControl(t, none, "access-request-hygiene")
	assert.Equal(t, ControlStatusPass, an.Status)

	resolved := EvaluateControls(&CompliancePosture{
		AccessRequests: AccessRequestPosture{TotalRequests: 5, Approved: 3, Rejected: 1, Withdrawn: 1, RequiredApprovals: 2},
	})
	ar := findControl(t, resolved, "access-request-hygiene")
	assert.Equal(t, ControlStatusPass, ar.Status, "all-resolved requests must not gap the control")

	lapsed := EvaluateControls(&CompliancePosture{
		AccessRequests: AccessRequestPosture{TotalRequests: 4, Pending: 1, Expired: 3, RequiredApprovals: 1},
	})
	al := findControl(t, lapsed, "access-request-hygiene")
	assert.Equal(t, ControlStatusGap, al.Status)
	assert.Contains(t, al.Detail, "3 expired without resolution")
	assert.Contains(t, al.Detail, "1 pending of 4 total request(s)")
	assert.Contains(t, al.Detail, "required approvers=1")

	// A degraded access-request collection must surface as unknown, never a false
	// pass just because Expired's zero value looks clean (#136).
	degraded := EvaluateControls(&CompliancePosture{
		DegradedReasons: []string{"access_requests:project=1: simulated db failure"},
	})
	ad := findControl(t, degraded, "access-request-hygiene")
	assert.Equal(t, ControlStatusUnknown, ad.Status)
}

// Once the scan has evaluated at least one certificate, the control reflects the real
// data: pass when none are expired, gap when at least one is.
func TestEvaluateControls_CertificateHygiene_ScanningEnabled(t *testing.T) {
	t.Parallel()
	healthy := EvaluateControls(&CompliancePosture{
		Certificates: CertificatePosture{TotalCertificates: 2, ExpiringSoon: 0, Expired: 0, NotEvaluated: 0},
	})
	ch := findControl(t, healthy, "certificate-hygiene")
	assert.Equal(t, ControlStatusPass, ch.Status)

	expired := EvaluateControls(&CompliancePosture{
		Certificates: CertificatePosture{TotalCertificates: 2, Expired: 1, NotEvaluated: 0},
	})
	ce := findControl(t, expired, "certificate-hygiene")
	assert.Equal(t, ControlStatusGap, ce.Status)

	// Partially scanned (some evaluated, some not) uses real data rather than
	// falling back to not-configured, since the scan clearly IS enabled here --
	// but it is NOT Pass (corrected 2026-09-07): this test previously asserted
	// Pass for this exact case, which was the bug this fix closes -- an
	// unevaluated certificate is a genuine unknown, not an implicit pass. See
	// TestCertificateHygieneControl_MixedEvaluationIsNotPass for the dedicated
	// regression.
	partial := EvaluateControls(&CompliancePosture{
		Certificates: CertificatePosture{TotalCertificates: 3, Expired: 0, NotEvaluated: 1},
	})
	cp := findControl(t, partial, "certificate-hygiene")
	assert.Equal(t, ControlStatusPartiallyEvaluated, cp.Status)
	assert.Contains(t, cp.Detail, "1 not yet evaluated")
}
