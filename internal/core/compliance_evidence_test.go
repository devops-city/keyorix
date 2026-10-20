// compliance_evidence_test.go — #362: GenerateComplianceEvidence independently
// re-queries several of the same signals GetCompliancePosture already rolled up
// (risk exceptions, SoD violations, rotation status, per-project campaigns/
// break-glass) rather than reusing the posture's result — so each of those had its
// OWN copy of the #136 fail-open bug shape. These tests pin that a query failure on
// the EVIDENCE PACK'S OWN copy of each query now flips ev.Posture.Degraded (via the
// shared posture.degrade helper) instead of silently leaving the archivable,
// timestamped evidence pack's slice at its pre-initialized empty value —
// indistinguishable from "queried, found genuinely none".
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #362: risk_exceptions — models.RiskException deliberately not migrated.
func TestGenerateComplianceEvidence_DegradesOnRiskExceptionsQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t)

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err, "a single failed evidence sub-query must not abort the whole pack")

	assert.Empty(t, ev.RiskExceptions, "the field itself still reads as its pre-initialized empty value")
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded, "a failed risk-exceptions query must flip the shared Degraded signal")
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:risk_exceptions"), "got %v", ev.Posture.DegradedReasons)
}

// #362: sod_violations — models.SoDPolicy deliberately not migrated.
func TestGenerateComplianceEvidence_DegradesOnSoDViolationsQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t)

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.SoDViolations)
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:sod_violations"), "got %v", ev.Posture.DegradedReasons)
}

// #362: rotation_overdue — models.RotationPolicy deliberately not migrated. Before the
// fix this was the permanently-archivable evidence pack's own copy of #358.
func TestGenerateComplianceEvidence_DegradesOnRotationOverdueQueryError(t *testing.T) {
	t.Parallel()
	c := compliancePostureCore(t)

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.RotationOverdue)
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:rotation_overdue"), "got %v", ev.Posture.DegradedReasons)
}

// #362: campaigns, per project — models.AccessReviewCampaign deliberately not migrated.
func TestGenerateComplianceEvidence_DegradesOnCampaignsQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.BreakGlassActivation{}, &models.UserRole{}, &models.Group{}, &models.GroupRole{}, &models.AuditEvent{}))

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.Campaigns)
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:campaigns:project=1"), "got %v", ev.Posture.DegradedReasons)
}

// #362: break-glass register, per project — models.BreakGlassActivation deliberately
// not migrated. The evidence pack's break-glass register hiding an active emergency
// activation is the most severe of this family.
func TestGenerateComplianceEvidence_DegradesOnBreakGlassQueryError(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreWithProject(t)
	require.NoError(t, db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.UserRole{}, &models.Group{}, &models.GroupRole{}, &models.AuditEvent{}))

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)

	assert.Empty(t, ev.BreakGlass, "the register must not silently read as empty (= no emergency access) on a query error")
	require.NotNil(t, ev.Posture)
	assert.True(t, ev.Posture.Degraded)
	assert.True(t, containsSubstring(ev.Posture.DegradedReasons, "evidence:break_glass:project=1"), "got %v", ev.Posture.DegradedReasons)
}

// divergingRiskExceptionsStore wraps LocalStorage and returns an EMPTY risk-exception
// list on its FIRST call, then the real (non-empty) rows on every call after —
// simulating a risk exception being created/approved CONCURRENTLY, landing in the gap
// between what used to be GetCompliancePosture's own read of the table and
// GenerateComplianceEvidence's independent re-read of the same table (#256). It also
// counts how many times the query actually ran, so a test can pin that the fix
// collapses what used to be several independent reads into one.
type divergingRiskExceptionsStore struct {
	calls int
}

func newDivergingRiskExceptionsStore(inner storage.Storage) (storage.Storage, *divergingRiskExceptionsStore) {
	s := &divergingRiskExceptionsStore{}
	return hooked(inner, &storeHooks{
		ListRiskExceptions: func(next storage.Storage, ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
			s.calls++
			rows, err := next.ListRiskExceptions(ctx, activeOnly)
			if err != nil || s.calls > 1 {
				return rows, err
			}
			// First read: report as if the exception hadn't landed yet — the state a second,
			// independently-timed pass would NOT have seen.
			return nil, nil
		},
	}), s
}

// #256: GenerateComplianceEvidence used to compute the posture via
// GetCompliancePosture, then independently re-query the SAME underlying signals a
// second time (risk exceptions among them) with no transaction or snapshot isolation
// between the two passes. A real concurrent write landing between them — here
// simulated by divergingRiskExceptionsStore returning a different result on its
// second call — could make the embedded Posture.Risk rollup and the evidence pack's
// own RiskExceptions field describe two DIFFERENT instants, even though both ship
// inside the one HMAC-signed pack an auditor trusts as a single atomic snapshot.
//
// The fix collapses the whole generation onto one shared complianceSnapshot fetched
// once at the top, so there is only one read left for divergingRiskExceptionsStore to
// serve — this test pins both (a) the underlying query now runs exactly once, and
// (b) the pack's two views of risk exceptions are therefore always mutually
// consistent, where before the fix they could diverge.
func TestGenerateComplianceEvidence_RiskExceptionsConsistentWithPostureAcrossConcurrentChange(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreDB(t)
	require.NoError(t, db.AutoMigrate(&models.RiskException{}))
	require.NoError(t, db.Create(&models.RiskException{
		Title: "accepted gap", Category: "other", Justification: "test",
		CreatedBy: 1, CreatedAt: c.now(), ExpiresAt: c.now().Add(30 * 24 * time.Hour),
	}).Error)

	wrapped, mock := newDivergingRiskExceptionsStore(c.storage)
	c.storage = wrapped

	ev, err := c.GenerateComplianceEvidence(context.Background())
	require.NoError(t, err)
	require.NotNil(t, ev.Posture)

	assert.Equal(t, 1, mock.calls, "the shared snapshot must read risk exceptions exactly once, not once per section that needs them")
	assert.Equal(t, len(ev.RiskExceptions), ev.Posture.Risk.ActiveExceptions,
		"the evidence pack's own risk-exceptions register and its embedded posture rollup must describe the SAME snapshot, not two independently-timed reads")
	assert.Empty(t, ev.RiskExceptions, "both views must reflect the FIRST read (pre-change) consistently, not a torn mix of before/after state")
	assert.Equal(t, 0, ev.Posture.Risk.ActiveExceptions)
}
