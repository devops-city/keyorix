package core

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

// defaultGather lists the metric family names on the default (public) registry.
func defaultGather() ([]string, error) {
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(fams))
	for _, mf := range fams {
		names = append(names, mf.GetName())
	}
	return names, nil
}

// Deliberately NOT parallel: the gauges are process-global, and parallel tests are
// held back until the serial ones finish, so this one sees only its own writes.
func TestAuditVerifyMetrics_FollowThePersistedState(t *testing.T) {
	const segments = 4
	c, db, clk := newIncrementalTestCore(t, segments)
	logIncrEvents(t, c, clk, 40)
	tickOK(t, c)

	tail := auditVerifyLastSuccess.WithLabelValues(auditVerifyCheckTail)
	assert.InDelta(t, float64(clk.t.Unix()), testutil.ToFloat64(tail), 5, "a passing tail check stamps its success time")
	assert.Equal(t, float64(0), testutil.ToFloat64(auditVerifyFailureRecorded))
	assert.Equal(t, float64(0), testutil.ToFloat64(auditVerifyStateRejected))

	// A break the verification detects raises the failure flag. Row 3 is behind the
	// rolling cycle's first segment, so it is found within one cycle.
	tamperDescription(t, db, 3)
	for range segments + 1 {
		clk.advance()
		logIncrEvents(t, c, clk, 1)
		_, _ = c.RunAuditVerificationTick(context.Background())
	}
	assert.Equal(t, float64(1), testutil.ToFloat64(auditVerifyFailureRecorded),
		"a recorded verification failure must be visible to the alerting metric")
}

// TestAuditVerifyMetrics_AreNotOnThePublicEndpoint: these three must live on the
// protected registry only. An anonymous GET /metrics reader must not learn when an
// integrity check last passed or whether it found a break.
func TestAuditVerifyMetrics_AreNotOnThePublicEndpoint(t *testing.T) {
	protected := map[string]bool{}
	pf, err := protectedmetrics.Registry.Gather()
	require.NoError(t, err)
	for _, mf := range pf {
		protected[mf.GetName()] = true
	}
	for _, name := range []string{"keyorix_audit_verify_failure_recorded", "keyorix_audit_verify_state_rejected"} {
		assert.True(t, protected[name], "%s must be on the protected registry", name)
	}
	df, err := defaultGather()
	require.NoError(t, err)
	for _, name := range df {
		assert.NotContains(t, name, "keyorix_audit_verify_", "audit-verify metrics must not be on the default (public) registry")
	}
}
