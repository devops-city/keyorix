package core

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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

// A save carrying an older generation that lands after a newer one (a status reader
// that loaded generation N without the lock and publishes after a concurrent save of
// N+1 recorded a failure) must not lower the failure gauge and mask the tamper page.
// Serial for the same reason as the test above: the gauges are process-global.
func TestAuditVerifyMetrics_StalePublishCannotLowerFailureGauge(t *testing.T) {
	c, _, clk := newIncrementalTestCore(t, 4)
	ctx := context.Background()
	t.Cleanup(func() {
		auditVerifyFailureRecorded.Set(0)
		auditVerifyStateRejected.Set(0)
	})

	require.NoError(t, c.saveAuditVerifyState(ctx, &auditVerifyState{Gen: 2,
		Failure: &auditVerifyFailure{DetectedAt: clk.t, Gen: 2, Source: "test", Reason: "break"}}))
	require.Equal(t, float64(1), testutil.ToFloat64(auditVerifyFailureRecorded))

	// The late generation 1 (no failure) must not overwrite it.
	require.NoError(t, c.saveAuditVerifyState(ctx, &auditVerifyState{Gen: 1}))
	assert.Equal(t, float64(1), testutil.ToFloat64(auditVerifyFailureRecorded),
		"a stale (older generation) publish must not lower the failure gauge")

	// A newer generation that cleared the failure legitimately lowers it.
	require.NoError(t, c.saveAuditVerifyState(ctx, &auditVerifyState{Gen: 3}))
	assert.Equal(t, float64(0), testutil.ToFloat64(auditVerifyFailureRecorded),
		"a newer generation without the failure clears the gauge")
}

// An untrusted (replayed or rolled-back) row keeps its sticky Failure, so loading it
// must raise the failure gauge, and a later clean run must not clear a failure that
// is still present in what the process reads.
func TestAuditVerifyMetrics_UntrustedRowWithStickyFailureRaisesGauge(t *testing.T) {
	c, _, clk := newIncrementalTestCore(t, 4)
	ctx := context.Background()
	t.Cleanup(func() {
		auditVerifyFailureRecorded.Set(0)
		auditVerifyStateRejected.Set(0)
	})

	require.NoError(t, c.saveAuditVerifyState(ctx, &auditVerifyState{Gen: 5,
		Failure: &auditVerifyFailure{DetectedAt: clk.t, Gen: 5, Source: "test", Reason: "break"}}))

	// This process has since seen a newer generation, so the stored row is a replay:
	// untrusted, but its failure is kept.
	auditVerifyFailureRecorded.Set(0)
	c.bumpAuditVerifyGen(9)
	st, reason, err := c.loadAuditVerifyState(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, reason, "the row must be untrusted")
	require.NotNil(t, st.Failure)
	assert.Equal(t, float64(1), testutil.ToFloat64(auditVerifyStateRejected))
	assert.Equal(t, float64(1), testutil.ToFloat64(auditVerifyFailureRecorded),
		"an untrusted row carrying a sticky failure must raise the failure gauge")
}

const freshGaugesChildEnv = "KEYORIX_TEST_AUDIT_VERIFY_FRESH_GAUGES_CHILD"

// A fresh process must report the two flag gauges as unknown (NaN), not 0, until it
// has read the persisted state. The gauges are process-global, so no in-process test
// can see their starting value once any other test has written them: the test
// re-executes the test binary running only this test, and the child reads the REAL
// gauges, as exported on the protected registry, with nothing else having touched them.
func TestAuditVerifyMetrics_FreshProcessStartsUnknown(t *testing.T) {
	if os.Getenv(freshGaugesChildEnv) == "1" {
		fams, err := protectedmetrics.Registry.Gather()
		require.NoError(t, err)
		for _, mf := range fams {
			switch mf.GetName() {
			case "keyorix_audit_verify_failure_recorded", "keyorix_audit_verify_state_rejected":
				fmt.Printf("FRESH_GAUGE %s %v\n", mf.GetName(), mf.GetMetric()[0].GetGauge().GetValue())
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditVerifyMetrics_FreshProcessStartsUnknown$", "-test.count=1")
	cmd.Env = append(os.Environ(), freshGaugesChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child process output:\n%s", out)
	got := map[string]string{}
	for line := range strings.SplitSeq(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "FRESH_GAUGE" {
			got[f[1]] = f[2]
		}
	}
	require.Len(t, got, 2, "the child must report both gauges, output:\n%s", out)
	assert.Equal(t, "NaN", got["keyorix_audit_verify_failure_recorded"],
		"a fresh process must report the failure flag as unknown, not 0")
	assert.Equal(t, "NaN", got["keyorix_audit_verify_state_rejected"],
		"a fresh process must report the rejected flag as unknown, not 0")
}

// A restart must not read as "no break recorded" until the first checkpoint tick,
// which AuditCheckpointFirstTickDelay defers by up to one interval (24 h by default):
// the startup publish restores the persisted sticky failure into gauges that start
// unknown (the starting value itself is proven by TestAuditVerifyMetrics_FreshProcessStartsUnknown;
// here the gauges are only put back to it). Serial: the gauges are process-global.
func TestAuditVerifyMetrics_RestartRepublishesStickyFailure(t *testing.T) {
	c, db, clk := newIncrementalTestCore(t, 4)
	ctx := context.Background()
	t.Cleanup(func() {
		auditVerifyFailureRecorded.Set(0)
		auditVerifyStateRejected.Set(0)
	})
	require.NoError(t, c.saveAuditVerifyState(ctx, &auditVerifyState{Gen: 3,
		Failure: &auditVerifyFailure{DetectedAt: clk.t, Gen: 3, Source: "test", Reason: "break"}}))
	require.Equal(t, float64(1), testutil.ToFloat64(auditVerifyFailureRecorded))

	// Restart: a new process over the same database, gauges at their initial value.
	auditVerifyFailureRecorded.Set(math.NaN())
	auditVerifyStateRejected.Set(math.NaN())
	restarted := NewKeyorixCore(store.NewLocalStorage(db))
	restarted.now = c.now
	restarted.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")

	require.NoError(t, restarted.PublishAuditVerifyState(ctx))
	assert.Equal(t, float64(1), testutil.ToFloat64(auditVerifyFailureRecorded),
		"the startup publish must restore the persisted sticky failure")
	assert.Equal(t, float64(0), testutil.ToFloat64(auditVerifyStateRejected))
}
