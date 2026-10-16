package solewriter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gatherValues(t *testing.T) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(newMetricsCollector())
	fams, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, mf := range fams {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			for _, lp := range m.GetLabel() {
				key += "{" + lp.GetName() + "=" + lp.GetValue() + "}"
			}
			if m.GetGauge() != nil {
				out[key] = m.GetGauge().GetValue()
			} else {
				out[key] = m.GetCounter().GetValue()
			}
		}
	}
	return out
}

func TestMetrics_DisabledReportsEnabledZeroOnly(t *testing.T) {
	restore := SetCurrentForTest(nil)
	defer restore()
	got := gatherValues(t)
	assert.Equal(t, map[string]float64{"keyorix_single_writer_enabled": 0}, got)
}

func TestMetrics_ConfirmingGuardIsOneHot(t *testing.T) {
	restore := SetCurrentForTest(GuardForTest("poll failed"))
	defer restore()
	got := gatherValues(t)
	assert.Equal(t, 1.0, got["keyorix_single_writer_enabled"])
	assert.Equal(t, 1.0, got["keyorix_single_writer_state{state=confirming}"])
	assert.Equal(t, 0.0, got["keyorix_single_writer_state{state=authoritative}"])
	assert.Equal(t, 0.0, got["keyorix_single_writer_state{state=settling}"])
	assert.Contains(t, got, "keyorix_single_writer_last_poll_age_seconds")
	assert.Contains(t, got, "keyorix_single_writer_unattributed_bumps_total")
}

func TestMetrics_CollectorIsLintClean(t *testing.T) {
	problems, err := testutil.CollectAndLint(newMetricsCollector())
	require.NoError(t, err)
	assert.Empty(t, problems)
}
