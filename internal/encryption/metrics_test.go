package encryption

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

func stateSeries(t *testing.T, svc *Service) map[string]float64 {
	t.Helper()
	c := &stateCollector{svc: svc, state: stateMetrics.state, provider: stateMetrics.provider}
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	fams, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, mf := range fams {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			for _, lp := range m.GetLabel() {
				key += "{" + lp.GetValue() + "}"
			}
			out[key] = m.GetGauge().GetValue()
		}
	}
	return out
}

func TestStateMetric_DisabledUninitializedReady(t *testing.T) {
	disabled := NewService(&config.EncryptionConfig{Enabled: false}, t.TempDir())
	got := stateSeries(t, disabled)
	assert.Equal(t, 1.0, got["keyorix_encryption_state{disabled}"], "disabled encryption must be visible")
	assert.Equal(t, 0.0, got["keyorix_encryption_state{ready}"])

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, t.TempDir())
	got = stateSeries(t, svc)
	assert.Equal(t, 1.0, got["keyorix_encryption_state{uninitialized}"])
	assert.Equal(t, 1.0, got["keyorix_encryption_kek_provider_info{password}"])

	require.NoError(t, svc.Initialize("test-passphrase-obs1"))
	got = stateSeries(t, svc)
	assert.Equal(t, 1.0, got["keyorix_encryption_state{ready}"])
	assert.Equal(t, 0.0, got["keyorix_encryption_state{uninitialized}"])
}

// TestStateMetric_NoServiceButDisabledStillReports: a server with encryption off has
// no Service; RegisterDisabledMetrics must still make state=disabled visible.
func TestStateMetric_NoServiceButDisabledStillReports(t *testing.T) {
	c := &stateCollector{disabled: true, state: stateMetrics.state, provider: stateMetrics.provider}
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	fams, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, fams, 1)
	assert.Equal(t, "keyorix_encryption_state", fams[0].GetName())
	for _, m := range fams[0].GetMetric() {
		want := 0.0
		if m.GetLabel()[0].GetValue() == stateDisabled {
			want = 1
		}
		assert.Equal(t, want, m.GetGauge().GetValue(), m.GetLabel()[0].GetValue())
	}

	empty := &stateCollector{state: stateMetrics.state, provider: stateMetrics.provider}
	reg2 := prometheus.NewRegistry()
	reg2.MustRegister(empty)
	fams, err = reg2.Gather()
	require.NoError(t, err)
	assert.Empty(t, fams, "an unregistered service reports nothing rather than a guess")
}

func TestProviderLabelIsBounded(t *testing.T) {
	assert.Equal(t, "password", providerLabel(""))
	assert.Equal(t, "aws-kms", providerLabel("aws-kms"))
	assert.Equal(t, "other", providerLabel("attacker-chosen-"+t.Name()), "an unknown type must collapse to one series")
}

// TestOperationFailureMetric asserts the effect: a failing decrypt/encrypt moves
// the counter, a successful round trip does not.
func TestOperationFailureMetric(t *testing.T) {
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, t.TempDir())
	dec := opFailuresTotal.WithLabelValues(opDecrypt)
	enc := opFailuresTotal.WithLabelValues(opEncrypt)

	d0, e0 := testutil.ToFloat64(dec), testutil.ToFloat64(enc)
	_, _, err := svc.EncryptSecret([]byte("x")) // not initialised -> error
	require.Error(t, err)
	assert.Equal(t, e0+1, testutil.ToFloat64(enc))
	assert.Equal(t, d0, testutil.ToFloat64(dec))

	require.NoError(t, svc.Initialize("test-passphrase-obs1"))
	ct, _, err := svc.EncryptSecret([]byte("hello"))
	require.NoError(t, err)
	pt, err := svc.DecryptSecret(ct)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(pt))
	assert.Equal(t, e0+1, testutil.ToFloat64(enc), "success must not count")
	assert.Equal(t, d0, testutil.ToFloat64(dec))

	_, err = svc.DecryptSecret([]byte("not an encrypted blob"))
	require.Error(t, err)
	assert.Equal(t, d0+1, testutil.ToFloat64(dec))
}
