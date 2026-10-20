// metrics.go — Prometheus view of the encryption service's state and failures.
//
// The server derives its KEK at start-up (it refuses to start if that fails), so
// there is no runtime seal/unseal transition to watch; what an operator needs is
//   - whether encryption is on and ready (a server running with encryption disabled
//     stores secrets in plaintext and must be alertable),
//   - which KEK source is configured (a weaker source than intended is a posture
//     problem),
//   - encrypt/decrypt failures (wrong key after a restore, corrupt rows, tampering),
//   - a runtime KEK-provider downgrade having actually fired.
//
// Label values are closed sets: state is one of three constants, op is
// encrypt|decrypt, provider is normalised to the known provider types.
package encryption

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/keyorixhq/keyorix/internal/protectedmetrics"
)

const (
	stateDisabled      = "disabled"
	stateUninitialized = "uninitialized"
	stateReady         = "ready"
)

const (
	opEncrypt = "encrypt"
	opDecrypt = "decrypt"
)

// knownProviders mirrors the cases of buildSingleProvider; anything else is "other"
// so a config typo can never mint a new series.
var knownProviders = map[string]bool{
	"password": true, "file": true, "env": true, "exec": true, "shamir": true,
	"tpm": true, "aws-kms": true, "gcp-kms": true, "azure-kms": true,
}

func providerLabel(t string) string {
	if t == "" {
		return "password"
	}
	if knownProviders[t] {
		return t
	}
	return "other"
}

// Everything in this file registers on internal/protectedmetrics, NOT the default
// registry: an anonymous GET /metrics reader must not learn that encryption is off,
// which KEK source is configured, that decrypts are failing or that the KEK chain
// downgraded. They are served at the authenticated /api/v1/admin/scheduler-metrics.
var (
	opFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "keyorix_encryption_operation_failures_total",
		Help: "Secret encrypt/decrypt operations that returned an error (including a service that was not initialised), by op (encrypt|decrypt). Decrypt failures after a restore or key change mean the wrong key or corrupt rows.",
	}, []string{"op"})

	kekDowngradesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "keyorix_encryption_kek_provider_downgrades_total",
		Help: "Times a configured KEK fallback chain actually fell back to a weaker provider at runtime.",
	})
)

func init() {
	protectedmetrics.MustRegister(opFailuresTotal, kekDowngradesTotal)
	opFailuresTotal.WithLabelValues(opEncrypt)
	opFailuresTotal.WithLabelValues(opDecrypt)
}

// noteOp counts a failed operation; called from a defer on the Service methods.
func noteOp(op string, err error) {
	if err != nil {
		opFailuresTotal.WithLabelValues(op).Inc()
	}
}

type stateCollector struct {
	mu       sync.RWMutex
	svc      *Service
	disabled bool // encryption is off in config; no Service exists

	state    *prometheus.Desc
	provider *prometheus.Desc
}

var stateMetrics = &stateCollector{
	state: prometheus.NewDesc(
		"keyorix_encryption_state",
		"Encryption service state, one series per state (disabled|uninitialized|ready) with value 1 for the current one. disabled means secrets are stored as plaintext.",
		[]string{"state"}, nil,
	),
	provider: prometheus.NewDesc(
		"keyorix_encryption_kek_provider_info",
		"Configured KEK source (password|file|env|exec|shamir|tpm|aws-kms|gcp-kms|azure-kms|other); always 1.",
		[]string{"provider"}, nil,
	),
}

func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.state
	ch <- c.provider
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	svc, disabled := c.svc, c.disabled
	c.mu.RUnlock()
	if svc == nil {
		if disabled {
			c.collectState(ch, stateDisabled)
		}
		return
	}
	cur := stateUninitialized
	switch {
	case !svc.IsEnabled():
		cur = stateDisabled
	case svc.IsInitialized():
		cur = stateReady
	}
	c.collectState(ch, cur)
	ch <- prometheus.MustNewConstMetric(c.provider, prometheus.GaugeValue, 1, providerLabel(svc.config.KeyProvider.Type))
}

func (c *stateCollector) collectState(ch chan<- prometheus.Metric, cur string) {
	for _, s := range []string{stateDisabled, stateUninitialized, stateReady} {
		v := 0.0
		if s == cur {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.state, prometheus.GaugeValue, v, s)
	}
}

var registerStateOnce sync.Once

// RegisterMetrics exposes svc's state on the protected registry. Call it once from
// the server after NewService; a later call replaces the observed service. CLI
// tools that build short-lived Services do not call it.
func RegisterMetrics(svc *Service) {
	registerStateOnce.Do(func() { protectedmetrics.MustRegister(stateMetrics) })
	stateMetrics.mu.Lock()
	stateMetrics.svc, stateMetrics.disabled = svc, false
	stateMetrics.mu.Unlock()
}

// RegisterDisabledMetrics reports keyorix_encryption_state{state="disabled"} 1 for a
// server that runs with storage.encryption.enabled=false (no Service exists then),
// so "encryption off in production" is alertable rather than merely absent.
func RegisterDisabledMetrics() {
	registerStateOnce.Do(func() { protectedmetrics.MustRegister(stateMetrics) })
	stateMetrics.mu.Lock()
	stateMetrics.svc, stateMetrics.disabled = nil, true
	stateMetrics.mu.Unlock()
}
