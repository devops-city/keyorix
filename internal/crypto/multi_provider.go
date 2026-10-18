package crypto

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

// MultiKeyProvider tries its providers in order, returning the KEK from the
// first that succeeds. If all fail it returns a wrapped error. An empty list
// is a configuration error.
type MultiKeyProvider struct {
	providers   []KeyProvider
	onDowngrade DowngradeHook
}

// DowngradeHook is called when KEK() actually falls back, at runtime, to a
// provider whose tier is weaker than the strongest tier seen earlier in the chain
// (see DetectFallbackDowngrade) — i.e. an ACTUAL downgrade occurrence for THIS KEK
// derivation, not merely a configuration that permits one. Set via
// SetDowngradeHook; nil (the default) means the event is only recorded via the
// loud "SECURITY:" log line KEK() always emits on a downgrading fallback.
type DowngradeHook func(d FallbackDowngrade)

// NewMultiKeyProvider creates a MultiKeyProvider. Returns error if list is empty.
func NewMultiKeyProvider(providers []KeyProvider) (*MultiKeyProvider, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("multi key provider: at least one provider is required")
	}
	return &MultiKeyProvider{providers: providers}, nil
}

// SetDowngradeHook wires an optional callback invoked whenever KEK() actually
// falls back to a weaker-tier provider. The loud "SECURITY:" log line in KEK()
// fires either way; a caller that has a queryable audit trail available (the
// encryption.Service does, once storage is up) should wire one here so the
// downgrade isn't only observable in logs.
func (m *MultiKeyProvider) SetDowngradeHook(hook DowngradeHook) {
	m.onDowngrade = hook
}

// Name returns "multi(p1,p2,...)" for logging/status output.
func (m *MultiKeyProvider) Name() string {
	names := make([]string, len(m.providers))
	for i, p := range m.providers {
		names[i] = p.Name()
	}
	return "multi(" + strings.Join(names, ",") + ")"
}

// KEK tries each provider in order. The first successful result is returned. If
// the provider that succeeds is weaker (see ProviderTier) than the strongest tier
// among the providers tried before it — e.g. a TPM/KMS-backed primary that failed
// and fell through to a password fallback — that is a REAL, live downgrade of this
// process's encryption strength, not just a permitted configuration shape. It is
// always logged loudly, and reported to onDowngrade if one is wired (see
// SetDowngradeHook), so a caller with a real audit trail available can record it
// as more than a log line.
func (m *MultiKeyProvider) KEK() ([]byte, error) {
	var errs []string
	maxTier := ProviderTierOf(m.providers[0].Name())
	for i, p := range m.providers {
		key, err := p.KEK()
		if err == nil {
			if len(m.providers) > 1 {
				log.Printf("key provider: %s succeeded", p.Name())
			}
			if tier := ProviderTierOf(p.Name()); i > 0 && tier < maxTier {
				d := FallbackDowngrade{Index: i, Provider: p.Name(), FromTier: maxTier, ToTier: tier}
				log.Printf("SECURITY: key provider fallback downgraded KEK strength: now using %q (%s) after an earlier, %s provider in the configured chain failed", p.Name(), tier, maxTier)
				if m.onDowngrade != nil {
					m.onDowngrade(d)
				}
			}
			return key, nil
		}
		// A configuration refusal, not an unavailable provider: falling through
		// to the next one would turn the refusal into a silent downgrade.
		if errors.Is(err, ErrKMSContextFallbackNotNeeded) {
			return nil, err
		}
		log.Printf("key provider: %s failed (%v), trying next", p.Name(), err)
		errs = append(errs, fmt.Sprintf("%s: %v", p.Name(), err))
		if t := ProviderTierOf(p.Name()); t > maxTier {
			maxTier = t
		}
	}
	return nil, fmt.Errorf("all key providers failed: %s", strings.Join(errs, "; "))
}
