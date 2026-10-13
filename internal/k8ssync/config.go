package k8ssync

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// Config is the Keyorix Kubernetes sync agent's configuration: where the Keyorix
// server is, how often to reconcile, and which secrets map to which Kubernetes
// Secrets. The Keyorix auth token is NOT part of this file — it is read from the
// KEYORIX_TOKEN environment variable so it can come from a mounted Secret.
type Config struct {
	KeyorixURL string `yaml:"keyorix_url"`
	// ProjectID is the numeric id of the single Keyorix project this agent's
	// machine-identity token belongs to (a MachineIdentity — and so its tokens — is
	// always scoped to exactly one project). Every mapping's Ref names only an
	// environment and a secret ("<environment>/<name>"), never a project, because
	// environment names are unique per-project, not globally: two different
	// projects can each have a "production" environment. Without ProjectID pinning
	// every secret lookup to this one project server-side, the fetcher would have
	// to search across every project/environment the token can see and could
	// return a same-named secret from the WRONG project (#Bug1). Required.
	ProjectID  uint   `yaml:"project_id"`
	Interval   string `yaml:"interval"`    // Go duration (e.g. "5m"); default 5m
	HealthPort int    `yaml:"health_port"` // probe/status HTTP port; default 8080
	Cleanup    bool   `yaml:"cleanup"`     // reap orphaned owned Secrets; default false
	// PruneOnRevoke gates WithPruneOnRevoke/WithKeepOnRevoke (see their doc
	// comments) — whether a confirmed-gone/revoked upstream reference actually
	// removes/trims its target Secret, vs. leaving it untouched. Defaults to true
	// (wipe — the secure default restored 2026-09-25, coordinator inbox item 1)
	// when unset. Distinct from Cleanup above, which reaps Secrets for mappings
	// REMOVED FROM THIS CONFIG; this instead governs mappings still IN the config
	// whose upstream Keyorix value became inaccessible.
	//
	// A tri-state (*bool, not bool) is required: a plain bool's zero value (the
	// field simply omitted from YAML) would be indistinguishable from an explicit
	// `prune_on_revoke: false`, silently defaulting every new deployment to Keep
	// instead of the secure default. nil means "unset — use the default";
	// non-nil is always an explicit, deliberate choice. See GetPruneOnRevoke.
	PruneOnRevoke *bool `yaml:"prune_on_revoke"`
	// MassPruneAck acknowledges the mass-revocation circuit breaker (K8S track
	// coordinator inbox item 1): an RFC3339 timestamp, valid for massPruneAckWindow
	// after it's set. When the breaker trips (more than one target, more than 20%
	// of all managed targets, confirmed gone/revoked in the SAME reconcile pass —
	// see massRevocationTripped), none of them are wiped/trimmed even with
	// PruneOnRevoke true, until this ack is present and recent. Leave unset in
	// normal operation; set it only in direct response to an observed
	// mass-revocation alert (the "MASS REVOCATION SUSPECTED" log line / the
	// suspected metric/status count), then unset it again once resolved — a
	// permanently-set ack defeats the breaker for every future incident, not just
	// this one.
	// OnSuspend is what happens to a target Secret while a referenced Keyorix secret is
	// SUSPENDED (an operator's "block value reads" switch; the server answers 409
	// SecretSuspended): "retain" (the default when unset) leaves the target Secret
	// exactly as it is; "clear" empties the keys this agent manages in it (the Secret
	// object is never deleted, and a Secret the agent does not own is never touched).
	// Resuming restores the data on the next pass in both modes. An EXPIRED source is
	// always retained. Fetch failures (server unreachable, timeouts, 5xx) never modify the
	// target in either mode. See GetOnSuspend.
	OnSuspend        string `yaml:"on_suspend"`
	MassPruneAck     string `yaml:"mass_prune_ack"`
	massPruneAckTime time.Time
	Mappings         []SecretMapping `yaml:"mappings"`
}

// GetPruneOnRevoke returns whether a confirmed-gone/revoked upstream reference
// should actually wipe/trim its target Secret, defaulting to true (the secure
// default) when PruneOnRevoke is unset in the config file.
func (c *Config) GetPruneOnRevoke() bool {
	if c.PruneOnRevoke == nil {
		return true
	}
	return *c.PruneOnRevoke
}

// Values of Config.OnSuspend.
const (
	OnSuspendRetain = "retain"
	OnSuspendClear  = "clear"
)

// GetOnSuspend returns the normalized on_suspend setting: OnSuspendRetain when unset.
func (c *Config) GetOnSuspend() string {
	if strings.TrimSpace(c.OnSuspend) == "" {
		return OnSuspendRetain
	}
	return strings.ToLower(strings.TrimSpace(c.OnSuspend))
}

// GetMassPruneAck returns the parsed mass_prune_ack timestamp (set by validate),
// or the zero Time if unset — a zero Time never satisfies massPruneAckValid.
func (c *Config) GetMassPruneAck() time.Time {
	return c.massPruneAckTime
}

const defaultSyncInterval = 5 * time.Minute

// LoadConfig reads and validates the agent config at path.
func LoadConfig(path string) (*Config, error) {
	raw, err := secretenv.ReadRegularFile("config", path) // operator-provided config path; a FIFO is refused, not waited on
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.KeyorixURL) == "" {
		return fmt.Errorf("keyorix_url is required")
	}
	// The agent sends the machine-identity token (KEYORIX_TOKEN) as a Bearer header on
	// every request, so keyorix_url MUST be https (http only for loopback in dev) — an
	// http endpoint would ship a secrets-read-capable token in cleartext over the cluster
	// network. The operator (CRD) path already requires https; this matches it.
	if err := validateKeyorixURL(c.KeyorixURL); err != nil {
		return err
	}
	if c.ProjectID == 0 {
		return fmt.Errorf("project_id is required")
	}
	if len(c.Mappings) == 0 {
		return fmt.Errorf("at least one mapping is required")
	}
	for i, m := range c.Mappings {
		if err := validateMapping(m); err != nil {
			return fmt.Errorf("mapping %d: %w", i, err)
		}
	}
	if c.Interval != "" {
		if _, err := time.ParseDuration(c.Interval); err != nil {
			return fmt.Errorf("invalid interval %q: %w", c.Interval, err)
		}
	}
	if g := c.GetOnSuspend(); g != OnSuspendRetain && g != OnSuspendClear {
		return fmt.Errorf("invalid on_suspend %q: must be %q or %q", c.OnSuspend, OnSuspendRetain, OnSuspendClear)
	}
	if c.MassPruneAck != "" {
		t, err := time.Parse(time.RFC3339, c.MassPruneAck)
		if err != nil {
			return fmt.Errorf("invalid mass_prune_ack %q: must be an RFC3339 timestamp: %w", c.MassPruneAck, err)
		}
		c.massPruneAckTime = t
	}
	return nil
}

// validateKeyorixURL rejects a keyorix_url that is not https (http is allowed only for a
// loopback host, for local development/testing).
func validateKeyorixURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid keyorix_url %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		// K8SSYNC-007: only the hostname "localhost" is allowed over http, not any
		// loopback IP — an attacker who controls DNS can map a loopback IP to a
		// hostname of their choosing, so accepting raw IPs widens the bypass surface.
		return fmt.Errorf("keyorix_url %q must use https (http is allowed only for localhost); sending the bearer token over plaintext would expose it", raw)
	default:
		return fmt.Errorf("keyorix_url %q must use https", raw)
	}
}

// GetInterval returns the reconcile interval, defaulting to 5m when unset.
func (c *Config) GetInterval() time.Duration {
	if c.Interval != "" {
		if d, err := time.ParseDuration(c.Interval); err == nil && d > 0 {
			return d
		}
	}
	return defaultSyncInterval
}

const defaultHealthPort = 8080

// GetHealthPort returns the health/probe HTTP port, defaulting to 8080 when unset.
func (c *Config) GetHealthPort() int {
	if c.HealthPort > 0 {
		return c.HealthPort
	}
	return defaultHealthPort
}
