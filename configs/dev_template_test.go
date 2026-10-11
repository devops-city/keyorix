package configs

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDevConfigTemplate: every replacement applies (DevConfigTemplate errors
// otherwise), the result is labelled DEV-ONLY, parses, and relaxes exactly the
// three settings it names while the default template keeps them secure.
func TestDevConfigTemplate(t *testing.T) {
	dev, err := DevConfigTemplate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(dev), "# ======") || !strings.Contains(string(dev)[:400], "DEV-ONLY CONFIG") {
		t.Fatal("the --dev config does not open with the DEV-ONLY banner")
	}
	if strings.Contains(string(DefaultConfigTemplate), "DEV-ONLY") {
		t.Fatal("the default (secure) template mentions DEV-ONLY")
	}

	type listener struct {
		TLS struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"tls"`
		RateLimit struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"ratelimit"`
		MetricsTokenFile string `yaml:"metrics_token_file"`
	}
	type doc struct {
		Server struct {
			HTTP listener `yaml:"http"`
			GRPC listener `yaml:"grpc"`
		} `yaml:"server"`
		Security struct {
			RequireTransportTLS bool `yaml:"require_transport_tls"`
			RequireMFA          bool `yaml:"require_mfa"`
		} `yaml:"security"`
	}
	parse := func(b []byte) doc {
		var d doc
		if err := yaml.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}

	secure := parse(DefaultConfigTemplate)
	for name, l := range map[string]listener{"http": secure.Server.HTTP, "grpc": secure.Server.GRPC} {
		if !l.TLS.Enabled || !l.RateLimit.Enabled || l.MetricsTokenFile == "" {
			t.Errorf("default template server.%s: tls=%v ratelimit=%v metrics_token_file=%q, want all set", name, l.TLS.Enabled, l.RateLimit.Enabled, l.MetricsTokenFile)
		}
	}
	if !secure.Security.RequireTransportTLS || !secure.Security.RequireMFA {
		t.Error("default template must set require_transport_tls and require_mfa")
	}

	relaxed := parse(dev)
	for name, l := range map[string]listener{"http": relaxed.Server.HTTP, "grpc": relaxed.Server.GRPC} {
		if l.TLS.Enabled || l.RateLimit.Enabled || l.MetricsTokenFile != "" {
			t.Errorf("--dev server.%s: tls=%v ratelimit=%v metrics_token_file=%q, want all off", name, l.TLS.Enabled, l.RateLimit.Enabled, l.MetricsTokenFile)
		}
	}
	if relaxed.Security.RequireTransportTLS {
		t.Error("--dev config still requires transport TLS")
	}
	// --dev relaxes only what its banner names: MFA stays required (never require_mfa: false).
	if !relaxed.Security.RequireMFA {
		t.Error("--dev config turned off require_mfa")
	}
}
