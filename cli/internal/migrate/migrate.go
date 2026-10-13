// Package migrate detects a server URL configured by the old, pre-ADR-108 CLI, so
// `keyorix login` can offer to reuse it instead of asking the operator to retype
// a URL they already have on this machine. It never reads or copies a CREDENTIAL --
// only a server URL. Silently copying the old CLI's stored API key would slip a
// possibly-already-revoked or stale secret into the new credential store without the
// operator ever seeing it happen, and the two credentials aren't even the same kind
// (a long-lived API key vs. this CLI's session token) -- so the operator authenticates
// fresh either way; this package only saves them from retyping a URL.
//
// Deliberately does not import internal/cli/config (forbidden by cli/'s depguard,
// ADR-108 Decision A) -- it re-implements the tiny subset of the old config shapes
// (docs/cli-split-inventory.md §4) needed to read one string field out of each.
package migrate

import (
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
	"gopkg.in/yaml.v3"
)

// Candidate is a server URL found in an old-CLI config file.
type Candidate struct {
	ServerURL string
	Source    string // absolute path this was found at, for the operator-facing prompt
}

// oldServerConfig mirrors the handful of fields this package reads out of
// ./keyorix.yaml -- the server's own config format, also written by the old CLI's
// `auth login --server`/`config set-remote` (docs/cli-split-inventory.md §4).
type oldServerConfig struct {
	Storage struct {
		Remote struct {
			BaseURL string `yaml:"base_url"`
		} `yaml:"remote"`
	} `yaml:"storage"`
}

// oldCLIConfig mirrors the handful of fields this package reads out of the old CLI's
// own connection-mode config (~/.keyorix/cli.yaml or $XDG_CONFIG_HOME/keyorix/cli.yaml).
type oldCLIConfig struct {
	Client struct {
		Endpoint string `yaml:"endpoint"`
	} `yaml:"client"`
}

// DetectOldServerURL looks for a server URL in either of the pre-ADR-108 CLI's two
// overlapping config files, preferring ./keyorix.yaml (the CWD-relative one `auth
// login`/`config set-remote` write, so it reflects the most recent explicit login)
// over the connection-mode ~/.keyorix/cli.yaml. Returns found=false if neither exists
// or neither has a server URL set.
func DetectOldServerURL() (Candidate, bool) {
	if c, ok := detectFromCWDConfig("keyorix.yaml"); ok {
		return c, true
	}
	if c, ok := detectFromCLIConfig(); ok {
		return c, true
	}
	return Candidate{}, false
}

func detectFromCWDConfig(path string) (Candidate, bool) {
	data, err := regularfile.ReadFile("old server config", path) // fixed CWD-relative filename, matches the old CLI's own behavior being migrated away from
	if err != nil {
		return Candidate{}, false
	}
	var cfg oldServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Candidate{}, false
	}
	if cfg.Storage.Remote.BaseURL == "" {
		return Candidate{}, false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return Candidate{ServerURL: cfg.Storage.Remote.BaseURL, Source: abs}, true
}

func detectFromCLIConfig() (Candidate, bool) {
	path := oldCLIConfigPath()
	if path == "" {
		return Candidate{}, false
	}
	data, err := regularfile.ReadFile("old CLI config", path) // path is derived from XDG/home-dir env vars, not user input
	if err != nil {
		return Candidate{}, false
	}
	var cfg oldCLIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Candidate{}, false
	}
	if cfg.Client.Endpoint == "" {
		return Candidate{}, false
	}
	return Candidate{ServerURL: cfg.Client.Endpoint, Source: path}, true
}

// oldCLIConfigPath reimplements the old CLI's getDefaultCLIConfigPath (unexported,
// internal/cli/config/cli_config.go) precedence: $XDG_CONFIG_HOME/keyorix/cli.yaml,
// else ~/.keyorix/cli.yaml, else "" (the old CLI's own last resort, a CWD-relative
// ./keyorix-cli.yaml, is intentionally not replicated here -- it is indistinguishable
// from an unrelated file an operator happens to have in the current directory).
func oldCLIConfigPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "keyorix", "cli.yaml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".keyorix", "cli.yaml")
	}
	return ""
}
