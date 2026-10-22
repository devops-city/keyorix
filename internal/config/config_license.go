package config

import (
	"time"
)

// LicenseConfig points at an installed offline license token and tunes its evaluation
// (ADR-065). All fields are optional; an empty Path means no license is installed.
type LicenseConfig struct {
	// Path is the file holding the license token (as written by `keyorix license install`).
	Path string `yaml:"path"`
	// DeploymentID, when set, is checked against a license bound to a deployment; a
	// mismatch degrades to the baseline (it never shuts the server down).
	DeploymentID string `yaml:"deployment_id"`
	// GraceHours is the post-expiry tolerance window during which features are retained
	// (with a loud warning) so a lapse doesn't instantly drop entitlement. Default 336 (14d).
	GraceHours int `yaml:"grace_hours"`
}

// LicenseGrace returns the configured post-expiry grace window, defaulting to 14 days.
func (c *Config) LicenseGrace() time.Duration {
	if c.License.GraceHours <= 0 {
		return 14 * 24 * time.Hour
	}
	return time.Duration(c.License.GraceHours) * time.Hour
}
