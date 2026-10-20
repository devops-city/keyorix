package startup

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestAppendSCIMJITPosture(t *testing.T) {
	cfg := &config.Config{}
	cfg.SCIM.Enabled = true
	cfg.SSO.Enabled = true
	cfg.SSO.Providers = []config.SSOProviderConfig{{Name: "okta", AutoProvision: true}}
	res := &ValidationResult{}
	appendSCIMJITPosture(cfg, res)
	assert.Equal(t, []string{config.SCIMJITUnmanagedWarning([]string{"okta"})}, res.Warnings)

	// only one of the two features: no warning
	cfg.SCIM.Enabled = false
	res = &ValidationResult{}
	appendSCIMJITPosture(cfg, res)
	assert.Empty(t, res.Warnings)
}
