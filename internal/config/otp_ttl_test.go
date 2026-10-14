package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// OTP-EXPIRY-1: one-time-password lifetimes. There is deliberately no value that
// means "never expires": empty, garbage, zero and negative all give the default.
func TestSecurityConfig_OneTimePasswordExpiries(t *testing.T) {
	cases := map[string]struct {
		recovery, otp         string
		wantRecovery, wantOTP time.Duration
	}{
		"unset":             {"", "", 24 * time.Hour, 72 * time.Hour},
		"configured":        {"2h", "168h", 2 * time.Hour, 168 * time.Hour},
		"garbage":           {"tomorrow", "soon", 24 * time.Hour, 72 * time.Hour},
		"zero is not never": {"0", "0s", 24 * time.Hour, 72 * time.Hour},
		"negative":          {"-1h", "-5m", 24 * time.Hour, 72 * time.Hour},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := config.SecurityConfig{RecoveryOneTimePasswordExpiry: tc.recovery, OneTimePasswordExpiry: tc.otp}
			assert.Equal(t, tc.wantRecovery, s.GetRecoveryOneTimePasswordExpiry())
			assert.Equal(t, tc.wantOTP, s.GetOneTimePasswordExpiry())
		})
	}
}

func TestSecurityConfig_OneTimePasswordExpiries_YAMLKeys(t *testing.T) {
	var cfg struct {
		Security config.SecurityConfig `yaml:"security"`
	}
	doc := "security:\n  recovery_one_time_password_ttl: 12h\n  one_time_password_ttl: 48h\n"
	assert.NoError(t, yaml.Unmarshal([]byte(doc), &cfg))
	assert.Equal(t, 12*time.Hour, cfg.Security.GetRecoveryOneTimePasswordExpiry())
	assert.Equal(t, 48*time.Hour, cfg.Security.GetOneTimePasswordExpiry())
}

// internal/config cannot import internal/core, so the defaults are declared twice;
// this keeps them in step.
func TestOneTimePasswordExpiryDefaults_MatchCore(t *testing.T) {
	assert.Equal(t, core.DefaultRecoveryOneTimePasswordExpiry, config.DefaultRecoveryOneTimePasswordExpiry)
	assert.Equal(t, core.DefaultOneTimePasswordExpiry, config.DefaultOneTimePasswordExpiry)
}
