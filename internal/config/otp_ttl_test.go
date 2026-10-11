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
func TestSecurityConfig_OneTimePasswordTTLs(t *testing.T) {
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
			s := config.SecurityConfig{RecoveryOneTimePasswordTTL: tc.recovery, OneTimePasswordTTL: tc.otp}
			assert.Equal(t, tc.wantRecovery, s.GetRecoveryOneTimePasswordTTL())
			assert.Equal(t, tc.wantOTP, s.GetOneTimePasswordTTL())
		})
	}
}

func TestSecurityConfig_OneTimePasswordTTLs_YAMLKeys(t *testing.T) {
	var cfg struct {
		Security config.SecurityConfig `yaml:"security"`
	}
	doc := "security:\n  recovery_one_time_password_ttl: 12h\n  one_time_password_ttl: 48h\n"
	assert.NoError(t, yaml.Unmarshal([]byte(doc), &cfg))
	assert.Equal(t, 12*time.Hour, cfg.Security.GetRecoveryOneTimePasswordTTL())
	assert.Equal(t, 48*time.Hour, cfg.Security.GetOneTimePasswordTTL())
}

// internal/config cannot import internal/core, so the defaults are declared twice;
// this keeps them in step.
func TestOneTimePasswordTTLDefaults_MatchCore(t *testing.T) {
	assert.Equal(t, core.DefaultRecoveryOneTimePasswordTTL, config.DefaultRecoveryOneTimePasswordTTL)
	assert.Equal(t, core.DefaultOneTimePasswordTTL, config.DefaultOneTimePasswordTTL)
}
