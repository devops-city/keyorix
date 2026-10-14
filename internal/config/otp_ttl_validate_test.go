package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OTP-EXPIRY-1: a one-time-password TTL that is set but unusable is a startup error,
// not a silent fall-back to the default (a "7d" typo would otherwise become 72h).
func TestValidate_OneTimePasswordExpiries(t *testing.T) {
	cases := map[string]struct {
		recovery, otp string
		wantErr       string // "" = valid
	}{
		"unset is valid":           {"", "", ""},
		"in range":                 {"2h", "168h", ""},
		"exactly the maximum":      {"168h", "168h", ""},
		"days suffix is not Go":    {"", "7d", "security.one_time_password_ttl"},
		"garbage recovery":         {"tomorrow", "", "security.recovery_one_time_password_ttl"},
		"zero is not never":        {"0s", "", "security.recovery_one_time_password_ttl"},
		"negative":                 {"", "-1h", "security.one_time_password_ttl"},
		"over the maximum":         {"", "169h", "security.one_time_password_ttl"},
		"effectively never (100y)": {"876000h", "", "security.recovery_one_time_password_ttl"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := validLocalConfig()
			c.Security.RecoveryOneTimePasswordExpiry = tc.recovery
			c.Security.OneTimePasswordExpiry = tc.otp
			err := c.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
