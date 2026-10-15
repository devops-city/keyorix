package startup

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ADR-112 Amendment 4: insecure_audit_skip_reads is an `admin validate`
// deviation while set; the default records nothing.
func TestAppendAuditSkipReadsPosture(t *testing.T) {
	res := &ValidationResult{}
	appendAuditSkipReadsPosture(&config.Config{}, res)
	assert.Empty(t, res.Warnings)
	assert.Empty(t, res.InsecureSettings)

	cfg := &config.Config{}
	cfg.Storage.Database.InsecureAuditSkipReads = true
	res = &ValidationResult{}
	appendAuditSkipReadsPosture(cfg, res)
	assert.Equal(t, []string{AuditReadsSkippedWarning}, res.Warnings)
	assert.Contains(t, AuditReadsSkippedWarning, "Secret reads are NOT audited")
	require.Len(t, res.InsecureSettings, 1)
	assert.Equal(t, config.InsecureAuditSkipReadsSettingName, res.InsecureSettings[0].Name)
	assert.True(t, res.InsecureSettings[0].InEffect)
}
