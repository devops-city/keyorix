package core

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// The unwired fallback in SecretPurgeAt must be exactly the config default, so an
// unwired service shows the date an unconfigured server would. If the config default
// changes, this fails until core's constant follows.
func TestDefaultSoftDeleteRetentionDays_MatchesConfigDefault(t *testing.T) {
	if got := (config.SoftDeleteConfig{}).GetRetentionDays(); got != defaultSoftDeleteRetentionDays {
		t.Fatalf("config default retention = %d days, core fallback = %d", got, defaultSoftDeleteRetentionDays)
	}
}
