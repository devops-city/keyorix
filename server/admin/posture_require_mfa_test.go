package admin

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// collectRequireMFAPosture must read the same facts the server's boot does
// (server/adr112_grace.go): on an upgraded deployment (users exist, no
// config.ADR112RequireMFAEnforcedMarker) that never set require_mfa, the server
// does NOT enforce MFA, so the posture report counts that as a deviation even
// though config.Load resolved the field to true.
func TestCollectRequireMFAPosture_ADR112Grace(t *testing.T) {
	ctx := context.Background()
	graceDeviation := func(r *postureReport) *postureDeviation {
		for i := range r.deviations {
			if r.deviations[i].category == "grace-period" && strings.Contains(r.deviations[i].detail, "require_mfa") {
				return &r.deviations[i]
			}
		}
		return nil
	}
	run := func(t *testing.T, cfg *config.Config, setup func(corestorage.Storage) error) (*postureReport, bool) {
		t.Helper()
		report := &postureReport{}
		var inGrace bool
		require.NoError(t, withUsableStorage(cfg, func(store corestorage.Storage) error {
			if setup != nil {
				if err := setup(store); err != nil {
					return err
				}
			}
			var err error
			inGrace, err = collectRequireMFAPosture(ctx, cfg, store, report)
			return err
		}))
		return report, inGrace
	}
	addUser := func(store corestorage.Storage) error {
		_, err := store.CreateUser(ctx, &models.User{
			Username: "root", UsernameFolded: "root", Email: "root@x.io", EmailFolded: "root@x.io",
			IsActive: true, AccountState: core.AccountActive,
		})
		return err
	}

	t.Run("upgrade without marker is a grace-period deviation", func(t *testing.T) {
		cfg := writeSecureBaselineConfig(t) // never sets require_mfa
		require.True(t, cfg.Security.RequireMFA && cfg.Security.RequireMFAImplicitDefault, "premise: implicit default")
		report, inGrace := run(t, cfg, addUser)
		require.True(t, inGrace)
		d := graceDeviation(report)
		require.NotNil(t, d, "an upgrade in the require_mfa grace period must be a deviation: %+v", report.deviations)
		require.Equal(t, originShippedDefault, d.origin)
		require.Contains(t, d.detail, "does NOT enforce MFA")
		// #2986: the registry entry must see the grace state too, or the
		// posture report counts the grace period once but never as a setting.
		require.Equal(t, config.RequireMFAGraceNotEnforced, cfg.Security.RequireMFAState())
		insecure := &postureReport{}
		collectInsecureSettingsPosture(cfg, nil, insecure)
		var found bool
		for _, dev := range insecure.deviations {
			found = found || strings.HasPrefix(dev.detail, "security.insecure_disable_mfa_requirement is in effect (grace-not-enforced)")
		}
		require.True(t, found, "registry deviation missing: %+v", insecure.deviations)
	})
	// #2923: the deviation names the end of the recorded window; past the
	// deadline (by the later of now and the recorded clock) it is no deviation.
	t.Run("recorded window: days left in the deviation", func(t *testing.T) {
		cfg := writeSecureBaselineConfig(t)
		start := time.Now().Add(-10 * 24 * time.Hour).UTC().Truncate(time.Second)
		report, inGrace := run(t, cfg, func(store corestorage.Storage) error {
			if err := addUser(store); err != nil {
				return err
			}
			return store.SetSystemMetadata(ctx, config.ADR112RequireMFAGraceStartedKey, start.Format(time.RFC3339))
		})
		require.True(t, inGrace)
		d := graceDeviation(report)
		require.NotNil(t, d)
		require.Contains(t, d.detail, "ends at "+start.Add(config.ADR112RequireMFAGracePeriod).Format(time.RFC3339)+" (20 day(s) left)")
		require.Contains(t, d.detail, "first administrator enrols")
	})
	t.Run("recorded clock past the deadline: enforced, no deviation", func(t *testing.T) {
		cfg := writeSecureBaselineConfig(t)
		start := time.Now().Add(-10 * 24 * time.Hour).UTC()
		report, inGrace := run(t, cfg, func(store corestorage.Storage) error {
			if err := addUser(store); err != nil {
				return err
			}
			if err := store.SetSystemMetadata(ctx, config.ADR112RequireMFAGraceStartedKey, start.Format(time.RFC3339)); err != nil {
				return err
			}
			return store.SetSystemMetadata(ctx, config.ADR112RequireMFAGraceClockKey, start.Add(31*24*time.Hour).Format(time.RFC3339))
		})
		require.False(t, inGrace, "a clock set back must not reopen the grace period in the report either")
		require.Nil(t, graceDeviation(report))
	})
	t.Run("corrupt grace start: error, not a clean report", func(t *testing.T) {
		cfg := writeSecureBaselineConfig(t)
		report := &postureReport{}
		err := withUsableStorage(cfg, func(store corestorage.Storage) error {
			if err := addUser(store); err != nil {
				return err
			}
			if err := store.SetSystemMetadata(ctx, config.ADR112RequireMFAGraceStartedKey, "garbage"); err != nil {
				return err
			}
			_, err := collectRequireMFAPosture(ctx, cfg, store, report)
			return err
		})
		require.ErrorContains(t, err, "not an RFC 3339 time")
	})
	t.Run("marker present: enforced, no deviation", func(t *testing.T) {
		cfg := writeSecureBaselineConfig(t)
		report, inGrace := run(t, cfg, func(store corestorage.Storage) error {
			if err := addUser(store); err != nil {
				return err
			}
			return store.SetSystemMetadata(ctx, config.ADR112RequireMFAEnforcedMarker, "2026-10-10T00:00:00Z")
		})
		require.False(t, inGrace)
		require.Nil(t, graceDeviation(report))
	})
	t.Run("fresh install (no users): enforced, no deviation", func(t *testing.T) {
		cfg := writeSecureBaselineConfig(t)
		report, inGrace := run(t, cfg, nil)
		require.False(t, inGrace)
		require.Empty(t, report.deviations)
	})
	t.Run("explicit false is a deviation", func(t *testing.T) {
		cfg := writeSecureBaselineConfig(t)
		cfg.Security.RequireMFA, cfg.Security.RequireMFAImplicitDefault = false, false
		report, _ := run(t, cfg, nil)
		require.Len(t, report.deviations, 1)
		require.Contains(t, report.deviations[0].detail, "security.require_mfa is false")
	})
}
