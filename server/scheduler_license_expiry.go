package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockLicenseExp is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockLicenseExp int64 = 0x4B455953_4C494345 // "KEYSLICE"

// startLicenseExpiryScheduler starts the "license_expiry" background job.
//
// Start the license-expiry reminder — opt-in (ADR-065 Phase 2c). Notifies install-wide
// admins when the offline commercial license is approaching or past expiry, so a lapse
// (which silently disables commercial features) doesn't go unnoticed. Single-replica-
// gated (ADR-039) so N replicas don't each notify.
func startLicenseExpiryScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.LicenseExpiry.Enabled {
		interval := cfg.LicenseExpiry.GetInterval()
		leadDays := cfg.LicenseExpiry.LeadDays
		log.Printf("License-expiry reminder enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "license_expiry", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockLicenseExp, "License-expiry", func(ctx context.Context) error {
				n, rerr := coreService.ScanLicenseExpiry(ctx, leadDays)
				if rerr != nil {
					log.Printf("License-expiry reminder error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("License-expiry reminder: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}
}
