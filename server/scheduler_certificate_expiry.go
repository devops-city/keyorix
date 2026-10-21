package main

import (
	"context"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockCertExpiry is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockCertExpiry int64 = 0x4B455953_43455254 // "KEYSCERT"

// startCertificateExpiryScheduler starts the "certificate_expiry" background job.
//
// Start the certificate-expiry scan — opt-in (ADR-055). Parses certificate-typed
// secrets and notifies project admins of certs expired/expiring within the window.
// Single-replica-gated (ADR-039).
func startCertificateExpiryScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	if cfg.CertificateExpiry.Enabled {
		interval := cfg.CertificateExpiry.GetInterval()
		leadDays := cfg.CertificateExpiry.LeadDays
		log.Printf("Certificate-expiry scan enabled: every %s (lead %dd)", interval, leadDays)
		runScheduler(ctx, "certificate_expiry", interval, func() middleware.SchedulerOutcome {
			return lockedRun(ctx, coreService.Storage(), schedLockCertExpiry, "Certificate-expiry", func(ctx context.Context) error {
				n, rerr := coreService.ScanCertificateExpiry(ctx, leadDays)
				if rerr != nil {
					log.Printf("Certificate-expiry scan error: %v", rerr)
					return rerr
				}
				if n > 0 {
					log.Printf("Certificate-expiry scan: sent %d notification(s)", n)
				}
				return nil
			})
		})
	}
}
