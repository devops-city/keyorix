package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// schedLockAnomaly is a background-job advisory-lock key (ADR-039); every schedLock*
// value is distinct (TestSchedulerLockKeysAreDistinct).
const schedLockAnomaly int64 = 0x4B455953_414E4F4D // "KEYSANOM"

// startAnomalyDetectionScheduler starts the "anomaly_detection" background job.
//
// Start anomaly detection scheduler. Single-replica-gated (ADR-039) so N
// replicas don't emit N copies of each alert. When anomaly_alerts is enabled,
// each detection pass is followed by an alerting pass that pushes newly detected
// anomalies to project admins + the audit/SIEM pipeline.
func startAnomalyDetectionScheduler(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) {
	detector := core.NewAnomalyDetector(coreService.Storage())
	if bh := cfg.AnomalyAlerts.BusinessHours; bh.Timezone != "" || bh.OffHoursStart != 0 || bh.OffHoursEnd != 0 {
		tzLabel := bh.Timezone
		if tzLabel == "" {
			tzLabel = "UTC"
		}
		if err := detector.SetBusinessHours(ctx, bh.Timezone, bh.OffHoursStart, bh.OffHoursEnd); err != nil {
			// Misconfigured timezone: keep the safe UTC default rather than fail startup.
			log.Printf("Anomaly off-hours config ignored (%v); using UTC 22:00–06:00", err)
		} else {
			log.Printf("Anomaly off-hours rule configured (timezone %s)", tzLabel)
		}
	}
	if mlc := cfg.AnomalyAlerts.ML; mlc.Enabled {
		detector.SetMLConfig(core.MLConfig{
			Enabled:    true,
			Threshold:  mlc.Threshold,
			NumTrees:   mlc.NumTrees,
			SampleSize: mlc.SampleSize,
			Seed:       mlc.Seed,
		})
		log.Printf("Anomaly ML (Isolation Forest) detection enabled")
	}
	alertsEnabled := cfg.AnomalyAlerts.Enabled
	interval := cfg.AnomalyAlerts.GetInterval()
	// Scan a window at least as long as the cadence, so a longer schedule doesn't
	// leave the time between passes unexamined (floored at 1h inside SetLookback).
	detector.SetLookback(interval)
	detector.SetBaselineQuarantine(cfg.AnomalyAlerts.GetBaselineQuarantine())
	// Overlay the DB-persisted anomaly config on top of the file-based defaults.
	// Best-effort at startup: a storage error keeps the file-based settings rather
	// than aborting startup or leaving the detector unconfigured.
	if err := coreService.ApplyAnomalyConfig(ctx, detector); err != nil {
		log.Printf("Anomaly: could not load persisted config (%v); using file-based defaults", err)
	} else {
		log.Printf("Anomaly: persisted runtime config applied")
	}
	if alertsEnabled {
		log.Printf("Anomaly alerting enabled: scan + alert every %s", interval)
	}
	// First pass deferred + jittered, not run at startup — see anomalyFirstPassDelay.
	firstDelay := anomalyFirstPassDelay(interval, defaultRandN)
	log.Printf("Anomaly detection: first pass in %s, then every %s", firstDelay.Round(time.Second), interval)
	runSchedulerAfter(ctx, "anomaly_detection", interval, firstDelay, func() middleware.SchedulerOutcome {
		return lockedRun(ctx, coreService.Storage(), schedLockAnomaly, "Anomaly detection", func(ctx context.Context) error {
			// Hotload: re-apply the persisted config before each pass so an operator's
			// runtime change takes effect without a restart. Best-effort: a transient
			// storage failure here is logged but does not skip the detection pass.
			if err := coreService.ApplyAnomalyConfig(ctx, detector); err != nil {
				log.Printf("Anomaly: failed to reload persisted config (%v); running with prior settings", err)
			}
			if derr := detector.RunDetection(ctx, coreService.ListActiveSecrets(ctx)); derr != nil {
				return derr
			}
			if alertsEnabled {
				if n, aerr := coreService.AlertNewAnomalies(ctx); aerr != nil {
					return aerr
				} else if n > 0 {
					log.Printf("Anomaly alerting: announced %d new anomaly alert(s)", n)
				}
			}
			return nil
		})
	})
}
