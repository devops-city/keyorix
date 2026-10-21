package main

import (
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/audit/siem"
	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// wireAuditSkipReads is a core wiring step (coreWiringSteps in main.go).
func wireAuditSkipReads(cw *coreWiring) error {
	cfg, coreService, store := cw.cfg, cw.core, cw.store
	// ADR-112 Amendment 4: storage.database.insecure_audit_skip_reads. Set before
	// the server serves anything. The every-start WARNING comes from the
	// registry (warnInsecureSettingsInEffect); the every-start audit event is
	// written here so the chain itself records the window reads went unaudited.
	coreService.SetInsecureAuditSkipReads(cfg.Storage.Database.InsecureAuditSkipReads)
	if cfg.Storage.Database.InsecureAuditSkipReads {
		auditReadsSkippedStartup(store)
	}
	return nil
}

// wireAuditDurabilityNotice is a core wiring step (coreWiringSteps in main.go).
func wireAuditDurabilityNotice(cw *coreWiring) error {
	cfg := cw.cfg
	// Audit durability (ADR-112 Amendment 3, docs/specs/fast-audit-mode.md):
	// one INFO line every start with the effective level and its meaning.
	// Both levels are baseline, so this is never a WARNING and writes no
	// per-start audit event; a level change between two starts is audited by
	// the start-to-start settings diff (config.TrackedSettings).
	logAuditDurability(cfg)
	return nil
}

// wireSIEMForwarder is a core wiring step (coreWiringSteps in main.go).
func wireSIEMForwarder(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire native SIEM audit forwarding if configured. New returns (nil, nil)
	// when disabled, so SetAuditForwarder(nil) keeps forwarding off.
	if sc := cfg.Audit.SIEM; sc.Enabled {
		forwarder, ferr := siem.New(siem.Config{
			Enabled:                   sc.Enabled,
			Provider:                  siem.Provider(sc.Provider),
			Endpoint:                  sc.Endpoint,
			Token:                     sc.GetToken(),
			InsecureSkipVerify:        sc.InsecureSkipVerify,
			SpoolDir:                  sc.SpoolDir,
			AllowPrivateNetworkTarget: sc.AllowPrivateNetworkTarget,
			AllowInsecureTransport:    sc.AllowInsecureTransport,
		})
		if ferr != nil {
			return fmt.Errorf("failed to init SIEM audit forwarder: %w", ferr)
		}
		coreService.SetAuditForwarder(forwarder)
		log.Printf("SIEM audit forwarding enabled (provider=%s)", sc.Provider)
	}
	return nil
}

// wireAuditHighWaterWitness is a core wiring step (coreWiringSteps in main.go).
func wireAuditHighWaterWitness(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire the audit high-water rollback-protection witness file
	// (design-b3-backup-v2.md §6.3) for local/sqlite deployments -- the only
	// backend `admin backup`/`admin restore` support, and therefore the only
	// one a stale-backup restore is even possible against. Postgres
	// deployments back up manually (pg_dump, docs/SELF_HOSTING.md §5) and
	// have no `admin restore` path this witness would ever be compared
	// against, so leaving it unset there is correct, not an oversight.
	if cfg.Storage.Type == "local" || cfg.Storage.Type == "sqlite" {
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		coreService.SetAuditHighWaterWitnessPath(auditverify.WitnessPath(dbPath))
	}
	return nil
}
