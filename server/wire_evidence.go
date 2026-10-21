package main

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/evidencesink"
)

// wireEvidenceTargets is a core wiring step (coreWiringSteps in main.go).
func wireEvidenceTargets(cw *coreWiring) error {
	cfg, coreService := cw.cfg, cw.core
	// Wire any off-box evidence targets (webhook and/or S3-compatible object store),
	// so the scheduled evidence pack is delivered off-box in addition to (or instead
	// of) a local dir. When both are configured the pack fans out to both.
	var evidenceTargets []evidencesink.Forwarder
	if ew := cfg.EvidenceDelivery.Webhook; ew.Enabled {
		fwd, ferr := evidencesink.NewWebhook(evidencesink.WebhookConfig{
			Endpoint:                  ew.Endpoint,
			Token:                     ew.GetToken(),
			InsecureSkipVerify:        ew.InsecureSkipVerify,
			AllowPrivateNetworkTarget: ew.AllowPrivateNetworkTarget,
			AllowInsecureTransport:    ew.AllowInsecureTransport,
		})
		if ferr != nil {
			return fmt.Errorf("failed to init evidence webhook target: %w", ferr)
		}
		evidenceTargets = append(evidenceTargets, fwd)
		log.Printf("Evidence webhook target enabled (endpoint=%s)", ew.Endpoint)
	}
	if os := cfg.EvidenceDelivery.ObjectStore; os.Enabled {
		sink, oerr := evidencesink.NewObjectStore(context.Background(), evidencesink.ObjectStoreConfig{
			Bucket:         os.Bucket,
			Prefix:         os.Prefix,
			Region:         os.Region,
			Endpoint:       os.Endpoint,
			UsePathStyle:   os.UsePathStyle,
			LockMode:       os.LockMode,
			LockRetainDays: os.LockRetainDays,
			LegalHold:      os.LegalHold,
		})
		if oerr != nil {
			return fmt.Errorf("failed to init evidence object-store target: %w", oerr)
		}
		evidenceTargets = append(evidenceTargets, sink)
		log.Printf("Evidence object-store target enabled (bucket=%s, prefix=%q)", os.Bucket, os.Prefix)
	}
	switch len(evidenceTargets) {
	case 0:
	case 1:
		coreService.SetEvidenceForwarder(evidenceTargets[0])
	default:
		coreService.SetEvidenceForwarder(evidencesink.NewMulti(evidenceTargets...))
	}
	return nil
}
