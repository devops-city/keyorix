// key_provider_downgrade.go — records a key-provider fallback chain actually
// downgrading KEK-sourcing strength at KEK() time as a queryable audit event,
// not just a log line. See config.KeyProviderConfig.AllowWeakerFallback (the
// config-time, fail-closed gate) and crypto.MultiKeyProvider.SetDowngradeHook
// (the runtime hook this file wires into).
package encryption

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventKeyProviderFallbackDowngrade is the audit event type recorded when a
// configured key-provider fallback chain actually falls back, at runtime, to a
// provider whose strength tier is weaker than an earlier (higher-tier) provider
// in the chain — e.g. a TPM/KMS-backed primary failing over to a
// password-derived fallback. Distinct from the config-time startup refusal
// (NewKeyProviderFromConfig / AllowWeakerFallback): that fires whenever the
// config PERMITS a downgrade; this fires only when the downgrade actually
// happened for this process's own KEK derivation.
const EventKeyProviderFallbackDowngrade = "encryption.key_provider_fallback_downgrade" // #nosec G101 -- audit event type, not a credential

// AuditSink is a minimal audit-write hook, matching storage.Storage's
// LogAuditEvent method signature exactly so a caller can pass that method value
// directly (e.g. svc.SetAuditSink(store.LogAuditEvent)) without this package
// importing the full storage.Storage interface (which would pull encryption into
// a dependency cycle with the storage layer it is itself used by).
type AuditSink func(ctx context.Context, event *models.AuditEvent) error

// SetAuditSink wires the security-event sink the Service uses to record runtime
// events that don't otherwise have a models.AuditEvent home — currently just a
// key-provider fallback chain actually downgrading KEK strength at KEK()-derivation
// time. Optional and safe to leave unset: such events are still recorded via the
// loud "SECURITY:" log line crypto.MultiKeyProvider.KEK always emits either way;
// wiring a sink (typically store.LogAuditEvent, once storage is available) turns
// that into a real, queryable trail an operator can alert on instead of a log
// line that's easy to lose in noise. Must be called before Initialize for a
// downgrade during THIS process's own KEK derivation to be captured — call it
// right after NewService, before Initialize.
func (s *Service) SetAuditSink(sink AuditSink) {
	s.auditSinkMu.Lock()
	defer s.auditSinkMu.Unlock()
	s.auditSink = sink
}

// auditKeyProviderDowngrade is wired as the crypto.MultiKeyProvider downgrade hook
// in buildKeyProvider. It fires synchronously from inside KEK() — which itself
// runs from inside KeyManager.Initialize, called while Service.Initialize still
// holds s.mu — so it must use its own mutex (auditSinkMu), never s.mu, to avoid a
// self-deadlock. Best-effort: a sink write failure is logged but never propagated,
// since the KEK derivation it's reporting on has already succeeded by the time
// this runs and must not be undone by an audit-logging failure.
func (s *Service) auditKeyProviderDowngrade(d crypto.FallbackDowngrade) {
	kekDowngradesTotal.Inc()
	s.auditSinkMu.RLock()
	sink := s.auditSink
	s.auditSinkMu.RUnlock()
	if sink == nil {
		return
	}
	failed := false // the event itself reports a security-negative condition, not a success
	event := &models.AuditEvent{
		EventType: EventKeyProviderFallbackDowngrade,
		Description: fmt.Sprintf(
			"key provider fallback fired at runtime: KEK now sourced from %q (%s) after an earlier, %s provider in the configured chain failed",
			d.Provider, d.ToTier, d.FromTier),
		Success:   &failed,
		ActorType: "system",
		EventTime: time.Now(),
	}
	if err := sink(context.Background(), event); err != nil {
		log.Printf("SECURITY: key provider fallback downgrade: failed to write audit event: %v", err)
	}
}
