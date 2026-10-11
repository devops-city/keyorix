// kms_context_fallback_audit.go — records a KMS-provider (currently aws-kms)
// KMSAllowContextFallback decrypt actually firing as a queryable audit event, not
// just a log line. See config.KeyProviderConfig.KMSAllowContextFallback (the
// opt-in, transient migration aid this reports on) and awskms.FallbackHook (the
// runtime hook this file wires into). Modeled directly on
// key_provider_downgrade.go's AuditSink wiring for the sibling
// key_provider_fallback_downgrade event.
package encryption

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventKMSContextFallbackUsed is the audit event type recorded whenever a KMS key
// provider configured with kms_allow_context_fallback actually decrypts a blob via
// the no-context fallback path — i.e. an install accepted a KEK wrapping that is
// NOT bound to its own encryption context. This flag is meant as a transient
// migration aid; nothing else enforces that, so each use is recorded durably here
// rather than relying solely on the per-decrypt log.Printf line, which an operator
// who enables the flag and forgets to disable it could easily lose in log noise.
const EventKMSContextFallbackUsed = "encryption.kms_context_fallback_used" // #nosec G101 -- audit event type, not a credential

// auditKMSContextFallback is wired as the awskms.FallbackHook (via
// NewKeyProviderFromConfig's kmsFallbackHook parameter) when building a live
// aws-kms key provider in buildKeyProvider. It fires synchronously from inside
// Decrypt, so it must use its own mutex (auditSinkMu), never s.mu, exactly like
// auditKeyProviderDowngrade — the KEK-manager call chain that reaches here may
// already hold s.mu. Best-effort: a sink write failure is logged but never
// propagated, since the decrypt it's reporting on has already succeeded by the
// time this runs and must not be undone by an audit-logging failure.
func (s *Service) auditKMSContextFallback(ctx context.Context, keyID string) {
	s.auditSinkMu.RLock()
	sink := s.auditSink
	s.auditSinkMu.RUnlock()
	if sink == nil {
		return
	}
	failed := false // the event itself reports a security-negative condition, not a success
	event := &models.AuditEvent{
		EventType: EventKMSContextFallbackUsed,
		Description: fmt.Sprintf(
			"KMS decrypt for key %q succeeded only via the no-context fallback (insecure_allow_kms_context_fallback) — this blob is not bound to this install's encryption context; re-wrap it via 'keyorix encryption migrate-provider --to-kms-encryption-context=...' and disable insecure_allow_kms_context_fallback",
			keyID),
		Success:   &failed,
		ActorType: "system",
		EventTime: time.Now(),
	}
	if err := sink(ctx, event); err != nil {
		log.Printf("SECURITY: kms context fallback: failed to write audit event: %v", err)
	}
}
