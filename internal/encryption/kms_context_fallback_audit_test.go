//go:build !noaws

package encryption

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func testKMSFallbackAuditConfig() *config.EncryptionConfig {
	return &config.EncryptionConfig{
		Enabled:     true,
		DEKPath:     "dek.key",
		SaltPath:    "salt",
		KeyProvider: config.KeyProviderConfig{Type: "password"},
	}
}

// TestService_AuditKMSContextFallback_RecordsEvent is the whitebox unit test for
// auditKMSContextFallback (awskms-002): wired as the awskms.FallbackHook from
// buildKeyProvider, it must turn a fallback firing into a durable, queryable audit
// event — not just the log.Printf line awskms.Decrypt always emits — matching this
// codebase's established pattern for auditKeyProviderDowngrade (see
// key_provider_downgrade.go and its TestNewKeyProviderFromConfig_WeakFallback_
// RuntimeAuditEvent). A real end-to-end test through Service.Initialize (like that
// downgrade test does with tpm/password) isn't possible here without live AWS
// credentials, since aws-kms's New() now makes a real kms:DescribeKey call — so
// this exercises the hook function directly, matching the actual unit boundary.
func TestService_AuditKMSContextFallback_RecordsEvent(t *testing.T) {
	svc := NewService(testKMSFallbackAuditConfig(), t.TempDir())

	var got *models.AuditEvent
	svc.SetAuditSink(func(_ context.Context, event *models.AuditEvent) error {
		got = event
		return nil
	})

	svc.auditKMSContextFallback(context.Background(), "arn:aws:kms:us-east-1:123456789012:key/canonical-id")

	if got == nil {
		t.Fatal("a KMS context-fallback event must be recorded as an audit event, not just a log line")
	}
	if got.EventType != EventKMSContextFallbackUsed {
		t.Fatalf("EventType = %q, want %q", got.EventType, EventKMSContextFallbackUsed)
	}
	if got.ActorType != "system" {
		t.Fatalf("ActorType = %q, want %q", got.ActorType, "system")
	}
	if got.Success == nil || *got.Success {
		t.Fatal("a KMS context-fallback event reports a security-negative condition and must have Success = false")
	}
	if !strings.Contains(got.Description, "arn:aws:kms:us-east-1:123456789012:key/canonical-id") {
		t.Fatalf("Description must name the affected key, got %q", got.Description)
	}
	if !strings.Contains(got.Description, "insecure_allow_kms_context_fallback") {
		t.Fatalf("Description must reference insecure_allow_kms_context_fallback so an operator knows what to disable, got %q", got.Description)
	}
}

// TestService_AuditKMSContextFallback_NilSinkIsNoOp verifies the hook is safe to
// call before SetAuditSink is ever wired (matches auditKeyProviderDowngrade's
// nil-sink behavior): it must not panic, and obviously records nothing.
func TestService_AuditKMSContextFallback_NilSinkIsNoOp(t *testing.T) {
	svc := NewService(testKMSFallbackAuditConfig(), t.TempDir())
	svc.auditKMSContextFallback(context.Background(), "some-key-id") // must not panic
}

// TestService_AuditKMSContextFallback_SinkErrorIsBestEffort verifies a sink write
// failure is swallowed (logged, not propagated) — the caller of Decrypt already
// has its plaintext by the time this hook runs and must not be affected by an
// audit-logging failure.
func TestService_AuditKMSContextFallback_SinkErrorIsBestEffort(t *testing.T) {
	svc := NewService(testKMSFallbackAuditConfig(), t.TempDir())
	svc.SetAuditSink(func(_ context.Context, _ *models.AuditEvent) error {
		return errors.New("simulated sink write failure")
	})
	svc.auditKMSContextFallback(context.Background(), "some-key-id") // must not panic
}
