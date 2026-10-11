package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// OTP-EXPIRY-1: the recover-admin one-time password expires (default 24h,
// security.recovery_one_time_password_ttl), the expiry is stored with the
// credential, reported to the operator, audited, and enforced at login.

func TestPerformRecoverAdmin_OneTimePasswordExpiry_DefaultIs24h(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-exp", "admin-exp@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	before := time.Now()
	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	after := time.Now()
	if err != nil {
		t.Fatalf("performRecoverAdmin: %v", err)
	}

	if summary.oneTimePasswordExpiresAt.Before(before.Add(24*time.Hour)) || summary.oneTimePasswordExpiresAt.After(after.Add(24*time.Hour)) {
		t.Errorf("summary expiry %s is not 24h from the run (%s..%s)", summary.oneTimePasswordExpiresAt, before, after)
	}
	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.OneTimePasswordExpiresAt == nil {
		t.Fatalf("no expiry stored with the recovery one-time password")
	}
	if !got.OneTimePasswordExpiresAt.Equal(summary.oneTimePasswordExpiresAt) {
		t.Errorf("stored expiry %s != reported expiry %s", got.OneTimePasswordExpiresAt, summary.oneTimePasswordExpiresAt)
	}

	action := "admin.recover_admin"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("audit events: %v, err %v", len(events), err)
	}
	if want := summary.oneTimePasswordExpiresAt.UTC().Format(time.RFC3339); !strings.Contains(events[0].Description, want) {
		t.Errorf("audit event does not record the expiry %q: %s", want, events[0].Description)
	}
	if strings.Contains(events[0].Description, summary.oneTimePassword) {
		t.Errorf("audit event leaks the one-time password")
	}
}

func TestPerformRecoverAdmin_OneTimePasswordExpiry_ConfiguredTTL(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-ttl", "admin-ttl@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	before := time.Now()
	summary, err := performRecoverAdminWithTTL(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false, 90*time.Minute)
	if err != nil {
		t.Fatalf("performRecoverAdminWithTTL: %v", err)
	}
	if d := summary.oneTimePasswordExpiresAt.Sub(before); d < 90*time.Minute || d > 91*time.Minute {
		t.Errorf("expiry is %s after the run, want ~90m", d)
	}
}

// A non-positive TTL must never mean "no expiry".
func TestPerformRecoverAdmin_OneTimePasswordExpiry_NonPositiveTTLFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-zero", "admin-zero@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	summary, err := performRecoverAdminWithTTL(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false, 0)
	if err != nil {
		t.Fatalf("performRecoverAdminWithTTL: %v", err)
	}
	if d := time.Until(summary.oneTimePasswordExpiresAt); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("zero TTL produced an expiry %s away, want the 24h default", d)
	}
}

// The journey at the core layer: the printed password logs in until its expiry,
// then is refused exactly like a wrong password and audited.
func TestPerformRecoverAdmin_OneTimePasswordExpiry_RefusedAtLoginAfterExpiry(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-late", "admin-late@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("performRecoverAdmin: %v", err)
	}
	c := core.NewKeyorixCore(store)

	if _, err := c.VerifyPasswordCredentials(ctx, user.Username, summary.oneTimePassword); err != nil {
		t.Fatalf("a fresh recovery password must log in: %v", err)
	}

	// Time passes: move the stored expiry into the past (the same row the real
	// clock would eventually cross).
	past := time.Now().Add(-time.Minute)
	if err := store.SetOneTimePasswordExpiry(ctx, user.ID, &past, time.Now()); err != nil {
		t.Fatalf("SetOneTimePasswordExpiry: %v", err)
	}

	_, expiredErr := c.VerifyPasswordCredentials(ctx, user.Username, summary.oneTimePassword)
	_, wrongErr := c.VerifyPasswordCredentials(ctx, user.Username, "Not-the-password-1")
	if expiredErr == nil || wrongErr == nil {
		t.Fatalf("expired=%v wrong=%v: both must be refused", expiredErr, wrongErr)
	}
	if expiredErr.Error() != wrongErr.Error() {
		t.Errorf("expired-password error %q differs from wrong-password error %q: that is an oracle", expiredErr, wrongErr)
	}

	core.DrainBackgroundGoroutines() // the expired-OTP audit is written asynchronously
	action := core.EventOneTimePasswordExpired
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 %s audit event, got %d", core.EventOneTimePasswordExpired, len(events))
	}
	if strings.Contains(events[0].Description, summary.oneTimePassword) {
		t.Errorf("audit event leaks the one-time password")
	}

	// Running recover-admin again re-issues a working password with a fresh expiry.
	again, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("second performRecoverAdmin: %v", err)
	}
	if _, err := c.VerifyPasswordCredentials(ctx, user.Username, again.oneTimePassword); err != nil {
		t.Errorf("a re-issued recovery password must log in: %v", err)
	}
}
