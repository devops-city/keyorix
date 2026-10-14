// mfa_stepup_grant_prune_scheduler_test.go — store-mfa-002: confirms
// startSchedulers actually wires up and calls PruneMFAStepUpGrants, not just
// that PruneMFAStepUpGrants itself works (covered at the core layer in
// internal/core/mfa_stepup_grant_prune_test.go). Follows the same direct-call
// convention server_s27_test.go's TestStartSchedulers_S27_AnomalyOffHoursNumeric
// established for exercising a startSchedulers branch without a full HTTP
// listener.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestStartSchedulers_MFAStepUpGrantPrune_RemovesExpiredRow seeds a grant row
// expired well past the default 30-day retention window and one that is not
// expired at all, starts the real scheduler set, waits for the immediate
// first tick, then confirms: the long-expired row is gone (a follow-up manual
// prune call finds nothing left to remove) and the unexpired row survives.
func TestStartSchedulers_MFAStepUpGrantPrune_RemovesExpiredRow(t *testing.T) {
	initI18n(t)
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "mfa_grant_prune_scheduler.db"},
		},
	}
	coreService := mustInitCoreService(t, cfg)
	ctx := context.Background()

	now := time.Now().UTC()
	if err := coreService.Storage().CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID:    1,
		Purpose:   models.MFAStepUpPurposeRestrictedSecretRead,
		ExpiresAt: now.Add(-400 * 24 * time.Hour), // long expired, past any sane retention
	}); err != nil {
		t.Fatalf("seed long-expired grant: %v", err)
	}
	if err := coreService.Storage().CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{
		UserID:    2,
		Purpose:   models.MFAStepUpPurposeRestrictedSecretRead,
		ExpiresAt: now.Add(time.Hour), // not expired at all
	}); err != nil {
		t.Fatalf("seed unexpired grant: %v", err)
	}

	schedCtx := t.Context()
	startSchedulersForTest(t, schedCtx, cfg, coreService)

	// startSchedulers only wires up the scheduler goroutines and returns
	// immediately; give the mfa_stepup_grant_prune scheduler's first
	// (immediate) tick a moment to run.
	deadline := time.Now().Add(2 * time.Second)
	var oldGone bool
	for time.Now().Before(deadline) {
		// A wide manual prune (cutoff = now) removes anything still present
		// that expired before now. If the scheduler already removed the old
		// row, this returns 0.
		n, err := coreService.Storage().PruneMFAStepUpGrants(ctx, now)
		if err != nil {
			t.Fatalf("manual verification prune: %v", err)
		}
		if n == 0 {
			oldGone = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !oldGone {
		t.Fatal("mfa_stepup_grant_prune scheduler did not remove the long-expired grant row within the deadline")
	}

	// The unexpired grant must never have been touched.
	active, err := coreService.HasActiveMFAStepUp(ctx, 2, models.MFAStepUpPurposeRestrictedSecretRead)
	if err != nil {
		t.Fatalf("HasActiveMFAStepUp: %v", err)
	}
	if !active {
		t.Fatal("the unexpired grant must survive the prune sweep")
	}
}
