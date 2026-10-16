package core

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// An oversized batch is refused before any read or per-row work (CWE-400): the error
// is returned with no decisions, so a caller fails closed. The core has no storage on
// purpose: the guard must fire before the first storage call.
func TestAuthorizeSecretsBatch_OverLimitRefused(t *testing.T) {
	c := &KeyorixCore{}
	secrets := make([]*models.SecretNode, maxAuthorizeSecretsBatchSize+1)
	got, err := c.AuthorizeSecretsBatch(context.Background(), 1, permSecretsRead, secrets)
	if err == nil {
		t.Fatalf("over-limit batch: want error, got decisions %v", got)
	}
	if got != nil {
		t.Fatalf("over-limit batch: want no decisions, got %v", got)
	}
	if !strings.Contains(err.Error(), "maximum batch size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBatchSecretAncestry_OverLimitRefused(t *testing.T) {
	c := &KeyorixCore{}
	rows := make([]*models.SecretNode, maxAuthorizeSecretsBatchSize+1)
	if _, _, err := c.batchSecretAncestry(context.Background(), rows); err == nil {
		t.Fatal("over-limit rows: want error")
	}
}

// At the limit the batch is still decided (nil entries are skipped, so no storage read).
func TestAuthorizeSecretsBatch_AtLimitAllowed(t *testing.T) {
	c := &KeyorixCore{}
	secrets := make([]*models.SecretNode, maxAuthorizeSecretsBatchSize)
	got, err := c.AuthorizeSecretsBatch(context.Background(), 1, permSecretsRead, secrets)
	if err != nil {
		t.Fatalf("at-limit batch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty decisions, got %v", got)
	}
}
