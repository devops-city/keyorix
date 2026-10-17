package core

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestBulkRenameSecrets_ExceedsMaxBatchSize: the renames list is refused above
// maxBulkRenameBatchSize before any per-item storage work starts (#G44), like the
// other bulk operations' batch caps.
func TestBulkRenameSecrets_ExceedsMaxBatchSize(t *testing.T) {
	c := &KeyorixCore{now: time.Now} // no storage: the cap must refuse before touching it
	renames := make([]SecretRename, maxBulkRenameBatchSize+1)
	for i := range renames {
		renames[i] = SecretRename{ID: uint(i + 1), NewName: "X"}
	}
	_, err := c.BulkRenameSecrets(context.Background(), 1, renames, true, "alice", 1, "", "")
	if err == nil || !strings.Contains(err.Error(), "maximum batch size") {
		t.Fatalf("%d renames: err = %v, want the batch-size refusal", len(renames), err)
	}
}
