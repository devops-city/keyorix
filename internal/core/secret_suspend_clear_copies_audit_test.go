package core

// SUSPEND-PURGE-1, audit-before-effect: a suspension that asks the operator and
// k8s-sync to clear the synced Kubernetes copies is a compromise response that
// destroys data in clusters. It must never take effect without its
// secret.suspended record: the marker and the audit row commit together, or
// neither does and the caller is told to retry (same rule as the project-wide
// freeze with the choice, #3221).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSuspendSecret_ClearSyncedCopies_AuditWriteFails_NothingTakesEffect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct {
		name         string
		preSuspended bool // the "upgrade" path: already suspended, then the flag
	}{
		{"fresh suspend", false},
		{"upgrade of an existing suspension", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, id, db := newSuspendFixture(t)
			if tc.preSuspended {
				_, err := c.SuspendSecret(ctx, id, 1, "maintenance")
				require.NoError(t, err)
			}
			faulty := faultstorage.NewFaultyStorage(c.storage, nil)
			c.storage = faulty
			faulty.Arm(&faultstorage.FaultSpec{
				Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
			})

			_, err := c.SuspendSecretWithOptions(ctx, id, 1, "leaked", SuspendOptions{ClearSyncedCopies: true})
			require.True(t, faulty.Fired(), "the audit fault must be reached, or this test proves nothing")
			require.Error(t, err, "a clear-synced-copies suspension whose audit row failed must be reported as failed")

			var row models.SecretNode
			require.NoError(t, db.First(&row, id).Error)
			assert.False(t, row.SuspendClearSyncedCopies,
				"the clear marker must not be visible to the operator/k8s-sync without its audit row")
			if !tc.preSuspended {
				assert.Equal(t, SecretStatusActive, row.Status, "a failed audited suspend must leave the secret as it was")
			}

			faulty.Arm(nil)
			_, err = c.SuspendSecretWithOptions(ctx, id, 1, "leaked", SuspendOptions{ClearSyncedCopies: true})
			require.NoError(t, err, "the responder must be able to retry once the audit store is back")
			assert.True(t, suspendedRefusal(t, c, id).ClearSyncedCopies)
			descs := suspendAuditDescriptions(t, db)
			require.NotEmpty(t, descs)
			assert.Contains(t, descs[len(descs)-1], "clear_synced_copies=true")
		})
	}
}
