// secret_mutation_audit_fail_closed_test.go -- AUDIT-MUTATION-TX-1.
//
// A secret mutation's audit row commits in the mutation's own transaction, so a
// failed audit append must fail the request and change NOTHING: no secret row,
// no version, no audit row, no access log. Each catalog operation below is run
// with its first audit append (LogAuditEventWithAccessLog#1, which the mutation
// calls through its transaction-scoped storage) faulted, and the post-state must
// equal the pre-fault state in EVERY table.
//
// Deliberately stricter than oracle (a): the fuzz oracle accepts an error whose
// diff is confined to outcome-log tables (onlyOutcomeLogTables, AuditEvent
// among them), which is the right default for incidental audit rows but would
// let "audit row missing, mutation committed" through on these ops the moment
// the mutation's own tables happened to match. Here no table, outcome log or
// not, may differ, and no tolerance or accept-by-design applies.
//
// Before AUDIT-MUTATION-TX-1 every row was red: the mutation committed, the
// audit append ran afterwards through c.storage, its failure was only logged,
// and the request reported success.
package faultops

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// secretMutationAuditOps are the catalog operations whose audit row must share
// the mutation's transaction.
var secretMutationAuditOps = []string{
	"REST POST /api/v1/secrets/",
	"REST PUT /api/v1/secrets/{id}",
	"REST DELETE /api/v1/secrets/{id}",
	"REST POST /api/v1/secrets/{id}/rotate",
	"REST POST /api/v1/secrets/{id}/rollback",
	"REST DELETE /api/v1/folders/{id}",
	"GRPC keyorix.v1.SecretService.CreateSecret",
	"GRPC keyorix.v1.SecretService.UpdateSecret",
	"GRPC keyorix.v1.SecretService.DeleteSecret",
}

func TestSecretMutationAuditFailure_FailsClosedChangesNothing(t *testing.T) {
	ctx := context.Background()
	for _, key := range secretMutationAuditOps {
		t.Run(key, func(t *testing.T) {
			var op *operation
			for i := range opCatalog {
				if opCatalog[i].Key == key {
					op = &opCatalog[i]
				}
			}
			require.NotNil(t, op, "op %q is not in opCatalog", key)

			w := newFaultWorld(t, nil)
			var state any
			if op.Setup != nil {
				var err error
				state, err = op.Setup(ctx, w)
				require.NoError(t, err, "setup")
			}
			drainAllBackgroundGoroutines()
			before, err := snapshotDB(w.db)
			require.NoError(t, err)

			w.faulty.Arm(&faultstorage.FaultSpec{
				Method: "LogAuditEventWithAccessLog", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected,
			})
			result, execErr := op.Execute(ctx, w, state)
			fired := w.faulty.Fired() // before Arm(nil), which resets the latch
			w.faulty.Arm(nil)
			drainAllBackgroundGoroutines()

			require.True(t, fired, "%s never appended its audit row through storage -- the premise of this test is gone", key)
			require.NoError(t, execErr, "transport error")
			require.False(t, result.Success, "%s reported success although its audit row could not be written: %s", key, result.Detail)

			after, err := snapshotDB(w.db)
			require.NoError(t, err)
			require.Empty(t, diffTables(before, after),
				"%s failed its audit write but changed state anyway: the mutation (or a partial version) committed without its audit row", key)
		})
	}
}
