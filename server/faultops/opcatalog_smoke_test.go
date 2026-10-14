package faultops

import (
	"context"
	"testing"
)

// TestOpCatalog_SucceedsWithNoFaultArmed is the green control every opCatalog
// entry must pass before it can be trusted as a fuzz operation: driven against a
// fresh, fault-free world, it must actually succeed. An operation that can't
// even complete cleanly would make every fuzz finding involving it uninterpretable.
func TestOpCatalog_SucceedsWithNoFaultArmed(t *testing.T) {
	for _, op := range opCatalog {
		t.Run(op.Key, func(t *testing.T) {
			w := newFaultWorld(t, nil)
			res, err := runOp(context.Background(), w, op)
			if err != nil {
				t.Fatalf("op returned an error with no fault armed: %v", err)
			}
			if !res.Success {
				t.Fatalf("op reported failure with no fault armed: %s", res.Detail)
			}
		})
	}
}
