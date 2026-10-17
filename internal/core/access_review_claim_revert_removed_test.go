package core

// #2803: storage.Storage.RevertAccessReviewItemClaim had no production caller and,
// unlike UpdateAccessReviewItem's claim, no campaign-is-open condition, so a future
// caller could have rewritten an item of a CLOSED campaign (its recorded decision is
// the evidence an access review is audited on). It was deleted rather than fixed:
// the revoke path claims, removes and audits in ONE transaction (INV-CORE-41,
// access_review_decide_tx.go), so nothing ever needs to undo a claim.
//
// This pins the absence. Reintroducing an item-claim revert must come with the
// campaign-open condition and a caller, and re-justify the decision above here.

import (
	"reflect"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestStorageInterface_HasNoAccessReviewItemClaimRevert(t *testing.T) {
	st := reflect.TypeOf((*storage.Storage)(nil)).Elem()
	for _, name := range []string{"RevertAccessReviewItemClaim"} {
		if _, ok := st.MethodByName(name); ok {
			t.Errorf("storage.Storage has %s again (#2803): an item-claim revert must carry a campaign-is-open condition and a production caller; update this pin together with that change", name)
		}
	}
	// Calibration: the claim itself is still there, so the check is looking at the
	// right interface.
	if _, ok := st.MethodByName("UpdateAccessReviewItem"); !ok {
		t.Fatal("storage.Storage lost UpdateAccessReviewItem: this pin is inspecting the wrong interface")
	}
}
