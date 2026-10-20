package core

// REVIEW-3482B: a SCIM PATCH that names the same current member in both the add and
// the remove list. Before the split (a675a36c) the single transaction applied the
// adds first and the removals last, so the removal won and the member was gone. The
// split applies the removals in commit 1 and the adds in commit 2, so the member is
// removed and then re-added: the request's revocation is undone, with no audit
// outage involved.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReview3482B_SCIMPatchAddAndRemoveSameMember_RemovalWins(t *testing.T) {
	ctx := context.Background()
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		n := w.tag("rv-scim")
		a, err := w.c.ProvisionSCIMUser(ctx, 0, n, n, n+"@example.com", "ext-"+n, true)
		require.NoError(t, err)
		g, err := w.c.ProvisionSCIMGroup(ctx, 0, w.tag("rv-g"), []uint{a.ID})
		require.NoError(t, err)
		require.True(t, w.inGroup(a.ID, g.ID), "precondition: a is a member")

		_, err = w.c.PatchSCIMGroup(ctx, 0, g.ID, nil, []uint{a.ID}, []uint{a.ID})
		require.NoError(t, err)
		require.False(t, w.inGroup(a.ID, g.ID),
			"a PATCH that removes a member must not leave that member in the group (pre-split: adds first, removals last)")
	})
}
