package k8ssync

// FIX-3175D (REVIEW-3175B a, b): a held source (expired, or suspended under retain)
// freezes only ITS key. The target's other keys keep syncing in the same single Apply, a
// held key is never overwritten or deleted, and on_suspend=clear still empties a
// suspended key while a sibling is expired.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// heldFetcher serves values and refuses suspended / expired refs.
type heldFetcher struct {
	values    map[string][]byte
	suspended map[string]bool
	expired   map[string]bool
}

func (h *heldFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	switch {
	case h.suspended[ref]:
		return nil, fmt.Errorf("%q: %w", ref, ErrSourceSuspended)
	case h.expired[ref]:
		return nil, fmt.Errorf("%q: %w", ref, ErrSourceExpired)
	}
	return h.values[ref], nil
}

var heldMappings = []SecretMapping{
	{Ref: "prod/ok", Namespace: "app", Name: "s", Key: "ok"},
	{Ref: "prod/held", Namespace: "app", Name: "s", Key: "held"},
}

func heldWorld(f *heldFetcher, opts ...Option) (*Engine, *fakeSink) {
	sink := newFakeSink()
	sink.existing["app/s"] = map[string][]byte{"ok": []byte("old"), "held": []byte("held-value")}
	sink.owned["app/s"] = true
	return NewEngine(f, sink, opts...), sink
}

func TestPerKeyHold_ReadableSiblingKeepsSyncing(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *heldFetcher
		opts []Option
	}{
		{"expired", &heldFetcher{expired: map[string]bool{"prod/held": true}}, nil},
		{"suspended+retain", &heldFetcher{suspended: map[string]bool{"prod/held": true}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.f.values = map[string][]byte{"prod/ok": []byte("rotated"), "prod/held": []byte("must-not-be-written")}
			eng, sink := heldWorld(tc.f, tc.opts...)
			res, err := eng.Reconcile(context.Background(), heldMappings)
			require.NoError(t, err)
			assert.Equal(t, map[string][]byte{"ok": []byte("rotated"), "held": []byte("held-value")}, sink.applied["app/s"],
				"the readable sibling's rotation is applied, the held key is carried over untouched, in ONE Apply")
			assert.Equal(t, 1, res.Updated, "%+v", res)
			assert.Zero(t, res.Failed)
		})
	}
}

func TestPerKeyHold_AllMappingsHeldAppliesNothing(t *testing.T) {
	f := &heldFetcher{expired: map[string]bool{"prod/ok": true, "prod/held": true}}
	eng, sink := heldWorld(f)
	_, err := eng.Reconcile(context.Background(), heldMappings)
	require.NoError(t, err)
	assert.Empty(t, sink.applied, "nothing is written when every key is held")
}

func TestPerKeyHold_NeverSyncedHeldKeyIsAbsent(t *testing.T) {
	f := &heldFetcher{values: map[string][]byte{"prod/ok": []byte("v")}, expired: map[string]bool{"prod/held": true}}
	sink := newFakeSink()
	eng := NewEngine(f, sink)
	_, err := eng.Reconcile(context.Background(), heldMappings)
	require.NoError(t, err)
	assert.Equal(t, map[string][]byte{"ok": []byte("v")}, sink.applied["app/s"])
}

// on_suspend=clear is applied to a suspended mapping even while a sibling mapping of the
// same target is expired: only the suspended key is dropped, the expired one is held.
func TestPerKeyHold_ClearAppliesWithExpiredSibling(t *testing.T) {
	f := &heldFetcher{suspended: map[string]bool{"prod/ok": true}, expired: map[string]bool{"prod/held": true}}
	eng, sink := heldWorld(f, WithClearOnSuspend())
	_, err := eng.Reconcile(context.Background(), heldMappings)
	require.NoError(t, err)
	assert.Equal(t, map[string][]byte{"held": []byte("held-value")}, sink.applied["app/s"],
		"the suspended key is cleared, the expired key is held")
}
