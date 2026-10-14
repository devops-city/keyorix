package controller

// SUSPEND-PURGE-1: a suspension that asks (details.clear_synced_copies on the 409
// SecretSuspended) for the synced copies to be cleared is treated as onSuspend=Clear for
// that ref, over spec.onSuspend=Retain. Same Clear semantics as FIX-3175B: only the keys
// the operator manages are emptied, a Secret it does not own is never touched or created,
// the Secret object stays, and resuming restores the data on the next reconcile.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
)

func TestSourceState_ClearRequested_OverridesRetain_ThenRestoresOnResume(t *testing.T) {
	for _, mode := range []secretsv1alpha1.OnSuspend{"", secretsv1alpha1.OnSuspendRetain} {
		t.Run("onSuspend="+string(mode), func(t *testing.T) {
			f := newStateFetcher()
			r, c, rec := stateReconciler(t, f, mode)
			_, err := reconcile(t, r)
			require.NoError(t, err)
			original, _ := getTarget(t, c)
			require.NotEmpty(t, original.Data)

			f.suspended[refPW], f.suspended[refKey] = true, true
			f.clearRequested[refPW], f.clearRequested[refKey] = true, true
			_, err = reconcile(t, r)
			require.NoError(t, err)

			cleared, ok := getTarget(t, c)
			require.True(t, ok, "the Secret object is never deleted")
			assert.Empty(t, cleared.Data, "the suspension's request beats onSuspend=Retain")
			assert.Equal(t, original.Labels, cleared.Labels)
			assert.Equal(t, original.OwnerReferences, cleared.OwnerReferences)
			hc := condition(getKS(t, c), conditionSourceHealthy)
			require.NotNil(t, hc)
			assert.Equal(t, "SourceSecretSuspended", hc.Reason)
			assert.Contains(t, hc.Message, "cleared at the suspension's request")
			ev := drainEvents(rec)
			require.Len(t, ev, 1)
			assert.Contains(t, ev[0], "SourceSecretSuspended")

			// Resume: the request goes with the suspension; the data comes back.
			f.suspended = map[string]bool{}
			f.clearRequested = map[string]bool{}
			_, err = reconcile(t, r)
			require.NoError(t, err)
			restored, _ := getTarget(t, c)
			assert.Equal(t, original.Data, restored.Data)
			assert.Nil(t, condition(getKS(t, c), conditionSourceHealthy))
		})
	}
}

// Without the request, Retain still retains: the override is per suspension, not global.
func TestSourceState_PlainSuspend_StillRetainedUnderRetain(t *testing.T) {
	f := newStateFetcher()
	r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain)
	_, err := reconcile(t, r)
	require.NoError(t, err)
	original, _ := getTarget(t, c)

	f.suspended[refPW], f.suspended[refKey] = true, true
	_, err = reconcile(t, r)
	require.NoError(t, err)
	held, _ := getTarget(t, c)
	assert.Equal(t, original.Data, held.Data)
}

// #3215: a secret that is expired AND suspended with the request still has its copies
// cleared (the server answers SecretExpired carrying the marker); expired alone is
// retained with the usual warning.
func TestSourceState_ClearRequested_AlsoWhenExpired(t *testing.T) {
	t.Run("expired + suspended with the request: cleared, restored on resume", func(t *testing.T) {
		f := newStateFetcher()
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain)
		_, err := reconcile(t, r)
		require.NoError(t, err)
		original, _ := getTarget(t, c)
		require.NotEmpty(t, original.Data)

		f.expired[refPW], f.expired[refKey] = true, true
		f.clearRequested[refPW], f.clearRequested[refKey] = true, true
		_, err = reconcile(t, r)
		require.NoError(t, err)
		cleared, ok := getTarget(t, c)
		require.True(t, ok, "the Secret object is never deleted")
		assert.Empty(t, cleared.Data)
		assert.Equal(t, original.Labels, cleared.Labels)

		f.expired = map[string]bool{}
		f.clearRequested = map[string]bool{}
		_, err = reconcile(t, r)
		require.NoError(t, err)
		restored, _ := getTarget(t, c)
		assert.Equal(t, original.Data, restored.Data)
	})
	t.Run("expired only: retained (keep + warn unchanged)", func(t *testing.T) {
		f := newStateFetcher()
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain)
		_, err := reconcile(t, r)
		require.NoError(t, err)
		original, _ := getTarget(t, c)

		f.expired[refPW], f.expired[refKey] = true, true
		_, err = reconcile(t, r)
		require.NoError(t, err)
		held, _ := getTarget(t, c)
		assert.Equal(t, original.Data, held.Data)
		hc := condition(getKS(t, c), conditionSourceHealthy)
		require.NotNil(t, hc)
		assert.Equal(t, "SourceSecretExpired", hc.Reason)
	})
	t.Run("expired + request never touches an unowned Secret or creates one", func(t *testing.T) {
		foreign := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "app"},
			Data:       map[string][]byte{"THEIRS": []byte("keep-me")},
		}
		f := newStateFetcher()
		f.expired[refPW], f.expired[refKey] = true, true
		f.clearRequested[refPW], f.clearRequested[refKey] = true, true
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain, foreign)
		_, err := reconcile(t, r)
		require.NoError(t, err)
		got, ok := getTarget(t, c)
		require.True(t, ok)
		assert.Equal(t, map[string][]byte{"THEIRS": []byte("keep-me")}, got.Data)
	})
}

// The request clears only the refs whose suspension made it; a sibling that is merely
// suspended under Retain keeps its value and a readable sibling keeps syncing.
func TestSourceState_ClearRequested_AppliesPerRef(t *testing.T) {
	t.Run("sibling suspended without the request is retained", func(t *testing.T) {
		f := newStateFetcher()
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain)
		_, err := reconcile(t, r)
		require.NoError(t, err)

		f.suspended[refPW], f.suspended[refKey] = true, true
		f.clearRequested[refPW] = true // only the password was reported compromised
		_, err = reconcile(t, r)
		require.NoError(t, err)
		got, _ := getTarget(t, c)
		assert.Equal(t, map[string][]byte{"API_KEY": []byte("k3y")}, got.Data)
	})
	t.Run("readable sibling keeps syncing", func(t *testing.T) {
		f := newStateFetcher()
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain)
		_, err := reconcile(t, r)
		require.NoError(t, err)

		f.suspended[refKey], f.clearRequested[refKey] = true, true
		f.values[refPW] = []byte("rotated")
		_, err = reconcile(t, r)
		require.NoError(t, err)
		got, _ := getTarget(t, c)
		assert.Equal(t, map[string][]byte{"DB_PASSWORD": []byte("rotated")}, got.Data)
	})
}

// Clear semantics are exactly FIX-3175B's: an unowned Secret is never touched, and no
// empty Secret is created.
func TestSourceState_ClearRequested_NeverTouchesUnownedOrCreates(t *testing.T) {
	t.Run("unmanaged Secret with the target name is left alone", func(t *testing.T) {
		foreign := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "app"},
			Data:       map[string][]byte{"THEIRS": []byte("keep-me")},
		}
		f := newStateFetcher()
		f.suspended[refPW], f.suspended[refKey] = true, true
		f.clearRequested[refPW], f.clearRequested[refKey] = true, true
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain, foreign)
		_, err := reconcile(t, r)
		require.NoError(t, err)
		got, ok := getTarget(t, c)
		require.True(t, ok)
		assert.Equal(t, map[string][]byte{"THEIRS": []byte("keep-me")}, got.Data)
	})
	t.Run("no Secret yet: none is created", func(t *testing.T) {
		f := newStateFetcher()
		f.suspended[refPW], f.suspended[refKey] = true, true
		f.clearRequested[refPW], f.clearRequested[refKey] = true, true
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendRetain)
		_, err := reconcile(t, r)
		require.NoError(t, err)
		_, ok := getTarget(t, c)
		assert.False(t, ok)
	})
}
