package controller

// FIX-3175B: suspended / expired source secrets, and the expiry warnings ahead of them.
// Policy under test (Andrei, 2026-10-13): fetch failures never touch the target Secret;
// an expired source is retained; a suspended source is retained by default
// (spec.onSuspend: Retain) or cleared (Clear: the managed keys are emptied, the Secret
// object is not deleted); resuming restores the data on the next reconcile; every state
// raises a Warning Event + the SourceSecretHealthy condition + a gauge, cleared on recovery.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/keyorix"
)

const (
	refPW  = "app/production/db-password"
	refKey = "app/production/api-key"
)

// stateFetcher serves values and reports per-ref state, including expiration, so the
// reconciler's FetchValueInfo path is exercised.
type stateFetcher struct {
	values     map[string][]byte
	suspended  map[string]bool
	expired    map[string]bool
	transient  map[string]error
	expiration map[string]time.Time
}

func (f *stateFetcher) FetchValue(ctx context.Context, ref string) ([]byte, error) {
	v, err := f.FetchValueInfo(ctx, ref)
	return v.Data, err
}

func (f *stateFetcher) FetchValueInfo(_ context.Context, ref string) (keyorix.Value, error) {
	switch {
	case f.transient[ref] != nil:
		return keyorix.Value{}, f.transient[ref]
	case f.suspended[ref]:
		return keyorix.Value{}, fmt.Errorf("secret reference %q: SecretSuspended (HTTP 409): %w", ref, keyorix.ErrSecretSuspended)
	case f.expired[ref]:
		return keyorix.Value{}, fmt.Errorf("secret reference %q: SecretExpired (HTTP 409): %w", ref, keyorix.ErrSecretExpired)
	}
	v := keyorix.Value{Data: f.values[ref]}
	if t, ok := f.expiration[ref]; ok {
		v.Expiration = &t
	}
	return v, nil
}

func newStateFetcher() *stateFetcher {
	return &stateFetcher{
		values:     map[string][]byte{refPW: []byte("p4ss"), refKey: []byte("k3y")},
		suspended:  map[string]bool{},
		expired:    map[string]bool{},
		transient:  map[string]error{},
		expiration: map[string]time.Time{},
	}
}

func stateReconciler(t *testing.T, f *stateFetcher, onSuspend secretsv1alpha1.OnSuspend, objs ...client.Object) (*KeyorixSecretReconciler, client.Client, *events.FakeRecorder) {
	t.Helper()
	ks := ksFixture()
	ks.Spec.OnSuspend = onSuspend
	r, c := newReconciler(t, f, append([]client.Object{ks, tokenSecret()}, objs...)...)
	rec := events.NewFakeRecorder(32)
	r.Recorder = rec
	return r, c, rec
}

func getTarget(t *testing.T, c client.Client) (corev1.Secret, bool) {
	t.Helper()
	var s corev1.Secret
	err := c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &s)
	if err != nil {
		require.True(t, client.IgnoreNotFound(err) == nil, "unexpected error: %v", err)
		return s, false
	}
	return s, true
}

func getKS(t *testing.T, c client.Client) secretsv1alpha1.KeyorixSecret {
	t.Helper()
	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	return ks
}

func condition(ks secretsv1alpha1.KeyorixSecret, typ string) *metav1.Condition {
	return findCondition(ks.Status.Conditions, typ)
}

// drainEvents returns the events buffered so far.
func drainEvents(rec *events.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func gauge(state string) float64 {
	var m dto.Metric
	if err := sourceSecretsGauge.WithLabelValues(state).Write(&m); err != nil {
		panic(err)
	}
	return m.GetGauge().GetValue()
}

// Fetch failures other than a definitive answer never modify or delete the Secret: the
// error is surfaced on Ready and the reconcile is retried, in both onSuspend modes.
func TestSourceState_TransientFailuresNeverTouchTheTargetSecret(t *testing.T) {
	for _, mode := range []secretsv1alpha1.OnSuspend{secretsv1alpha1.OnSuspendRetain, secretsv1alpha1.OnSuspendClear} {
		for name, ferr := range map[string]error{
			"server unreachable": errors.New("request failed: dial tcp 10.0.0.1:443: connect: connection refused"),
			"timeout":            context.DeadlineExceeded,
			"5xx":                errors.New("server returned HTTP 503"),
			"schedule/max reads": fmt.Errorf("outside schedule: %w", keyorix.ErrSecretUnavailable),
		} {
			t.Run(string(mode)+"/"+name, func(t *testing.T) {
				f := newStateFetcher()
				r, c, rec := stateReconciler(t, f, mode)
				_, err := reconcile(t, r)
				require.NoError(t, err)
				before, ok := getTarget(t, c)
				require.True(t, ok)

				f.transient[refKey] = ferr
				_, err = reconcile(t, r)
				require.Error(t, err, "a failed fetch is retried with backoff")

				after, ok := getTarget(t, c)
				require.True(t, ok, "the target Secret must not be deleted")
				assert.Equal(t, before.Data, after.Data, "the target Secret must not be modified")
				assert.Equal(t, before.ResourceVersion, after.ResourceVersion, "not even rewritten")
				ks := getKS(t, c)
				ready := condition(ks, conditionReady)
				require.NotNil(t, ready)
				assert.Equal(t, metav1.ConditionFalse, ready.Status)
				assert.Equal(t, "SyncError", ready.Reason)
				assert.Nil(t, condition(ks, conditionSourceHealthy), "not a source-state situation")
				assert.Empty(t, drainEvents(rec))
			})
		}
	}
}

// Expired: always retained. Warning Event once, condition, gauge; cleared on recovery.
func TestSourceState_ExpiredIsRetained(t *testing.T) {
	f := newStateFetcher()
	r, c, rec := stateReconciler(t, f, "") // onSuspend irrelevant to expiry
	_, err := reconcile(t, r)
	require.NoError(t, err)
	before, _ := getTarget(t, c)

	f.values[refKey] = []byte("rotated-while-expired") // would be written if the sync ran
	f.expired[refKey] = true
	res, err := reconcile(t, r)
	require.NoError(t, err, "an expected state is not an error to back off from")
	assert.Positive(t, res.RequeueAfter, "re-checked at the refresh interval")

	after, ok := getTarget(t, c)
	require.True(t, ok, "an expired source must NOT delete the target Secret")
	assert.Equal(t, before.Data, after.Data, "nor change it")
	ks := getKS(t, c)
	hc := condition(ks, conditionSourceHealthy)
	require.NotNil(t, hc)
	assert.Equal(t, metav1.ConditionFalse, hc.Status)
	assert.Equal(t, "SourceSecretExpired", hc.Reason)
	assert.Contains(t, hc.Message, refKey)
	ready := condition(ks, conditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, "SourceSecretExpired", ready.Reason)
	assert.Equal(t, 1.0, gauge("expired"))
	ev := drainEvents(rec)
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "Warning")
	assert.Contains(t, ev[0], "SourceSecretExpired")

	// Still expired next interval: no Event spam.
	_, err = reconcile(t, r)
	require.NoError(t, err)
	assert.Empty(t, drainEvents(rec))

	// Recovered (expiry extended): data syncs, condition and gauge clear, Normal Event.
	delete(f.expired, refKey)
	_, err = reconcile(t, r)
	require.NoError(t, err)
	after, _ = getTarget(t, c)
	assert.Equal(t, []byte("rotated-while-expired"), after.Data["API_KEY"])
	ks = getKS(t, c)
	assert.Nil(t, condition(ks, conditionSourceHealthy))
	assert.Equal(t, metav1.ConditionTrue, condition(ks, conditionReady).Status)
	assert.Equal(t, 0.0, gauge("expired"))
	ev = drainEvents(rec)
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "Normal")
	assert.Contains(t, ev[0], "SourceSecretRecovered")
}

// Suspended + Retain (the default, also the empty value): nothing is written or removed;
// resuming restores on the next reconcile.
func TestSourceState_SuspendedRetain_SuspendThenResume(t *testing.T) {
	for _, mode := range []secretsv1alpha1.OnSuspend{"", secretsv1alpha1.OnSuspendRetain} {
		t.Run("onSuspend="+string(mode), func(t *testing.T) {
			f := newStateFetcher()
			r, c, rec := stateReconciler(t, f, mode)
			_, err := reconcile(t, r)
			require.NoError(t, err)
			original, _ := getTarget(t, c)

			f.suspended[refPW] = true
			f.suspended[refKey] = true
			res, err := reconcile(t, r)
			require.NoError(t, err)
			assert.Positive(t, res.RequeueAfter)

			held, ok := getTarget(t, c)
			require.True(t, ok)
			assert.Equal(t, original.Data, held.Data, "Retain keeps the last value")
			hc := condition(getKS(t, c), conditionSourceHealthy)
			require.NotNil(t, hc)
			assert.Equal(t, "SourceSecretSuspended", hc.Reason)
			assert.Equal(t, 1.0, gauge("suspended"))
			ev := drainEvents(rec)
			require.Len(t, ev, 1)
			assert.Contains(t, ev[0], "SourceSecretSuspended")

			// Resumed with a new value: the next reconcile restores/updates it.
			f.suspended = map[string]bool{}
			f.values[refPW] = []byte("after-resume")
			_, err = reconcile(t, r)
			require.NoError(t, err)
			restored, _ := getTarget(t, c)
			assert.Equal(t, []byte("after-resume"), restored.Data["DB_PASSWORD"])
			assert.Nil(t, condition(getKS(t, c), conditionSourceHealthy))
			assert.Equal(t, 0.0, gauge("suspended"))
		})
	}
}

// Suspended + Clear: the managed keys are emptied (the Secret object, its name, labels
// and owner stay), and the next reconcile after resume recreates the same data.
func TestSourceState_SuspendedClear_ClearsThenRestores(t *testing.T) {
	f := newStateFetcher()
	r, c, rec := stateReconciler(t, f, secretsv1alpha1.OnSuspendClear)
	_, err := reconcile(t, r)
	require.NoError(t, err)
	original, _ := getTarget(t, c)
	require.NotEmpty(t, original.Data)

	f.suspended[refPW] = true
	f.suspended[refKey] = true
	res, err := reconcile(t, r)
	require.NoError(t, err)
	assert.Positive(t, res.RequeueAfter)

	cleared, ok := getTarget(t, c)
	require.True(t, ok, "Clear empties the keys but never deletes the Secret")
	assert.Empty(t, cleared.Data)
	assert.Equal(t, original.Labels, cleared.Labels)
	assert.Equal(t, original.OwnerReferences, cleared.OwnerReferences)
	hc := condition(getKS(t, c), conditionSourceHealthy)
	require.NotNil(t, hc)
	assert.Equal(t, "SourceSecretSuspended", hc.Reason)
	ev := drainEvents(rec)
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "Warning")
	assert.Contains(t, ev[0], "SourceSecretSuspended")

	// A second pass while suspended changes nothing and raises no new Event.
	_, err = reconcile(t, r)
	require.NoError(t, err)
	again, _ := getTarget(t, c)
	assert.Empty(t, again.Data)
	assert.Empty(t, drainEvents(rec))

	// Resumed: the next reconcile recreates the same data under the same name and labels.
	f.suspended = map[string]bool{}
	_, err = reconcile(t, r)
	require.NoError(t, err)
	restored, ok := getTarget(t, c)
	require.True(t, ok)
	assert.Equal(t, original.Data, restored.Data, "same data as before the suspension")
	assert.Equal(t, original.Labels, restored.Labels)
	assert.Equal(t, original.OwnerReferences, restored.OwnerReferences)
	assert.Nil(t, condition(getKS(t, c), conditionSourceHealthy))
	ev = drainEvents(rec)
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "SourceSecretRecovered")
}

// Clear drops only the suspended refs' keys when others are readable.
func TestSourceState_SuspendedClear_PartialKeepsReadableKeys(t *testing.T) {
	f := newStateFetcher()
	r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendClear)
	_, err := reconcile(t, r)
	require.NoError(t, err)

	f.suspended[refKey] = true
	_, err = reconcile(t, r)
	require.NoError(t, err)
	got, _ := getTarget(t, c)
	assert.Equal(t, map[string][]byte{"DB_PASSWORD": []byte("p4ss")}, got.Data)
}

// Clear never touches a Secret the operator does not own, and never creates an empty one.
func TestSourceState_SuspendedClear_DoesNotTouchUnownedOrCreate(t *testing.T) {
	t.Run("unmanaged Secret with the target name is left alone", func(t *testing.T) {
		foreign := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "app"},
			Data:       map[string][]byte{"THEIRS": []byte("keep-me")},
		}
		f := newStateFetcher()
		f.suspended[refPW], f.suspended[refKey] = true, true
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendClear, foreign)
		_, err := reconcile(t, r)
		require.NoError(t, err)
		got, ok := getTarget(t, c)
		require.True(t, ok)
		assert.Equal(t, map[string][]byte{"THEIRS": []byte("keep-me")}, got.Data)
	})
	t.Run("no Secret yet: none is created", func(t *testing.T) {
		f := newStateFetcher()
		f.suspended[refPW], f.suspended[refKey] = true, true
		r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendClear)
		_, err := reconcile(t, r)
		require.NoError(t, err)
		_, ok := getTarget(t, c)
		assert.False(t, ok)
	})
}

// Ahead of an expiry the Warning Event fires when the secret first comes within 30
// days, again within 7, again within 1; nothing while the window is unchanged.
func TestSourceState_ExpiryWarningsAt30_7_1Days(t *testing.T) {
	f := newStateFetcher()
	r, c, rec := stateReconciler(t, f, "")
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	expiry := now.Add(60 * 24 * time.Hour)
	f.expiration[refPW] = expiry

	step := func(at time.Time) []string {
		now = at
		_, err := reconcile(t, r)
		require.NoError(t, err)
		return drainEvents(rec)
	}

	assert.Empty(t, step(now), "60 days out: no warning")
	assert.Nil(t, condition(getKS(t, c), conditionSourceHealthy))

	ev := step(expiry.Add(-29 * 24 * time.Hour))
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "SourceSecretExpiring")
	assert.Contains(t, ev[0], "30d")
	hc := condition(getKS(t, c), conditionSourceHealthy)
	require.NotNil(t, hc)
	assert.Equal(t, "SourceSecretExpiring", hc.Reason)
	assert.Equal(t, 1.0, gauge("expiring"))
	// The target is still synced normally while only warning.
	got, _ := getTarget(t, c)
	assert.Equal(t, []byte("p4ss"), got.Data["DB_PASSWORD"])
	assert.Equal(t, metav1.ConditionTrue, condition(getKS(t, c), conditionReady).Status)

	assert.Empty(t, step(expiry.Add(-20*24*time.Hour)), "same window: no new Event")

	ev = step(expiry.Add(-6 * 24 * time.Hour))
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "7d")

	ev = step(expiry.Add(-12 * time.Hour))
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "1d")

	// The expiry is extended on the server: warning clears with a Normal Event.
	f.expiration[refPW] = expiry.Add(365 * 24 * time.Hour)
	ev = step(expiry.Add(-6 * time.Hour))
	require.Len(t, ev, 1)
	assert.Contains(t, ev[0], "SourceSecretRecovered")
	assert.Nil(t, condition(getKS(t, c), conditionSourceHealthy))
	assert.Equal(t, 0.0, gauge("expiring"))
}

// Fetchers that cannot report an expiration (only FetchValue) simply give no warnings.
func TestSourceState_FetcherWithoutExpiryInfoStillSyncs(t *testing.T) {
	r, c := newReconciler(t, &fakeFetcher{values: map[string][]byte{refPW: []byte("p4ss"), refKey: []byte("k3y")}}, ksFixture(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)
	_, ok := getTarget(t, c)
	assert.True(t, ok)
}

// FIX-3175D (REVIEW-3175B a, b): a held ref (expired, or suspended under Retain) freezes
// only ITS keys. The other refs' keys keep syncing in the same single Secret update, so a
// rotation of a readable sibling propagates; a held key is never overwritten or deleted.
func TestSourceState_PerKeyHold_ReadableSiblingKeepsSyncing(t *testing.T) {
	cases := []struct {
		name   string
		mode   secretsv1alpha1.OnSuspend
		hold   func(f *stateFetcher)
		reason string
	}{
		{"expired", "", func(f *stateFetcher) { f.expired[refKey] = true }, "SourceSecretExpired"},
		{"suspended+Retain", secretsv1alpha1.OnSuspendRetain, func(f *stateFetcher) { f.suspended[refKey] = true }, "SourceSecretSuspended"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStateFetcher()
			r, c, rec := stateReconciler(t, f, tc.mode)
			_, err := reconcile(t, r)
			require.NoError(t, err)
			before, _ := getTarget(t, c)
			drainEvents(rec)

			tc.hold(f)
			f.values[refKey] = []byte("must-not-be-written") // the held ref's key
			f.values[refPW] = []byte("rotated-sibling")
			res, err := reconcile(t, r)
			require.NoError(t, err, "an expected state is not an error to back off from")
			assert.Positive(t, res.RequeueAfter)

			after, ok := getTarget(t, c)
			require.True(t, ok)
			assert.Equal(t, []byte("rotated-sibling"), after.Data["DB_PASSWORD"], "the readable sibling's rotation propagates")
			assert.Equal(t, before.Data["API_KEY"], after.Data["API_KEY"], "the held key is untouched")
			assert.Len(t, after.Data, 2, "the held key is never deleted")

			ks := getKS(t, c)
			ready := condition(ks, conditionReady)
			require.NotNil(t, ready)
			assert.Equal(t, metav1.ConditionFalse, ready.Status, "a held key keeps Ready False so alerts keep firing")
			assert.Equal(t, tc.reason, ready.Reason)
			assert.Contains(t, ready.Message, "API_KEY")
			hc := condition(ks, conditionSourceHealthy)
			require.NotNil(t, hc)
			assert.Equal(t, tc.reason, hc.Reason)
			ev := drainEvents(rec)
			require.Len(t, ev, 1)
			assert.Contains(t, ev[0], tc.reason)

			// A second sibling rotation while still held propagates too, with no new Event.
			f.values[refPW] = []byte("rotated-again")
			_, err = reconcile(t, r)
			require.NoError(t, err)
			again, _ := getTarget(t, c)
			assert.Equal(t, []byte("rotated-again"), again.Data["DB_PASSWORD"])
			assert.Equal(t, before.Data["API_KEY"], again.Data["API_KEY"])
			assert.Empty(t, drainEvents(rec))

			// Recovery: the held key syncs again, the condition clears.
			f.expired, f.suspended = map[string]bool{}, map[string]bool{}
			f.values[refKey] = []byte("fresh")
			_, err = reconcile(t, r)
			require.NoError(t, err)
			rec2, _ := getTarget(t, c)
			assert.Equal(t, []byte("fresh"), rec2.Data["API_KEY"])
			ks = getKS(t, c)
			assert.Nil(t, condition(ks, conditionSourceHealthy))
			assert.Equal(t, metav1.ConditionTrue, condition(ks, conditionReady).Status)
		})
	}
}

// Every ref held: nothing is written at all (not even a no-op update).
func TestSourceState_PerKeyHold_AllRefsHeldWritesNothing(t *testing.T) {
	f := newStateFetcher()
	r, c, _ := stateReconciler(t, f, "")
	_, err := reconcile(t, r)
	require.NoError(t, err)
	before, _ := getTarget(t, c)

	f.expired[refPW], f.expired[refKey] = true, true
	_, err = reconcile(t, r)
	require.NoError(t, err)
	after, _ := getTarget(t, c)
	assert.Equal(t, before.Data, after.Data)
	assert.Equal(t, before.ResourceVersion, after.ResourceVersion)
}

// A held key that was never synced has nothing to keep: the readable keys are still
// created; the held key is simply absent until its source recovers.
func TestSourceState_PerKeyHold_NeverSyncedHeldKeyIsAbsent(t *testing.T) {
	f := newStateFetcher()
	f.expired[refKey] = true
	r, c, _ := stateReconciler(t, f, "")
	_, err := reconcile(t, r)
	require.NoError(t, err)
	got, ok := getTarget(t, c)
	require.True(t, ok)
	assert.Equal(t, map[string][]byte{"DB_PASSWORD": []byte("p4ss")}, got.Data)
}

// onSuspend=Clear is applied to a suspended ref even while a sibling is expired: only the
// suspended ref's key is cleared, the expired ref's key is held, nothing else changes.
func TestSourceState_PerKeyHold_ClearAppliesWithExpiredSibling(t *testing.T) {
	f := newStateFetcher()
	r, c, _ := stateReconciler(t, f, secretsv1alpha1.OnSuspendClear)
	_, err := reconcile(t, r)
	require.NoError(t, err)
	before, _ := getTarget(t, c)

	f.suspended[refPW] = true
	f.expired[refKey] = true
	_, err = reconcile(t, r)
	require.NoError(t, err)
	got, ok := getTarget(t, c)
	require.True(t, ok, "the Secret object stays")
	assert.Equal(t, map[string][]byte{"API_KEY": before.Data["API_KEY"]}, got.Data,
		"the suspended ref's key is cleared, the expired ref's key is held")
	ready := condition(getKS(t, c), conditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, "SourceSecretExpired", ready.Reason)
}
