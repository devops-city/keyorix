package crypto

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fallbackKMS is fakeKMS plus the context-fallback report (#3398): bound says
// whether the stored blob opens with its context (no retry needed).
type fallbackKMS struct {
	fakeKMS
	enabled bool
	bound   bool
}

func (f *fallbackKMS) ContextFallbackEnabled() bool { return f.enabled }
func (f *fallbackKMS) DecryptReportingFallback(ctx context.Context, ct []byte) ([]byte, bool, error) {
	pt, err := f.Decrypt(ctx, ct)
	return pt, err == nil && f.enabled && !f.bound, err
}

func TestKMSKeyProvider_ContextFallback(t *testing.T) {
	dir := t.TempDir()
	_, err := NewKMSKeyProvider(&fakeKMS{tag: "k"}, "aws-kms", dir, "kek.kms").KEK()
	require.NoError(t, err)

	t.Run("bound KEK with the flag is refused", func(t *testing.T) {
		_, err := NewKMSKeyProvider(&fallbackKMS{fakeKMS: fakeKMS{tag: "k"}, enabled: true, bound: true}, "aws-kms", dir, "kek.kms").KEK()
		require.ErrorIs(t, err, ErrKMSContextFallbackNotNeeded)
	})
	t.Run("unbound KEK with the flag unwraps", func(t *testing.T) {
		kek, err := NewKMSKeyProvider(&fallbackKMS{fakeKMS: fakeKMS{tag: "k"}, enabled: true}, "aws-kms", dir, "kek.kms").KEK()
		require.NoError(t, err)
		assert.Len(t, kek, KEKSize)
	})
	t.Run("flag off is never refused", func(t *testing.T) {
		_, err := NewKMSKeyProvider(&fallbackKMS{fakeKMS: fakeKMS{tag: "k"}, bound: true}, "aws-kms", dir, "kek.kms").KEK()
		require.NoError(t, err)
	})
	t.Run("a decrypt failure is reported as one, not as the refusal", func(t *testing.T) {
		_, err := NewKMSKeyProvider(&fallbackKMS{fakeKMS: fakeKMS{tag: "other"}, enabled: true}, "aws-kms", dir, "kek.kms").KEK()
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrKMSContextFallbackNotNeeded))
	})
}

// The refusal is a configuration error: a fallback chain must stop on it rather
// than move on to the next (possibly weaker) provider.
func TestMultiKeyProvider_StopsOnContextFallbackRefusal(t *testing.T) {
	dir := t.TempDir()
	_, err := NewKMSKeyProvider(&fakeKMS{tag: "k"}, "aws-kms", dir, "kek.kms").KEK()
	require.NoError(t, err)
	next := &fakeKMS{tag: "k"}
	mp, err := NewMultiKeyProvider([]KeyProvider{
		NewKMSKeyProvider(&fallbackKMS{fakeKMS: fakeKMS{tag: "k"}, enabled: true, bound: true}, "aws-kms", dir, "kek.kms"),
		NewKMSKeyProvider(next, "aws-kms", dir, "kek.kms"),
	})
	require.NoError(t, err)
	_, err = mp.KEK()
	require.ErrorIs(t, err, ErrKMSContextFallbackNotNeeded)
	assert.Zero(t, next.decrypts, "the next provider must not be tried")
}
