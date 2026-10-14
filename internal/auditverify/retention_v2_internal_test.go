package auditverify

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRetentionAnchorCanonicalV2_ExactByteFormat pins the v2 (#3257) signed
// layout, which must byte-for-byte match
// internal/core.auditRetentionAnchorCanonicalV2. The differential tests prove
// the parity end to end (core writes, this package verifies).
func TestRetentionAnchorCanonicalV2_ExactByteFormat(t *testing.T) {
	got := retentionAnchorCanonicalV2(9, "prevhash", "entryhash", 1234, "v1")
	assert.Equal(t, "retanchor-v2\x009\x00prevhash\x00entryhash\x001234\x00v1", got)
}

func TestParseRetentionAnchorValue_V2RoundTrip(t *testing.T) {
	key := []byte("k")
	sig := SignRetentionAnchorV2(3, "prev", "entry", 17, "v1", key)
	val := strings.Join([]string{"v2", "3", "prev", "entry", "17", "v1", sig}, auditRetentionAnchorSep)
	a, ok := ParseRetentionAnchorValue(val)
	require.True(t, ok)
	assert.Equal(t, StoredRetentionAnchor{Layout: "v2", RowID: 3, PrevHash: "prev", EntryHash: "entry",
		PurgedEvents: 17, KeyVersion: "v1", Signature: sig}, a)
	assert.True(t, a.SigMatches(key))

	a.PurgedEvents = 18
	assert.False(t, a.SigMatches(key), "the purged count is covered by the signature")
}

func TestParseRetentionAnchorValue_V1IsPurgedZero(t *testing.T) {
	key := []byte("k")
	sig := SignRetentionAnchor(3, "prev", "entry", "v1", key)
	a, ok := ParseRetentionAnchorValue(strings.Join([]string{"v1", "3", "prev", "entry", "v1", sig}, auditRetentionAnchorSep))
	require.True(t, ok)
	assert.Equal(t, "v1", a.Layout)
	assert.Zero(t, a.PurgedEvents)
	assert.True(t, a.SigMatches(key))
}

// A v2 signature never verifies once the value is relabelled v1 (count
// dropped), and vice versa: the layouts are domain-separated.
func TestParseRetentionAnchorValue_LayoutsDomainSeparated(t *testing.T) {
	key := []byte("k")
	v2sig := SignRetentionAnchorV2(3, "prev", "entry", 0, "v1", key)
	a, ok := ParseRetentionAnchorValue(strings.Join([]string{"v1", "3", "prev", "entry", "v1", v2sig}, auditRetentionAnchorSep))
	require.True(t, ok)
	assert.False(t, a.SigMatches(key))

	v1sig := SignRetentionAnchor(3, "prev", "entry", "v1", key)
	a, ok = ParseRetentionAnchorValue(strings.Join([]string{"v2", "3", "prev", "entry", "0", "v1", v1sig}, auditRetentionAnchorSep))
	require.True(t, ok)
	assert.False(t, a.SigMatches(key))
}

func TestParseRetentionAnchorValue_Malformed(t *testing.T) {
	for _, val := range []string{
		strings.Join([]string{"v2", "3", "prev", "entry", "-1", "v1", "sig"}, auditRetentionAnchorSep), // negative count
		strings.Join([]string{"v2", "3", "prev", "entry", "x", "v1", "sig"}, auditRetentionAnchorSep),  // non-numeric count
		strings.Join([]string{"v2", "0", "prev", "entry", "1", "v1", "sig"}, auditRetentionAnchorSep),  // zero row id
		strings.Join([]string{"v2", "3", "prev", "entry", "v1", "sig"}, auditRetentionAnchorSep),       // v2 with 6 fields
		strings.Join([]string{"v3", "3", "prev", "entry", "1", "v1", "sig"}, auditRetentionAnchorSep),  // unknown layout
		strings.Join([]string{"v2", "3", "prev", "entry", "1", "v1", "sig"}, "\x00"),                   // NUL separator
	} {
		_, ok := ParseRetentionAnchorValue(val)
		assert.False(t, ok, "%q must not parse", val)
	}
}
