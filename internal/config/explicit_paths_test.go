package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExplicitlySetPathsIn_FlattensSequencesLikeSourcePaths(t *testing.T) {
	got, err := explicitlySetPathsIn([]byte(`
security:
  require_transport_tls: false
sso:
  providers:
    - name: a
    - name: b
      trust_asserted_email: true
`))
	require.NoError(t, err)
	for _, p := range []string{"security", "security.require_transport_tls", "sso.providers", "sso.providers.trust_asserted_email"} {
		assert.True(t, got[p], "%s is written by the file", p)
	}
	assert.False(t, got["security.require_mfa"], "an absent key is not explicit")
	assert.False(t, got["sso.providers.0.trust_asserted_email"], "sequence indices are flattened away")
}

func TestExplicitlySetPathsIn_EmptyFileWritesNothing(t *testing.T) {
	got, err := explicitlySetPathsIn([]byte("# comments only\n"))
	require.NoError(t, err)
	assert.Empty(t, got)
}

// yamlForDottedPath builds a minimal YAML document that writes path (alias-table
// spelling: a "seg[]" segment is a sequence with one element) to true.
func yamlForDottedPath(path string) string {
	var b strings.Builder
	indent := ""
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		last := i == len(segs)-1
		name := strings.TrimSuffix(seg, "[]")
		switch {
		case last:
			fmt.Fprintf(&b, "%s%s: true\n", indent, name)
		case strings.HasSuffix(seg, "[]"):
			fmt.Fprintf(&b, "%s%s:\n%s  - name: x\n", indent, name, indent)
			indent += "    "
		default:
			fmt.Fprintf(&b, "%s%s:\n", indent, name)
			indent += "  "
		}
	}
	return b.String()
}

// TestExplicitlySetPathsIn_DeprecatedAliasCountsAsItsCurrentKey is the guard for
// the #2899 x #2478 semantic merge: the posture report decides "explicit" vs
// "shipped default" by matching ExplicitlySetPaths against SourcePaths, and #2899
// moved every renamed entry's SourcePaths to the insecure_ name. A file that
// still writes the old (deprecated alias) key asked for the weakening just as
// explicitly, so for EVERY registry entry with a DeprecatedAlias, a file writing
// only the old key must be reported as writing one of its SourcePaths.
func TestExplicitlySetPathsIn_DeprecatedAliasCountsAsItsCurrentKey(t *testing.T) {
	checked := 0
	for _, s := range InsecureSettingsRegistry {
		if s.DeprecatedAlias == "" {
			continue
		}
		checked++
		doc := yamlForDottedPath(s.DeprecatedAlias)
		got, err := explicitlySetPathsIn([]byte(doc))
		require.NoError(t, err, s.Name)
		require.True(t, got[flattenSequencePath(s.DeprecatedAlias)], "%s: fixture must write the old key\n%s", s.Name, doc)
		found := false
		for _, p := range s.SourcePaths {
			found = found || got[p]
		}
		assert.True(t, found, "%s: a file writing only its deprecated alias %q must count as writing one of %v", s.Name, s.DeprecatedAlias, s.SourcePaths)
	}
	assert.NotZero(t, checked, "no registry entry has a DeprecatedAlias: this guard checks nothing")
}

func TestExplicitlySetPathsIn_FallbackChainAliasReportsCurrentKey(t *testing.T) {
	got, err := explicitlySetPathsIn([]byte(yamlForDottedPath("storage.encryption.key_provider.fallbacks[].allow_weaker_fallback")))
	require.NoError(t, err)
	assert.True(t, got["storage.encryption.key_provider.fallbacks.insecure_allow_weaker_kek_fallback"])
}
