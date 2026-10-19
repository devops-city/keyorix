package yamlescape

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/secrettemplate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// EscapeYAMLString must produce content that, wrapped in a pair of double quotes,
// round-trips back to the exact original value when parsed as a YAML double-quoted
// scalar — mirroring TestEscapeJSONString_RoundTrips for YAML.
func TestEscapeYAMLString_RoundTrips(t *testing.T) {
	cases := map[string]string{
		"double quote":           `x"y`,
		"backslash":              `x\y`,
		"quote and backslash":    `x\"y`,
		"newline":                "x\ny",
		"crlf":                   "x\r\ny",
		"tab":                    "x\ty",
		"colon":                  "x: y",
		"yaml injection payload": "x\"\nadmin: true\nx: \"",
		"unicode":                "snowman ☃ emoji \U0001F600",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			escaped := EscapeYAMLString(val)
			wrapped := `"` + escaped + `"`
			var got string
			require.NoError(t, yaml.Unmarshal([]byte(wrapped), &got), "escaped value wrapped in quotes must parse as a valid YAML double-quoted scalar: %q", wrapped)
			assert.Equal(t, val, got, "round-tripping the escaped value through a YAML double-quoted scalar must reproduce the original")
		})
	}
}

// Same scenario as TestRenderJSON_NeutralizesJSONFieldInjection, but for a template
// that builds a YAML flow-style mapping (YAML's flow style is close enough to JSON
// syntax that the same quote-breakout shape applies) around a placeholder.
func TestRenderYAML_NeutralizesFlowMappingInjection(t *testing.T) {
	const payload = `x", "admin": true, "x":"`
	resolve := func(ref string) (string, error) { return payload, nil }
	tmpl := `{"password": "${secret:prod/db}"}`

	raw, err := secrettemplate.Render(tmpl, resolve)
	require.NoError(t, err)
	var rawParsed map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(raw), &rawParsed), "raw output: %s", raw)
	assert.Equal(t, true, rawParsed["admin"], "raw Render's substitution let the secret value inject an unrelated admin field")

	out, err := RenderYAML(tmpl, resolve)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(out), &parsed), "RenderYAML output: %s", out)
	assert.Equal(t, payload, parsed["password"], "RenderYAML must preserve the secret value exactly, as the password field's content")
	_, hasAdmin := parsed["admin"]
	assert.False(t, hasAdmin, "RenderYAML must not allow the secret value to inject a sibling admin field")
}

// EscapeYAMLString must fall back to its defensive replacer when yaml.v3 doesn't
// encode the value as a plain double-quoted scalar: a value containing invalid
// UTF-8 makes yaml.Marshal emit a `!!binary "...."` tagged scalar instead (since a
// double-quoted style can't represent arbitrary binary), so the function's
// quote-stripping fast path (which assumes the marshaled form starts and ends with
// a bare `"`) doesn't apply. The fallback must still escape the *original* value's
// quotes/backslashes rather than leak yaml.Marshal's `!!binary` tag or base64 body
// into the caller's output.
func TestEscapeYAMLString_FallsBackOnInvalidUTF8(t *testing.T) {
	// Invalid UTF-8 byte combined with a quote and a backslash in the same value,
	// so the assertion exercises the replacer's actual escaping behavior rather
	// than merely "value passed through unchanged".
	val := "\xc3(\"back\\slash"

	got := EscapeYAMLString(val)

	want := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(val)
	assert.Equal(t, want, got, "fallback must escape the original value's quotes/backslashes")
	assert.NotContains(t, got, "!!binary", "must not leak yaml.Marshal's !!binary tag into the escaped output")
}
