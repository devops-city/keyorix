// Package yamlescape is the YAML counterpart of secrettemplate.EscapeJSONString /
// secrettemplate.RenderJSON: it escapes a resolved secret value for embedding in a
// double-quoted YAML scalar.
//
// It lives in its own leaf package, importing secrettemplate (never the reverse), so
// that gopkg.in/yaml.v3 stays out of the dependency closure of secrettemplate and
// therefore of internal/core, which reaches secrettemplate for plain Render only.
// TestCoreStaysLeanOfHeavyThirdParty (internal/core/ports) enforces that.
package yamlescape

import (
	"strings"

	"github.com/keyorixhq/keyorix/internal/secrettemplate"
	"gopkg.in/yaml.v3"
)

// EscapeYAMLString escapes val so it can be embedded inside a double-quoted YAML
// scalar's quotes (i.e. as the value written between the surrounding `"..."` a
// template already supplies), mirroring secrettemplate.EscapeJSONString for YAML
// documents. It forces yaml.v3's double-quoted scalar encoding (rather than letting
// it choose plain/single-quoted/literal style, which would produce output that
// doesn't fit inside pre-existing template quotes) and strips the quotes
// yaml.Marshal adds, since the template already supplies them.
func EscapeYAMLString(val string) string {
	node := yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: val}
	if b, err := yaml.Marshal(&node); err == nil {
		s := strings.TrimSuffix(string(b), "\n")
		if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
			return s[1 : len(s)-1]
		}
	}
	// yaml.Node.MarshalYAML on a double-quoted scalar node is not expected to fail or
	// return an unexpected shape; fall back defensively rather than risk emitting an
	// unescaped value.
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(val)
}

// RenderYAML is secrettemplate.Render with Escape set to EscapeYAMLString: use it
// when tmpl is a YAML document or fragment that embeds ${secret:<ref>} placeholders
// inside double-quoted scalar fields, so a substituted secret value cannot break out
// of its field.
func RenderYAML(tmpl string, resolve secrettemplate.Resolver) (string, error) {
	return secrettemplate.RenderWithOptions(tmpl, resolve, secrettemplate.RenderOptions{Escape: EscapeYAMLString})
}
