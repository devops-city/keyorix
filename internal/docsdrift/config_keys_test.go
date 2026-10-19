package docsdrift

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// DOCS-DRIFT-1 item 1: configuration keys named by the docs must exist.
//
// What is checked, per document in configDocs:
//
//   - every key path of every ```yaml fenced block that parses as a mapping
//     rooted at the config file's top level (a block whose first key is not a
//     top-level Config key is taken to be another file's YAML -- Helm values, a
//     compose file, a Kubernetes manifest -- and is counted as skipped in the
//     log, not checked);
//   - every backticked dotted key in a markdown table row whose first segment is
//     a top-level Config key (`storage.database.ssl_mode`, `security.require_mfa: true`).
//
// "Exists" means one of: a yaml-tagged field of config.Config (reflection, the
// same surface config.Load's KnownFields(true) decode accepts); the Name of an
// InsecureSettingsRegistry entry (the stable insecure_ identifier the docs use
// in posture tables); or the DeprecatedAlias of one (the old key Load still
// accepts and warns about).
//
// Reverse direction (security-relevant keys): every InsecureSettingsRegistry
// entry's Name must appear somewhere in configDocs.
//
// What this does NOT check: values (a doc may say `ssl_mode: bogus`), types, or
// YAML in docs outside configDocs. Prose that names a key without backticks, or
// outside a table, is not seen.

// child resolves one key under t. ok is false when the key is unknown. Below an
// interface (any) or a map every key is accepted.
func child(t reflect.Type, key string) (next reflect.Type, ok bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Interface:
		return t, true
	case reflect.Map:
		return t.Elem(), true
	case reflect.Struct:
		for f := range t.Fields() {
			if f.PkgPath != "" {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			if name == key {
				return f.Type, true
			}
		}
	}
	return nil, false
}

// resolves reports whether the dotted path names a field of config.Config, and
// if not, the first segment that failed.
func resolves(path string) (bool, string) {
	t := reflect.TypeFor[config.Config]()
	for seg := range strings.SplitSeq(path, ".") {
		seg = strings.TrimSuffix(seg, "[]")
		next, ok := child(t, seg)
		if !ok {
			return false, seg
		}
		t = next
	}
	return true, ""
}

func topLevelKeys() map[string]bool {
	out := map[string]bool{}
	for f := range reflect.TypeFor[config.Config]().Fields() {
		if f.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out[name] = true
	}
	return out
}

// knownKeyNames returns every dotted name the docs may use besides the struct
// paths: registry Names and deprecated aliases.
func registryNames() map[string]bool {
	out := map[string]bool{}
	for _, e := range config.InsecureSettingsRegistry {
		out[e.Name] = true
		if e.DeprecatedAlias != "" {
			out[e.DeprecatedAlias] = true
			// Load also rewrites the old key on each key_provider.fallbacks[]
			// entry (deprecatedSettingAliases, unexported); the registry lists only
			// the primary-provider spelling.
			if strings.Contains(e.DeprecatedAlias, ".key_provider.") {
				out[strings.Replace(e.DeprecatedAlias, ".key_provider.", ".key_provider.fallbacks[].", 1)] = true
			}
		}
	}
	return out
}

func keyExists(path string, extra map[string]bool) (bool, string) {
	norm := strings.ReplaceAll(path, "[]", "")
	if extra[path] || extra[norm] {
		return true, ""
	}
	return resolves(path)
}

// yamlKeyPaths returns every mapping-key path in a YAML document, with
// sequences descended transparently. Paths of keys under a null / scalar value
// are included for the key itself.
func yamlKeyPaths(n *yaml.Node, prefix string, out *[]string) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			yamlKeyPaths(c, prefix, out)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			yamlKeyPaths(c, prefix, out)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := n.Content[i].Value
			if prefix != "" {
				p = prefix + "." + p
			}
			*out = append(*out, p)
			yamlKeyPaths(n.Content[i+1], p, out)
		}
	}
}

// yamlDocKeyPaths parses a fenced block (possibly multi-document) and returns
// its key paths. ok is false when the block is not parseable YAML (placeholders,
// elided "..." lines) -- such a block is skipped and counted, not failed.
func yamlDocKeyPaths(body string) (paths []string, ok bool) {
	dec := yaml.NewDecoder(strings.NewReader(body))
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if err != nil {
			if err.Error() == "EOF" {
				return paths, true
			}
			return nil, false
		}
		yamlKeyPaths(&n, "", &paths)
	}
}

// rootedInConfig reports whether the first key path of a parsed block starts at
// a top-level Config key, i.e. it is a keyorix.yaml excerpt rather than another
// file's YAML.
func rootedInConfig(paths []string, top map[string]bool) bool {
	for _, p := range paths {
		if !strings.Contains(p, ".") {
			return top[p]
		}
	}
	return false
}

type keyFinding struct {
	Doc  string
	Line int
	Key  string
	Bad  string
	Kind string
}

var tableKeyToken = regexp.MustCompile("`([a-z][a-z0-9_]*(?:\\[\\])?(?:\\.[a-z][a-z0-9_]*(?:\\[\\])?)+)(?::[^`]*)?`")

// findConfigKeyDrift is the whole check, split out so the planted-error test
// can run it on synthetic documents.
func findConfigKeyDrift(docName, doc string) (findings []keyFinding, checkedBlocks, skippedBlocks, tokens int) {
	top := topLevelKeys()
	extra := registryNames()

	for _, f := range fences(doc) {
		if f.Lang != "yaml" && f.Lang != "yml" {
			continue
		}
		paths, ok := yamlDocKeyPaths(f.Body)
		if !ok || !rootedInConfig(paths, top) {
			skippedBlocks++
			continue
		}
		checkedBlocks++
		for _, p := range paths {
			if good, bad := keyExists(p, extra); !good {
				findings = append(findings, keyFinding{docName, f.Line, p, bad, "yaml"})
			}
		}
	}

	lines, nums := proseLines(doc)
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		for _, m := range tableKeyToken.FindAllStringSubmatch(line, -1) {
			key := m[1]
			if !top[strings.TrimSuffix(strings.SplitN(key, ".", 2)[0], "[]")] {
				continue
			}
			tokens++
			if good, bad := keyExists(key, extra); !good {
				findings = append(findings, keyFinding{docName, nums[i], key, bad, "table"})
			}
		}
	}
	return findings, checkedBlocks, skippedBlocks, tokens
}

func TestDocsConfigKeysExist(t *testing.T) {
	for _, rel := range configDocs {
		t.Run(rel, func(t *testing.T) {
			findings, blocks, skipped, tokens := findConfigKeyDrift(rel, readDoc(t, rel))
			t.Logf("%s: %d yaml blocks checked, %d skipped (not config excerpts or unparseable), %d table keys checked",
				rel, blocks, skipped, tokens)
			for _, f := range findings {
				t.Errorf("%s:%d: %s key %q does not exist in the config struct (no field %q)", f.Doc, f.Line, f.Kind, f.Key, f.Bad)
			}
		})
	}
}

// TestDocsConfigKeysCheckCatchesPlantedError is the red proof: a doc naming a
// key that does not exist (a misspelled leaf, a key under the wrong parent)
// must be reported, and a doc naming real keys must not.
func TestDocsConfigKeysCheckCatchesPlantedError(t *testing.T) {
	bad := "```yaml\nstorage:\n  database:\n    ssl_mod: require\nserver:\n  http:\n    port: 8080\n```\n\n" +
		"| Key | Meaning |\n|---|---|\n| `storage.databse.host` | typo |\n| `security.require_mfa` | real |\n"
	findings, blocks, _, tokens := findConfigKeyDrift("planted.md", bad)
	if blocks != 1 || tokens != 2 {
		t.Fatalf("planted doc not scanned: blocks=%d tokens=%d", blocks, tokens)
	}
	var got []string
	for _, f := range findings {
		got = append(got, f.Key)
	}
	sort.Strings(got)
	want := []string{"storage.database.ssl_mod", "storage.databse.host"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("findings = %v, want %v", got, want)
	}

	good := "```yaml\nstorage:\n  database:\n    ssl_mode: require\n```\n\n| `security.require_mfa` | real |\n"
	if f, _, _, _ := findConfigKeyDrift("good.md", good); len(f) != 0 {
		t.Fatalf("real keys reported: %v", f)
	}
}

// undocumentedRegistryEntries returns the registry entries that none of docs
// names. An entry counts as documented when the docs contain its Name (the
// insecure_ identifier; for the thirteen settings not yet renamed this is a
// synthetic name no YAML file uses) or one of its SourcePaths (the real key an
// operator types), as dotted text, as a key path of a ```yaml block, or as the
// bare last segment of the key when that segment contains an underscore (docs
// that show the key inside a section's yaml example, or in a comment, do not
// spell the whole path). A single-word leaf such as "enabled" is never accepted
// bare: it would match any document. The bare-leaf rule is a deliberate
// leniency: it can accept a doc that mentions the key name in unrelated prose.
func undocumentedRegistryEntries(docs string, yamlPaths map[string]bool, registry []config.InsecureSetting) []config.InsecureSetting {
	var missing []config.InsecureSetting
	for _, e := range registry {
		if strings.Contains(docs, e.Name) {
			continue
		}
		found := false
		for _, sp := range e.SourcePaths {
			l := sp[strings.LastIndex(sp, ".")+1:]
			if strings.Contains(docs, sp) || yamlPaths[sp] || (strings.Contains(l, "_") && strings.Contains(docs, l)) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, e)
		}
	}
	return missing
}

// TestInsecureRegistryEntriesAreDocumented is the reverse direction for
// security-relevant keys: every InsecureSettingsRegistry entry must be named in
// at least one of configDocs. A failure means a security-weakening switch exists
// that an operator reading the docs would not learn about.
func TestInsecureRegistryEntriesAreDocumented(t *testing.T) {
	var corpus strings.Builder
	yamlPaths := map[string]bool{}
	for _, rel := range configDocs {
		doc := readDoc(t, rel)
		corpus.WriteString(doc)
		corpus.WriteString("\n")
		for _, f := range fences(doc) {
			if f.Lang != "yaml" && f.Lang != "yml" {
				continue
			}
			if paths, ok := yamlDocKeyPaths(f.Body); ok {
				for _, p := range paths {
					yamlPaths[strings.ReplaceAll(p, "[]", "")] = true
				}
			}
		}
	}
	// The registry spells a per-provider key sso.providers.x, the docs sso.providers[].x.
	for _, e := range undocumentedRegistryEntries(strings.ReplaceAll(corpus.String(), "[]", ""), yamlPaths, config.InsecureSettingsRegistry) {
		t.Errorf("security-relevant setting %q (key %v, InsecureSettingsRegistry) is not named in %v", e.Name, e.SourcePaths, configDocs)
	}
}

// TestInsecureRegistryDocCheckCatchesPlantedError: a registry entry the docs do
// not mention must be reported, one they do mention (by Name or by key) must not.
func TestInsecureRegistryDocCheckCatchesPlantedError(t *testing.T) {
	reg := []config.InsecureSetting{
		{Name: "x.insecure_planted_switch", SourcePaths: []string{"x.planted_switch"}},
		{Name: "x.insecure_named", SourcePaths: []string{"x.named"}},
		{Name: "y.insecure_by_key", SourcePaths: []string{"y.real_key"}},
	}
	got := undocumentedRegistryEntries("see x.insecure_named and `y.real_key`", nil, reg)
	if len(got) != 1 || got[0].Name != "x.insecure_planted_switch" {
		t.Fatalf("undocumented = %v, want only x.insecure_planted_switch", got)
	}
}
