package deploy

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// `helm upgrade --reuse-values` replaces the new chart's values.yaml defaults
// with the OLD release's values. A key added after that release is then absent,
// and `.Values.secureBaseline.enabled` is a nil-pointer render error (v0.96.0
// from 0.95.3, found in the post-release review). The chart fills the gap with
// the keyorix.valuesDefaults helper; these tests render the chart with the
// 0.95.3 values.yaml AS THE ONLY DEFAULTS (testdata/helm-values-0.95.3.yaml,
// copied verbatim from the v0.95.3 tag) and require
//   - the render succeeds,
//   - it equals the render with the current defaults (so the helper's defaults
//     cannot drift from values.yaml), apart from generated random material.
//
// Not covered: a real `helm upgrade` against a cluster (verified on kind, see
// the PR).

// chartWithValues copies the chart to a temp dir with values.yaml replaced by
// valuesFile ("" keeps the current one) and returns the chart path.
func chartWithValues(t *testing.T, valuesFile string) string {
	t.Helper()
	src := filepath.Join("..", "deploy", "helm", "keyorix")
	dst := filepath.Join(t.TempDir(), "keyorix")
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	if valuesFile != "" {
		b, err := os.ReadFile(valuesFile) //nolint:gosec // test fixture path
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "values.yaml"), b, fs.FileMode(0o600)); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func helmTemplateDocs(t *testing.T, chart string, sets ...string) []map[string]any {
	t.Helper()
	args := []string{"template", "kx", chart, "--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, temp chart path and flags
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	var docs []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func requireHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping --reuse-values render check")
	}
}

func TestHelmReuseValues_RendersWithOnly095Values(t *testing.T) {
	requireHelm(t)
	old := chartWithValues(t, filepath.Join("testdata", "helm-values-0.95.3.yaml"))
	cur := chartWithValues(t, "")

	// The fixture really lacks the new keys (otherwise this test is vacuous).
	b, err := os.ReadFile(filepath.Join(old, "values.yaml")) //nolint:gosec // temp copy
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"secureBaseline:", "hsts:", "runAsUser:", "migrateOwnership:"} {
		if strings.Contains(string(b), k) {
			t.Fatalf("fixture unexpectedly contains %q; it must be the 0.95.3 values file", k)
		}
	}

	for _, mode := range [][]string{
		nil, // what `--reuse-values` / `--reset-then-reuse-values` leave: no flags.
		{"postgresql.migrateOwnership=true"},
	} {
		oldDocs := helmTemplateDocs(t, old, mode...)
		curDocs := helmTemplateDocs(t, cur, mode...)
		if len(oldDocs) == 0 {
			t.Fatal("no documents rendered")
		}
		got, want := normalizeDocs(oldDocs), normalizeDocs(curDocs)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("render with only 0.95.3 values (%v) differs from the render with the current defaults:\n got keys %v\nwant keys %v",
				mode, docKeys(got), docKeys(want))
			for k, w := range want {
				if g, ok := got[k]; ok && !reflect.DeepEqual(g, w) {
					t.Errorf("document %s differs:\n got %v\nwant %v", k, g, w)
				}
			}
		}
		// Secure baseline is on by default and Postgres runs as the alpine uid.
		if _, ok := got["Secret/kx-keyorix-secure-baseline"]; !ok {
			t.Errorf("secure-baseline Secret missing with 0.95.3 values only (%v)", mode)
		}
		pg, _ := yaml.Marshal(got["Deployment/kx-keyorix-postgresql"])
		if !strings.Contains(string(pg), "runAsUser: 70") {
			t.Errorf("postgres must run as uid 70 with 0.95.3 values only (%v):\n%s", mode, pg)
		}
	}
}

// An explicit false must survive the defaults (the helper only fills MISSING keys).
func TestHelmReuseValues_ExplicitOptOutIsKept(t *testing.T) {
	requireHelm(t)
	old := chartWithValues(t, filepath.Join("testdata", "helm-values-0.95.3.yaml"))
	docs := normalizeDocs(helmTemplateDocs(t, old, "secureBaseline.enabled=false"))
	if _, ok := docs["Secret/kx-keyorix-secure-baseline"]; ok {
		t.Error("secureBaseline.enabled=false must not render the secure-baseline Secret")
	}
}

// normalizeDocs keys documents by Kind/name and drops what is random per render
// (generated Secret data, tokens in checksum annotations).
func normalizeDocs(docs []map[string]any) map[string]any {
	out := map[string]any{}
	for _, d := range docs {
		kind, _ := d["kind"].(string)
		md, _ := d["metadata"].(map[string]any)
		name, _ := md["name"].(string)
		if kind == "Secret" {
			delete(d, "data")
			delete(d, "stringData")
		}
		stripChecksums(d)
		out[kind+"/"+name] = d
	}
	return out
}

func stripChecksums(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if strings.HasPrefix(k, "checksum/") {
				delete(x, k)
				continue
			}
			stripChecksums(c)
		}
	case []any:
		for _, c := range x {
			stripChecksums(c)
		}
	}
}

func docKeys(m map[string]any) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}
