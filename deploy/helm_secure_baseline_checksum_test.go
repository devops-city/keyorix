package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Kubernetes does not restart pods when a mounted Secret changes. With
// secureBaseline on, the server, web and bundled postgres pods carry
// checksum/secure-baseline, so a rotated Secret (delete it, helm upgrade) rolls
// them (#3053 review). The test pins that the annotation is the checksum of the
// Secret data rendered in the SAME run (the generated values are random, so an
// independent computation would not match), and that it is absent with
// secureBaseline off, where the render must stay what main renders.
//
// What this does not cover: that Helm's `lookup` keeps the existing Secret on a
// real upgrade (verified on kind, see the PR).

const secureBaselineChecksumKey = "checksum/secure-baseline"

type helmDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
	Spec struct {
		Template struct {
			Metadata struct {
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"metadata"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func renderHelmDocs(t *testing.T, sets ...string) []helmDoc {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart checksum check")
	}
	args := []string{"template", "kx", filepath.Join("..", "deploy", "helm", "keyorix"),
		"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, chart path and flags
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	var docs []helmDoc
	for {
		var d helmDoc
		if err := dec.Decode(&d); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, d)
	}
	return docs
}

// secretChecksum mirrors the keyorix.secureBaseline.checksum helper: sha256 over
// "key=value\n" for the sorted keys.
func secretChecksum(data map[string]string) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, data[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func TestHelmSecureBaseline_PodsCarryTheSecretChecksum(t *testing.T) {
	docs := renderHelmDocs(t, "secureBaseline.enabled=true")
	var secret map[string]string
	for _, d := range docs {
		if d.Kind == "Secret" && strings.HasSuffix(d.Metadata.Name, "-secure-baseline") {
			secret = d.Data
		}
	}
	if len(secret) == 0 {
		t.Fatal("no -secure-baseline Secret rendered with secureBaseline.enabled=true")
	}
	want := secretChecksum(secret)
	seen := map[string]bool{}
	for _, d := range docs {
		if d.Kind != "Deployment" && d.Kind != "StatefulSet" {
			continue
		}
		got, has := d.Spec.Template.Metadata.Annotations[secureBaselineChecksumKey]
		if !has {
			continue
		}
		seen[d.Metadata.Name] = true
		if got != want {
			t.Errorf("%s %s: %s = %s, want the checksum of the rendered Secret (%s)", d.Kind, d.Metadata.Name, secureBaselineChecksumKey, got, want)
		}
	}
	// Every workload that mounts the Secret must carry it.
	for _, suffix := range []string{"-server", "-web", "-postgresql"} {
		found := false
		for name := range seen {
			if strings.HasSuffix(name, suffix) {
				found = true
			}
		}
		if !found {
			t.Errorf("no workload ending in %q carries %s; a rotated Secret would not roll it (seen: %v)", suffix, secureBaselineChecksumKey, seen)
		}
	}
}

// The control: with secureBaseline off no pod template carries the annotation,
// so the default render is unchanged.
func TestHelmDefault_NoSecureBaselineChecksum(t *testing.T) {
	for _, d := range renderHelmDocs(t) {
		if _, has := d.Spec.Template.Metadata.Annotations[secureBaselineChecksumKey]; has {
			t.Errorf("%s %s carries %s with secureBaseline off", d.Kind, d.Metadata.Name, secureBaselineChecksumKey)
		}
	}
}
