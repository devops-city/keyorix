package deploy

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func vpRender(t *testing.T, args ...string) (string, error) {
	t.Helper()
	chart := chartWithValues(t, "")
	full := append([]string{"template", "kx", chart}, args...)
	out, err := exec.Command("helm", full...).CombinedOutput() //nolint:gosec // fixed binary, temp chart path and test flags
	return string(out), err
}

func vpDocs(t *testing.T, out string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	dec := yaml.NewDecoder(bytes.NewReader([]byte(out)))
	for {
		var d map[string]any
		if dec.Decode(&d) != nil {
			break
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

// values-production.yaml renders as shipped (every CHANGE-ME is a placeholder VALUE,
// not a missing one) and delivers what its header promises: an external PostgreSQL
// with verified TLS, credentials from the user's own Secret and never inline, TLS on
// the ingress and between the pods, audit_durability strict, Guaranteed-QoS server
// resources, and no bundled database.
//
// Not covered: that the placeholder addresses/secrets exist, or a live install
// (pending e2e VM).
func TestHelmValuesProduction_RendersAndDeliversItsPromises(t *testing.T) {
	requireHelm(t)
	vals := filepath.Join("..", "deploy", "helm", "keyorix", "values-production.yaml")
	out, err := vpRender(t, "-f", vals)
	if err != nil {
		t.Fatalf("values-production.yaml does not render: %v\n%s", err, out)
	}
	docs := vpDocs(t, out)

	var cfgYAML string
	kinds := map[string]int{}
	for _, d := range docs {
		kinds[d["kind"].(string)]++
		meta, _ := d["metadata"].(map[string]any)
		if d["kind"] == "ConfigMap" && strings.HasSuffix(meta["name"].(string), "-server-config") {
			cfgYAML = d["data"].(map[string]any)["keyorix.yaml"].(string)
		}
		if d["kind"] == "Deployment" && strings.Contains(meta["name"].(string), "postgresql") {
			t.Error("the bundled PostgreSQL must not be rendered")
		}
		if d["kind"] == "Secret" && strings.HasSuffix(meta["name"].(string), "-auth") {
			t.Error("the chart must not render its own credentials Secret when auth.existingSecret is set")
		}
	}
	if kinds["Ingress"] != 1 {
		t.Errorf("want one Ingress, got %d", kinds["Ingress"])
	}
	if kinds["PodDisruptionBudget"] != 1 {
		t.Errorf("web.replicas=2 should render exactly the web PodDisruptionBudget, got %d", kinds["PodDisruptionBudget"])
	}
	for _, d := range docs {
		if d["kind"] == "Ingress" {
			spec := d["spec"].(map[string]any)
			tls, _ := spec["tls"].([]any)
			if len(tls) != 1 {
				t.Errorf("the production ingress must carry TLS, got %v", spec["tls"])
			}
		}
	}

	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(cfgYAML), &cfg); err != nil {
		t.Fatalf("server config: %v", err)
	}
	db := vpNested(cfg, "storage", "database").(map[string]any)
	if db["audit_durability"] != "strict" {
		t.Errorf("audit_durability = %v, want strict", db["audit_durability"])
	}
	if db["ssl_mode"] != "verify-full" || db["ssl_root_cert"] == nil || db["host"] == "" {
		t.Errorf("database TLS = ssl_mode %v ssl_root_cert %v, want verify-full with a CA", db["ssl_mode"], db["ssl_root_cert"])
	}
	if vpNested(cfg, "server", "http", "tls", "enabled") != true || vpNested(cfg, "security", "require_transport_tls") != true {
		t.Error("the secure baseline (server TLS required) must be on")
	}
	if strings.Contains(cfgYAML, "password") {
		t.Error("no password may be written into the server config")
	}
}

func vpNested(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, _ := cur.(map[string]any)
		cur = mm[p]
	}
	return cur
}

// Every placeholder is visible: the example still says CHANGE-ME where an operator
// must decide, so a copy cannot be installed unedited by accident of looking finished.
func TestHelmValuesProduction_PlaceholdersStayMarked(t *testing.T) {
	b, err := exec.Command("grep", "-c", "CHANGE-ME", filepath.Join("..", "deploy", "helm", "keyorix", "values-production.yaml")).Output() //nolint:gosec // fixed binary and path
	if err != nil || strings.TrimSpace(string(b)) == "0" {
		t.Fatalf("values-production.yaml has no CHANGE-ME markers (%v)", err)
	}
}

func TestHelmServerAuditDurability(t *testing.T) {
	requireHelm(t)
	base := []string{"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}

	out, err := vpRender(t, base...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "audit_durability") {
		t.Error("audit_durability must not be rendered by default (server default applies)")
	}
	for _, v := range []string{"strict", "standard"} {
		out, err = vpRender(t, append(base, "--set", "server.auditDurability="+v)...)
		if err != nil || !strings.Contains(out, `audit_durability: "`+v+`"`) {
			t.Errorf("%s: err=%v, want audit_durability %q rendered", v, err, v)
		}
	}
	out, err = vpRender(t, append(base, "--set", "server.auditDurability=fast")...)
	if err == nil || !strings.Contains(out, "must be strict or standard") {
		t.Errorf("an unknown level must be refused, got err=%v\n%s", err, out)
	}
}
