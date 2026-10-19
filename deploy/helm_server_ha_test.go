package deploy

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// haRender renders the whole chart with an external database (the HA topology
// needs one) plus the given --set values, returning the output and any error.
func haRender(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	args := []string{"template", "kx", chartWithValues(t, ""),
		"--set", "auth.masterPassword=x", "--set", "postgresql.enabled=false",
		"--set", "externalDatabase.host=db", "--set", "externalDatabase.password=x"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, temp chart path and test flags
	return string(out), err
}

// haDocs is haRender decoded into documents, failing the test on a render error.
func haDocs(t *testing.T, sets ...string) []map[string]any {
	t.Helper()
	out, err := haRender(t, sets...)
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", sets, err, out)
	}
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

func findDoc(docs []map[string]any, kind, component string) map[string]any {
	for _, d := range docs {
		meta, _ := d["metadata"].(map[string]any)
		labels, _ := meta["labels"].(map[string]any)
		if d["kind"] == kind && labels["app.kubernetes.io/component"] == component {
			return d
		}
	}
	return nil
}

func serverConfigYAML(t *testing.T, docs []map[string]any) map[string]any {
	t.Helper()
	for _, d := range docs {
		if d["kind"] != "ConfigMap" {
			continue
		}
		data, _ := d["data"].(map[string]any)
		s, ok := data["keyorix.yaml"].(string)
		if !ok {
			continue
		}
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(s), &cfg); err != nil {
			t.Fatalf("server config does not parse: %v", err)
		}
		return cfg
	}
	t.Fatal("no server ConfigMap rendered")
	return nil
}

func nested(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, _ := cur.(map[string]any)
		cur = mm[p]
	}
	return cur
}

// The default is the single-instance deployment: one replica, Recreate rollouts, no
// PodDisruptionBudget (it could only block the singleton's one drain), no topology
// constraint, no replica-aware rate-limit setting, no single_writer.
func TestHelmServerHA_DefaultIsSingleInstance(t *testing.T) {
	requireHelm(t)
	docs := haDocs(t)
	dep := findDoc(docs, "Deployment", "server")
	if dep == nil {
		t.Fatal("no server Deployment")
	}
	if got := nested(dep, "spec", "replicas"); got != 1 {
		t.Errorf("replicas = %v, want 1", got)
	}
	if got := nested(dep, "spec", "strategy", "type"); got != "Recreate" {
		t.Errorf("strategy = %v, want Recreate", got)
	}
	if nested(dep, "spec", "template", "spec", "topologySpreadConstraints") != nil {
		t.Error("a single replica must not carry topologySpreadConstraints")
	}
	if findDoc(docs, "PodDisruptionBudget", "server") != nil {
		t.Error("a single replica must not render a server PodDisruptionBudget")
	}
	cfg := serverConfigYAML(t, docs)
	if nested(cfg, "security", "auth_rate_limit_fallback") != nil {
		t.Error("auth_rate_limit_fallback must not be set for one replica")
	}
	if nested(cfg, "storage", "database", "single_writer") != nil {
		t.Error("single_writer must not be set by default")
	}
}

// replicas > 1 on a shared keys volume is the HA topology: rolling updates, a
// PodDisruptionBudget, node and zone spread, the replica count handed to the
// auth rate-limit fallback, and still PostgreSQL (SQLite cannot be rendered).
func TestHelmServerHA_MultipleReplicas(t *testing.T) {
	requireHelm(t)
	docs := haDocs(t, "server.replicas=3", "server.keysPersistence.accessMode=ReadWriteMany")
	dep := findDoc(docs, "Deployment", "server")
	if got := nested(dep, "spec", "replicas"); got != 3 {
		t.Errorf("replicas = %v, want 3", got)
	}
	if got := nested(dep, "spec", "strategy", "type"); got != "RollingUpdate" {
		t.Errorf("strategy = %v, want RollingUpdate", got)
	}
	pdb := findDoc(docs, "PodDisruptionBudget", "server")
	if pdb == nil {
		t.Fatal("no server PodDisruptionBudget for 3 replicas")
	}
	if got := nested(pdb, "spec", "minAvailable"); got != 1 {
		t.Errorf("PDB minAvailable = %v, want 1", got)
	}
	spread, _ := nested(dep, "spec", "template", "spec", "topologySpreadConstraints").([]any)
	if len(spread) != 2 {
		t.Fatalf("topologySpreadConstraints = %v, want node and zone", spread)
	}
	keys := map[string]bool{}
	for _, s := range spread {
		sm, _ := s.(map[string]any)
		keys[sm["topologyKey"].(string)] = true
		if sm["whenUnsatisfiable"] != "ScheduleAnyway" {
			t.Errorf("%v: spread must be a preference (ScheduleAnyway) so small clusters still schedule", sm["topologyKey"])
		}
		if nested(sm, "labelSelector", "matchLabels", "app.kubernetes.io/component") != "server" {
			t.Errorf("%v: labelSelector must select the server pods", sm["topologyKey"])
		}
	}
	if !keys["kubernetes.io/hostname"] || !keys["topology.kubernetes.io/zone"] {
		t.Errorf("spread keys = %v, want hostname and zone", keys)
	}
	cfg := serverConfigYAML(t, docs)
	if got := nested(cfg, "security", "auth_rate_limit_fallback", "replicas"); got != 3 {
		t.Errorf("auth_rate_limit_fallback.replicas = %v, want 3", got)
	}
	if got := nested(cfg, "storage", "type"); got != "postgres" {
		t.Errorf("storage.type = %v: the chart must render PostgreSQL only (SQLite is single-process)", got)
	}
}

func TestHelmServerHA_OverridesAreHonoured(t *testing.T) {
	requireHelm(t)
	docs := haDocs(t, "server.replicas=2", "server.keysPersistence.accessMode=ReadWriteMany",
		"server.podDisruptionBudget.minAvailable=null", "server.podDisruptionBudget.maxUnavailable=1",
		"server.topologySpreadConstraints[0].maxSkew=2", "server.topologySpreadConstraints[0].topologyKey=rack",
		"server.topologySpreadConstraints[0].whenUnsatisfiable=DoNotSchedule")
	pdb := findDoc(docs, "PodDisruptionBudget", "server")
	if nested(pdb, "spec", "minAvailable") != nil || nested(pdb, "spec", "maxUnavailable") != 1 {
		t.Errorf("PDB spec = %v, want maxUnavailable 1 only", pdb["spec"])
	}
	dep := findDoc(docs, "Deployment", "server")
	spread, _ := nested(dep, "spec", "template", "spec", "topologySpreadConstraints").([]any)
	if len(spread) != 1 || nested(spread[0].(map[string]any), "topologyKey") != "rack" {
		t.Errorf("topologySpreadConstraints = %v, want exactly the user's rack constraint", spread)
	}
	docs = haDocs(t, "server.replicas=2", "server.keysPersistence.accessMode=ReadWriteMany", "server.podDisruptionBudget.enabled=false")
	if findDoc(docs, "PodDisruptionBudget", "server") != nil {
		t.Error("podDisruptionBudget.enabled=false must not render a PDB")
	}
}

func TestHelmServerHA_SingleWriterRendersTheSetting(t *testing.T) {
	requireHelm(t)
	cfg := serverConfigYAML(t, haDocs(t, "server.singleWriter=true"))
	if got := nested(cfg, "storage", "database", "single_writer"); got != true {
		t.Errorf("single_writer = %v, want true", got)
	}
}

// The render is refused (fail closed) for every combination that cannot work.
func TestHelmServerHA_RefusesUnsafeCombinations(t *testing.T) {
	requireHelm(t)
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{"replicas with single_writer", []string{"server.replicas=2", "server.singleWriter=true", "server.keysPersistence.accessMode=ReadWriteMany"}, "single-writer"},
		{"replicas on a ReadWriteOnce keys volume", []string{"server.replicas=2"}, "ReadWriteMany"},
		{"replicas without a keys volume", []string{"server.replicas=2", "server.keysPersistence.enabled=false"}, "ReadWriteMany"},
		{"zero replicas", []string{"server.replicas=0"}, "at least 1"},
		{"single_writer with a transaction pooler", []string{"server.singleWriter=true", "externalDatabase.pooler=pgbouncer-transaction"}, "pgbouncer-transaction"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := haRender(t, tc.sets...)
			if err == nil {
				t.Fatalf("render succeeded, want a refusal mentioning %q", tc.want)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("refusal does not mention %q:\n%s", tc.want, out)
			}
		})
	}
}

// web is horizontally scalable already; with replicas > 1 it spreads too.
func TestHelmWebSpreadsWhenScaledOut(t *testing.T) {
	requireHelm(t)
	web := findDoc(haDocs(t, "web.replicas=2"), "Deployment", "web")
	spread, _ := nested(web, "spec", "template", "spec", "topologySpreadConstraints").([]any)
	if len(spread) != 2 {
		t.Errorf("web topologySpreadConstraints = %v, want node and zone", spread)
	}
	web = findDoc(haDocs(t), "Deployment", "web")
	if nested(web, "spec", "template", "spec", "topologySpreadConstraints") != nil {
		t.Error("a single web replica must not carry topologySpreadConstraints")
	}
}
