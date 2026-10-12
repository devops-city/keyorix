package deploy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The required-key check of secureBaseline.existingSecret lives behind Helm's
// `lookup`, which only sees a cluster on install/upgrade (plain `helm template`
// returns nothing). To test it without a cluster, `helm template --dry-run=server`
// is pointed (KUBECONFIG) at a tiny in-process fake API server that answers
// discovery and GET /api/v1/namespaces/<ns>/secrets/<name> for the Secrets the
// test registers. The real helm binary and the real chart templates run; only the
// cluster is fake.
//
// What this does not cover: a real API server (RBAC for the lookup, admission),
// the dry-run=server resource validation Helm skips for `template`, and Helm
// versions without `--dry-run=server` (3.13+ is required). The pods actually
// mounting a bad Secret is covered by the kind run on the e2e VM, not here.

const lookupNamespace = "kx-ns"

// fakeKube serves just enough of the Kubernetes API for `lookup "v1" "Secret"`.
// secrets maps name -> key -> raw (not yet base64) value.
// releaseOwned names the Secrets that belong to release "kx" (Helm ownership
// metadata), as the chart-generated Secret does on an upgrade: Helm refuses to
// adopt a rendered object that exists without it.
func fakeKube(t *testing.T, secrets map[string]map[string]string, releaseOwned ...string) string {
	t.Helper()
	meta := func(name string) map[string]any {
		m := map[string]any{"name": name, "namespace": lookupNamespace}
		for _, o := range releaseOwned {
			if o == name {
				m["labels"] = map[string]string{"app.kubernetes.io/managed-by": "Helm"}
				m["annotations"] = map[string]string{"meta.helm.sh/release-name": "kx", "meta.helm.sh/release-namespace": lookupNamespace}
			}
		}
		return m
	}
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]string{"major": "1", "minor": "29", "gitVersion": "v1.29.0"})
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
	})
	// helm builds every rendered object even for `template`, which needs a REST
	// mapping per kind: advertise the kinds the chart can render (discovery only,
	// nothing is stored).
	type res struct{ name, kind string }
	core := []res{{"secrets", "Secret"}, {"configmaps", "ConfigMap"}, {"services", "Service"},
		{"serviceaccounts", "ServiceAccount"}, {"persistentvolumeclaims", "PersistentVolumeClaim"}}
	groups := map[string][]res{
		"apps":                      {{"deployments", "Deployment"}, {"statefulsets", "StatefulSet"}},
		"networking.k8s.io":         {{"networkpolicies", "NetworkPolicy"}, {"ingresses", "Ingress"}},
		"policy":                    {{"poddisruptionbudgets", "PodDisruptionBudget"}},
		"batch":                     {{"jobs", "Job"}, {"cronjobs", "CronJob"}},
		"autoscaling":               {{"horizontalpodautoscalers", "HorizontalPodAutoscaler"}},
		"rbac.authorization.k8s.io": {{"roles", "Role"}, {"rolebindings", "RoleBinding"}},
	}
	versions := map[string]string{"autoscaling": "v2"}
	resourceList := func(gv string, rs []res) map[string]any {
		var out []map[string]any
		for _, r := range rs {
			out = append(out, map[string]any{"name": r.name, "singularName": strings.ToLower(r.kind),
				"namespaced": true, "kind": r.kind, "verbs": []string{"get", "list", "create", "patch", "delete"}})
		}
		return map[string]any{"kind": "APIResourceList", "groupVersion": gv, "resources": out}
	}
	mux.HandleFunc("/apis", func(w http.ResponseWriter, _ *http.Request) {
		var gs []map[string]any
		for g := range groups {
			v := "v1"
			if o, ok := versions[g]; ok {
				v = o
			}
			gv := map[string]string{"groupVersion": g + "/" + v, "version": v}
			gs = append(gs, map[string]any{"name": g, "versions": []any{gv}, "preferredVersion": gv})
		}
		writeJSON(w, 200, map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": gs})
	})
	for g, rs := range groups {
		v := "v1"
		if o, ok := versions[g]; ok {
			v = o
		}
		mux.HandleFunc("/apis/"+g+"/"+v, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, resourceList(g+"/"+v, rs))
		})
	}
	mux.HandleFunc("/api/v1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, resourceList("v1", core))
	})
	prefix := "/api/v1/namespaces/" + lookupNamespace + "/secrets/"
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, prefix)
		raw, ok := secrets[name]
		if !ok {
			writeJSON(w, 404, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure",
				"reason": "NotFound", "code": 404, "message": "secrets \"" + name + "\" not found"})
			return
		}
		data := map[string]string{}
		for k, v := range raw {
			data[k] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		writeJSON(w, 200, map[string]any{"kind": "Secret", "apiVersion": "v1",
			"metadata": meta(name), "data": data})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Helm probes each rendered object by name (does it exist?): NotFound is
		// the right answer and not worth logging. Anything else is a gap in the fake.
		if !strings.Contains(r.URL.Path, "/namespaces/") {
			t.Logf("fake apiserver: unhandled %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 404, map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	kubeconfig := "apiVersion: v1\nkind: Config\ncurrent-context: fake\n" +
		"clusters:\n- name: fake\n  cluster:\n    server: " + srv.URL + "\n" +
		"contexts:\n- name: fake\n  context:\n    cluster: fake\n    user: fake\n" +
		"users:\n- name: fake\n  user: {}\n"
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// helmTemplateLookup renders the chart with `lookup` answered by the fake API
// server behind kubeconfig.
func helmTemplateLookup(t *testing.T, kubeconfig string, sets ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping lookup check")
	}
	args := []string{"template", "kx", filepath.Join("..", "deploy", "helm", "keyorix"),
		"--dry-run=server", "--disable-openapi-validation", "--namespace", lookupNamespace,
		"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x",
		"--set", "secureBaseline.enabled=true"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("helm", args...) //nolint:gosec // fixed binary, chart path and flags
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String() + stderr.String(), err
}

func completeBaseline() map[string]string {
	return map[string]string{
		"server.crt": "crt", "server.key": "key", "metrics_token": "tok",
		"postgres.crt": "pgcrt", "postgres.key": "pgkey",
	}
}

func without(m map[string]string, drop ...string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	for _, k := range drop {
		delete(out, k)
	}
	return out
}

var baselineChecksumRE = regexp.MustCompile(`checksum/secure-baseline: ([0-9a-f]{64})`)

func baselineChecksum(t *testing.T, render string) string {
	t.Helper()
	m := baselineChecksumRE.FindStringSubmatch(render)
	if m == nil {
		t.Fatalf("no checksum/secure-baseline annotation in the render:\n%.2000s", render)
	}
	return m[1]
}

func TestHelmSecureBaselineExistingSecret_LookupChecksRequiredKeys(t *testing.T) {
	// Control first: a complete Secret renders. Without it, the failing cases
	// below could be failing because the fake cluster is broken, not because of
	// the missing key.
	kc := fakeKube(t, map[string]map[string]string{byoSecretName: completeBaseline()})
	if out, err := helmTemplateLookup(t, kc, "secureBaseline.existingSecret="+byoSecretName); err != nil {
		t.Fatalf("complete Secret must render (is `helm template --dry-run=server` supported by this helm?): %v\n%.3000s", err, out)
	} else if strings.Contains(out, "kx-keyorix-secure-baseline") {
		t.Error("a render with existingSecret references the chart's own Secret name")
	}

	cases := []struct {
		name    string
		secret  map[string]string
		sets    []string
		wantErr []string // each must appear in the failure
		notErr  []string // must NOT appear: only the missing keys are named
	}{
		{"missing metrics_token", without(completeBaseline(), "metrics_token"), nil,
			[]string{`"my-baseline"`, "missing required key(s)", "metrics_token"}, []string{"server.crt", "postgres"}},
		{"missing server pair", without(completeBaseline(), "server.crt", "server.key"), nil,
			[]string{"server.crt, server.key"}, []string{"metrics_token", "postgres"}},
		{"missing postgres pair with bundled postgres", without(completeBaseline(), "postgres.crt", "postgres.key"), nil,
			[]string{"postgres.crt, postgres.key"}, []string{"server."}},
		{"empty value counts as missing", func() map[string]string {
			m := completeBaseline()
			m["server.key"] = ""
			return m
		}(), nil, []string{"server.key"}, []string{"metrics_token"}},
		{"empty Secret", map[string]string{}, nil,
			[]string{"server.crt", "server.key", "metrics_token", "postgres.crt", "postgres.key"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kc := fakeKube(t, map[string]map[string]string{byoSecretName: c.secret})
			out, err := helmTemplateLookup(t, kc, append([]string{"secureBaseline.existingSecret=" + byoSecretName}, c.sets...)...)
			if err == nil {
				t.Fatalf("render succeeded with an incomplete Secret:\n%.1500s", out)
			}
			for _, w := range c.wantErr {
				if !strings.Contains(out, w) {
					t.Errorf("error does not contain %q:\n%s", w, out)
				}
			}
			// Only the error line is inspected: the dump may repeat key names elsewhere.
			var line string
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, "missing required key(s)") {
					line = l
				}
			}
			for _, n := range c.notErr {
				if strings.Contains(line, n) {
					t.Errorf("error names %q although it is present:\n%s", n, line)
				}
			}
		})
	}

	t.Run("postgres pair not required without bundled postgres", func(t *testing.T) {
		kc := fakeKube(t, map[string]map[string]string{byoSecretName: without(completeBaseline(), "postgres.crt", "postgres.key")})
		out, err := helmTemplateLookup(t, kc, "secureBaseline.existingSecret="+byoSecretName,
			"postgresql.enabled=false", "externalDatabase.host=db.example.com", "externalDatabase.password=x")
		if err != nil {
			t.Fatalf("postgresql.enabled=false must not require the postgres keys: %v\n%.2000s", err, out)
		}
	})

	t.Run("Secret absent from the cluster is not an error (helm template / not yet created)", func(t *testing.T) {
		kc := fakeKube(t, map[string]map[string]string{})
		if out, err := helmTemplateLookup(t, kc, "secureBaseline.existingSecret="+byoSecretName); err != nil {
			t.Fatalf("an absent Secret is indistinguishable from `helm template` and must render: %v\n%.2000s", err, out)
		}
	})
}

// The generated path must be untouched by the BYO logic: with a generated
// Secret already in the cluster its data is reused, not regenerated, so the
// checksum matches across renders (and the fake cluster is demonstrably read).
func TestHelmSecureBaselineGenerated_LookupReusesExistingData(t *testing.T) {
	const generated = "kx-keyorix-secure-baseline"
	kc := fakeKube(t, map[string]map[string]string{generated: completeBaseline()}, generated)
	a, err := helmTemplateLookup(t, kc)
	if err != nil {
		t.Fatalf("helm template: %v\n%.2000s", err, a)
	}
	b, err := helmTemplateLookup(t, kc)
	if err != nil {
		t.Fatalf("helm template: %v\n%.2000s", err, b)
	}
	if baselineChecksum(t, a) != baselineChecksum(t, b) {
		t.Error("generated Secret present in the cluster, yet two renders have different checksums: lookup data is not reused")
	}
	// An incomplete generated Secret is completed, never rejected (today's behaviour).
	kc = fakeKube(t, map[string]map[string]string{generated: without(completeBaseline(), "metrics_token")}, generated)
	if out, err := helmTemplateLookup(t, kc); err != nil {
		t.Fatalf("an incomplete generated Secret must be completed, not rejected: %v\n%.2000s", err, out)
	}
}

// existingSecretRevision (rotation under GitOps): the pod annotation is constant
// under `helm template` because the Secret is invisible, so a GitOps-visible
// revision must change it; unset it must change nothing.
func TestHelmSecureBaselineExistingSecretRevision_FeedsPodAnnotation(t *testing.T) {
	base := []string{"secureBaseline.enabled=true", "secureBaseline.existingSecret=" + byoSecretName, "auth.existingSecret=my-auth"}
	render := func(extra ...string) string {
		t.Helper()
		out, err := helmTemplateRaw(t, append(append([]string{}, base...), extra...)...)
		if err != nil {
			t.Fatalf("helm template: %v\n%.2000s", err, out)
		}
		return out
	}
	unset := render()
	rev1 := render("secureBaseline.existingSecretRevision=1")
	rev1Again := render("secureBaseline.existingSecretRevision=1")
	rev2 := render("secureBaseline.existingSecretRevision=2")
	explicitEmpty := render("secureBaseline.existingSecretRevision=")

	if unset != explicitEmpty {
		t.Error("an empty existingSecretRevision changed the render: the default must be unchanged")
	}
	if rev1 != rev1Again {
		t.Error("the same revision renders differently: the output is not deterministic")
	}
	if baselineChecksum(t, rev1) == baselineChecksum(t, unset) {
		t.Error("setting a revision did not change the checksum annotation: a GitOps change would not roll the pods")
	}
	if baselineChecksum(t, rev1) == baselineChecksum(t, rev2) {
		t.Error("bumping the revision did not change the checksum annotation")
	}
	// All three workloads carry it (server, web, bundled postgres).
	if got := len(baselineChecksumRE.FindAllString(rev1, -1)); got != 3 {
		t.Errorf("checksum/secure-baseline appears %d times, want 3 (server, web, postgresql)", got)
	}
	for _, m := range baselineChecksumRE.FindAllStringSubmatch(rev1, -1) {
		if m[1] != baselineChecksum(t, rev1) {
			t.Error("the workloads carry different checksum/secure-baseline values")
		}
	}
	// Only the annotations may differ between unset and rev1.
	strip := func(s string) string { return baselineChecksumRE.ReplaceAllString(s, "checksum/secure-baseline: X") }
	if strip(unset) != strip(rev1) {
		t.Error("the revision changed something other than the checksum annotation")
	}
}

// Silently ignoring the revision would let the operator believe a rotation
// rolls pods that the chart does not manage.
func TestHelmSecureBaselineExistingSecretRevision_RequiresExistingSecret(t *testing.T) {
	out, err := helmTemplateRaw(t, "secureBaseline.enabled=true", "secureBaseline.existingSecretRevision=1")
	if err == nil {
		t.Fatal("helm template succeeded with existingSecretRevision set and no existingSecret")
	}
	if !strings.Contains(out, "secureBaseline.existingSecretRevision is set but secureBaseline.existingSecret is empty") {
		t.Errorf("unhelpful error:\n%s", out)
	}
}
