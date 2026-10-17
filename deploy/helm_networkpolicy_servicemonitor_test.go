package deploy

import (
	"os/exec"
	"strings"
	"testing"
)

func npFindNamed(docs []map[string]any, kind, name string) map[string]any {
	for _, d := range docs {
		meta, _ := d["metadata"].(map[string]any)
		if d["kind"] == kind && meta["name"] == name {
			return d
		}
	}
	return nil
}

func npSlice(v any) []any { s, _ := v.([]any); return s }

// Defaults are unchanged: web ingress stays unrestricted (policyTypes has no
// Ingress), the server accepts only same-namespace pods, and no ServiceMonitor is
// rendered (it needs the Prometheus Operator CRDs).
func TestHelmNetworkPolicy_DefaultsUnchanged(t *testing.T) {
	requireHelm(t)
	docs := helmTemplateDocs(t, chartWithValues(t, ""))
	web := npFindNamed(docs, "NetworkPolicy", "kx-keyorix-web")
	if web == nil {
		t.Fatal("no web NetworkPolicy")
	}
	if got := npNested(web, "spec", "policyTypes"); strings.Contains(strings.ToLower(npJoin(got)), "ingress") {
		t.Errorf("web policyTypes = %v, want no Ingress by default", got)
	}
	if npNested(web, "spec", "ingress") != nil {
		t.Error("web must have no ingress rules by default")
	}
	srv := npFindNamed(docs, "NetworkPolicy", "kx-keyorix-server")
	from := npSlice(npNested(npSlice(npNested(srv, "spec", "ingress"))[0].(map[string]any), "from"))
	if len(from) != 1 {
		t.Errorf("server ingress from = %v, want only the same-namespace podSelector", from)
	}
	if npFindNamed(docs, "ServiceMonitor", "kx-keyorix-server") != nil {
		t.Error("ServiceMonitor must be off by default")
	}
}

func npJoin(v any) string {
	var b strings.Builder
	for _, x := range npSlice(v) {
		b.WriteString(x.(string))
		b.WriteString(" ")
	}
	return b.String()
}

// The ingress-controller and monitoring namespaces are admitted exactly where asked:
// the controller to web (port 80), Prometheus to the server port, nothing else added.
func TestHelmNetworkPolicy_IngressNamespaces(t *testing.T) {
	requireHelm(t)
	docs := helmTemplateDocs(t, chartWithValues(t, ""),
		`networkPolicy.ingress.controllerNamespaceSelector.kubernetes\.io/metadata\.name=ingress-nginx`,
		`networkPolicy.ingress.monitoringNamespaceSelector.kubernetes\.io/metadata\.name=monitoring`)

	web := npFindNamed(docs, "NetworkPolicy", "kx-keyorix-web")
	if !strings.Contains(npJoin(npNested(web, "spec", "policyTypes")), "Ingress") {
		t.Fatalf("web policyTypes = %v, want Ingress", npNested(web, "spec", "policyTypes"))
	}
	rule := npSlice(npNested(web, "spec", "ingress"))[0].(map[string]any)
	from := npSlice(rule["from"])
	if len(from) != 2 {
		t.Fatalf("web ingress from = %v, want own pods + controller namespace", from)
	}
	ns := npNested(from[1].(map[string]any), "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")
	if ns != "ingress-nginx" {
		t.Errorf("web controller namespace = %v, want ingress-nginx", ns)
	}
	if p := npSlice(rule["ports"]); len(p) != 1 || p[0].(map[string]any)["port"] != 80 {
		t.Errorf("web ingress ports = %v, want TCP 80 only", rule["ports"])
	}

	srv := npFindNamed(docs, "NetworkPolicy", "kx-keyorix-server")
	sfrom := npSlice(npNested(npSlice(npNested(srv, "spec", "ingress"))[0].(map[string]any), "from"))
	if len(sfrom) != 2 || npNested(sfrom[1].(map[string]any), "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "monitoring" {
		t.Errorf("server ingress from = %v, want own namespace + monitoring", sfrom)
	}
}

// With an external database the egress rule for it exists only when named, uses
// externalDatabase.port, and the KMS rule uses kmsPorts; the bundled-Postgres case
// never gets a databaseTo rule.
func TestHelmNetworkPolicy_ExternalDatabaseAndKMSEgress(t *testing.T) {
	requireHelm(t)
	chart := chartWithValues(t, "")
	ext := []string{"postgresql.enabled=false", "externalDatabase.host=db.example", "externalDatabase.password=x", "externalDatabase.port=6432"}

	egress := func(sets ...string) []any {
		docs := helmTemplateDocs(t, chart, append(append([]string{}, ext...), sets...)...)
		return npSlice(npNested(npFindNamed(docs, "NetworkPolicy", "kx-keyorix-server"), "spec", "egress"))
	}
	hasPort := func(rules []any, port int) bool {
		for _, r := range rules {
			for _, p := range npSlice(r.(map[string]any)["ports"]) {
				if p.(map[string]any)["port"] == port && r.(map[string]any)["to"] != nil {
					return true
				}
			}
		}
		return false
	}

	if hasPort(egress(), 6432) {
		t.Error("no databaseTo given: the chart must not invent a destination for the external database")
	}
	rules := egress("networkPolicy.egress.databaseTo[0].ipBlock.cidr=10.20.0.0/24")
	if !hasPort(rules, 6432) {
		t.Errorf("databaseTo given: want an egress rule on externalDatabase.port 6432, got %v", rules)
	}
	rules = egress("networkPolicy.egress.kmsTo[0].ipBlock.cidr=10.30.0.5/32", "networkPolicy.egress.kmsPorts={8200}")
	if !hasPort(rules, 8200) || hasPort(rules, 443) {
		t.Errorf("kmsTo with kmsPorts 8200: want a rule on 8200 only, got %v", rules)
	}
	rules = egress("networkPolicy.egress.kmsTo[0].ipBlock.cidr=10.30.0.5/32")
	if !hasPort(rules, 443) {
		t.Errorf("kmsTo without kmsPorts: want the default 443, got %v", rules)
	}

	// Bundled Postgres: databaseTo is ignored (the in-chart rule already covers it).
	docs := helmTemplateDocs(t, chart, "networkPolicy.egress.databaseTo[0].ipBlock.cidr=10.20.0.0/24")
	for _, r := range npSlice(npNested(npFindNamed(docs, "NetworkPolicy", "kx-keyorix-server"), "spec", "egress")) {
		for _, to := range npSlice(r.(map[string]any)["to"]) {
			if npNested(to.(map[string]any), "ipBlock") != nil {
				t.Errorf("bundled Postgres must not get a databaseTo ipBlock rule: %v", r)
			}
		}
	}
}

// The ServiceMonitor scrapes the server's /metrics the way the server serves it:
// HTTPS verified against the chart's certificate plus the generated bearer token with
// the secure baseline, plain HTTP without it; the cross-namespace combination that
// would leave the CA/token unreadable is refused.
func TestHelmServiceMonitor(t *testing.T) {
	requireHelm(t)
	chart := chartWithValues(t, "")
	docs := helmTemplateDocs(t, chart, "monitoring.serviceMonitor.enabled=true", "monitoring.serviceMonitor.labels.release=prom")
	sm := npFindNamed(docs, "ServiceMonitor", "kx-keyorix-server")
	if sm == nil {
		t.Fatal("no ServiceMonitor")
	}
	if npNested(sm, "metadata", "labels", "release") != "prom" {
		t.Errorf("extra labels not applied: %v", npNested(sm, "metadata", "labels"))
	}
	ep := npSlice(npNested(sm, "spec", "endpoints"))[0].(map[string]any)
	if ep["port"] != "http" || ep["path"] != "/metrics" || ep["scheme"] != "https" {
		t.Errorf("endpoint = %v, want port http, /metrics, https", ep)
	}
	if npNested(ep, "tlsConfig", "serverName") != "kx-keyorix-server" ||
		npNested(ep, "tlsConfig", "ca", "secret", "key") != "server.crt" ||
		npNested(ep, "authorization", "credentials", "key") != "metrics_token" {
		t.Errorf("secure-baseline scrape must verify the chart certificate and send the metrics token: %v", ep)
	}
	if npNested(ep, "tlsConfig", "insecureSkipVerify") != nil {
		t.Error("the scrape must never skip TLS verification")
	}

	docs = helmTemplateDocs(t, chart, "monitoring.serviceMonitor.enabled=true", "secureBaseline.enabled=false")
	ep = npSlice(npNested(npFindNamed(docs, "ServiceMonitor", "kx-keyorix-server"), "spec", "endpoints"))[0].(map[string]any)
	if ep["scheme"] != "http" || ep["tlsConfig"] != nil || ep["authorization"] != nil {
		t.Errorf("baseline off: want plain http with no tls/authorization, got %v", ep)
	}

	out, err := npRender(t, "monitoring.serviceMonitor.enabled=true", "monitoring.serviceMonitor.namespace=monitoring")
	if err == nil || !strings.Contains(out, "differs from the release namespace") {
		t.Errorf("cross-namespace ServiceMonitor with the baseline must be refused, got err=%v\n%s", err, out)
	}
}

// npNested walks nested maps by key path, returning nil when any step is missing.
func npNested(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, _ := cur.(map[string]any)
		cur = mm[p]
	}
	return cur
}

// npRender renders the chart with the default bundled database plus the given --set
// values and returns the raw output and error, for cases that must be refused.
func npRender(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	args := []string{"template", "kx", chartWithValues(t, ""), "--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary, temp chart path and test flags
	return string(out), err
}
